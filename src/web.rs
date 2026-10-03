//! Admin panel + JSON API. Password login -> session cookie (HttpOnly,
//! SameSite=Strict) + per-session CSRF token. A bearer API key also works for
//! automation (no CSRF needed because it is not a cookie).
use crate::{
    auth::{password_ok, verify_pw},
    dns,
    model::*,
    policy::{norm, valid_domain},
    state::*,
    sys, wire,
};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse, Response,
    },
    routing::{delete, get, post, put},
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::{atomic::Ordering::Relaxed, Arc},
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;
use tokio_rustls::TlsAcceptor;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

pub type S = Arc<AppState>;

const APP: &str = include_str!("../assets/app.html");
const LOGIN: &str = include_str!("../assets/login.html");

// ---------- plumbing ----------

pub struct ApiErr(StatusCode, String);
impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
impl From<String> for ApiErr {
    fn from(s: String) -> Self {
        ApiErr(StatusCode::BAD_REQUEST, s)
    }
}
impl From<anyhow::Error> for ApiErr {
    fn from(e: anyhow::Error) -> Self {
        ApiErr(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}
fn ie<E: std::fmt::Display>(e: E) -> ApiErr {
    ApiErr(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
fn bad(m: &str) -> ApiErr {
    ApiErr(StatusCode::BAD_REQUEST, m.into())
}
fn nf() -> ApiErr {
    ApiErr(StatusCode::NOT_FOUND, "not found".into())
}
type R<T = StatusCode> = Result<T, ApiErr>;
const OK: R = Ok(StatusCode::NO_CONTENT);

#[derive(Clone)]
struct Ctx {
    sid: Option<String>,
    csrf: String,
    ip: IpAddr,
}

pub fn client_ip(st: &AppState, peer: SocketAddr, h: &HeaderMap) -> IpAddr {
    if peer.ip().is_loopback() && st.live.load().settings.trust_forwarded {
        if let Some(first) = h.get("x-forwarded-for").and_then(|v| v.to_str().ok()).and_then(|v| v.split(',').next()) {
            if let Ok(ip) = first.trim().parse() {
                return ip;
            }
        }
    }
    peer.ip()
}

fn cookie(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(header::COOKIE)?.to_str().ok()?.split(';').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

async fn sec_headers(req: Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"),
        );
    }
    r
}

async fn guard(State(st): State<S>, ConnectInfo(peer): ConnectInfo<SocketAddr>, mut req: Request, next: Next) -> Response {
    let ip = client_ip(&st, peer, req.headers());
    let bearer = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).map(str::to_string);
    if let Some(k) = bearer {
        if st.auth.check_api_key(&k) {
            req.extensions_mut().insert(Ctx { sid: None, csrf: String::new(), ip });
            return next.run(req).await;
        }
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let idle = st.live.load().settings.session_idle_min as i64 * 60;
    let Some(tok) = cookie(req.headers(), "dg_s") else { return StatusCode::UNAUTHORIZED.into_response() };
    let Some((csrf, sid)) = st.sessions.check(&tok, idle) else { return StatusCode::UNAUTHORIZED.into_response() };
    if req.method() != Method::GET {
        let ok = req.headers().get("x-csrf").and_then(|v| v.to_str().ok()).map_or(false, |v| ct_eq(v.as_bytes(), csrf.as_bytes()));
        if !ok {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    req.extensions_mut().insert(Ctx { sid: Some(sid), csrf, ip });
    next.run(req).await
}

// ---------- login / session ----------

async fn panel(State(st): State<S>, headers: HeaderMap) -> Html<&'static str> {
    let idle = st.live.load().settings.session_idle_min as i64 * 60;
    let ok = cookie(&headers, "dg_s").and_then(|t| st.sessions.check(&t, idle)).is_some();
    Html(if ok { APP } else { LOGIN })
}

#[derive(Deserialize)]
struct LoginIn {
    password: String,
    #[serde(default)]
    code: String,
}

fn session_cookie(st: &AppState, token: &str, max_age: u64) -> String {
    format!(
        "dg_s={token}; Path=/{}; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        st.cfg.admin_path,
        if st.cfg.web_tls { "; Secure" } else { "" }
    )
}

async fn login(State(st): State<S>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(b): Json<LoginIn>) -> Response {
    let ip = client_ip(&st, peer, &headers);
    let (max_fails, lock_min) = {
        let l = st.live.load();
        (l.settings.login_max_fails, l.settings.login_lock_min)
    };
    if let Some(left) = st.lockouts.locked(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "locked", "retry_secs": left }))).into_response();
    }
    let hash = st.auth.password_hash();
    let pw = b.password.clone();
    let pw_ok = tokio::task::spawn_blocking(move || verify_pw(&hash, &pw)).await.unwrap_or(false);
    if pw_ok && st.auth.totp_enabled() && b.code.trim().is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "need_totp", "need_totp": true }))).into_response();
    }
    let ok = pw_ok && (!st.auth.totp_enabled() || st.auth.totp_check(&b.code));
    if !ok {
        let locked = st.lockouts.fail(ip, max_fails, lock_min);
        st.audit.log(ip, "login_failed", if locked { "address locked" } else { "" });
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "bad_credentials" }))).into_response();
    }
    st.lockouts.ok(ip);
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("");
    let (token, _csrf) = st.sessions.create(ip, ua);
    st.audit.log(ip, "login", "");
    ([(header::SET_COOKIE, session_cookie(&st, &token, 86_400))], Json(json!({ "ok": true }))).into_response()
}

async fn logout(State(st): State<S>, Extension(cx): Extension<Ctx>) -> Response {
    if let Some(s) = &cx.sid {
        st.sessions.revoke(s);
    }
    st.audit.log(cx.ip, "logout", "");
    ([(header::SET_COOKIE, session_cookie(&st, "", 0))], StatusCode::NO_CONTENT).into_response()
}

async fn me(State(st): State<S>, Extension(cx): Extension<Ctx>) -> Json<Value> {
    Json(json!({
        "csrf": cx.csrf, "session": cx.sid, "totp": st.auth.totp_enabled(),
        "version": env!("CARGO_PKG_VERSION"), "admin_path": st.cfg.admin_path,
        "public_ip": st.cfg.public_ip, "web_port": st.cfg.web_bind.port(), "ip": cx.ip,
    }))
}

// ---------- dashboard ----------

async fn overview(State(st): State<S>) -> Json<Value> {
    let live = st.live.load_full();
    let now = now_secs();
    let mut c = HashMap::<&str, u32>::new();
    for x in live.by_id.values() {
        *c.entry(match x.status(now) {
            Status::Active => "active",
            Status::Disabled => "disabled",
            Status::Expired => "expired",
            Status::OverQuota => "over_quota",
        })
        .or_default() += 1;
    }
    let (np, nb) = live.rules.counts();
    let cfg = &st.cfg;
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime": st.started.elapsed().as_secs(),
        "stats": st.stats_json(),
        "cache_entries": st.cache.entry_count(),
        "clients": { "total": live.by_id.len(), "by_status": c },
        "rules": { "proxied": np, "blocked": nb, "records": live.records.len() },
        "sys": { "rss": sys::rss_bytes(), "mem_total": sys::mem_total(), "load": sys::loadavg(), "threads": sys::threads() },
        "tls": st.tls.info(),
        "allow_all": live.settings.allow_all,
        "listen": { "dns": cfg.dns_bind, "dot": cfg.dot_bind, "relay": cfg.proxy_bind, "http_relay": cfg.http_relay_bind, "web": cfg.web_bind, "public_ip": cfg.public_ip },
    }))
}

async fn series(State(st): State<S>) -> Json<Vec<Sample>> {
    Json(st.series.read().unwrap().iter().cloned().collect())
}

fn top_n(m: HashMap<String, u32>, n: usize) -> Vec<Value> {
    let mut v: Vec<_> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.into_iter().take(n).map(|(k, c)| json!({ "key": k, "count": c })).collect()
}

async fn top(State(st): State<S>) -> Json<Value> {
    let (mut dom, mut cli, mut act) = (HashMap::new(), HashMap::new(), HashMap::new());
    for e in st.log_ring.read().unwrap().iter() {
        *dom.entry(e.name.clone()).or_default() += 1;
        *cli.entry(e.client.as_deref().map(str::to_string).unwrap_or_else(|| e.ip.to_string())).or_default() += 1;
        *act.entry(e.action.to_string()).or_default() += 1;
    }
    Json(json!({ "domains": top_n(dom, 10), "clients": top_n(cli, 10), "actions": top_n(act, 10) }))
}

async fn logs(State(st): State<S>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let limit = q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(200usize).min(2000);
    let needle = q.get("q").map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    let action = q.get("action").cloned().unwrap_or_default();
    let client = q.get("client").map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    let r = st.log_ring.read().unwrap();
    let out: Vec<&LogEntry> = r
        .iter()
        .rev()
        .filter(|e| needle.is_empty() || e.name.contains(&needle))
        .filter(|e| action.is_empty() || e.action == action)
        .filter(|e| client.is_empty() || e.ip.to_string().contains(&client) || e.client.as_deref().map_or(false, |c| c.to_ascii_lowercase().contains(&client)))
        .take(limit)
        .collect();
    Json(json!(out))
}

async fn stream(State(st): State<S>) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let s = BroadcastStream::new(st.log_bcast.subscribe()).filter_map(|r| r.ok().map(|j| Ok::<Event, Infallible>(Event::default().data(j))));
    Sse::new(s).keep_alive(KeepAlive::default())
}

// ---------- clients ----------

fn client_json(c: &ClientRt, now: i64) -> Value {
    let r = &c.rec;
    json!({
        "id": r.id, "name": r.name, "note": r.note, "ips": r.ips, "max_ips": r.max_ips,
        "token": r.token, "doh_token": r.doh_token, "enabled": r.enabled, "expires_at": r.expires_at,
        "quota_bytes": r.quota_bytes, "presets": r.presets, "custom_proxied": r.custom_proxied,
        "custom_blocked": r.custom_blocked, "created_at": r.created_at, "status": c.status(now),
        "usage": { "up": c.usage.up.load(Relaxed), "down": c.usage.down.load(Relaxed), "queries": c.usage.queries.load(Relaxed) },
    })
}

async fn clients_list(State(st): State<S>) -> Json<Value> {
    let live = st.live.load_full();
    let now = now_secs();
    let list: Vec<Value> = st.snapshot().clients.iter().filter_map(|c| live.by_id.get(&c.id)).map(|c| client_json(c, now)).collect();
    Json(json!(list))
}

fn t() -> bool {
    true
}
fn one() -> u8 {
    1
}

#[derive(Deserialize)]
struct ClientIn {
    name: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    ips: Vec<IpAddr>,
    #[serde(default = "one")]
    max_ips: u8,
    #[serde(default = "t")]
    enabled: bool,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    quota_bytes: u64,
    #[serde(default)]
    presets: Option<Vec<String>>,
    #[serde(default)]
    custom_proxied: Vec<String>,
    #[serde(default)]
    custom_blocked: Vec<String>,
}

fn clean_domains(list: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for d in list {
        let n = norm(d);
        if n.is_empty() {
            continue;
        }
        if !valid_domain(&n) {
            return Err(format!("invalid domain: {d}"));
        }
        out.push(n);
    }
    Ok(out)
}

fn apply_in(rec: &mut ClientRec, b: ClientIn) -> Result<(), String> {
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err("name: 1 to 64 characters".into());
    }
    if !(1..=16).contains(&b.max_ips) || b.ips.len() > b.max_ips as usize {
        return Err("max_ips must be 1..16 and >= number of IPs".into());
    }
    if b.note.chars().count() > 300 {
        return Err("note too long".into());
    }
    rec.name = name.to_string();
    rec.note = b.note;
    rec.ips = b.ips;
    rec.max_ips = b.max_ips;
    rec.enabled = b.enabled;
    rec.expires_at = b.expires_at;
    rec.quota_bytes = b.quota_bytes;
    rec.presets = b.presets;
    rec.custom_proxied = clean_domains(&b.custom_proxied)?;
    rec.custom_blocked = clean_domains(&b.custom_blocked)?;
    Ok(())
}

fn check_client(p: &Persist, rec: &ClientRec) -> Result<(), String> {
    if let Some(list) = &rec.presets {
        let known: HashSet<String> = all_presets(p).into_iter().map(|v| v.name).collect();
        if let Some(x) = list.iter().find(|x| !known.contains(*x)) {
            return Err(format!("unknown preset: {x}"));
        }
    }
    for ip in &rec.ips {
        if p.clients.iter().any(|c| c.id != rec.id && c.ips.contains(ip)) {
            return Err(format!("{ip} already belongs to another client"));
        }
    }
    Ok(())
}

fn new_rec(name: &str) -> (ClientRec, String) {
    let secret = rand_hex(8);
    (
        ClientRec {
            id: uuid_v4(), name: name.into(), note: String::new(), ips: vec![], max_ips: 1,
            token: rand_hex(12), doh_token: rand_hex(16), secret_hash: sha256_hex(&secret),
            enabled: true, expires_at: None, quota_bytes: 0, presets: None,
            custom_proxied: vec![], custom_blocked: vec![], created_at: now_secs(),
        },
        secret,
    )
}

async fn client_create(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(b): Json<ClientIn>) -> R<Json<Value>> {
    let (mut rec, secret) = new_rec("x");
    apply_in(&mut rec, b)?;
    let (r2, id) = (rec.clone(), rec.id.clone());
    st.mutate(|p| {
        check_client(p, &r2)?;
        p.clients.push(r2);
        Ok(())
    })?;
    st.audit.log(cx.ip, "client_create", &rec.name);
    let live = st.live.load_full();
    let c = live.by_id.get(&id).ok_or_else(nf)?;
    Ok(Json(json!({ "client": client_json(c, now_secs()), "secret": secret })))
}

async fn client_update(State(st): State<S>, Extension(cx): Extension<Ctx>, Path(id): Path<String>, Json(b): Json<ClientIn>) -> R {
    let id2 = id.clone();
    st.mutate(|p| {
        let i = p.clients.iter().position(|c| c.id == id2).ok_or("client not found")?;
        let mut rec = p.clients[i].clone();
        apply_in(&mut rec, b)?;
        check_client(p, &rec)?;
        p.clients[i] = rec;
        Ok(())
    })?;
    st.audit.log(cx.ip, "client_update", &id);
    OK
}

async fn client_delete(State(st): State<S>, Extension(cx): Extension<Ctx>, Path(id): Path<String>) -> R {
    st.mutate(|p| {
        let n = p.clients.len();
        p.clients.retain(|c| c.id != id);
        if p.clients.len() == n { Err("client not found".into()) } else { Ok(()) }
    })?;
    st.usage.remove(&id);
    st.audit.log(cx.ip, "client_delete", &id);
    OK
}

#[derive(Deserialize)]
struct ActionIn {
    action: String,
}

async fn client_action(State(st): State<S>, Extension(cx): Extension<Ctx>, Path(id): Path<String>, Json(b): Json<ActionIn>) -> R<Json<Value>> {
    let mut secret: Option<String> = None;
    let act = b.action.clone();
    let id2 = id.clone();
    let new_secret = rand_hex(8);
    st.mutate(|p| {
        let c = p.clients.iter_mut().find(|c| c.id == id2).ok_or("client not found")?;
        match act.as_str() {
            "suspend" => c.enabled = false,
            "resume" => c.enabled = true,
            "clear_ips" => c.ips.clear(),
            "regen_tokens" => {
                c.token = rand_hex(12);
                c.doh_token = rand_hex(16);
            }
            "regen_secret" => {
                c.secret_hash = sha256_hex(&new_secret);
                secret = Some(new_secret.clone());
            }
            "reset_usage" => {}
            _ => return Err("unknown action".into()),
        }
        Ok(())
    })?;
    if b.action == "reset_usage" {
        if let Some(u) = st.usage.get(&id) {
            u.reset();
        }
        st.save_usage();
    }
    st.audit.log(cx.ip, &format!("client_{}", b.action), &id);
    Ok(Json(json!({ "secret": secret })))
}

#[derive(Deserialize)]
struct ImportIn {
    text: String,
}

async fn clients_import(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(b): Json<ImportIn>) -> R<Json<Value>> {
    let mut recs = Vec::new();
    for line in b.text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let toks: Vec<&str> = line.split(|c: char| c.is_whitespace() || c == ',').filter(|s| !s.is_empty()).collect();
        let Some(ip) = toks.iter().find_map(|t| t.parse::<IpAddr>().ok()) else { continue };
        let name: Vec<&str> = toks.iter().copied().filter(|t| t.parse::<IpAddr>().is_err()).collect();
        let name = if name.is_empty() { ip.to_string() } else { name.join(" ") };
        let (mut rec, _) = new_rec(&name.chars().take(64).collect::<String>());
        rec.ips = vec![ip];
        recs.push(rec);
    }
    let mut added = 0usize;
    st.mutate(|p| {
        for r in recs {
            if check_client(p, &r).is_ok() {
                p.clients.push(r);
                added += 1;
            }
        }
        Ok(())
    })?;
    st.audit.log(cx.ip, "clients_import", &added.to_string());
    Ok(Json(json!({ "added": added })))
}

// ---------- policies ----------

async fn presets_list(State(st): State<S>) -> Json<Value> {
    let p = st.snapshot();
    let v: Vec<Value> = all_presets(&p)
        .into_iter()
        .map(|x| {
            let on = preset_enabled(&p, &x);
            json!({ "name": x.name, "title": x.title, "group": x.group, "builtin": x.builtin, "default_on": x.default_on, "enabled": on, "domains": x.domains })
        })
        .collect();
    Json(json!(v))
}

#[derive(Deserialize)]
struct Toggle {
    enabled: bool,
}

async fn preset_toggle(State(st): State<S>, Extension(cx): Extension<Ctx>, Path(name): Path<String>, Json(b): Json<Toggle>) -> R {
    st.mutate(|p| {
        if !all_presets(p).iter().any(|v| v.name == name) {
            return Err("unknown preset".into());
        }
        p.presets.insert(name.clone(), b.enabled);
        Ok(())
    })?;
    st.audit.log(cx.ip, "preset_toggle", &format!("{} {}", name, b.enabled));
    OK
}

async fn preset_custom_save(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(mut b): Json<CustomPreset>) -> R {
    b.name = b.name.trim().to_ascii_lowercase();
    let ok = !b.name.is_empty() && b.name.len() <= 32 && b.name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-');
    if !ok || crate::presets::PRESETS.iter().any(|x| x.name == b.name) {
        return Err(bad("name: a-z 0-9 _ - (max 32), and must not match a built-in preset"));
    }
    b.title = b.title.trim().chars().take(60).collect();
    if b.title.is_empty() {
        b.title = b.name.clone();
    }
    b.domains = clean_domains(&b.domains)?;
    let n = b.name.clone();
    st.mutate(|p| {
        p.custom_presets.retain(|x| x.name != b.name);
        p.custom_presets.push(b);
        Ok(())
    })?;
    st.audit.log(cx.ip, "preset_custom_save", &n);
    OK
}

async fn preset_custom_delete(State(st): State<S>, Extension(cx): Extension<Ctx>, Path(name): Path<String>) -> R {
    st.mutate(|p| {
        p.custom_presets.retain(|x| x.name != name);
        p.presets.remove(&name);
        for c in p.clients.iter_mut() {
            if let Some(l) = c.presets.as_mut() {
                l.retain(|x| *x != name);
            }
        }
        Ok(())
    })?;
    st.audit.log(cx.ip, "preset_custom_delete", &name);
    OK
}

async fn rules_get(State(st): State<S>) -> Json<Value> {
    let p = st.snapshot();
    Json(json!({ "proxied": p.custom_proxied, "blocked": p.custom_blocked }))
}

#[derive(Deserialize)]
struct RulesIn {
    proxied: Vec<String>,
    blocked: Vec<String>,
}

async fn rules_put(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(b): Json<RulesIn>) -> R {
    let (pr, bl) = (clean_domains(&b.proxied)?, clean_domains(&b.blocked)?);
    st.mutate(|p| {
        p.custom_proxied = pr;
        p.custom_blocked = bl;
        Ok(())
    })?;
    st.audit.log(cx.ip, "rules_update", "");
    OK
}

#[derive(Deserialize)]
struct RulesImport {
    text: String,
    target: String,
}

async fn rules_import(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(b): Json<RulesImport>) -> R<Json<Value>> {
    let list = parse_domain_list(&b.text);
    let mut added = 0usize;
    let target = b.target.clone();
    st.mutate(|p| {
        let dst = match target.as_str() {
            "blocked" => &mut p.custom_blocked,
            "proxied" => &mut p.custom_proxied,
            _ => return Err("target must be blocked or proxied".into()),
        };
        let mut seen: HashSet<String> = dst.iter().cloned().collect();
        for d in list {
            if seen.insert(d.clone()) {
                dst.push(d);
                added += 1;
            }
        }
        Ok(())
    })?;
    st.audit.log(cx.ip, "rules_import", &format!("{} +{}", b.target, added));
    Ok(Json(json!({ "added": added })))
}

async fn records_get(State(st): State<S>) -> Json<Vec<StaticRecord>> {
    Json(st.snapshot().records)
}

async fn records_put(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(mut v): Json<Vec<StaticRecord>>) -> R {
    if v.len() > 2000 {
        return Err(bad("max 2000 records"));
    }
    for r in v.iter_mut() {
        r.name = norm(&r.name);
        r.rtype = r.rtype.to_ascii_uppercase();
        if !valid_domain(&r.name) || !(1..=86_400).contains(&r.ttl) {
            return Err(bad(&format!("bad name or ttl: {}", r.name)));
        }
        let ok = match r.rtype.as_str() {
            "A" => r.value.parse::<std::net::Ipv4Addr>().is_ok(),
            "AAAA" => r.value.parse::<std::net::Ipv6Addr>().is_ok(),
            "CNAME" => wire::encode_name(&r.value).is_some(),
            "TXT" => !r.value.is_empty() && r.value.len() <= 1000,
            _ => false,
        };
        if !ok {
            return Err(bad(&format!("invalid {} value for {}", r.rtype, r.name)));
        }
    }
    st.mutate(|p| {
        p.records = v;
        Ok(())
    })?;
    st.audit.log(cx.ip, "records_update", "");
    OK
}

#[derive(Deserialize)]
struct TestIn {
    name: String,
    #[serde(default)]
    qtype: String,
    ip: IpAddr,
}

async fn dns_test(State(st): State<S>, Json(b): Json<TestIn>) -> R<Json<Value>> {
    let qt = if b.qtype.is_empty() { wire::A } else { wire::parse_qtype(&b.qtype).ok_or_else(|| bad("unsupported qtype"))? };
    if !valid_domain(&norm(&b.name)) {
        return Err(bad("invalid name"));
    }
    Ok(Json(dns::dry_run(&st, b.ip, &b.name, qt).await))
}

// ---------- settings, upstreams, cache ----------

async fn settings_get(State(st): State<S>) -> Json<Settings> {
    Json(st.live.load().settings.clone())
}

async fn settings_put(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(b): Json<Settings>) -> R {
    b.validate()?;
    st.mutate(|p| {
        p.settings = b;
        Ok(())
    })?;
    st.audit.log(cx.ip, "settings_update", "");
    OK
}

async fn upstreams(State(st): State<S>) -> Json<Value> {
    let live = st.live.load_full();
    let v: Vec<Value> = live
        .settings
        .upstreams
        .iter()
        .map(|a| {
            let s = st.upstream_stat(*a);
            json!({ "addr": a, "wins": s.wins.load(Relaxed), "timeouts": s.timeouts.load(Relaxed), "rtt_ms": s.rtt_us.load(Relaxed) as f64 / 1000.0 })
        })
        .collect();
    Json(json!(v))
}

async fn bench(State(st): State<S>) -> R<Json<Value>> {
    let ups = st.live.load().settings.upstreams.clone();
    let names = ["google.com", "cloudflare.com", "wikipedia.org", "github.com", "amazon.com"];
    let mut res = Vec::new();
    for up in ups {
        let (mut rtts, mut lost) = (Vec::<f64>::new(), 0u32);
        for n in names {
            let sock = UdpSocket::bind(if up.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await.map_err(ie)?;
            let pkt = wire::build_query(rand::random::<u16>(), n, wire::A).ok_or_else(|| bad("query"))?;
            let t0 = Instant::now();
            let _ = sock.send_to(&pkt, up).await;
            let mut buf = [0u8; 2048];
            match tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) if from == up && len >= 12 => rtts.push(t0.elapsed().as_secs_f64() * 1000.0),
                _ => lost += 1,
            }
        }
        rtts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        res.push(json!({ "addr": up, "median_ms": rtts.get(rtts.len() / 2), "best_ms": rtts.first(), "lost": lost, "sent": names.len() }));
    }
    Ok(Json(json!(res)))
}

async fn cache_info(State(st): State<S>) -> Json<Value> {
    st.cache.run_pending_tasks();
    Json(json!({
        "entries": st.cache.entry_count(), "capacity": st.cfg.cache_entries,
        "hits": st.stats.cache_hits.load(Relaxed), "stale_hits": st.stats.stale_hits.load(Relaxed),
        "misses": st.stats.direct.load(Relaxed),
    }))
}

async fn cache_flush(State(st): State<S>, Extension(cx): Extension<Ctx>) -> R {
    st.cache.invalidate_all();
    st.dns_cache.invalidate_all();
    st.audit.log(cx.ip, "cache_flush", "");
    OK
}

// ---------- TLS ----------

async fn tls_get(State(st): State<S>) -> Json<Value> {
    Json(json!({ "info": st.tls.info(), "loaded": st.tls.loaded(), "web_tls": st.cfg.web_tls, "dot": st.cfg.dot_bind }))
}

#[derive(Deserialize)]
struct PemIn {
    cert: String,
    key: String,
}

async fn tls_put(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(b): Json<PemIn>) -> R {
    st.tls.install_pem(&b.cert, &b.key, "uploaded").map_err(|e| bad(&e.to_string()))?;
    st.audit.log(cx.ip, "tls_upload", &st.tls.info().subject);
    OK
}

#[derive(Deserialize)]
struct NamesIn {
    #[serde(default)]
    names: Vec<String>,
}

async fn tls_selfsigned(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(b): Json<NamesIn>) -> R {
    if b.names.len() > 20 || b.names.iter().any(|n| n.len() > 253 || n.contains(' ')) {
        return Err(bad("invalid names"));
    }
    st.tls.self_signed(b.names).map_err(ie)?;
    st.audit.log(cx.ip, "tls_selfsigned", "");
    OK
}

// ---------- security ----------

#[derive(Deserialize)]
struct PwIn {
    current: String,
    new: String,
}

async fn password(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(b): Json<PwIn>) -> R {
    password_ok(&b.new).map_err(bad)?;
    let hash = st.auth.password_hash();
    let cur = b.current.clone();
    if !tokio::task::spawn_blocking(move || verify_pw(&hash, &cur)).await.unwrap_or(false) {
        st.audit.log(cx.ip, "password_change_failed", "");
        return Err(ApiErr(StatusCode::FORBIDDEN, "current password is wrong".into()));
    }
    let (st2, new) = (st.clone(), b.new);
    tokio::task::spawn_blocking(move || st2.auth.set_password(&new)).await.map_err(ie)?.map_err(ie)?;
    st.sessions.revoke_except(cx.sid.as_deref());
    st.audit.log(cx.ip, "password_changed", "other sessions revoked");
    OK
}

async fn totp_setup(State(st): State<S>) -> R<Json<Value>> {
    let secret = st.auth.totp_begin().map_err(ie)?;
    Ok(Json(json!({ "secret": secret, "uri": format!("otpauth://totp/dnsgate:admin?secret={secret}&issuer=dnsgate") })))
}

#[derive(Deserialize)]
struct CodeIn {
    code: String,
    #[serde(default)]
    password: String,
}

async fn totp_enable(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(b): Json<CodeIn>) -> R {
    if !st.auth.totp_check(&b.code) {
        return Err(bad("wrong code"));
    }
    st.auth.totp_set_enabled(true).map_err(ie)?;
    st.audit.log(cx.ip, "2fa_enabled", "");
    OK
}

async fn totp_disable(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(b): Json<CodeIn>) -> R {
    let hash = st.auth.password_hash();
    let pw = b.password.clone();
    if !tokio::task::spawn_blocking(move || verify_pw(&hash, &pw)).await.unwrap_or(false) || !st.auth.totp_check(&b.code) {
        return Err(ApiErr(StatusCode::FORBIDDEN, "password or code is wrong".into()));
    }
    st.auth.totp_set_enabled(false).map_err(ie)?;
    st.audit.log(cx.ip, "2fa_disabled", "");
    OK
}

async fn apikey_rotate(State(st): State<S>, Extension(cx): Extension<Ctx>) -> R<Json<Value>> {
    let k = st.auth.rotate_api_key().map_err(ie)?;
    st.audit.log(cx.ip, "apikey_rotated", "");
    Ok(Json(json!({ "api_key": k })))
}

async fn sessions_list(State(st): State<S>, Extension(cx): Extension<Ctx>) -> Json<Value> {
    let v: Vec<Value> = st.sessions.list().into_iter().map(|(id, s)| json!({ "id": id, "created": s.created, "last": s.last, "ip": s.ip, "ua": s.ua, "current": cx.sid.as_deref() == Some(id.as_str()) })).collect();
    Json(json!(v))
}

async fn session_revoke(State(st): State<S>, Path(id): Path<String>) -> R {
    st.sessions.revoke(&id);
    OK
}

async fn sessions_revoke_others(State(st): State<S>, Extension(cx): Extension<Ctx>) -> R {
    st.sessions.revoke_except(cx.sid.as_deref());
    OK
}

async fn lockouts_list(State(st): State<S>) -> Json<Value> {
    Json(json!(st.lockouts.list().into_iter().map(|(ip, f, left)| json!({ "ip": ip, "fails": f, "retry_secs": left })).collect::<Vec<_>>()))
}

async fn lockouts_clear(State(st): State<S>, Extension(cx): Extension<Ctx>) -> R {
    st.lockouts.clear();
    st.audit.log(cx.ip, "lockouts_cleared", "");
    OK
}

async fn audit(State(st): State<S>) -> Json<Value> {
    Json(json!(st.audit.recent()))
}

// ---------- backup ----------

async fn backup(State(st): State<S>, Extension(cx): Extension<Ctx>) -> Response {
    st.audit.log(cx.ip, "backup_download", "");
    (
        [(header::CONTENT_TYPE, "application/json"), (header::CONTENT_DISPOSITION, "attachment; filename=\"dnsgate-backup.json\"")],
        Json(st.snapshot()),
    )
        .into_response()
}

async fn restore(State(st): State<S>, Extension(cx): Extension<Ctx>, Json(b): Json<Persist>) -> R {
    b.settings.validate()?;
    st.mutate(|p| {
        *p = b;
        Ok(())
    })?;
    st.audit.log(cx.ip, "restore", "");
    OK
}

// ---------- assembly ----------

pub async fn serve(st: S) -> anyhow::Result<()> {
    let base = format!("/{}", st.cfg.admin_path);
    let api = Router::new()
        .route("/me", get(me))
        .route("/logout", post(logout))
        .route("/overview", get(overview))
        .route("/series", get(series))
        .route("/top", get(top))
        .route("/logs", get(logs))
        .route("/stream", get(stream))
        .route("/clients", get(clients_list).post(client_create))
        .route("/clients/import", post(clients_import))
        .route("/clients/:id", put(client_update).delete(client_delete))
        .route("/clients/:id/action", post(client_action))
        .route("/presets", get(presets_list))
        .route("/presets/custom", post(preset_custom_save))
        .route("/presets/custom/:name", delete(preset_custom_delete))
        .route("/presets/:name", put(preset_toggle))
        .route("/rules", get(rules_get).put(rules_put))
        .route("/rules/import", post(rules_import))
        .route("/records", get(records_get).put(records_put))
        .route("/test", post(dns_test))
        .route("/settings", get(settings_get).put(settings_put))
        .route("/upstreams", get(upstreams))
        .route("/upstreams/benchmark", post(bench))
        .route("/cache", get(cache_info))
        .route("/cache/flush", post(cache_flush))
        .route("/tls", get(tls_get).put(tls_put))
        .route("/tls/selfsigned", post(tls_selfsigned))
        .route("/password", post(password))
        .route("/2fa/setup", post(totp_setup))
        .route("/2fa/enable", post(totp_enable))
        .route("/2fa/disable", post(totp_disable))
        .route("/apikey/rotate", post(apikey_rotate))
        .route("/sessions", get(sessions_list))
        .route("/sessions/revoke-others", post(sessions_revoke_others))
        .route("/sessions/:id", delete(session_revoke))
        .route("/lockouts", get(lockouts_list))
        .route("/lockouts/clear", post(lockouts_clear))
        .route("/audit", get(audit))
        .route("/backup", get(backup))
        .route("/restore", post(restore))
        .route_layer(middleware::from_fn_with_state(st.clone(), guard))
        .layer(DefaultBodyLimit::max(64 << 20));

    let app = Router::new()
        .route(&base, get(panel))
        .route(&format!("{base}/"), get(panel))
        .route(&format!("{base}/api/login"), post(login))
        .nest(&format!("{base}/api/v1"), api)
        .merge(crate::public::routes())
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(middleware::from_fn(sec_headers))
        .with_state(st.clone());

    let listener = tokio::net::TcpListener::bind(st.cfg.web_bind).await?;
    let acceptor = if st.cfg.web_tls { Some(TlsAcceptor::from(st.tls.server_config(&[b"h2", b"http/1.1"])?)) } else { None };
    tracing::info!("panel on {}://{}{}", if acceptor.is_some() { "https" } else { "http" }, st.cfg.web_bind, base);
    crate::net::serve_http(listener, acceptor, app).await
}
