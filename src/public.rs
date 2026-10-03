//! Public routes: subscriber portal, IP self-registration and DNS-over-HTTPS.
use crate::{
    dns::{self, Src},
    model::*,
    state::AppState,
    web::client_ip,
};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::json;
use std::{collections::HashMap, net::{IpAddr, SocketAddr}, sync::Arc};

type S = Arc<AppState>;

pub fn routes() -> Router<S> {
    Router::new()
        .route("/", get(|| async { StatusCode::NOT_FOUND }))
        .route("/robots.txt", get(|| async { "User-agent: *\nDisallow: /\n" }))
        .route("/sub/:token", get(portal))
        .route("/ip/:token", get(ip_help).post(register))
        .route("/dns-query", get(doh_get).post(doh_post))
        .route("/dns-query/:token", get(doh_get_t).post(doh_post_t))
}

fn err(code: u16, m: &str) -> Response {
    (StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST), Json(json!({ "error": m }))).into_response()
}

// ---------- DoH ----------

async fn doh_core(st: &S, peer: SocketAddr, h: &HeaderMap, token: Option<&str>, pkt: Vec<u8>) -> Response {
    if pkt.len() < 12 || pkt.len() > 4096 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let ip = client_ip(st, peer, h);
    match dns::handle(st, &Src { ip, doh: token }, &pkt).await {
        Some(b) => ([(header::CONTENT_TYPE, "application/dns-message"), (header::CACHE_CONTROL, "no-store")], b).into_response(),
        None => StatusCode::BAD_REQUEST.into_response(),
    }
}

fn dns_param(q: &HashMap<String, String>) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(q.get("dns")?).ok()
}

async fn doh_get(State(st): State<S>, ConnectInfo(peer): ConnectInfo<SocketAddr>, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    match dns_param(&q) {
        Some(p) => doh_core(&st, peer, &h, None, p).await,
        None => StatusCode::BAD_REQUEST.into_response(),
    }
}
async fn doh_get_t(State(st): State<S>, ConnectInfo(peer): ConnectInfo<SocketAddr>, h: HeaderMap, Path(t): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    match dns_param(&q) {
        Some(p) => doh_core(&st, peer, &h, Some(&t), p).await,
        None => StatusCode::BAD_REQUEST.into_response(),
    }
}
async fn doh_post(State(st): State<S>, ConnectInfo(peer): ConnectInfo<SocketAddr>, h: HeaderMap, body: Bytes) -> Response {
    doh_core(&st, peer, &h, None, body.to_vec()).await
}
async fn doh_post_t(State(st): State<S>, ConnectInfo(peer): ConnectInfo<SocketAddr>, h: HeaderMap, Path(t): Path<String>, body: Bytes) -> Response {
    doh_core(&st, peer, &h, Some(&t), body.to_vec()).await
}

// ---------- portal ----------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}
fn gb(b: u64) -> String {
    format!("{:.2} GB", b as f64 / 1_073_741_824.0)
}
fn date(ts: i64) -> String {
    let (y, m, d) = civil_from_days(ts.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

const PAGE: &str = r#"<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>{{TITLE}}</title><style>
:root{--bg:#eef1f4;--ink:#14202b;--mut:#5b6b7a;--line:#cfd7de;--card:#fff;--acc:#1f5eff;--bad:#c62828;--ok:#1b7f4b}
@media(prefers-color-scheme:dark){:root{--bg:#10161c;--ink:#e6edf3;--mut:#8b9aa8;--line:#26323d;--card:#17202a;--acc:#6b9bff;--bad:#ff6b6b;--ok:#4cc38a}}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.7 ui-sans-serif,system-ui,Tahoma,sans-serif}
main{max-width:520px;margin:0 auto;padding:16px}h1{font-size:20px}
.c{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;margin-bottom:12px}
.r{display:flex;justify-content:space-between;gap:8px;padding:4px 0}.r span:first-child{color:var(--mut)}
.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden}.bar i{display:block;height:100%;background:var(--acc)}
code{direction:ltr;unicode-bidi:embed;word-break:break-all}.ok{color:var(--ok)}.bad{color:var(--bad)}
input,button{font:inherit;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink)}
button{background:var(--acc);color:#fff;border-color:var(--acc);cursor:pointer}#m{min-height:1.6em}
</style></head><body><main><h1>{{NAME}}</h1>
<div class="c"><div class="r"><span>وضعیت</span><b class="{{SCLS}}">{{STATUS}}</b></div>
<div class="r"><span>انقضا</span><span>{{EXPIRES}}</span></div>
<div class="r"><span>مصرف</span><span>{{USED}} / {{QUOTA}}</span></div>{{BAR}}</div>
<div class="c"><div class="r"><span>آدرس DNS</span><code>{{HOST}}</code></div>
<div class="r"><span>DNS-over-TLS</span><code>{{HOST}}</code></div>
<div class="r"><span>DNS-over-HTTPS</span><code>{{DOH}}</code></div></div>
<div class="c"><div class="r"><span>IP ثبت‌شده</span><code>{{IPS}}</code></div>
<div class="r"><span>IP فعلی شما</span><code>{{MYIP}}</code></div>
<p>برای ثبت IP فعلی، رمز ثبت‌نام خود را وارد کنید.</p>
<input id="s" type="password" placeholder="رمز ثبت‌نام" autocomplete="off"> <button id="b">ثبت IP من</button><div id="m" role="status"></div></div>
<script>
document.getElementById('b').onclick=async()=>{const m=document.getElementById('m');m.textContent='...';
try{const r=await fetch(location.pathname.replace('/sub/','/ip/'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({secret:document.getElementById('s').value})});
const j=await r.json();const E={bad_secret:'رمز نادرست است',ip_in_use:'این IP به اشتراک دیگری متصل است',disabled:'اشتراک غیرفعال است',expired:'اشتراک منقضی شده',over_quota:'حجم مصرف شده',rate_limited:'درخواست زیاد؛ کمی صبر کنید'};
m.textContent=r.ok?('ثبت شد: '+j.ip):(E[j.error]||'خطا');if(r.ok)setTimeout(()=>location.reload(),1200)}catch(e){m.textContent='خطای شبکه'}};
</script></main></body></html>"#;

async fn portal(State(st): State<S>, ConnectInfo(peer): ConnectInfo<SocketAddr>, h: HeaderMap, Path(token): Path<String>) -> Response {
    let ip = client_ip(&st, peer, &h);
    if !st.portal_limiter.allow(ip, 2, 30) {
        return err(429, "rate_limited");
    }
    let live = st.live.load_full();
    let Some(c) = live.by_token.get(&token) else { return StatusCode::NOT_FOUND.into_response() };
    let r = &c.rec;
    let status = c.status(now_secs());
    let (stxt, scls) = match status {
        crate::model::Status::Active => ("فعال", "ok"),
        crate::model::Status::Disabled => ("غیرفعال", "bad"),
        crate::model::Status::Expired => ("منقضی شده", "bad"),
        crate::model::Status::OverQuota => ("حجم تمام شده", "bad"),
    };
    let used = c.usage.total();
    let bar = if r.quota_bytes > 0 {
        format!(r#"<div class="bar"><i style="width:{}%"></i></div>"#, (used * 100 / r.quota_bytes).min(100))
    } else {
        String::new()
    };
    let host = if live.settings.portal_domain.is_empty() { st.cfg.public_ip.to_string() } else { live.settings.portal_domain.clone() };
    let doh = format!("https://{}:{}/dns-query/{}", host, st.cfg.web_bind.port(), r.doh_token);
    let ips = if r.ips.is_empty() { "—".to_string() } else { r.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ") };
    let html = PAGE
        .replace("{{TITLE}}", &esc(&live.settings.portal_title))
        .replace("{{NAME}}", &esc(&r.name))
        .replace("{{SCLS}}", scls)
        .replace("{{STATUS}}", stxt)
        .replace("{{EXPIRES}}", &r.expires_at.map(date).unwrap_or_else(|| "نامحدود".into()))
        .replace("{{USED}}", &gb(used))
        .replace("{{QUOTA}}", &if r.quota_bytes > 0 { gb(r.quota_bytes) } else { "نامحدود".into() })
        .replace("{{BAR}}", &bar)
        .replace("{{HOST}}", &esc(&host))
        .replace("{{DOH}}", &esc(&doh))
        .replace("{{IPS}}", &esc(&ips))
        .replace("{{MYIP}}", &esc(&ip.to_string()));
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::HeaderName::from_static("x-robots-tag"), "noindex, nofollow"),
            (header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'"),
        ],
        html,
    )
        .into_response()
}

async fn ip_help() -> Response {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], "POST JSON {\"secret\": \"...\"} to this URL to bind your current IP.\nبرای ثبت IP، یک درخواست POST با فیلد secret به همین آدرس بفرستید.\n").into_response()
}

#[derive(Deserialize)]
struct Reg {
    secret: String,
    ip: Option<IpAddr>,
}

async fn register(State(st): State<S>, ConnectInfo(peer): ConnectInfo<SocketAddr>, h: HeaderMap, Path(token): Path<String>, Json(b): Json<Reg>) -> Response {
    let caller = client_ip(&st, peer, &h);
    if !st.portal_limiter.allow(caller, 1, 10) {
        return err(429, "rate_limited");
    }
    let live = st.live.load_full();
    let Some(c) = live.by_token.get(&token) else { return err(404, "not_found") };
    if !ct_eq(sha256_hex(&b.secret).as_bytes(), c.rec.secret_hash.as_bytes()) {
        st.audit.log(caller, "portal_bad_secret", &c.rec.name);
        return err(403, "bad_secret");
    }
    match c.status(now_secs()) {
        crate::model::Status::Active => {}
        crate::model::Status::Disabled => return err(403, "disabled"),
        crate::model::Status::Expired => return err(403, "expired"),
        crate::model::Status::OverQuota => return err(403, "over_quota"),
    }
    let ip = b.ip.unwrap_or(caller);
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return err(400, "bad_ip");
    }
    if let Some(other) = live.by_ip.get(&ip) {
        if other.rec.id != c.rec.id {
            return err(409, "ip_in_use"); // shared CGNAT addresses are normal: refuse, don't punish
        }
    }
    let id = c.rec.id.clone();
    let res = st.mutate(|p| {
        let rec = p.clients.iter_mut().find(|x| x.id == id).ok_or("gone")?;
        rec.ips.retain(|x| *x != ip);
        rec.ips.push(ip);
        let max = rec.max_ips.max(1) as usize;
        while rec.ips.len() > max {
            rec.ips.remove(0);
        }
        Ok(())
    });
    match res {
        Ok(()) => {
            st.audit.log(caller, "portal_register", &format!("{} -> {}", c.rec.name, ip));
            Json(json!({ "ok": true, "ip": ip })).into_response()
        }
        Err(_) => err(500, "internal"),
    }
}
