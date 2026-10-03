use crate::{
    auth::{Audit, AuthStore, Creds, Lockouts, Sessions},
    cache::{self, Cache},
    config::Config,
    model::*,
    policy::{norm, valid_domain, Rules},
    presets::PRESETS,
    sys, tls::TlsState, wire,
};
use arc_swap::ArcSwap;
use dashmap::{DashMap, DashSet};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{atomic::{AtomicU64, Ordering::Relaxed}, Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, mpsc, Semaphore};

const LOG_CAP: usize = 5000;
const SERIES_CAP: usize = 600;

#[derive(Default)]
pub struct Stats {
    pub queries: AtomicU64,
    pub cache_hits: AtomicU64,
    pub stale_hits: AtomicU64,
    pub direct: AtomicU64,
    pub proxied: AtomicU64,
    pub blocked: AtomicU64,
    pub refused: AtomicU64,
    pub limited: AtomicU64,
    pub servfail: AtomicU64,
    pub relays_active: AtomicU64,
    pub relays_total: AtomicU64,
    pub relays_rejected: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

#[derive(Default)]
pub struct UpStat {
    pub wins: AtomicU64,
    pub timeouts: AtomicU64,
    pub rtt_us: AtomicU64,
}

#[derive(Clone, Serialize)]
pub struct LogEntry {
    pub t: i64,
    pub ip: IpAddr,
    pub client: Option<Arc<str>>,
    pub name: String,
    pub qtype: u16,
    pub action: &'static str,
    pub rcode: u8,
    pub us: u32,
}

#[derive(Clone, Serialize)]
pub struct Sample {
    pub t: i64,
    pub q: u64,
    pub hit: u64,
    pub direct: u64,
    pub proxy: u64,
    pub block: u64,
    pub refused: u64,
    pub relays: u64,
    pub rss: u64,
    pub cpu: f32,
}

pub struct Limiter {
    map: DashMap<IpAddr, (f32, Instant)>,
}
impl Limiter {
    pub fn new() -> Self {
        Self { map: DashMap::new() }
    }
    pub fn allow(&self, ip: IpAddr, qps: u32, burst: u32) -> bool {
        let now = Instant::now();
        let burst = burst.max(1) as f32;
        let mut e = self.map.entry(ip).or_insert((burst, now));
        let dt = now.duration_since(e.1).as_secs_f32();
        e.0 = (e.0 + dt * qps as f32).min(burst);
        e.1 = now;
        if e.0 >= 1.0 {
            e.0 -= 1.0;
            true
        } else {
            false
        }
    }
    pub fn gc(&self) {
        let now = Instant::now();
        self.map.retain(|_, v| now.duration_since(v.1) < Duration::from_secs(60));
    }
}

pub struct ClientRt {
    pub rec: ClientRec,
    pub name: Arc<str>,
    pub rules: Arc<Rules>,
    pub usage: Arc<Usage>,
}
impl ClientRt {
    pub fn status(&self, now: i64) -> Status {
        if !self.rec.enabled {
            return Status::Disabled;
        }
        if self.rec.expires_at.map_or(false, |e| now >= e) {
            return Status::Expired;
        }
        if self.rec.quota_bytes > 0 && self.usage.total() >= self.rec.quota_bytes {
            return Status::OverQuota;
        }
        Status::Active
    }
}

pub struct RecordRt {
    pub rtype: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

pub enum Who<'a> {
    Client(&'a ClientRt),
    Anon,
    Denied,
}

/// One immutable snapshot of everything the query path reads.
/// Swapped atomically after each change: readers never lock.
pub struct Live {
    pub settings: Settings,
    pub rules: Arc<Rules>,
    pub by_ip: HashMap<IpAddr, Arc<ClientRt>>,
    pub by_token: HashMap<String, Arc<ClientRt>>,
    pub by_doh: HashMap<String, Arc<ClientRt>>,
    pub by_id: HashMap<String, Arc<ClientRt>>,
    pub records: HashMap<String, Vec<RecordRt>>,
}

impl Live {
    pub fn identify(&self, ip: IpAddr, doh: Option<&str>) -> Who<'_> {
        let found = match doh {
            Some(t) => self.by_doh.get(t),
            None => self.by_ip.get(&ip),
        };
        match found {
            Some(c) => {
                if c.status(now_secs()) == Status::Active {
                    Who::Client(&**c)
                } else {
                    Who::Denied
                }
            }
            None => {
                if doh.is_none() && self.settings.allow_all {
                    Who::Anon
                } else {
                    Who::Denied
                }
            }
        }
    }
}

#[derive(Serialize, Clone)]
pub struct PresetView {
    pub name: String,
    pub title: String,
    pub group: String,
    pub default_on: bool,
    pub builtin: bool,
    pub domains: Vec<String>,
}

pub fn all_presets(p: &Persist) -> Vec<PresetView> {
    let mut v: Vec<PresetView> = PRESETS
        .iter()
        .map(|x| PresetView {
            name: x.name.into(),
            title: x.title.into(),
            group: x.group.into(),
            default_on: x.default_on,
            builtin: true,
            domains: x.domains.iter().map(|d| d.to_string()).collect(),
        })
        .collect();
    v.extend(p.custom_presets.iter().map(|c| PresetView {
        name: c.name.clone(),
        title: c.title.clone(),
        group: "custom".into(),
        default_on: c.default_on,
        builtin: false,
        domains: c.domains.clone(),
    }));
    v
}

pub fn preset_enabled(p: &Persist, v: &PresetView) -> bool {
    p.presets.get(&v.name).copied().unwrap_or(v.default_on)
}

fn build_rules(p: &Persist, only: Option<&ClientRec>) -> Rules {
    let mut proxied: HashSet<String> = HashSet::new();
    for v in all_presets(p).iter().filter(|v| preset_enabled(p, v)) {
        if let Some(c) = only {
            if let Some(list) = &c.presets {
                if !list.contains(&v.name) {
                    continue;
                }
            }
        }
        proxied.extend(v.domains.iter().map(|d| norm(d)));
    }
    proxied.extend(p.custom_proxied.iter().map(|d| norm(d)));
    let mut blocked: HashSet<String> = p.custom_blocked.iter().map(|d| norm(d)).collect();
    if let Some(c) = only {
        proxied.extend(c.custom_proxied.iter().map(|d| norm(d)));
        blocked.extend(c.custom_blocked.iter().map(|d| norm(d)));
    }
    Rules::new(proxied, blocked)
}

fn build_records(p: &Persist) -> HashMap<String, Vec<RecordRt>> {
    let mut m: HashMap<String, Vec<RecordRt>> = HashMap::new();
    for r in &p.records {
        let rdata = match r.rtype.as_str() {
            "A" => r.value.parse::<std::net::Ipv4Addr>().ok().map(|a| (wire::A, a.octets().to_vec())),
            "AAAA" => r.value.parse::<std::net::Ipv6Addr>().ok().map(|a| (wire::AAAA, a.octets().to_vec())),
            "CNAME" => wire::encode_name(&r.value).map(|d| (wire::CNAME, d)),
            "TXT" => {
                let mut d = Vec::new();
                for ch in r.value.as_bytes().chunks(255) {
                    d.push(ch.len() as u8);
                    d.extend_from_slice(ch);
                }
                Some((wire::TXT, d))
            }
            _ => None,
        };
        if let Some((rtype, rdata)) = rdata {
            m.entry(norm(&r.name)).or_default().push(RecordRt { rtype, ttl: r.ttl, rdata });
        }
    }
    m
}

pub fn build_live(p: &Persist, usage: &DashMap<String, Arc<Usage>>) -> Live {
    let global = Arc::new(build_rules(p, None));
    let mut by_ip = HashMap::new();
    let mut by_token = HashMap::new();
    let mut by_doh = HashMap::new();
    let mut by_id = HashMap::new();
    for rec in &p.clients {
        let u = usage.entry(rec.id.clone()).or_default().clone();
        let rules = if rec.presets.is_none() && rec.custom_proxied.is_empty() && rec.custom_blocked.is_empty() {
            global.clone()
        } else {
            Arc::new(build_rules(p, Some(rec)))
        };
        let rt = Arc::new(ClientRt { rec: rec.clone(), name: Arc::from(rec.name.as_str()), rules, usage: u });
        for ip in &rec.ips {
            by_ip.insert(*ip, rt.clone());
        }
        by_token.insert(rec.token.clone(), rt.clone());
        by_doh.insert(rec.doh_token.clone(), rt.clone());
        by_id.insert(rec.id.clone(), rt);
    }
    Live { settings: p.settings.clone(), rules: global, by_ip, by_token, by_doh, by_id, records: build_records(p) }
}

/// Parse "domain" lists and hosts-file lines ("0.0.0.0 ads.example.com").
pub fn parse_domain_list(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let first = parts.next().unwrap_or("");
        let cand = if first.parse::<IpAddr>().is_ok() { parts.next().unwrap_or("") } else { first };
        let d = norm(cand);
        if d != "localhost" && valid_domain(&d) {
            out.push(d);
        }
    }
    out
}

pub struct AppState {
    pub cfg: Config,
    pub live: ArcSwap<Live>,
    persist: Mutex<Persist>,
    pub usage: DashMap<String, Arc<Usage>>,
    pub cache: Cache,
    pub refreshing: DashSet<String>,
    pub dns_cache: moka::sync::Cache<String, Arc<Vec<SocketAddr>>>,
    pub inflight: Arc<Semaphore>,
    pub limiter: Limiter,
    pub portal_limiter: Limiter,
    pub stats: Stats,
    pub upstream_stats: DashMap<SocketAddr, Arc<UpStat>>,
    pub auth: AuthStore,
    pub sessions: Sessions,
    pub lockouts: Lockouts,
    pub audit: Audit,
    pub tls: TlsState,
    pub log_tx: mpsc::Sender<LogEntry>,
    log_rx: Mutex<Option<mpsc::Receiver<LogEntry>>>,
    pub log_ring: RwLock<VecDeque<LogEntry>>,
    pub log_bcast: broadcast::Sender<String>,
    pub series: RwLock<VecDeque<Sample>>,
    pub started: Instant,
    dir: PathBuf,
}

fn write_atomic(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    crate::auth::write_private(path, bytes)
}

impl AppState {
    pub fn new(cfg: Config) -> anyhow::Result<(Arc<Self>, Option<Creds>)> {
        std::fs::create_dir_all(&cfg.data_dir)?;
        let dir = PathBuf::from(&cfg.data_dir);
        let persist: Persist = match std::fs::read(dir.join("state.json")) {
            Ok(b) => serde_json::from_slice(&b)?,
            Err(_) => Persist::default(),
        };
        let usage: DashMap<String, Arc<Usage>> = DashMap::new();
        if let Ok(b) = std::fs::read(dir.join("usage.json")) {
            if let Ok(m) = serde_json::from_slice::<HashMap<String, UsageSnap>>(&b) {
                for (id, s) in m {
                    let u = Usage::default();
                    u.up.store(s.up, Relaxed);
                    u.down.store(s.down, Relaxed);
                    u.queries.store(s.queries, Relaxed);
                    usage.insert(id, Arc::new(u));
                }
            }
        }
        let (auth, creds) = AuthStore::load_or_init(&cfg.data_dir)?;
        let (log_tx, log_rx) = mpsc::channel(8192);
        let live = build_live(&persist, &usage);
        let st = Arc::new(Self {
            live: ArcSwap::from_pointee(live),
            persist: Mutex::new(persist),
            usage,
            cache: cache::build(cfg.cache_entries),
            refreshing: DashSet::new(),
            dns_cache: moka::sync::Cache::builder().max_capacity(20_000).time_to_live(Duration::from_secs(60)).build(),
            inflight: Arc::new(Semaphore::new(cfg.max_inflight_queries)),
            limiter: Limiter::new(),
            portal_limiter: Limiter::new(),
            stats: Stats::default(),
            upstream_stats: DashMap::new(),
            auth,
            sessions: Sessions::default(),
            lockouts: Lockouts::default(),
            audit: Audit::new(&cfg.data_dir),
            tls: TlsState::new(&cfg.data_dir),
            log_tx,
            log_rx: Mutex::new(Some(log_rx)),
            log_ring: RwLock::new(VecDeque::new()),
            log_bcast: broadcast::channel(512).0,
            series: RwLock::new(VecDeque::new()),
            started: Instant::now(),
            dir,
            cfg,
        });
        Ok((st, creds))
    }

    pub fn snapshot(&self) -> Persist {
        self.persist.lock().unwrap().clone()
    }

    /// Mutate settings/clients/rules, persist, then swap the live snapshot.
    pub fn mutate<F: FnOnce(&mut Persist) -> Result<(), String>>(&self, f: F) -> Result<(), String> {
        let mut g = self.persist.lock().unwrap();
        let mut next = g.clone();
        f(&mut next)?;
        let bytes = serde_json::to_vec_pretty(&next).map_err(|e| e.to_string())?;
        write_atomic(&self.dir.join("state.json"), &bytes).map_err(|e| e.to_string())?;
        self.live.store(Arc::new(build_live(&next, &self.usage)));
        *g = next;
        Ok(())
    }

    pub fn upstream_stat(&self, a: SocketAddr) -> Arc<UpStat> {
        self.upstream_stats.entry(a).or_default().clone()
    }

    pub fn save_usage(&self) {
        let ids: HashSet<String> = self.snapshot().clients.into_iter().map(|c| c.id).collect();
        let m: HashMap<String, UsageSnap> = self
            .usage
            .iter()
            .filter(|e| ids.contains(e.key()))
            .map(|e| {
                let u = e.value();
                (e.key().clone(), UsageSnap { up: u.up.load(Relaxed), down: u.down.load(Relaxed), queries: u.queries.load(Relaxed) })
            })
            .collect();
        if let Ok(b) = serde_json::to_vec(&m) {
            let _ = write_atomic(&self.dir.join("usage.json"), &b);
        }
    }

    pub fn reset_all_usage(&self) {
        for u in self.usage.iter() {
            u.value().reset();
        }
    }

    pub fn stats_json(&self) -> serde_json::Value {
        let s = &self.stats;
        serde_json::json!({
            "queries": s.queries.load(Relaxed), "cache_hits": s.cache_hits.load(Relaxed),
            "stale_hits": s.stale_hits.load(Relaxed), "direct": s.direct.load(Relaxed),
            "proxied": s.proxied.load(Relaxed), "blocked": s.blocked.load(Relaxed),
            "refused": s.refused.load(Relaxed), "limited": s.limited.load(Relaxed),
            "servfail": s.servfail.load(Relaxed), "relays_active": s.relays_active.load(Relaxed),
            "relays_total": s.relays_total.load(Relaxed), "relays_rejected": s.relays_rejected.load(Relaxed),
            "bytes_up": s.bytes_up.load(Relaxed), "bytes_down": s.bytes_down.load(Relaxed),
        })
    }
}

// ---------- background tasks ----------

pub async fn logger(st: Arc<AppState>) {
    let rx = st.log_rx.lock().unwrap().take();
    let Some(mut rx) = rx else { return };
    while let Some(e) = rx.recv().await {
        if st.log_bcast.receiver_count() > 0 {
            if let Ok(j) = serde_json::to_string(&e) {
                let _ = st.log_bcast.send(j);
            }
        }
        let mut r = st.log_ring.write().unwrap();
        if r.len() >= LOG_CAP {
            r.pop_front();
        }
        r.push_back(e);
    }
}

pub async fn sampler(st: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let g = |a: &AtomicU64| a.load(Relaxed);
    let mut prev = [0u64; 6];
    let mut prev_cpu = sys::cpu_ticks().unwrap_or(0);
    loop {
        tick.tick().await;
        let s = &st.stats;
        let cur = [g(&s.queries), g(&s.cache_hits), g(&s.direct), g(&s.proxied), g(&s.blocked), g(&s.refused)];
        let cpu_now = sys::cpu_ticks().unwrap_or(prev_cpu);
        let sample = Sample {
            t: now_secs(),
            q: cur[0].saturating_sub(prev[0]),
            hit: cur[1].saturating_sub(prev[1]),
            direct: cur[2].saturating_sub(prev[2]),
            proxy: cur[3].saturating_sub(prev[3]),
            block: cur[4].saturating_sub(prev[4]),
            refused: cur[5].saturating_sub(prev[5]),
            relays: g(&s.relays_active),
            rss: sys::rss_bytes().unwrap_or(0),
            cpu: cpu_now.saturating_sub(prev_cpu) as f32, // ticks/s at CLK_TCK=100 == percent of one core
        };
        prev = cur;
        prev_cpu = cpu_now;
        let mut w = st.series.write().unwrap();
        if w.len() >= SERIES_CAP {
            w.pop_front();
        }
        w.push_back(sample);
    }
}

pub async fn maintenance(st: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tick.tick().await;
        st.save_usage();
        st.limiter.gc();
        st.portal_limiter.gc();
        st.lockouts.gc();
        let idle = st.live.load().settings.session_idle_min as i64 * 60;
        st.sessions.gc(idle);
        st.cache.run_pending_tasks();
        maybe_reset_traffic(&st);
    }
}

fn maybe_reset_traffic(st: &Arc<AppState>) {
    let day = st.live.load().settings.traffic_reset_day;
    if day == 0 {
        return;
    }
    let (y, m, d) = civil_from_days(now_secs().div_euclid(86_400));
    let tag = format!("{y:04}-{m:02}");
    if d as u8 >= day && st.snapshot().last_reset != tag {
        st.reset_all_usage();
        st.save_usage();
        let _ = st.mutate(|p| {
            p.last_reset = tag.clone();
            Ok(())
        });
        st.audit.log("system", "traffic_reset", &tag);
    }
}
