use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
pub fn now_secs() -> i64 {
    now_ms() / 1000
}
pub fn rand_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
/// RFC 9562 version-4 UUID.
pub fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}
/// Days since 1970-01-01 -> (year, month, day). Howard Hinnant's algorithm.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn yes() -> bool {
    true
}
fn one() -> u8 {
    1
}

/// Everything the operator can change live from the panel.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub allow_all: bool,
    pub upstreams: Vec<SocketAddr>,
    pub query_timeout_ms: u64,
    pub cache_enabled: bool,
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    pub serve_stale_secs: u32,
    pub prefetch: bool,
    pub proxy_ttl: u32,
    pub rate_qps: u32,
    pub rate_burst: u32,
    pub query_log: bool,
    pub fragment_size: usize,
    pub fragment_delay_ms: u64,
    pub relay_idle_secs: u64,
    pub relay_connect_ms: u64,
    pub block_private_targets: bool,
    pub portal_title: String,
    pub portal_domain: String,
    pub session_idle_min: u64,
    pub login_max_fails: u32,
    pub login_lock_min: u64,
    /// Day of month (1-28) to reset every client's usage; 0 = never.
    pub traffic_reset_day: u8,
    /// Trust X-Forwarded-For when the TCP peer is loopback (reverse proxy).
    pub trust_forwarded: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allow_all: false,
            upstreams: ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"].iter().map(|s| s.parse().unwrap()).collect(),
            query_timeout_ms: 2500,
            cache_enabled: true,
            cache_min_ttl: 5,
            cache_max_ttl: 3600,
            serve_stale_secs: 30,
            prefetch: true,
            proxy_ttl: 30,
            rate_qps: 200,
            rate_burst: 400,
            query_log: true,
            fragment_size: 0,
            fragment_delay_ms: 2,
            relay_idle_secs: 120,
            relay_connect_ms: 4000,
            block_private_targets: true,
            portal_title: "DNS".into(),
            portal_domain: String::new(),
            session_idle_min: 30,
            login_max_fails: 5,
            login_lock_min: 10,
            traffic_reset_day: 0,
            trust_forwarded: false,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), String> {
        if self.upstreams.is_empty() || self.upstreams.len() > 8 {
            return Err("upstreams: 1 to 8 entries".into());
        }
        if self.cache_min_ttl > self.cache_max_ttl {
            return Err("cache_min_ttl must be <= cache_max_ttl".into());
        }
        if !(200..=10_000).contains(&self.query_timeout_ms) {
            return Err("query_timeout_ms: 200..10000".into());
        }
        if self.fragment_size > 1400 || self.fragment_delay_ms > 500 {
            return Err("fragment_size <= 1400, fragment_delay_ms <= 500".into());
        }
        if !(10..=3600).contains(&self.relay_idle_secs) || !(500..=30_000).contains(&self.relay_connect_ms) {
            return Err("relay_idle_secs 10..3600, relay_connect_ms 500..30000".into());
        }
        if !(1..=1440).contains(&self.session_idle_min) || self.login_max_fails == 0 || self.login_lock_min == 0 {
            return Err("session/login limits out of range".into());
        }
        if self.traffic_reset_day > 28 {
            return Err("traffic_reset_day: 0..28".into());
        }
        if self.portal_title.len() > 60 || self.portal_domain.len() > 253 {
            return Err("portal fields too long".into());
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientRec {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub ips: Vec<IpAddr>,
    #[serde(default = "one")]
    pub max_ips: u8,
    pub token: String,
    pub doh_token: String,
    /// sha256 of the registration secret; the secret itself is shown once.
    #[serde(default)]
    pub secret_hash: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub quota_bytes: u64,
    /// None = every globally enabled preset.
    #[serde(default)]
    pub presets: Option<Vec<String>>,
    #[serde(default)]
    pub custom_proxied: Vec<String>,
    #[serde(default)]
    pub custom_blocked: Vec<String>,
    #[serde(default)]
    pub created_at: i64,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,
    Disabled,
    Expired,
    OverQuota,
}

#[derive(Default)]
pub struct Usage {
    pub up: AtomicU64,
    pub down: AtomicU64,
    pub queries: AtomicU64,
}
impl Usage {
    pub fn total(&self) -> u64 {
        self.up.load(Relaxed) + self.down.load(Relaxed)
    }
    pub fn reset(&self) {
        self.up.store(0, Relaxed);
        self.down.store(0, Relaxed);
        self.queries.store(0, Relaxed);
    }
}
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct UsageSnap {
    pub up: u64,
    pub down: u64,
    pub queries: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CustomPreset {
    pub name: String,
    pub title: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub default_on: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StaticRecord {
    pub name: String,
    /// "A" | "AAAA" | "CNAME" | "TXT"
    pub rtype: String,
    pub value: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}
fn default_ttl() -> u32 {
    300
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Persist {
    pub settings: Settings,
    pub clients: Vec<ClientRec>,
    pub presets: HashMap<String, bool>,
    pub custom_presets: Vec<CustomPreset>,
    pub custom_proxied: Vec<String>,
    pub custom_blocked: Vec<String>,
    pub records: Vec<StaticRecord>,
    pub last_reset: String,
}
