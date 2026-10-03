//! Startup configuration (needs a restart). Everything the panel can change
//! live is in `model::Settings`.
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub data_dir: String,
    pub dns_bind: SocketAddr,
    pub dot_bind: Option<SocketAddr>,
    pub proxy_bind: SocketAddr,
    pub http_relay_bind: Option<SocketAddr>,
    /// Admin panel + subscriber portal + DoH (`/dns-query`).
    pub web_bind: SocketAddr,
    pub web_tls: bool,
    pub admin_path: String,
    pub public_ip: Ipv4Addr,
    pub public_ipv6: Option<Ipv6Addr>,
    pub max_relays: usize,
    pub max_inflight_queries: usize,
    /// UDP sockets (SO_REUSEPORT). 0 = one per CPU core.
    pub udp_workers: usize,
    pub cache_entries: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: ".".into(),
            dns_bind: "0.0.0.0:53".parse().unwrap(),
            dot_bind: Some("0.0.0.0:853".parse().unwrap()),
            proxy_bind: "0.0.0.0:443".parse().unwrap(),
            http_relay_bind: Some("0.0.0.0:80".parse().unwrap()),
            web_bind: "0.0.0.0:8443".parse().unwrap(),
            web_tls: true,
            admin_path: String::new(),
            public_ip: Ipv4Addr::UNSPECIFIED,
            public_ipv6: None,
            max_relays: 4096,
            max_inflight_queries: 4096,
            udp_workers: 0,
            cache_entries: 200_000,
        }
    }
}

impl Config {
    pub fn load_or_create(path: &str) -> anyhow::Result<Self> {
        let existing = std::fs::read(path).ok();
        let mut dirty = existing.is_none();
        let mut c: Config = match &existing {
            Some(b) => serde_json::from_slice(b)?,
            None => Config::default(),
        };
        if c.admin_path.is_empty() {
            c.admin_path = crate::model::rand_hex(8);
            dirty = true;
        }
        if dirty {
            c.save(path)?;
        }
        Ok(c)
    }

    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}
