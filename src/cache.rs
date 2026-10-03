use moka::Expiry;
use std::{sync::Arc, time::{Duration, Instant}};

pub struct Entry {
    pub bytes: Vec<u8>,
    pub stored: Instant,
    pub ttl: u32,
    pub stale: u32,
    /// The original query, so the entry can be refreshed in the background.
    pub query: Vec<u8>,
}

struct PerEntry;
impl Expiry<String, Arc<Entry>> for PerEntry {
    fn expire_after_create(&self, _k: &String, v: &Arc<Entry>, _created: Instant) -> Option<Duration> {
        Some(Duration::from_secs(v.ttl as u64 + v.stale as u64))
    }
}

pub type Cache = moka::sync::Cache<String, Arc<Entry>>;

pub fn build(max_entries: u64) -> Cache {
    moka::sync::Cache::builder().max_capacity(max_entries).expire_after(PerEntry).build()
}
