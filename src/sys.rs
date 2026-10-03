//! Process/system metrics from /proc (Linux). Returns None elsewhere.
pub fn rss_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = s.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

/// utime + stime in clock ticks (usually 100/s).
pub fn cpu_ticks() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/stat").ok()?;
    let rest = s.rsplit_once(')')?.1;
    let f: Vec<&str> = rest.split_whitespace().collect();
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

pub fn loadavg() -> Option<[f32; 3]> {
    let s = std::fs::read_to_string("/proc/loadavg").ok()?;
    let mut it = s.split_whitespace().map(|x| x.parse::<f32>().ok());
    Some([it.next()??, it.next()??, it.next()??])
}

pub fn mem_total() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    let l = s.lines().find(|l| l.starts_with("MemTotal:"))?;
    Some(l.split_whitespace().nth(1)?.parse::<u64>().ok()? * 1024)
}

pub fn threads() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines().find(|l| l.starts_with("Threads:"))?.split_whitespace().nth(1)?.parse().ok()
}
