use crate::{
    cache::Entry,
    model::*,
    policy::{Action, Rules},
    state::{AppState, ClientRt, LogEntry, Who},
    wire,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{atomic::Ordering::Relaxed, Arc},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

pub struct Src<'a> {
    pub ip: IpAddr,
    /// DoH path token (identifies a client independent of its IP).
    pub doh: Option<&'a str>,
}

pub struct Fwd {
    pub key: String,
    pub name: String,
    pub qtype: u16,
    pub ip: IpAddr,
    pub client: Option<Arc<str>>,
    pub t0: Instant,
}

pub enum Out {
    Reply(Vec<u8>),
    Forward(Fwd),
    Drop,
}

fn log(st: &AppState, on: bool, ip: IpAddr, client: Option<Arc<str>>, name: &str, qtype: u16, action: &'static str, rcode: u8, t0: Instant) {
    if on {
        let _ = st.log_tx.try_send(LogEntry {
            t: now_ms(),
            ip,
            client,
            name: name.to_string(),
            qtype,
            action,
            rcode,
            us: t0.elapsed().as_micros().min(u32::MAX as u128) as u32,
        });
    }
}

/// Synchronous fast path: rate limit, parse, identify, policy, cache.
/// Performs no network I/O, so UDP can answer inline without spawning.
pub fn decide(st: &Arc<AppState>, src: &Src, pkt: &[u8]) -> Out {
    let t0 = Instant::now();
    st.stats.queries.fetch_add(1, Relaxed);
    let live = st.live.load();
    let s = &live.settings;
    if s.rate_qps > 0 && !st.limiter.allow(src.ip, s.rate_qps, s.rate_burst) {
        st.stats.limited.fetch_add(1, Relaxed);
        return Out::Drop;
    }
    let q = match wire::parse_query(pkt) {
        Ok(q) => q,
        Err(Some(rc)) => return wire::error_reply(pkt, rc).map(Out::Reply).unwrap_or(Out::Drop),
        Err(None) => return Out::Drop,
    };
    let ql = s.query_log;

    let (rules, client): (&Rules, Option<&ClientRt>) = match live.identify(src.ip, src.doh) {
        Who::Client(c) => {
            c.usage.queries.fetch_add(1, Relaxed);
            (&*c.rules, Some(c))
        }
        Who::Anon => (&*live.rules, None),
        Who::Denied => {
            st.stats.refused.fetch_add(1, Relaxed);
            log(st, ql, src.ip, None, &q.name, q.qtype, "refused", 5, t0);
            return Out::Reply(wire::reply(pkt, &q, 5, &[]));
        }
    };
    let cname: Option<Arc<str>> = client.map(|c| c.name.clone());

    // Static records (split-horizon DNS).
    if let Some(recs) = live.records.get(q.name.as_str()) {
        let ans: Vec<wire::Ans> = recs
            .iter()
            .filter(|r| r.rtype == q.qtype || r.rtype == wire::CNAME)
            .map(|r| wire::Ans { rtype: r.rtype, ttl: r.ttl, rdata: &r.rdata })
            .collect();
        log(st, ql, src.ip, cname, &q.name, q.qtype, "static", 0, t0);
        return Out::Reply(wire::reply(pkt, &q, 0, &ans));
    }

    match rules.lookup(&q.name).map(|x| x.0).unwrap_or(Action::Direct) {
        Action::Block => {
            st.stats.blocked.fetch_add(1, Relaxed);
            log(st, ql, src.ip, cname, &q.name, q.qtype, "block", 3, t0);
            Out::Reply(wire::reply(pkt, &q, 3, &[]))
        }
        Action::Proxy => {
            st.stats.proxied.fetch_add(1, Relaxed);
            let v4 = st.cfg.public_ip.octets();
            let v6 = st.cfg.public_ipv6.map(|a| a.octets());
            let mut ans: Vec<wire::Ans> = Vec::with_capacity(1);
            // A -> this server, AAAA -> this server's v6 if configured. Every other
            // type (HTTPS/SVCB included) gets an empty NOERROR so nothing leaks the origin.
            if q.qtype == wire::A {
                ans.push(wire::Ans { rtype: wire::A, ttl: s.proxy_ttl, rdata: &v4 });
            } else if q.qtype == wire::AAAA {
                if let Some(v) = &v6 {
                    ans.push(wire::Ans { rtype: wire::AAAA, ttl: s.proxy_ttl, rdata: v });
                }
            }
            log(st, ql, src.ip, cname, &q.name, q.qtype, "proxy", 0, t0);
            Out::Reply(wire::reply(pkt, &q, 0, &ans))
        }
        Action::Direct => {
            let key = format!("{}|{}|{}", q.name, q.qtype, q.do_bit as u8);
            if s.cache_enabled {
                if let Some(e) = st.cache.get(&key) {
                    let age = e.stored.elapsed().as_secs().min(u32::MAX as u64) as u32;
                    let fresh = age < e.ttl;
                    if fresh || age < e.ttl.saturating_add(e.stale) {
                        let mut out = e.bytes.clone();
                        out[0..2].copy_from_slice(&pkt[0..2]);
                        wire::adjust_ttls(&mut out, age);
                        if fresh {
                            st.stats.cache_hits.fetch_add(1, Relaxed);
                        } else {
                            st.stats.stale_hits.fetch_add(1, Relaxed);
                        }
                        if s.prefetch && (!fresh || age.saturating_mul(10) >= e.ttl.saturating_mul(9)) {
                            spawn_refresh(st, key, e.clone());
                        }
                        log(st, ql, src.ip, cname, &q.name, q.qtype, if fresh { "cache" } else { "stale" }, wire::rcode(&out), t0);
                        return Out::Reply(out);
                    }
                }
            }
            st.stats.direct.fetch_add(1, Relaxed);
            Out::Forward(Fwd { key, name: q.name, qtype: q.qtype, ip: src.ip, client: cname, t0 })
        }
    }
}

fn spawn_refresh(st: &Arc<AppState>, key: String, e: Arc<Entry>) {
    if !st.refreshing.insert(key.clone()) {
        return;
    }
    let st = st.clone();
    tokio::spawn(async move {
        if let Ok(_p) = st.inflight.clone().try_acquire_owned() {
            let _ = upstream(&st, &e.query, &key).await;
        }
        st.refreshing.remove(&key);
    });
}

async fn tcp_query(addr: SocketAddr, pkt: &[u8]) -> Option<Vec<u8>> {
    let mut s = timeout(Duration::from_millis(1500), TcpStream::connect(addr)).await.ok()?.ok()?;
    let mut out = (pkt.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(pkt);
    s.write_all(&out).await.ok()?;
    let mut lb = [0u8; 2];
    timeout(Duration::from_secs(2), s.read_exact(&mut lb)).await.ok()?.ok()?;
    let mut buf = vec![0u8; u16::from_be_bytes(lb) as usize];
    timeout(Duration::from_secs(2), s.read_exact(&mut buf)).await.ok()?.ok()?;
    Some(buf)
}

fn maybe_cache(st: &AppState, s: &Settings, key: &str, query: &[u8], resp: &[u8]) {
    if !s.cache_enabled || wire::truncated(resp) {
        return;
    }
    let rc = wire::rcode(resp);
    if rc != 0 && rc != 3 {
        return;
    }
    let ttl = wire::min_ttl(resp).unwrap_or(s.cache_min_ttl).max(s.cache_min_ttl).min(s.cache_max_ttl);
    if ttl == 0 {
        return;
    }
    st.cache.insert(
        key.to_string(),
        Arc::new(Entry { bytes: resp.to_vec(), stored: Instant::now(), ttl, stale: s.serve_stale_secs, query: query.to_vec() }),
    );
}

/// Race every upstream, first valid reply wins; retry over TCP when truncated.
pub async fn upstream(st: &Arc<AppState>, pkt: &[u8], key: &str) -> Option<Vec<u8>> {
    let live = st.live.load_full();
    let s = &live.settings;
    let v4 = s.upstreams.iter().any(|a| a.is_ipv4());
    let targets: Vec<SocketAddr> = s.upstreams.iter().copied().filter(|a| a.is_ipv4() == v4).collect();
    if targets.is_empty() {
        return None;
    }
    let sock = UdpSocket::bind(if v4 { "0.0.0.0:0" } else { "[::]:0" }).await.ok()?;
    let t0 = Instant::now();
    for t in &targets {
        let _ = sock.send_to(pkt, t).await;
    }
    let mut buf = vec![0u8; 4096];
    let res = timeout(Duration::from_millis(s.query_timeout_ms), async {
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, from)) if n >= 12 && targets.contains(&from) && buf[0..2] == pkt[0..2] => return Some((n, from)),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    })
    .await;
    let (n, from) = match res {
        Ok(Some(v)) => v,
        _ => {
            for t in &targets {
                st.upstream_stat(*t).timeouts.fetch_add(1, Relaxed);
            }
            return None;
        }
    };
    buf.truncate(n);
    let us = st.upstream_stat(from);
    us.wins.fetch_add(1, Relaxed);
    let rtt = t0.elapsed().as_micros() as u64;
    let old = us.rtt_us.load(Relaxed);
    us.rtt_us.store(if old == 0 { rtt } else { (old * 7 + rtt) / 8 }, Relaxed);
    if wire::truncated(&buf) {
        if let Some(b) = tcp_query(from, pkt).await {
            buf = b;
        }
    }
    maybe_cache(st, s, key, pkt, &buf);
    Some(buf)
}

pub async fn forward_inner(st: &Arc<AppState>, pkt: &[u8], f: Fwd) -> Option<Vec<u8>> {
    let r = upstream(st, pkt, &f.key).await;
    let (action, rc) = match &r {
        Some(b) => ("direct", wire::rcode(b)),
        None => {
            st.stats.servfail.fetch_add(1, Relaxed);
            ("servfail", 2)
        }
    };
    let ql = st.live.load().settings.query_log;
    log(st, ql, f.ip, f.client, &f.name, f.qtype, action, rc, f.t0);
    r.or_else(|| wire::error_reply(pkt, 2))
}

/// Full path for transports that already run in their own task (TCP/DoT/DoH).
pub async fn handle(st: &Arc<AppState>, src: &Src<'_>, pkt: &[u8]) -> Option<Vec<u8>> {
    match decide(st, src, pkt) {
        Out::Reply(r) => Some(r),
        Out::Drop => None,
        Out::Forward(f) => {
            let _permit = st.inflight.try_acquire().ok()?;
            forward_inner(st, pkt, f).await
        }
    }
}

fn bind_reuseport(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    UdpSocket::from_std(s.into())
}

async fn udp_loop(st: Arc<AppState>, sock: Arc<UdpSocket>) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let src = Src { ip: peer.ip(), doh: None };
        match decide(&st, &src, &buf[..n]) {
            Out::Reply(mut r) => {
                wire::truncate_for_udp(&mut r, 1232);
                let _ = sock.send_to(&r, peer).await;
            }
            Out::Drop => {}
            Out::Forward(f) => {
                let Ok(permit) = st.inflight.clone().try_acquire_owned() else { continue };
                let (pkt, st, sock) = (buf[..n].to_vec(), st.clone(), sock.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(mut r) = forward_inner(&st, &pkt, f).await {
                        wire::truncate_for_udp(&mut r, 1232);
                        let _ = sock.send_to(&r, peer).await;
                    }
                });
            }
        }
    }
}

pub async fn serve_udp(st: Arc<AppState>) -> anyhow::Result<()> {
    let workers = match st.cfg.udp_workers {
        0 => std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        n => n,
    };
    tracing::info!("dns udp/tcp on {} ({workers} udp sockets)", st.cfg.dns_bind);
    let mut tasks = Vec::new();
    for _ in 0..workers {
        let sock = Arc::new(bind_reuseport(st.cfg.dns_bind)?);
        tasks.push(tokio::spawn(udp_loop(st.clone(), sock)));
    }
    for t in tasks {
        t.await??;
    }
    Ok(())
}

/// Length-prefixed DNS over any byte stream (TCP and DoT share this).
pub async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin>(st: Arc<AppState>, mut s: S, ip: IpAddr, idle: Duration) {
    loop {
        let mut lb = [0u8; 2];
        match timeout(idle, s.read_exact(&mut lb)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let len = u16::from_be_bytes(lb) as usize;
        if len < 12 {
            break;
        }
        let mut pkt = vec![0u8; len];
        match timeout(Duration::from_secs(10), s.read_exact(&mut pkt)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let Some(resp) = handle(&st, &Src { ip, doh: None }, &pkt).await else { break };
        let mut out = (resp.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&resp);
        if s.write_all(&out).await.is_err() {
            break;
        }
    }
}

pub async fn serve_tcp(st: Arc<AppState>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(st.cfg.dns_bind).await?;
    let limit = Arc::new(Semaphore::new(512));
    loop {
        let Ok((s, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else { continue };
        let st = st.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_stream(st, s, peer.ip(), Duration::from_secs(30)).await;
        });
    }
}

pub async fn serve_dot(st: Arc<AppState>, bind: SocketAddr) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(st.tls.server_config(&[b"dot"])?);
    let listener = TcpListener::bind(bind).await?;
    tracing::info!("dns-over-tls on {bind}");
    let limit = Arc::new(Semaphore::new(1024));
    loop {
        let Ok((s, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else { continue };
        let (st, acceptor) = (st.clone(), acceptor.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(tls)) = timeout(Duration::from_secs(10), acceptor.accept(s)).await else { return };
            // 60 s idle keeps a phone's Private DNS connection warm between lookups.
            serve_stream(st, tls, peer.ip(), Duration::from_secs(60)).await;
        });
    }
}

/// What would happen to `name` for source `ip`? Used by the panel's tester.
pub async fn dry_run(st: &Arc<AppState>, ip: IpAddr, name: &str, qtype: u16) -> serde_json::Value {
    let live = st.live.load_full();
    let name = norm_name(name);
    let (who, rules): (String, &Rules) = match live.identify(ip, None) {
        Who::Client(c) => (format!("client:{}", c.rec.name), &*c.rules),
        Who::Anon => ("anonymous (allow_all)".into(), &*live.rules),
        Who::Denied => return serde_json::json!({"who": "denied", "action": "refused"}),
    };
    let hit = rules.lookup(&name);
    let action = if live.records.contains_key(&name) { "static" } else { hit.map(|h| h.0).unwrap_or(Action::Direct).as_str() };
    let mut v = serde_json::json!({"who": who, "action": action, "matched_rule": hit.map(|h| h.1)});
    if action == "direct" {
        if let Some(pkt) = wire::build_query(rand::random::<u16>(), &name, qtype) {
            let t = Instant::now();
            let r = handle(st, &Src { ip, doh: None }, &pkt).await;
            v["resolved"] = match r {
                Some(b) => serde_json::json!({
                    "rcode": wire::rcode(&b), "answers": wire::ancount(&b), "ips": wire::answer_ips(&b),
                    "ttl": wire::min_ttl(&b), "ms": t.elapsed().as_millis() as u64
                }),
                None => serde_json::json!({"error": "no reply"}),
            };
        }
    }
    v
}

fn norm_name(n: &str) -> String {
    n.trim().trim_matches('.').to_ascii_lowercase()
}
