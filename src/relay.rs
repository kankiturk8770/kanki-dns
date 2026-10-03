//! Transparent relay. Port 443 reads the TLS ClientHello (SNI), port 80 reads
//! the HTTP Host header. Only names the caller's policy marks as `proxy` are
//! relayed, so this is never an open proxy. TLS is never terminated.
use crate::{
    model::Usage,
    policy::{Action, Rules},
    sni::parse_sni,
    state::{AppState, Who},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{atomic::{AtomicU64, Ordering::Relaxed}, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{lookup_host, TcpListener, TcpStream},
    sync::Semaphore,
    time::{sleep, timeout},
};

#[derive(Clone, Copy)]
pub enum Kind {
    Tls,
    Http,
}

pub async fn serve(st: Arc<AppState>, bind: SocketAddr, kind: Kind) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!("{} relay on {bind}", if matches!(kind, Kind::Tls) { "sni" } else { "http" });
    let limit = Arc::new(Semaphore::new(st.cfg.max_relays));
    loop {
        let Ok((s, peer)) = listener.accept().await else {
            sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            st.stats.relays_rejected.fetch_add(1, Relaxed);
            continue; // reject instead of queueing: a flood must not exhaust memory
        };
        let st = st.clone();
        tokio::spawn(async move {
            let _permit = permit;
            st.stats.relays_active.fetch_add(1, Relaxed);
            st.stats.relays_total.fetch_add(1, Relaxed);
            if let Err(e) = handle(&st, s, peer, kind).await {
                tracing::debug!("relay {peer}: {e}");
            }
            st.stats.relays_active.fetch_sub(1, Relaxed);
        });
    }
}

/// Never relay into private space or back to ourselves (SSRF / loops).
pub fn forbidden(ip: IpAddr, own: IpAddr) -> bool {
    if ip == own {
        return true;
    }
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified() || v.is_broadcast()
                || v.is_multicast() || (o[0] == 100 && (o[1] & 0xC0) == 64)
        }
        IpAddr::V6(v) => {
            let s = v.segments()[0];
            v.is_loopback() || v.is_unspecified() || v.is_multicast() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

async fn read_hello(c: &mut TcpStream) -> anyhow::Result<(Vec<u8>, String)> {
    let mut buf = vec![0u8; 4096];
    let mut n = 0;
    loop {
        let k = c.read(&mut buf[n..]).await?;
        if k == 0 || (n == 0 && buf[0] != 0x16) {
            anyhow::bail!("not tls");
        }
        n += k;
        if let Some(sni) = parse_sni(&buf[..n]) {
            buf.truncate(n);
            return Ok((buf, sni));
        }
        if n == buf.len() {
            anyhow::bail!("hello too large");
        }
    }
}

async fn read_http(c: &mut TcpStream) -> anyhow::Result<(Vec<u8>, String)> {
    let mut buf = vec![0u8; 8192];
    let mut n = 0;
    loop {
        let k = c.read(&mut buf[n..]).await?;
        if k == 0 {
            anyhow::bail!("eof");
        }
        n += k;
        if let Some(end) = buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
            let head = std::str::from_utf8(&buf[..end])?;
            let host = head
                .lines()
                .skip(1)
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim().eq_ignore_ascii_case("host").then(|| v.trim().to_ascii_lowercase())
                })
                .ok_or_else(|| anyhow::anyhow!("no host header"))?;
            let host = host.split(':').next().unwrap_or("").to_string();
            if host.is_empty() || !host.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_')) {
                anyhow::bail!("bad host");
            }
            buf.truncate(n);
            return Ok((buf, host));
        }
        if n == buf.len() {
            anyhow::bail!("header too large");
        }
    }
}

fn keepalive(s: &TcpStream) {
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(60)).with_interval(Duration::from_secs(20));
    let _ = socket2::SockRef::from(s).set_tcp_keepalive(&ka);
}

async fn resolve(st: &AppState, host: &str, port: u16, block_private: bool) -> Vec<SocketAddr> {
    let key = format!("{host}:{port}");
    if let Some(v) = st.dns_cache.get(&key) {
        return v.as_ref().clone();
    }
    let own = IpAddr::V4(st.cfg.public_ip);
    let addrs: Vec<SocketAddr> = match timeout(Duration::from_secs(5), lookup_host((host, port))).await {
        Ok(Ok(it)) => it.filter(|a| !(block_private && forbidden(a.ip(), own)) && a.ip() != own).collect(),
        _ => vec![],
    };
    if !addrs.is_empty() {
        st.dns_cache.insert(key, Arc::new(addrs.clone()));
    }
    addrs
}

/// Copy one direction with an idle deadline, counting bytes.
async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    idle: Duration,
    global: &AtomicU64,
    client: Option<&AtomicU64>,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match timeout(idle, r.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        global.fetch_add(n as u64, Relaxed);
        if let Some(c) = client {
            c.fetch_add(n as u64, Relaxed);
        }
    }
    let _ = w.shutdown().await;
}

async fn handle(st: &Arc<AppState>, mut c: TcpStream, peer: SocketAddr, kind: Kind) -> anyhow::Result<()> {
    let live = st.live.load_full();
    let s = &live.settings;
    let (rules, usage): (Arc<Rules>, Option<Arc<Usage>>) = match live.identify(peer.ip(), None) {
        Who::Client(cl) => (cl.rules.clone(), Some(cl.usage.clone())),
        Who::Anon => (live.rules.clone(), None),
        Who::Denied => return Ok(()),
    };
    c.set_nodelay(true)?;
    let (hello, host, port) = match kind {
        Kind::Tls => {
            let (b, h) = timeout(Duration::from_secs(5), read_hello(&mut c)).await??;
            (b, h, 443u16)
        }
        Kind::Http => {
            let (b, h) = timeout(Duration::from_secs(5), read_http(&mut c)).await??;
            (b, h, 80u16)
        }
    };
    if rules.lookup(&host).map(|x| x.0) != Some(Action::Proxy) {
        return Ok(());
    }
    let addrs = resolve(st, &host, port, s.block_private_targets).await;
    let mut up = None;
    for a in addrs.iter().take(4) {
        if let Ok(Ok(u)) = timeout(Duration::from_millis(s.relay_connect_ms), TcpStream::connect(a)).await {
            up = Some(u);
            break;
        }
    }
    let Some(mut up) = up else { return Ok(()) };
    up.set_nodelay(true)?;
    keepalive(&c);
    keepalive(&up);

    // Anti-DPI: split the ClientHello so the SNI straddles two TCP segments.
    let frag = s.fragment_size;
    if matches!(kind, Kind::Tls) && frag > 0 && hello.len() > frag {
        up.write_all(&hello[..frag]).await?;
        up.flush().await?;
        sleep(Duration::from_millis(s.fragment_delay_ms)).await;
        up.write_all(&hello[frag..]).await?;
    } else {
        up.write_all(&hello).await?;
    }

    let idle = Duration::from_secs(s.relay_idle_secs);
    let (cr, cw) = c.into_split();
    let (ur, uw) = up.into_split();
    tokio::join!(
        pump(cr, uw, idle, &st.stats.bytes_up, usage.as_ref().map(|u| &u.up)),
        pump(ur, cw, idle, &st.stats.bytes_down, usage.as_ref().map(|u| &u.down)),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_and_self() {
        let own: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(forbidden("127.0.0.1".parse().unwrap(), own));
        assert!(forbidden("10.1.2.3".parse().unwrap(), own));
        assert!(forbidden("100.64.0.1".parse().unwrap(), own));
        assert!(forbidden("::1".parse().unwrap(), own));
        assert!(forbidden(own, own));
        assert!(!forbidden("1.1.1.1".parse().unwrap(), own));
    }
}
