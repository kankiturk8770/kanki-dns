mod auth;
mod cache;
mod config;
mod dns;
mod model;
mod net;
mod policy;
mod presets;
mod public;
mod relay;
mod sni;
mod state;
mod sys;
mod tls;
mod totp;
mod web;
mod wire;

use std::future::Future;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const USAGE: &str = "dnsgate [config.json]\n  dnsgate init <config.json> <public_ipv4>   write a config\n  dnsgate reset-password <config.json> [--no-2fa]\n  dnsgate version";

async fn opt<F: Future<Output = anyhow::Result<()>>>(f: Option<F>) -> anyhow::Result<()> {
    match f {
        Some(f) => f.await,
        None => std::future::pending().await,
    }
}

fn cli(args: &[String]) -> Option<anyhow::Result<()>> {
    match args.first().map(String::as_str) {
        Some("version") | Some("--version") => {
            println!("dnsgate {}", env!("CARGO_PKG_VERSION"));
            Some(Ok(()))
        }
        Some("help") | Some("--help") | Some("-h") => {
            println!("{USAGE}");
            Some(Ok(()))
        }
        Some("init") => Some((|| -> anyhow::Result<()> {
            let (path, ip) = (args.get(1).ok_or_else(|| anyhow::anyhow!(USAGE))?, args.get(2).ok_or_else(|| anyhow::anyhow!(USAGE))?);
            let mut c = config::Config::load_or_create(path)?;
            c.public_ip = ip.parse()?;
            c.save(path)?;
            println!("wrote {path} (admin path: /{})", c.admin_path);
            Ok(())
        })()),
        Some("reset-password") => Some((|| -> anyhow::Result<()> {
            let path = args.get(1).ok_or_else(|| anyhow::anyhow!(USAGE))?;
            let cfg = config::Config::load_or_create(path)?;
            let (store, _) = auth::AuthStore::load_or_init(&cfg.data_dir)?;
            let pw = {
                use rand::{distributions::Alphanumeric, Rng};
                rand::thread_rng().sample_iter(&Alphanumeric).take(18).map(char::from).collect::<String>()
            };
            store.set_password(&pw)?;
            if args.iter().any(|a| a == "--no-2fa") {
                store.totp_set_enabled(false)?;
            }
            println!("new admin password: {pw}");
            Ok(())
        })()),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(r) = cli(&args) {
        return r;
    }

    let path = args.first().cloned().unwrap_or_else(|| "config.json".into());
    let mut cfg = config::Config::load_or_create(&path)?;
    if let Ok(ip) = std::env::var("DNSGATE_PUBLIC_IP") {
        cfg.public_ip = ip.parse()?;
    }
    if cfg.public_ip.is_unspecified() {
        anyhow::bail!("set \"public_ip\" in {path} (or: dnsgate init {path} <ip>), then start again");
    }

    let (st, creds) = state::AppState::new(cfg)?;
    st.tls.ensure(st.cfg.public_ip)?;
    if let Some(c) = creds {
        println!("\n=== first start: save these now, they are shown once ===\n  panel:    {}://<server>:{}/{}\n  password: {}\n  api key:  {}\n=======================================================\n",
            if st.cfg.web_tls { "https" } else { "http" }, st.cfg.web_bind.port(), st.cfg.admin_path, c.password, c.api_key);
    }

    tokio::spawn(state::logger(st.clone()));
    tokio::spawn(state::sampler(st.clone()));
    tokio::spawn(state::maintenance(st.clone()));

    let dot = st.cfg.dot_bind.map(|b| dns::serve_dot(st.clone(), b));
    let http_relay = st.cfg.http_relay_bind.map(|b| relay::serve(st.clone(), b, relay::Kind::Http));

    #[cfg(unix)]
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    #[cfg(unix)]
    let term_fut = term.recv();
    #[cfg(not(unix))]
    let term_fut = std::future::pending::<Option<()>>();

    tokio::select! {
        r = dns::serve_udp(st.clone()) => r?,
        r = dns::serve_tcp(st.clone()) => r?,
        r = opt(dot) => r?,
        r = relay::serve(st.clone(), st.cfg.proxy_bind, relay::Kind::Tls) => r?,
        r = opt(http_relay) => r?,
        r = web::serve(st.clone()) => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("interrupt, shutting down"),
        _ = term_fut => tracing::info!("terminate, shutting down"),
    }
    st.save_usage();
    Ok(())
}
