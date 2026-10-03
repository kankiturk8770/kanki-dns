//! Certificate holder with hot-swap: listeners keep a resolver, and installing
//! a new certificate takes effect on the next handshake without a restart.
use arc_swap::ArcSwapOption;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig,
};
use serde::Serialize;
use std::{path::PathBuf, sync::{Arc, Mutex}};

#[derive(Debug, Default)]
struct Holder(ArcSwapOption<CertifiedKey>);

impl ResolvesServerCert for Holder {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.load_full()
    }
}

#[derive(Clone, Serialize, Default)]
pub struct TlsInfo {
    pub source: String,
    pub subject: String,
    pub names: Vec<String>,
    pub not_after: i64,
}

pub struct TlsState {
    holder: Arc<Holder>,
    dir: PathBuf,
    info: Mutex<TlsInfo>,
}

fn describe(der: &[u8]) -> (String, Vec<String>, i64) {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else { return (String::new(), vec![], 0) };
    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(d) = gn {
                names.push(d.to_string());
            }
        }
    }
    (cert.subject().to_string(), names, cert.validity().not_after.timestamp())
}

impl TlsState {
    pub fn new(data_dir: &str) -> Self {
        Self {
            holder: Arc::new(Holder::default()),
            dir: PathBuf::from(data_dir).join("certs"),
            info: Mutex::new(TlsInfo { source: "none".into(), ..Default::default() }),
        }
    }

    pub fn info(&self) -> TlsInfo {
        self.info.lock().unwrap().clone()
    }
    pub fn loaded(&self) -> bool {
        self.holder.0.load().is_some()
    }

    fn install(&self, cert_pem: &str, key_pem: &str, source: &str) -> anyhow::Result<()> {
        let mut cr = cert_pem.as_bytes();
        let certs = rustls_pemfile::certs(&mut cr).collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            anyhow::bail!("no certificate found in PEM");
        }
        let mut kr = key_pem.as_bytes();
        let key = rustls_pemfile::private_key(&mut kr)?.ok_or_else(|| anyhow::anyhow!("no private key found in PEM"))?;
        let signing = rustls::crypto::ring::sign::any_supported_type(&key)?;
        let (subject, names, not_after) = describe(certs[0].as_ref());
        self.holder.0.store(Some(Arc::new(CertifiedKey::new(certs, signing))));
        *self.info.lock().unwrap() = TlsInfo { source: source.into(), subject, names, not_after };
        Ok(())
    }

    /// Validate, persist (0600) and hot-swap.
    pub fn install_pem(&self, cert_pem: &str, key_pem: &str, source: &str) -> anyhow::Result<()> {
        self.install(cert_pem, key_pem, source)?;
        std::fs::create_dir_all(&self.dir)?;
        crate::auth::write_private(&self.dir.join("cert.pem"), cert_pem.as_bytes())?;
        crate::auth::write_private(&self.dir.join("key.pem"), key_pem.as_bytes())?;
        std::fs::write(self.dir.join("source"), source)?;
        Ok(())
    }

    pub fn self_signed(&self, names: Vec<String>) -> anyhow::Result<()> {
        let names = if names.is_empty() { vec!["localhost".to_string()] } else { names };
        let ck = rcgen::generate_simple_self_signed(names)?;
        self.install_pem(&ck.cert.pem(), &ck.key_pair.serialize_pem(), "self-signed")
    }

    /// Load from disk, or create a self-signed certificate on first start.
    pub fn ensure(&self, public_ip: std::net::Ipv4Addr) -> anyhow::Result<()> {
        let c = std::fs::read_to_string(self.dir.join("cert.pem"));
        let k = std::fs::read_to_string(self.dir.join("key.pem"));
        if let (Ok(c), Ok(k)) = (c, k) {
            let src = std::fs::read_to_string(self.dir.join("source")).unwrap_or_else(|_| "uploaded".into());
            if self.install(&c, &k, src.trim()).is_ok() {
                return Ok(());
            }
        }
        let mut names = vec!["localhost".to_string()];
        if !public_ip.is_unspecified() {
            names.push(public_ip.to_string());
        }
        self.self_signed(names)
    }

    pub fn server_config(&self, alpn: &[&[u8]]) -> anyhow::Result<Arc<ServerConfig>> {
        let mut cfg = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(self.holder.clone());
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        Ok(Arc::new(cfg))
    }
}
