use crate::{model::*, totp};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use dashmap::DashMap;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, io::Write, net::IpAddr, path::PathBuf, sync::Mutex};

pub struct Creds {
    pub password: String,
    pub api_key: String,
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthData {
    pub password_hash: String,
    pub api_key_hash: String,
    pub totp_secret: String,
    pub totp_enabled: bool,
    pub totp_last_step: u64,
}

pub fn hash_pw(pw: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!(e.to_string()))
}

pub fn verify_pw(hash: &str, pw: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(p) => Argon2::default().verify_password(pw.as_bytes(), &p).is_ok(),
        Err(_) => false,
    }
}

pub fn password_ok(pw: &str) -> Result<(), &'static str> {
    let classes = [
        pw.chars().any(|c| c.is_ascii_lowercase()),
        pw.chars().any(|c| c.is_ascii_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    if pw.chars().count() < 10 {
        Err("password must be at least 10 characters")
    } else if classes < 2 && pw.chars().count() < 16 {
        Err("use two character classes, or 16+ characters")
    } else {
        Ok(())
    }
}

pub fn write_private(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(tmp, path)
}

pub struct AuthStore {
    path: PathBuf,
    data: Mutex<AuthData>,
}

impl AuthStore {
    pub fn load_or_init(dir: &str) -> anyhow::Result<(Self, Option<Creds>)> {
        let path = PathBuf::from(dir).join("auth.json");
        let mut data: AuthData = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let mut creds = None;
        if data.password_hash.is_empty() {
            let pw: String = rand::thread_rng().sample_iter(&Alphanumeric).take(18).map(char::from).collect();
            let key = rand_hex(32);
            data.password_hash = hash_pw(&pw)?;
            data.api_key_hash = sha256_hex(&key);
            creds = Some(Creds { password: pw, api_key: key });
        }
        let s = Self { path, data: Mutex::new(data) };
        s.save()?;
        Ok((s, creds))
    }

    fn save(&self) -> anyhow::Result<()> {
        let d = self.data.lock().unwrap().clone();
        write_private(&self.path, &serde_json::to_vec_pretty(&d)?)?;
        Ok(())
    }

    pub fn password_hash(&self) -> String {
        self.data.lock().unwrap().password_hash.clone()
    }
    pub fn set_password(&self, pw: &str) -> anyhow::Result<()> {
        let h = hash_pw(pw)?;
        self.data.lock().unwrap().password_hash = h;
        self.save()
    }
    pub fn check_api_key(&self, key: &str) -> bool {
        let d = self.data.lock().unwrap();
        !d.api_key_hash.is_empty() && ct_eq(sha256_hex(key).as_bytes(), d.api_key_hash.as_bytes())
    }
    pub fn rotate_api_key(&self) -> anyhow::Result<String> {
        let k = rand_hex(32);
        self.data.lock().unwrap().api_key_hash = sha256_hex(&k);
        self.save()?;
        Ok(k)
    }
    pub fn totp_enabled(&self) -> bool {
        self.data.lock().unwrap().totp_enabled
    }
    /// Start enrolment: new pending secret (not active until confirmed).
    pub fn totp_begin(&self) -> anyhow::Result<String> {
        let s = totp::b32_encode(&totp::gen_secret());
        {
            let mut d = self.data.lock().unwrap();
            d.totp_secret = s.clone();
            d.totp_enabled = false;
            d.totp_last_step = 0;
        }
        self.save()?;
        Ok(s)
    }
    /// Verify a code against the stored secret, enforcing single use.
    pub fn totp_check(&self, code: &str) -> bool {
        let mut d = self.data.lock().unwrap();
        let Some(secret) = totp::b32_decode(&d.totp_secret) else { return false };
        if secret.is_empty() {
            return false;
        }
        match totp::verify(&secret, code, now_secs(), d.totp_last_step) {
            Some(step) => {
                d.totp_last_step = step;
                drop(d);
                let _ = self.save();
                true
            }
            None => false,
        }
    }
    pub fn totp_set_enabled(&self, on: bool) -> anyhow::Result<()> {
        {
            let mut d = self.data.lock().unwrap();
            d.totp_enabled = on;
            if !on {
                d.totp_secret.clear();
            }
        }
        self.save()
    }
    pub fn totp_secret(&self) -> String {
        self.data.lock().unwrap().totp_secret.clone()
    }
}

#[derive(Clone, Serialize)]
pub struct Session {
    pub created: i64,
    pub last: i64,
    pub ip: IpAddr,
    pub ua: String,
    #[serde(skip)]
    pub csrf: String,
}

#[derive(Default)]
pub struct Sessions {
    map: DashMap<String, Session>,
}

impl Sessions {
    pub fn create(&self, ip: IpAddr, ua: &str) -> (String, String) {
        let (token, csrf) = (rand_hex(32), rand_hex(16));
        let now = now_secs();
        self.map.insert(
            sha256_hex(&token),
            Session { created: now, last: now, ip, ua: ua.chars().take(120).collect(), csrf: csrf.clone() },
        );
        (token, csrf)
    }
    /// Returns (csrf, public session id) and refreshes the idle timer.
    pub fn check(&self, token: &str, idle_secs: i64) -> Option<(String, String)> {
        let id = sha256_hex(token);
        let now = now_secs();
        let mut s = self.map.get_mut(&id)?;
        if now - s.last > idle_secs || now - s.created > 86_400 {
            drop(s);
            self.map.remove(&id);
            return None;
        }
        s.last = now;
        Some((s.csrf.clone(), id[..16].to_string()))
    }
    pub fn list(&self) -> Vec<(String, Session)> {
        self.map.iter().map(|e| (e.key()[..16].to_string(), e.value().clone())).collect()
    }
    pub fn revoke(&self, public_id: &str) {
        if public_id.len() >= 16 {
            self.map.retain(|k, _| !k.starts_with(public_id));
        }
    }
    pub fn revoke_except(&self, keep: Option<&str>) {
        self.map.retain(|k, _| keep.map_or(false, |p| k.starts_with(p)));
    }
    pub fn gc(&self, idle_secs: i64) {
        let now = now_secs();
        self.map.retain(|_, s| now - s.last <= idle_secs && now - s.created <= 86_400);
    }
}

#[derive(Default)]
pub struct Lockouts {
    map: DashMap<IpAddr, (u32, i64)>,
}

impl Lockouts {
    pub fn locked(&self, ip: IpAddr) -> Option<i64> {
        let e = self.map.get(&ip)?;
        let left = e.1 - now_secs();
        (left > 0).then_some(left)
    }
    /// Records a failure; returns true if the address is now locked.
    pub fn fail(&self, ip: IpAddr, max: u32, lock_min: u64) -> bool {
        let now = now_secs();
        let mut e = self.map.entry(ip).or_insert((0, 0));
        if e.1 != 0 && e.1 <= now {
            *e = (0, 0);
        }
        e.0 += 1;
        if e.0 >= max {
            e.1 = now + lock_min as i64 * 60;
            true
        } else {
            false
        }
    }
    pub fn ok(&self, ip: IpAddr) {
        self.map.remove(&ip);
    }
    pub fn clear(&self) {
        self.map.clear();
    }
    pub fn list(&self) -> Vec<(IpAddr, u32, i64)> {
        let now = now_secs();
        self.map.iter().filter(|e| e.value().1 > now).map(|e| (*e.key(), e.value().0, e.value().1 - now)).collect()
    }
    pub fn gc(&self) {
        let now = now_secs();
        self.map.retain(|_, v| v.1 > now || (v.1 == 0 && v.0 > 0));
    }
}

#[derive(Clone, Serialize)]
pub struct AuditEntry {
    pub t: i64,
    pub ip: String,
    pub action: String,
    pub detail: String,
}

pub struct Audit {
    ring: Mutex<VecDeque<AuditEntry>>,
    path: PathBuf,
}

impl Audit {
    pub fn new(dir: &str) -> Self {
        Self { ring: Mutex::new(VecDeque::new()), path: PathBuf::from(dir).join("audit.log") }
    }
    pub fn log(&self, ip: impl ToString, action: &str, detail: &str) {
        let e = AuditEntry { t: now_secs(), ip: ip.to_string(), action: action.into(), detail: detail.chars().take(300).collect() };
        if let Ok(line) = serde_json::to_string(&e) {
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
                let _ = writeln!(f, "{line}");
            }
        }
        let mut r = self.ring.lock().unwrap();
        if r.len() >= 500 {
            r.pop_front();
        }
        r.push_back(e);
    }
    pub fn recent(&self) -> Vec<AuditEntry> {
        self.ring.lock().unwrap().iter().rev().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_policy() {
        assert!(password_ok("short1A").is_err());
        assert!(password_ok("alllowercaseonly").is_ok()); // 16+ chars
        assert!(password_ok("Abcdefgh12").is_ok());
        assert!(password_ok("alllowerxx").is_err());
    }

    #[test]
    fn lockout_after_failures() {
        let l = Lockouts::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!l.fail(ip, 3, 1));
        assert!(!l.fail(ip, 3, 1));
        assert!(l.fail(ip, 3, 1));
        assert!(l.locked(ip).is_some());
        l.ok(ip);
        assert!(l.locked(ip).is_none());
    }

    #[test]
    fn session_lifecycle() {
        let s = Sessions::default();
        let (tok, csrf) = s.create("1.1.1.1".parse().unwrap(), "ua");
        let (c2, id) = s.check(&tok, 60).unwrap();
        assert_eq!(csrf, c2);
        s.revoke(&id);
        assert!(s.check(&tok, 60).is_none());
    }
}
