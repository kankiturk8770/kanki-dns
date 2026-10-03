use std::collections::HashSet;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Direct,
    Proxy,
    Block,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Direct => "direct",
            Action::Proxy => "proxy",
            Action::Block => "block",
        }
    }
}

#[derive(Default)]
pub struct Rules {
    proxied: HashSet<String>,
    blocked: HashSet<String>,
}

pub fn norm(d: &str) -> String {
    d.trim().trim_start_matches("*.").trim_matches('.').to_ascii_lowercase()
}

pub fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
}

impl Rules {
    pub fn new(proxied: HashSet<String>, blocked: HashSet<String>) -> Self {
        Self { proxied, blocked }
    }
    pub fn counts(&self) -> (usize, usize) {
        (self.proxied.len(), self.blocked.len())
    }

    /// `name` must be lowercase. Longest matching suffix wins; at the same
    /// depth Block outranks Proxy. Returns the matched suffix. No allocation.
    pub fn lookup<'a>(&self, name: &'a str) -> Option<(Action, &'a str)> {
        let mut s = name.trim_end_matches('.');
        loop {
            if self.blocked.contains(s) {
                return Some((Action::Block, s));
            }
            if self.proxied.contains(s) {
                return Some((Action::Proxy, s));
            }
            match s.find('.') {
                Some(i) => s = &s[i + 1..],
                None => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(v: &[&str]) -> HashSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn longest_suffix_wins() {
        let r = Rules::new(set(&["example.com"]), set(&["ads.example.com"]));
        assert_eq!(r.lookup("example.com.").map(|x| x.0), Some(Action::Proxy));
        assert_eq!(r.lookup("a.b.example.com").map(|x| x.0), Some(Action::Proxy));
        assert_eq!(r.lookup("x.ads.example.com"), Some((Action::Block, "ads.example.com")));
        assert_eq!(r.lookup("notexample.com"), None);
    }

    #[test]
    fn domain_validation() {
        assert!(valid_domain("a-b.example.com"));
        assert!(!valid_domain("bad domain.com"));
        assert!(!valid_domain(".."));
    }
}
