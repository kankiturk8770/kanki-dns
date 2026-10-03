# dnsgate

SmartDNS + transparent SNI/HTTP relay + full admin panel, in Rust. One binary, no database.
(نام و لایسنس را خودتان انتخاب کنید؛ کد از صفر نوشته شده است.)

## Quick start
```bash
cargo build --release
sudo ./scripts/install.sh ./target/release/dnsgate <public_ipv4>
journalctl -u dnsgate -n 40 --no-pager      # shows panel URL, password and API key once
```
Manual run: `dnsgate init config.json <ip> && dnsgate config.json`.
Forgot the password: `dnsgate reset-password config.json [--no-2fa]`.

## How a query is handled
1. Per-IP rate limit → parse (wire format, no tree allocation)
2. Identify the caller by source IP (or DoH token) → status check: disabled / expired / over quota ⇒ REFUSED
3. Static records (split-horizon) → policy (longest suffix; per-client rules) → `proxy` (answer = this server, AAAA/HTTPS empty) | `block` (NXDOMAIN) | `direct`
4. `direct`: cache (per-record TTL, serve-stale, prefetch) → race all upstreams → TCP retry on truncation

Relay on :443 reads the SNI, on :80 the Host header. It relays only names the caller's policy marks `proxy`,
refuses private/loopback/own addresses, enforces idle timeouts, counts bytes per client for quotas, never terminates TLS.

## Panel
Hidden path (random, in config.json), password + optional TOTP, HttpOnly/SameSite=Strict cookie, per-session CSRF, lockout, audit log.
Pages: dashboard (live charts) · live query log (SSE) · clients (IPs, quota, expiry, per-client presets/rules, portal links) ·
policies (presets, custom groups, global rules, list import, policy tester) · local records · upstreams (race, benchmark, cache) ·
settings · TLS (upload / self-signed, hot reload) · security (password, 2FA, API key, sessions, lockouts, audit) · backup/restore.

Subscriber portal: `https://host:8443/sub/<token>` shows status/usage and lets the user bind their current IP with a secret.
DoH: `/dns-query` (by IP) or `/dns-query/<token>` (by client, works from any IP). DoT: port 853.

## Operating notes
* Put a **real certificate** on the panel/DoT/DoH (Settings → TLS). Renewal hook: `PUT /api/v1/tls` with the API key.
* Ports 53, 80, 443, 853 need root or `CAP_NET_BIND_SERVICE` (the unit file grants it). Port numbers live in config.json.
* Relayed traffic uses this server's bandwidth. Heavy downloads are a separate preset that is off by default.
* `allow_all` turns the server into an open resolver; leave it off.

## Not included
Automatic ACME issuing (use certbot/acme.sh + the TLS API), IPv6-only upstream mixing, DoH/DoT *upstreams*, DNSSEC validation.
