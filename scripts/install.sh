#!/usr/bin/env bash
# Usage: sudo ./scripts/install.sh [path/to/dnsgate] <public_ipv4>
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
BIN="${1:-./target/release/dnsgate}"
IP="${2:-}"
[ -x "$BIN" ] || { echo "binary not found: $BIN (run: cargo build --release)"; exit 1; }
[ -n "$IP" ] || { echo "usage: $0 <binary> <public_ipv4>"; exit 1; }

install -m755 "$BIN" /usr/local/bin/dnsgate
id dnsgate >/dev/null 2>&1 || useradd --system --home /var/lib/dnsgate --shell /usr/sbin/nologin dnsgate
install -d -o dnsgate -g dnsgate -m750 /var/lib/dnsgate
install -m644 "$(dirname "$0")/dnsgate.service" /etc/systemd/system/dnsgate.service

# systemd-resolved's stub listener occupies 127.0.0.53:53 and blocks 0.0.0.0:53.
if systemctl is-active --quiet systemd-resolved; then
  mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/dnsgate.conf
  systemctl restart systemd-resolved
fi

sudo -u dnsgate /usr/local/bin/dnsgate init /var/lib/dnsgate/config.json "$IP"
systemctl daemon-reload
systemctl enable --now dnsgate
echo
echo "Started. The admin password and API key are printed once in the journal:"
echo "  journalctl -u dnsgate -n 40 --no-pager"
echo "Lost it?  sudo -u dnsgate dnsgate reset-password /var/lib/dnsgate/config.json"
