#!/bin/sh
# One-off install on the VPS. Run as root after copying the collabmcp binary to /tmp/collabmcp.
set -eu
command -v git >/dev/null 2>&1 || { echo "git is required: apt-get install -y git" >&2; exit 1; }
id collabmcp >/dev/null 2>&1 || useradd --system --home /var/lib/collabmcp --shell /usr/sbin/nologin collabmcp
install -d -o collabmcp -g collabmcp -m 700 /var/lib/collabmcp
install -d -m 755 /opt/collabmcp
install -m 755 /tmp/collabmcp /opt/collabmcp/collabmcp
install -m 644 deploy/collabmcp.service /etc/systemd/system/collabmcp.service
install -m 644 deploy/Caddyfile.collab /etc/caddy/conf.d/collab.caddy
systemctl daemon-reload
echo "Next: sudo -u collabmcp env COLLAB_DIR=/var/lib/collabmcp /opt/collabmcp/collabmcp passwd && ... totp"
echo "Then: systemctl enable --now collabmcp && systemctl reload caddy"
