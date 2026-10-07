#!/bin/sh
# Install cfseats on a systemd Linux host. Run as root from the repo root:
#   sudo sh deploy/install.sh
# Idempotent. Never overwrites an existing /etc/cfseats/cfseats.env.
# Does NOT enable the timer or live mode.
set -eu

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }

# System user with no login shell and no home directory
if ! id cfseats >/dev/null 2>&1; then
    NOLOGIN=$(command -v nologin || echo /usr/sbin/nologin)
    useradd --system --no-create-home --home-dir /nonexistent --shell "$NOLOGIN" cfseats
fi

install -d -o root -g root   -m 0755 /opt/cfseats
install    -o root -g root   -m 0755 "$REPO_DIR/cfseats.py" /opt/cfseats/cfseats.py

install -d -o root -g cfseats -m 0750 /etc/cfseats
if [ ! -e /etc/cfseats/cfseats.env ]; then
    install -o root -g cfseats -m 0640 "$REPO_DIR/.env.example" /etc/cfseats/cfseats.env
    echo "created /etc/cfseats/cfseats.env (fill in CLOUDFLARE_API_TOKEN and CF_ACCOUNT_ID)"
else
    chown root:cfseats /etc/cfseats/cfseats.env
    chmod 0640 /etc/cfseats/cfseats.env
    echo "kept existing /etc/cfseats/cfseats.env"
fi

install -o root -g root -m 0644 "$REPO_DIR/deploy/cfseats.service" /etc/systemd/system/cfseats.service
install -o root -g root -m 0644 "$REPO_DIR/deploy/cfseats.timer"   /etc/systemd/system/cfseats.timer
systemctl daemon-reload

systemd-analyze verify /etc/systemd/system/cfseats.service /etc/systemd/system/cfseats.timer
echo "installed. timer NOT enabled. next: edit /etc/cfseats/cfseats.env, then: systemctl start cfseats.service"
