# cfseats

Hourly systemd job that frees Cloudflare Zero Trust seats held by idle users.
Python 3 standard library only.

## Why

Cloudflare's free Zero Trust plan caps you at **50 users**, and a seat stays
occupied once a user has logged in — so a team that rotates through more than 50
people, or just accumulates stale logins, hits the limit and can't onboard
anyone new without upgrading to a paid plan.

This tool works around that limitation by reclaiming the 50 seats for whoever is
actually active: it periodically revokes the seats of idle users (those whose
last login is older than `CF_MAX_IDLE_HOURS`) and, if still over budget, the
oldest remaining holders — keeping you under the free-plan cap so active users
always have a seat. Idle users simply re-authenticate the next time they need
access.

## Install (on the Linux host, as root)

    sudo sh deploy/install.sh          # user, files, units, systemd-analyze verify; timer NOT enabled
    sudoedit /etc/cfseats/cfseats.env  # set CLOUDFLARE_API_TOKEN and CF_ACCOUNT_ID
    sudo systemctl start cfseats.service
    journalctl -u cfseats -n 50 --no-pager

The API token needs **Access: Organizations, Identity Providers, and Groups — Edit**
(read users, update seats) on the account.

## Operate

    sudo systemctl enable --now cfseats.timer    # enable hourly
    sudo systemctl disable --now cfseats.timer   # disable
    systemctl list-timers cfseats.timer          # next run
    journalctl -u cfseats -f                     # follow logs
    # go live: set CF_DRY_RUN=false in /etc/cfseats/cfseats.env (no restart needed)

## Configuration

Settings live in `/etc/cfseats/cfseats.env` (template: `.env.example`).
systemd loads it via `EnvironmentFile=`; manual runs load it automatically when readable:

    sudo -u cfseats python3 /opt/cfseats/cfseats.py         # uses /etc/cfseats/cfseats.env
    python3 cfseats.py --env-file .env                      # local file (gitignored)

Variables already set in the environment override the file.

## Test

    python3 -m unittest discover -s tests -v
