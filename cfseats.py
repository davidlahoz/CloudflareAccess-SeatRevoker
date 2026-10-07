#!/usr/bin/env python3
"""Free Cloudflare Zero Trust seats held by idle users.

Runs as a oneshot (systemd timer, hourly). Standard library only.

Environment (see /etc/cfseats/cfseats.env):
  CLOUDFLARE_API_TOKEN  required, never logged
  CF_ACCOUNT_ID         required
  CF_EXCLUDE            comma-separated emails that are never removed
  CF_MAX_IDLE_HOURS     default 24
  CF_MAX_SEATS          default 50
  CF_HEADROOM           default 5
  CF_DRY_RUN            anything other than exactly "false" means dry run

Exit codes: 0 success (or dry run), 1 any failure.
"""

import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

API_BASE = "https://api.cloudflare.com/client/v4"
PER_PAGE = 1000
BATCH_SIZE = 50
TIMEOUT_S = 30
MAX_RETRIES = 3
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
DEFAULT_ENV_FILE = "/etc/cfseats/cfseats.env"


class ConfigError(Exception):
    pass


class ApiError(Exception):
    def __init__(self, message, errors=None, status=None):
        super().__init__(message)
        self.errors = errors if errors is not None else []
        self.status = status


# --------------------------------------------------------------------------
# Logging: JSON lines; errors to stderr. Callers must never pass the token.
# --------------------------------------------------------------------------

def log(event, stream=None, **fields):
    record = {"event": event}
    record.update(fields)
    print(json.dumps(record, sort_keys=False), file=stream or sys.stdout, flush=True)


def log_err(event, **fields):
    log(event, stream=sys.stderr, **fields)


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

def _int_env(env, name, default, minimum):
    raw = env.get(name, "").strip()
    if raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError("%s must be an integer" % name)
    if value < minimum:
        raise ConfigError("%s must be >= %d" % (name, minimum))
    return value


def load_config(env):
    token = env.get("CLOUDFLARE_API_TOKEN", "").strip()
    account = env.get("CF_ACCOUNT_ID", "").strip()
    if not token:
        raise ConfigError("CLOUDFLARE_API_TOKEN is not set")
    if not account:
        raise ConfigError("CF_ACCOUNT_ID is not set")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", account):
        raise ConfigError("CF_ACCOUNT_ID must be a 32-character hex id")

    max_seats = _int_env(env, "CF_MAX_SEATS", 50, 1)
    headroom = _int_env(env, "CF_HEADROOM", 5, 0)
    if headroom >= max_seats:
        raise ConfigError("CF_HEADROOM must be smaller than CF_MAX_SEATS")

    exclude = {e.strip().lower() for e in env.get("CF_EXCLUDE", "").split(",") if e.strip()}

    return {
        "token": token,
        "account_id": account,
        "exclude": exclude,
        "max_idle_hours": _int_env(env, "CF_MAX_IDLE_HOURS", 24, 1),
        "max_seats": max_seats,
        "headroom": headroom,
        # Only the exact string "false" enables live mode.
        "dry_run": env.get("CF_DRY_RUN") != "false",
    }


# --------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?"
    r"(Z|[+-]\d{2}:?\d{2})?$"
)


def parse_ts(value):
    """Parse ISO 8601 (with "Z" or offset, optional fractional seconds) to aware UTC.

    Returns None for empty or unparseable input. Naive timestamps are taken as UTC.
    Implemented by hand because datetime.fromisoformat only accepts "Z" and
    arbitrary fraction lengths from Python 3.11.
    """
    if not value or not isinstance(value, str):
        return None
    m = _ISO_RE.match(value.strip())
    if not m:
        return None
    year, month, day, hour, minute, second, frac, tz = m.groups()
    micros = int((frac or "0")[:6].ljust(6, "0"))
    try:
        dt = datetime(int(year), int(month), int(day), int(hour), int(minute),
                      int(second or 0), micros, tzinfo=timezone.utc)
    except ValueError:
        return None
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        dt -= sign * offset
    return dt


def last_seen(user):
    return (parse_ts(user.get("last_successful_login"))
            or parse_ts(user.get("created_at"))
            or EPOCH)


def fmt_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Selection (pure)
# --------------------------------------------------------------------------

def select(users, now, cfg):
    """Decide which seats to free.

    Returns a dict with:
      holders   all seat holders (access_seat or gateway_seat)
      excluded  holders whose email is in CF_EXCLUDE
      idle      candidates with last_seen <= now - CF_MAX_IDLE_HOURS
      overflow  oldest non-idle candidates removed to reach the seat target
      keep      candidates left untouched
      target    CF_MAX_SEATS - CF_HEADROOM
      shortfall seats still above target after removing every candidate
    All candidate lists are ordered oldest-first.
    """
    holders = [u for u in users if u.get("access_seat") or u.get("gateway_seat")]
    excluded = [u for u in holders if (u.get("email") or "").lower() in cfg["exclude"]]
    excluded_ids = {id(u) for u in excluded}
    candidates = sorted((u for u in holders if id(u) not in excluded_ids), key=last_seen)

    cutoff = now - timedelta(hours=cfg["max_idle_hours"])
    idle = [u for u in candidates if last_seen(u) <= cutoff]
    remaining = [u for u in candidates if last_seen(u) > cutoff]

    target = cfg["max_seats"] - cfg["headroom"]
    over = max(0, len(holders) - len(idle) - target)
    overflow = remaining[:over]
    keep = remaining[over:]

    return {
        "holders": holders,
        "excluded": excluded,
        "idle": idle,
        "overflow": overflow,
        "keep": keep,
        "target": target,
        "shortfall": over - len(overflow),
    }


def build_batches(users, size=BATCH_SIZE):
    """Yield PATCH bodies. Each body is always a JSON array, even for one user."""
    for i in range(0, len(users), size):
        yield [
            {"seat_uid": u["seat_uid"], "access_seat": False, "gateway_seat": False}
            for u in users[i:i + size]
        ]


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def _sleep_for(attempt, retry_after):
    try:
        if retry_after is not None:
            return min(float(retry_after), 60.0)
    except ValueError:
        pass
    return float(2 ** attempt)  # 2s, 4s, 8s


def api_request(cfg, method, path, body=None, sleep=None):
    """Call the Cloudflare API and return the parsed envelope.

    Retries 429/5xx and network errors up to MAX_RETRIES times with backoff.
    Raises ApiError (carrying the `errors` payload) on any failure or when
    `success` is not true.
    """
    sleep = sleep or time.sleep
    url = API_BASE + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Authorization": "Bearer " + cfg["token"], "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"

    attempt = 0
    while True:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        status, retry_after, raw = None, None, None
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            status, retry_after, raw = e.code, e.headers.get("Retry-After"), e.read()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            reason = getattr(e, "reason", e)
            if attempt < MAX_RETRIES:
                attempt += 1
                log_err("retry", method=method, path=path, attempt=attempt, reason=str(reason))
                sleep(_sleep_for(attempt, None))
                continue
            raise ApiError("%s %s failed: %s" % (method, path, reason))

        if (status == 429 or status >= 500) and attempt < MAX_RETRIES:
            attempt += 1
            log_err("retry", method=method, path=path, attempt=attempt, status=status)
            sleep(_sleep_for(attempt, retry_after))
            continue

        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            raise ApiError("%s %s returned non-JSON (HTTP %s)" % (method, path, status), status=status)

        if not isinstance(payload, dict) or payload.get("success") is not True:
            errors = payload.get("errors", []) if isinstance(payload, dict) else []
            raise ApiError("%s %s unsuccessful (HTTP %s)" % (method, path, status),
                           errors=errors, status=status)
        return payload


def list_users(cfg, request=api_request):
    users, page, total_pages = [], 1, 1
    while page <= total_pages:
        resp = request(cfg, "GET", "/accounts/%s/access/users?page=%d&per_page=%d"
                       % (cfg["account_id"], page, PER_PAGE))
        users.extend(resp.get("result") or [])
        total_pages = int((resp.get("result_info") or {}).get("total_pages") or 1)
        page += 1
    return users


def remove_seats(cfg, users, request=api_request):
    """PATCH seats off in batches. Logs each user once its batch succeeds."""
    path = "/accounts/%s/access/seats" % cfg["account_id"]
    removed = 0
    for i, body in enumerate(build_batches(users)):
        batch_users = users[i * BATCH_SIZE:(i + 1) * BATCH_SIZE]
        try:
            request(cfg, "PATCH", path, body)
        except ApiError:
            for u in users[i * BATCH_SIZE:]:
                log_err("user", email=u.get("email"), last_seen=fmt_ts(last_seen(u)),
                        action="not_removed", reason=u["_reason"])
            raise
        for u in batch_users:
            log("user", email=u.get("email"), last_seen=fmt_ts(last_seen(u)), action="removed",
                reason=u["_reason"])
        removed += len(batch_users)
    return removed


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def run(env, now=None, request=api_request):
    try:
        cfg = load_config(env)
    except ConfigError as e:
        log_err("config_error", error=str(e))
        return 1

    now = now or datetime.now(timezone.utc)
    try:
        users = list_users(cfg, request=request)
    except ApiError as e:
        log_err("api_error", stage="list_users", error=str(e), errors=e.errors)
        return 1

    sel = select(users, now, cfg)
    for u in sel["idle"]:
        u["_reason"] = "idle"
    for u in sel["overflow"]:
        u["_reason"] = "overflow"
    to_remove = sel["idle"] + sel["overflow"]
    no_uid = [u for u in to_remove if not u.get("seat_uid")]

    log("summary",
        dry_run=cfg["dry_run"],
        users=len(users),
        holders=len(sel["holders"]),
        excluded=len(sel["excluded"]),
        idle=len(sel["idle"]),
        overflow=len(sel["overflow"]),
        remove=len(to_remove),
        holders_after=len(sel["holders"]) - len(to_remove),
        target=sel["target"],
        max_idle_hours=cfg["max_idle_hours"])

    if sel["shortfall"]:
        log_err("warning", message="cannot reach seat target; all non-excluded candidates removed",
                shortfall=sel["shortfall"])

    def user_line(u, action, stream=None):
        log("user", stream=stream, email=u.get("email"), last_seen=fmt_ts(last_seen(u)),
            action=action)

    for u in sel["excluded"]:
        user_line(u, "excluded")
    for u in sel["keep"]:
        user_line(u, "keep")

    if no_uid:
        for u in no_uid:
            user_line(u, "error_missing_seat_uid", stream=sys.stderr)
        log_err("aborted", reason="selected users without seat_uid", count=len(no_uid))
        return 1

    if cfg["dry_run"]:
        for u in to_remove:
            user_line(u, "would_remove_" + u["_reason"])
        return 0

    try:
        remove_seats(cfg, to_remove, request=request)
    except ApiError as e:
        log_err("api_error", stage="remove_seats", error=str(e), errors=e.errors)
        return 1
    return 0


def load_env_file(path):
    """Parse KEY=VALUE lines (systemd EnvironmentFile style) into a dict.

    Ignores blank lines and # comments, accepts an optional "export " prefix and
    strips one pair of matching surrounding quotes. Values are never logged.
    """
    values = {}
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            key, sep, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                raise ConfigError("%s:%d: expected KEY=VALUE" % (path, lineno))
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key] = value
    return values


def build_env(environ, env_file=None):
    """Merge an env file under the process environment (real env vars win).

    An explicit env_file must exist. Otherwise DEFAULT_ENV_FILE is loaded when
    readable, so manual runs pick it up; under systemd it is already applied
    via EnvironmentFile= and this is a no-op.
    """
    import os
    path = env_file or DEFAULT_ENV_FILE
    if env_file is None and not os.access(path, os.R_OK):
        return dict(environ)
    merged = load_env_file(path)
    merged.update(environ)
    return merged


def main(argv=None):
    import argparse
    import os
    parser = argparse.ArgumentParser(description="Free idle Cloudflare Zero Trust seats.")
    parser.add_argument("--env-file", metavar="PATH",
                        help="KEY=VALUE file to load (default: %s if readable). "
                             "Variables already set in the environment take precedence."
                             % DEFAULT_ENV_FILE)
    args = parser.parse_args(argv)
    try:
        env = build_env(os.environ, args.env_file)
    except (ConfigError, OSError) as e:
        log_err("config_error", error="cannot load env file: %s" % e)
        sys.exit(1)
    sys.exit(run(env))


if __name__ == "__main__":
    main()
