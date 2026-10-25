"""TLS Watch: persistent HTTPS certificate monitor using Flask.

Run with ``python app.py`` (Python 3.11+). The scheduler runs inside this
process, so leave this process running for unattended daily checks.
"""

from __future__ import annotations

import base64
import csv
import io
import hmac
import hashlib
import json
import uuid
import ipaddress
import os
import secrets
import socket
import sqlite3
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, dsa, rsa
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import NameOID
from flask import Flask, Response, jsonify, request, send_file

from integrations import EVENTS, RANGES, needs_attention, classify_events, normalize_webhook_url, send_webhook

BASE = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DB_PATH", str(BASE / "data" / "certificates.sqlite3")))
TIMEOUT = max(2.0, min(30.0, float(os.getenv("TLS_TIMEOUT_SECONDS", "7"))))
MAX_WORKERS = max(1, min(20, int(os.getenv("MAX_CHECK_WORKERS", "6"))))
ALLOW_PRIVATE = os.getenv("ALLOW_PRIVATE_TARGETS", "true").lower() in ("true", "1", "yes")
TZ_NAME = os.getenv("APP_TIMEZONE", "America/New_York")
try:
    LOCAL_TZ = ZoneInfo(TZ_NAME)
except ZoneInfoNotFoundError as exc:
    raise RuntimeError(f"Invalid APP_TIMEZONE: {TZ_NAME}") from exc

AUTH_USER = os.getenv("APP_USERNAME", "admin")
AUTH_PASSWORD = os.getenv("APP_PASSWORD", "ipc29042904")
if bool(AUTH_USER) != bool(AUTH_PASSWORD):
    raise RuntimeError("Set both APP_USERNAME and APP_PASSWORD, or neither")

SQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS sites (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 url TEXT NOT NULL UNIQUE,
 hostname TEXT NOT NULL,
 port INTEGER NOT NULL DEFAULT 443,
 paused INTEGER NOT NULL DEFAULT 0,
 issuer TEXT,
 issued_at TEXT,
 expires_at TEXT,
 days_left INTEGER,
 last_checked_at TEXT,
 next_check_at TEXT,
 last_error TEXT,
 tls_verified INTEGER,
 verify_error TEXT,
 created_at TEXT NOT NULL,
 certificate_pem TEXT,
 certificate_observed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sites_due ON sites(paused, next_check_at);
CREATE TABLE IF NOT EXISTS monitoring_agents (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL COLLATE NOCASE UNIQUE,
 token_hash TEXT, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
 last_seen_at TEXT, version TEXT
);
CREATE TABLE IF NOT EXISTS agent_enrollments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL REFERENCES monitoring_agents(id) ON DELETE CASCADE,
 code_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, consumed_at TEXT
);
CREATE TABLE IF NOT EXISTS groups (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL COLLATE NOCASE UNIQUE,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS site_groups (
 site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
 group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
 PRIMARY KEY(site_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_site_groups_group ON site_groups(group_id, site_id);
CREATE TABLE IF NOT EXISTS api_keys (
 id INTEGER PRIMARY KEY CHECK(id=1), key_hash TEXT NOT NULL, prefix TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webhook_config (
 id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 0,
 url TEXT NOT NULL DEFAULT '', events_json TEXT NOT NULL DEFAULT '[]',
 signing_secret TEXT NOT NULL DEFAULT '', updated_at TEXT,
 allow_http INTEGER NOT NULL DEFAULT 0,
 allow_private INTEGER NOT NULL DEFAULT 0,
 allow_self_signed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
 id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
 event TEXT NOT NULL, site_id INTEGER, url TEXT NOT NULL,
 payload TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT, delivered_at TEXT,
 response_code INTEGER, last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_delivery_pending ON webhook_deliveries(status, next_attempt_at);
CREATE TABLE IF NOT EXISTS certificate_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
 fingerprint TEXT NOT NULL, issuer TEXT, issued_at TEXT, expires_at TEXT,
 certificate_pem TEXT NOT NULL, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
 UNIQUE(site_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_cert_history_site ON certificate_history(site_id, first_seen_at DESC);
CREATE TABLE IF NOT EXISTS check_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
 checked_at TEXT NOT NULL, success INTEGER NOT NULL, tls_verified INTEGER,
 days_left INTEGER, message TEXT, fingerprint TEXT
);
CREATE INDEX IF NOT EXISTS idx_check_history_site ON check_history(site_id, id DESC);
CREATE TABLE IF NOT EXISTS webhook_targets (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL COLLATE NOCASE UNIQUE,
 enabled INTEGER NOT NULL, url TEXT NOT NULL, events_json TEXT NOT NULL,
 signing_secret TEXT NOT NULL, allow_http INTEGER NOT NULL DEFAULT 0,
 allow_private INTEGER NOT NULL DEFAULT 0, allow_self_signed INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 all_groups INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS webhook_target_groups (
 target_id INTEGER NOT NULL REFERENCES webhook_targets(id) ON DELETE CASCADE,
 group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
 PRIMARY KEY(target_id, group_id)
);

"""

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def days_remaining(expires_at: datetime, checked_at: datetime) -> int:
    """Round positive partial days up, negative partial days down for expired certs."""
    import math
    seconds = (expires_at - checked_at).total_seconds()
    return math.ceil(seconds / 86400) if seconds >= 0 else math.floor(seconds / 86400)


def next_random_check(now: datetime | None = None) -> str:
    """Choose a uniform random instant in the next LOCAL calendar day (DST-safe)."""
    now = now or utcnow()
    next_date = now.astimezone(LOCAL_TZ).date() + timedelta(days=1)
    start = datetime(next_date.year, next_date.month, next_date.day, tzinfo=LOCAL_TZ)
    end_date = next_date + timedelta(days=1)
    end = datetime(end_date.year, end_date.month, end_date.day, tzinfo=LOCAL_TZ)
    length_seconds = int((end.astimezone(timezone.utc) - start.astimezone(timezone.utc)).total_seconds())
    return utc_iso(start.astimezone(timezone.utc) + timedelta(seconds=secrets.randbelow(length_seconds)))


def normalize_url(raw: str) -> tuple[str, str, int]:
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty entry")
    if len(raw) > 2048:
        raise ValueError("URL is too long")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() != "https":
            raise ValueError("Only HTTPS websites are supported")
        if parsed.username or parsed.password:
            raise ValueError("URLs with credentials are not permitted")
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Missing hostname")
        # Enforce a canonical ASCII representation; prevents different spellings of same host.
        hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if not hostname or len(hostname) > 253 or any(c.isspace() for c in hostname):
            raise ValueError("Invalid hostname")
        port = parsed.port or 443
        if not (1 <= port <= 65535):
            raise ValueError("Invalid port")
        if parsed.netloc.count("@"):
            raise ValueError("URLs with credentials are not permitted")
        # Certificate is bound to the TLS host/port, not an HTTP URL path.
        host_display = f"[{hostname}]" if ":" in hostname else hostname
        canonical = f"https://{host_display}{(':' + str(port)) if port != 443 else ''}"
        return canonical, hostname, port
    except (ValueError, UnicodeError) as exc:
        raise ValueError(str(exc) or "Invalid HTTPS URL") from exc


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH, timeout=15) as con:
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(SQL_SCHEMA)
        # v4.4 distributed monitoring: in-place migrations preserve inventory and history.
        distributed_cols = {row[1] for row in con.execute("PRAGMA table_info(sites)")}
        for field, sqltype in (("agent_id", "INTEGER"), ("agent_lease", "TEXT"), ("lease_until", "TEXT")):
            if field not in distributed_cols:
                con.execute(f"ALTER TABLE sites ADD COLUMN {field} {sqltype}")
        con.execute("CREATE INDEX IF NOT EXISTS idx_sites_agent_due ON sites(agent_id,paused,next_check_at)")
        history_cols = {row[1] for row in con.execute("PRAGMA table_info(check_history)")}
        if "agent_id" not in history_cols:
            con.execute("ALTER TABLE check_history ADD COLUMN agent_id INTEGER")
        # Safely upgrade databases from earlier TLS Watch versions in place.
        columns = {row[1] for row in con.execute("PRAGMA table_info(sites)")}
        upgrading = "certificate_pem" not in columns
        for column in ("certificate_pem", "certificate_observed_at"):
            if column not in columns:
                con.execute(f"ALTER TABLE sites ADD COLUMN {column} TEXT")
        con.execute("""INSERT OR IGNORE INTO webhook_config
            (id, enabled, url, events_json, signing_secret, updated_at)
            VALUES (1, 0, '', ?, '', ?)""", (json.dumps(list(EVENTS)), utc_iso(utcnow())))
        # Upgrade v4 SQLite installations without changing stored webhook URLs/events.
        wh_cols = {row[1] for row in con.execute("PRAGMA table_info(webhook_config)")}
        for column in ("allow_http", "allow_private", "allow_self_signed"):
            if column not in wh_cols:
                con.execute(f"ALTER TABLE webhook_config ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0")
        site_cols = {row[1] for row in con.execute("PRAGMA table_info(sites)")}
        if "last_successful_at" not in site_cols:
            con.execute("ALTER TABLE sites ADD COLUMN last_successful_at TEXT")
            con.execute("""UPDATE sites SET last_successful_at=certificate_observed_at
                WHERE certificate_observed_at IS NOT NULL""")
            con.execute("""UPDATE sites SET last_successful_at=last_checked_at
                WHERE last_successful_at IS NULL AND last_error IS NULL
                  AND expires_at IS NOT NULL""")
        if "stale_notified" not in site_cols:
            con.execute("ALTER TABLE sites ADD COLUMN stale_notified INTEGER NOT NULL DEFAULT 0")
        deliveries_cols = {row[1] for row in con.execute("PRAGMA table_info(webhook_deliveries)")}
        if "target_id" not in deliveries_cols:
            con.execute("ALTER TABLE webhook_deliveries ADD COLUMN target_id INTEGER")
        target_cols={row[1] for row in con.execute("PRAGMA table_info(webhook_targets)")}
        if "all_groups" not in target_cols:
            con.execute("ALTER TABLE webhook_targets ADD COLUMN all_groups INTEGER NOT NULL DEFAULT 0")
        # Preserve the certificate already observed by previous versions.
        for old in con.execute("""SELECT id, certificate_pem, certificate_observed_at,
            last_checked_at, issuer, issued_at, expires_at FROM sites
            WHERE certificate_pem IS NOT NULL AND certificate_pem!=''"""):
            stamp = old["certificate_observed_at"] or old["last_checked_at"] or utc_iso(utcnow())
            fingerprint = hashlib.sha256(old["certificate_pem"].encode()).hexdigest()
            con.execute("""INSERT OR IGNORE INTO certificate_history
                (site_id, fingerprint, certificate_pem, issuer, issued_at, expires_at,first_seen_at,last_seen_at)
                VALUES (?,?,?,?,?,?,?,?)""", (old["id"], fingerprint, old["certificate_pem"],
                old["issuer"],old["issued_at"],old["expires_at"],stamp,stamp))
        # A crash mid-delivery must not strand retries permanently.
        con.execute("""UPDATE webhook_deliveries SET status='pending'
            WHERE status='sending'""")
        if upgrading:
            # Capture full certificates for previously monitored sites soon after upgrade.
            # Only do this once: failed lookups should retain their randomized daily schedule.
            con.execute("""UPDATE sites SET next_check_at=?
                WHERE paused=0 AND last_checked_at IS NOT NULL""", (utc_iso(utcnow()),))


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=15000")
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


class DNSLookupFailure(OSError):
    """A target hostname could not be resolved by the computer's DNS resolver."""


def resolve_target(host: str, port: int, allow_private: bool | None = None) -> list[tuple[int, tuple]]:
    """Resolve once, vet IPs, connect to one vetted address. No DNS re-resolution."""
    if allow_private is None:
        allow_private = ALLOW_PRIVATE  # Existing certificate-site monitoring policy.
    try:
        results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        # On Windows, 11001 (WSAHOST_NOT_FOUND) means the DNS lookup failed.
        # Include the *actual parsed hostname* so URL typos are easy to spot.
        reason = "Temporary name resolution failure" if exc.errno in (
            getattr(socket, "EAI_AGAIN", None), 11002
        ) else "Hostname was not found in DNS"
        raise DNSLookupFailure(
            f"DNS lookup failed for {host!r} (port {port}; error {exc.errno}). "
            f"{reason}. Check the hostname spelling and whether your VPN/DNS "
            f"can resolve it. In Windows Command Prompt, run: nslookup {host}"
        ) from exc
    if not results:
        raise DNSLookupFailure(
            f"DNS lookup returned no addresses for {host!r}. "
            f"In Windows Command Prompt, run: nslookup {host}"
        )
    allowed = []
    for family, socktype, proto, canon, sockaddr in results:
        address = ipaddress.ip_address(sockaddr[0].split("%")[0])
        if not allow_private and not address.is_global:
            raise OSError(
                f"Host {host!r} resolved to a private/local IP ({address}), which is blocked. "
                "For trusted internal sites only, set ALLOW_PRIVATE_TARGETS=true."
            )
        allowed.append((family, sockaddr))
    return allowed


def tls_socket(host: str, destination: tuple[int, tuple], verified: bool) -> bytes | None:
    family, sockaddr = destination
    context = ssl.create_default_context() if verified else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verified:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.socket(family, socket.SOCK_STREAM) as raw:
        raw.settimeout(TIMEOUT)
        raw.connect(sockaddr)
        with context.wrap_socket(raw, server_hostname=host) as tls:
            return None if verified else tls.getpeercert(binary_form=True)


def issuer_name(name: x509.Name) -> str:
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
    return name.rfc4514_string()


def inspect_certificate(host: str, port: int) -> dict:
    destinations = resolve_target(host, port)
    der = None
    destination = None
    last_error = None
    for candidate in destinations:
        try:
            der = tls_socket(host, candidate, verified=False)
            destination = candidate
            break
        except (OSError, ssl.SSLError) as exc:
            last_error = exc
    if not der:
        if last_error:
            raise last_error
        raise RuntimeError("Server did not present a certificate")
    cert = x509.load_der_x509_certificate(der)
    result = {
        "issuer": issuer_name(cert.issuer),
        "issued_at": utc_iso(cert.not_valid_before_utc),
        "expires_at": utc_iso(cert.not_valid_after_utc),
        "tls_verified": 1,
        "verify_error": None,
        "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    }
    try:
        tls_socket(host, destination, verified=True)
    except (ssl.SSLError, OSError) as exc:
        result["tls_verified"] = 0
        result["verify_error"] = str(exc)[:600]
    return result


init_db()
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="tls-check")
running: set[int] = set()
running_lock = threading.Lock()
stop_scheduler = threading.Event()


def stale_status(site: dict, now: datetime | None = None) -> str:
    """Fresh / warning / critical. Paused sites aren't considered stale."""
    if site.get("paused"):
        return "paused"
    basis = site.get("last_successful_at") or site.get("created_at")
    if not basis:
        return "unknown"
    try:
        age = ((now or utcnow()) - parse_datetime(basis)).total_seconds() / 3600
    except (ValueError, TypeError):
        return "unknown"
    return "critical" if age > 48 else "warning" if age > 24 else "fresh"


def site_needs_attention(site: dict) -> bool:
    return needs_attention(site) or stale_status(site) in ("warning", "critical")


def record_certificate_version(con: sqlite3.Connection, site_id: int, previous: dict,
                               current: dict, checked: datetime) -> None:
    pem = current.get("certificate_pem")
    if not pem:
        return
    digest = hashlib.sha256(pem.encode("utf-8")).hexdigest()
    stamp = utc_iso(checked)
    con.execute("""INSERT INTO certificate_history
        (site_id,fingerprint,issuer,issued_at,expires_at,certificate_pem,first_seen_at,last_seen_at)
        VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(site_id,fingerprint) DO UPDATE
        SET last_seen_at=excluded.last_seen_at""",
        (site_id,digest,current.get("issuer"),current.get("issued_at"),current.get("expires_at"),pem,stamp,stamp))


def record_check(con: sqlite3.Connection, site_id: int, at: datetime, success: bool,
                 current: dict, agent_id: int | None = None) -> None:
    pem = current.get("certificate_pem") if success else None
    fingerprint = hashlib.sha256(pem.encode()).hexdigest() if pem else None
    con.execute("""INSERT INTO check_history
        (site_id,checked_at,success,tls_verified,days_left,message,fingerprint,agent_id)
        VALUES (?,?,?,?,?,?,?,?)""",
        (site_id,utc_iso(at),int(success),current.get("tls_verified") if success else None,current.get("days_left"),
         current.get("verify_error") if success else current.get("last_error"),fingerprint,agent_id))
    # Bound history growth; keep the 1000 most recent checks per website.
    con.execute("""DELETE FROM check_history WHERE site_id=? AND id NOT IN
        (SELECT id FROM check_history WHERE site_id=? ORDER BY id DESC LIMIT 1000)""",(site_id,site_id))


def site_public_record(site: dict) -> dict:
    """Read-only API and event payload: never expose raw PEM or local internals."""
    keep = ("id", "url", "hostname", "port", "paused", "issuer", "issued_at",
            "expires_at", "days_left", "last_checked_at", "next_check_at",
            "last_error", "tls_verified", "verify_error", "certificate_observed_at", "last_successful_at", "agent_id")
    obj = {k: site.get(k) for k in keep}
    obj["paused"] = bool(obj["paused"])
    obj["tls_verified"] = (None if obj["tls_verified"] is None else bool(obj["tls_verified"]))
    obj["stale_status"] = stale_status(site)
    obj["needs_attention"] = site_needs_attention(site)
    return obj


def queue_events(con: sqlite3.Connection, before: dict, after: dict) -> None:
    """Route transitions to the default webhook and any group-scoped destinations."""
    event_names = [e for e in classify_events(before, after)
                   if e not in ("needs_attention", "attention_cleared")]
    # Staleness contributes to Needs Attention alongside expiry and TLS problems.
    prior_attention = site_needs_attention(before)
    current_attention = site_needs_attention(after)
    if prior_attention != current_attention:
        event_names.append("needs_attention" if current_attention else "attention_cleared")
    # New history-backed change events are independent of basic change detection.
    if not after.get("last_error") and before.get("certificate_pem") and after.get("certificate_pem") \
            and before["certificate_pem"] != after["certificate_pem"]:
        old_exp = before.get("expires_at")
        new_exp = after.get("expires_at")
        if old_exp and new_exp:
            if parse_datetime(new_exp) > parse_datetime(old_exp):
                event_names.append("certificate_renewed")
            elif parse_datetime(new_exp) < parse_datetime(old_exp):
                event_names.append("certificate_expiration_shortened")
        if before.get("issuer") != after.get("issuer"):
            event_names.append("certificate_issuer_changed")
    if not event_names:
        return
    group_rows = con.execute("""SELECT sg.group_id, g.name FROM site_groups sg
        JOIN groups g ON g.id=sg.group_id WHERE sg.site_id=?""",(after["id"],)).fetchall()
    group_ids = [r["group_id"] for r in group_rows]
    group_names = [r["name"] for r in group_rows]
    setting = con.execute("SELECT * FROM webhook_config WHERE id=1").fetchone()
    targets = []
    if setting and setting["enabled"] and setting["url"]:
        targets.append((None, setting, set(json.loads(setting["events_json"]))))
    for target in con.execute("SELECT * FROM webhook_targets WHERE enabled=1 AND url!=''"):
        assigned = {r[0] for r in con.execute(
            "SELECT group_id FROM webhook_target_groups WHERE target_id=?", (target["id"],))}
        if not target["all_groups"] and not assigned.intersection(group_ids):
            continue
        targets.append((target["id"], target, set(json.loads(target["events_json"]))))
    for event_name in list(dict.fromkeys(event_names)):
        for target_id, cfg, enabled_events in targets:
            if event_name not in enabled_events:
                continue
            event_id = str(uuid.uuid4())
            created_at = utc_iso(utcnow())
            payload = json.dumps({"event_id": event_id, "event": event_name,
                "occurred_at": created_at, "site": site_public_record(after),
                "group_ids": group_ids, "groups": group_names,
                "previous": {"days_left": before.get("days_left"),
                             "issuer": before.get("issuer"), "expires_at": before.get("expires_at"),
                             "last_error": before.get("last_error"),
                             "tls_verified": None if before.get("tls_verified") is None
                             else bool(before.get("tls_verified"))}}, separators=(",", ":"))
            con.execute("""INSERT INTO webhook_deliveries
                (event_id,event,site_id,url,payload,created_at,next_attempt_at,target_id)
                VALUES (?,?,?,?,?,?,?,?)""",
                (event_id,event_name,after["id"],cfg["url"],payload,created_at,created_at,target_id))


def process_webhook_delivery() -> None:
    """Claim one queued event and attempt delivery; retry 3 times after errors."""
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("""SELECT * FROM webhook_deliveries WHERE status='pending'
            AND next_attempt_at<=? ORDER BY id LIMIT 1""", (utc_iso(utcnow()),)).fetchone()
        if row is None:
            return
        cfg = con.execute("SELECT * FROM webhook_targets WHERE id=?", (row["target_id"],)).fetchone() \
            if row["target_id"] is not None else con.execute("SELECT * FROM webhook_config WHERE id=1").fetchone()
        if not cfg or not cfg["enabled"] or row["url"] != cfg["url"]:
            con.execute("UPDATE webhook_deliveries SET status='cancelled' WHERE id=?", (row["id"],))
            return
        if row["target_id"] is not None and row["site_id"] is not None and not cfg["all_groups"]:
            allowed = con.execute("""SELECT 1 FROM site_groups sg
                JOIN webhook_target_groups tg ON tg.group_id=sg.group_id
                WHERE tg.target_id=? AND sg.site_id=? LIMIT 1""",
                (row["target_id"],row["site_id"])).fetchone()
            if allowed is None:
                con.execute("UPDATE webhook_deliveries SET status='cancelled' WHERE id=?",(row["id"],))
                return
        con.execute("UPDATE webhook_deliveries SET status='sending', attempts=attempts+1 WHERE id=?", (row["id"],))
    try:
        # Per-webhook policy is deliberately independent of monitored HTTPS sites.
        private_allowed = bool(cfg["allow_private"])
        def resolve_webhook(host, port):
            return resolve_target(host, port, allow_private=private_allowed)
        http_code = send_webhook(row["url"], row["payload"], cfg["signing_secret"],
                                 row["event"], row["event_id"], resolve_webhook,
                                 timeout=TIMEOUT, allow_private=private_allowed,
                                 allow_http=bool(cfg["allow_http"]),
                                 allow_self_signed=bool(cfg["allow_self_signed"]))
        with db() as con:
            con.execute("""UPDATE webhook_deliveries SET status='delivered', response_code=?,
                delivered_at=?, last_error=NULL, next_attempt_at=NULL WHERE id=?""",
                (http_code, utc_iso(utcnow()), row["id"]))
    except Exception as exc:
        attempts = row["attempts"] + 1
        final = attempts >= 3
        next_at = None if final else utc_iso(utcnow() + timedelta(seconds=(60 if attempts == 1 else 300)))
        with db() as con:
            con.execute("""UPDATE webhook_deliveries SET status=?, last_error=?,
                next_attempt_at=?, response_code=NULL WHERE id=?""",
                ("failed" if final else "pending", f"{type(exc).__name__}: {exc}"[:500],
                 next_at, row["id"]))


webhook_send_lock = threading.Lock()
webhook_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="tls-webhooks")

def webhook_delivery_job():
    try:
        process_webhook_delivery()
    finally:
        webhook_send_lock.release()


def run_check(site_id: int) -> None:
    checked = utcnow()
    try:
        with db() as con:
            site = con.execute("SELECT hostname, port,agent_id FROM sites WHERE id=?", (site_id,)).fetchone()
        if site is None or site["agent_id"] is not None:
            return
        result = inspect_certificate(site["hostname"], site["port"])
        checked = utcnow()
        days_left = days_remaining(parse_datetime(result["expires_at"]), checked)
        with db() as con:
            previous = con.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
            if previous is None or previous["agent_id"] is not None:
                return
            con.execute("""UPDATE sites SET issuer=?, issued_at=?, expires_at=?, days_left=?,
                last_checked_at=?, last_error=NULL, tls_verified=?, verify_error=?,
                certificate_pem=COALESCE(?, certificate_pem),
                certificate_observed_at=CASE WHEN ? IS NOT NULL THEN ? ELSE certificate_observed_at END,
                next_check_at=CASE WHEN paused=1 THEN NULL ELSE ? END,
                last_successful_at=?, stale_notified=0
                WHERE id=?""", (
                result["issuer"], result["issued_at"], result["expires_at"], days_left,
                utc_iso(checked), result["tls_verified"], result["verify_error"],
                result.get("certificate_pem"), result.get("certificate_pem"), utc_iso(checked),
                next_random_check(checked), utc_iso(checked), site_id,
            ))
            current = con.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
            record_certificate_version(con, site_id, dict(previous), dict(current), checked)
            record_check(con, site_id, checked, True, dict(current))
            queue_events(con, dict(previous), dict(current))
    except Exception as exc:
        checked = utcnow()
        msg = (str(exc) if isinstance(exc, DNSLookupFailure)
               else f"{type(exc).__name__}: {str(exc)}")[:800]
        with db() as con:
            row = con.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
            if row is None or row["agent_id"] is not None:
                return
            days_left = (days_remaining(parse_datetime(row["expires_at"]), checked)
                         if row["expires_at"] else None)
            con.execute("""UPDATE sites SET last_checked_at=?, last_error=?, days_left=?,
                next_check_at=CASE WHEN paused=1 THEN NULL ELSE ? END WHERE id=?""",
                (utc_iso(checked), msg, days_left, next_random_check(checked), site_id))
            current = con.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
            record_check(con, site_id, checked, False, dict(current))
            queue_events(con, dict(row), dict(current))
    finally:
        with running_lock:
            running.discard(site_id)


def enqueue(site_id: int) -> bool:
    """Run local sites in-process; mark remote sites due for outbound agent poll."""
    with db() as con:
        site = con.execute("SELECT agent_id,agent_lease,lease_until FROM sites WHERE id=?", (site_id,)).fetchone()
        if site is None:
            return False
        if site["agent_id"] is not None:
            if site["agent_lease"] and site["lease_until"] and site["lease_until"] > utc_iso(utcnow()):
                return False
            con.execute("UPDATE sites SET next_check_at=? WHERE id=?", (utc_iso(utcnow()), site_id))
            return True
    with running_lock:
        if site_id in running:
            return False
        running.add(site_id)
    try:
        executor.submit(run_check, site_id)
    except RuntimeError:
        with running_lock:
            running.discard(site_id)
        raise
    return True


def check_stale_sites() -> None:
    """Emit warning/critical once on crossing, including when no TLS check occurs."""
    with db() as con:
        for row in con.execute("SELECT * FROM sites WHERE paused=0"):
            site=dict(row)
            level=stale_status(site)
            code=2 if level=="critical" else 1 if level=="warning" else 0
            old=site.get("stale_notified") or 0
            if code>old:
                event="monitoring_stale_critical" if code==2 else "monitoring_stale_warning"
                # Synthetic transition: same existing event routing with an explicit event list.
                queue_specific_event(con,site,event)
                if old == 0 and not needs_attention(site):
                    queue_specific_event(con,site,"needs_attention")
                con.execute("UPDATE sites SET stale_notified=? WHERE id=?",(code,site["id"]))


def queue_specific_event(con: sqlite3.Connection, site: dict, event: str) -> None:
    group_rows=con.execute("""SELECT sg.group_id,g.name FROM site_groups sg JOIN groups g
        ON g.id=sg.group_id WHERE sg.site_id=?""",(site["id"],)).fetchall()
    group_ids=[r[0] for r in group_rows]
    group_names=[r[1] for r in group_rows]
    cfgs=[]
    default=con.execute("SELECT * FROM webhook_config WHERE id=1").fetchone()
    if default and default["enabled"] and default["url"]: cfgs.append((None,default))
    for cfg in con.execute("SELECT * FROM webhook_targets WHERE enabled=1 AND url!=''"):
        selected={r[0] for r in con.execute("SELECT group_id FROM webhook_target_groups WHERE target_id=?",(cfg["id"],))}
        if cfg["all_groups"] or selected.intersection(group_ids): cfgs.append((cfg["id"],cfg))
    for target_id,cfg in cfgs:
        if event not in json.loads(cfg["events_json"]): continue
        event_id=str(uuid.uuid4()); stamp=utc_iso(utcnow())
        payload=json.dumps({"event_id":event_id,"event":event,"occurred_at":stamp,
            "site":site_public_record(site),"group_ids":group_ids,"groups":group_names},separators=(",",":"))
        con.execute("""INSERT INTO webhook_deliveries
            (event_id,event,site_id,url,payload,created_at,next_attempt_at,target_id)
            VALUES (?,?,?,?,?,?,?,?)""",(event_id,event,site["id"],cfg["url"],payload,stamp,stamp,target_id))


def scheduler_loop() -> None:
    while not stop_scheduler.is_set():
        try:
            now = utc_iso(utcnow())
            with db() as con:
                due = con.execute("""SELECT id FROM sites WHERE paused=0 AND agent_id IS NULL AND next_check_at IS NOT NULL
                    AND next_check_at<=? ORDER BY next_check_at LIMIT 25""", (now,)).fetchall()
            for row in due:
                with running_lock:
                    # Avoid unbounded queue growth on large bulk imports.
                    if len(running) >= MAX_WORKERS * 2:
                        break
                enqueue(row["id"])
            check_stale_sites()
            if webhook_send_lock.acquire(blocking=False):
                try:
                    webhook_executor.submit(webhook_delivery_job)
                except RuntimeError:
                    webhook_send_lock.release()
        except Exception as exc:
            print(f"[scheduler] {exc}", flush=True)
        stop_scheduler.wait(10)




# Only one Flask process should run at a time: the scheduler is in-process.
app = Flask(__name__, static_folder=str(BASE / "static"), static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 2_200_000  # 2MB import payload plus JSON escaping overhead
scheduler_thread: threading.Thread | None = None


def start_scheduler() -> None:
    global scheduler_thread
    if scheduler_thread is not None and scheduler_thread.is_alive():
        return
    stop_scheduler.clear()
    scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True, name="tls-scheduler")
    scheduler_thread.start()


@app.before_request
def access_control():
    """Optional HTTP Basic auth plus same-origin protection for write requests."""
    # Only an API key authorizes remote read-only v1 endpoints.
    # An API key is deliberately never accepted for dashboard/admin writes.
    if request.path.startswith("/agent/v1/"):
        # Agents authenticate with separate per-agent bearer tokens, not dashboard credentials.
        # The enrollment endpoint uses a short-lived, single-use pairing code.
        if request.path != "/agent/v1/enroll" and not authenticate_agent():
            return error(401, "Active agent bearer token required")
        if request.method in {"POST", "PUT", "DELETE"} and request.content_length and request.content_length > 100_000:
            return error(413, "Agent request too large")
        return None
    if request.path.startswith("/api/v1/"):
        if request.method != "GET":
            return error(405, "Read-only API: GET requests only")
        provided = request.headers.get("X-API-Key", "")
        bearer = request.headers.get("Authorization", "")
        if not provided and bearer.startswith("Bearer "):
            provided = bearer[7:]
        if not valid_api_key(provided):
            resp = jsonify({"detail": "Valid API key required (X-API-Key or Bearer)"})
            resp.status_code = 401
            resp.headers["Cache-Control"] = "no-store"
            return resp
        return None
    if not AUTH_USER and request.remote_addr not in ("127.0.0.1", "::1"):
        return error(403, "Remote dashboard access requires APP_USERNAME and APP_PASSWORD")
    if AUTH_USER:
        token = request.headers.get("Authorization", "")
        authorized = False
        if token.startswith("Basic "):
            try:
                decoded = base64.b64decode(token[6:], validate=True).decode("utf-8")
                username, password = decoded.split(":", 1)
                authorized = (hmac.compare_digest(username, AUTH_USER)
                              and hmac.compare_digest(password, AUTH_PASSWORD))
            except (ValueError, UnicodeDecodeError):
                pass
        if not authorized:
            return Response(status=401, headers={"WWW-Authenticate": 'Basic realm="TLS Watch"'})
    if request.path.startswith("/api/settings/") or request.path == "/api/settings":
        # No configured Basic credentials: setup is accessible only from this PC.
        # To administer from LAN, configure APP_USERNAME and APP_PASSWORD and HTTPS.
        if not AUTH_USER and request.remote_addr not in ("127.0.0.1", "::1"):
            return error(403, "Configure APP_USERNAME and APP_PASSWORD to administer remotely")
    if request.method in {"POST", "DELETE", "PUT", "PATCH"}:
        origin = request.headers.get("Origin")
        if origin:
            try:
                parsed = urlsplit(origin)
                if (parsed.scheme not in ("http", "https")
                        or parsed.netloc.lower() != request.host.lower()):
                    return error(403, "Origin not allowed")
            except ValueError:
                return error(403, "Origin not allowed")


def error(code: int, message: str):
    return jsonify({"detail": message}), code


def json_body() -> dict | None:
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


def to_dict(row: sqlite3.Row) -> dict:
    obj = dict(row)
    # Don't send potentially large PEM contents on the inventory polling endpoint.
    obj["has_certificate"] = bool(obj.pop("certificate_pem", None))
    obj["paused"] = bool(obj["paused"])
    with running_lock:
        obj["checking"] = obj["id"] in running
    obj["tls_verified"] = None if obj["tls_verified"] is None else bool(obj["tls_verified"])
    obj["stale_status"] = stale_status(obj)
    obj["needs_attention"] = site_needs_attention(obj)
    return obj


class GroupNotFound(ValueError):
    """Unknown inventory group (never silently substitute ALL)."""


@app.errorhandler(GroupNotFound)
def group_not_found(exc):
    return error(404, str(exc))


def validate_group_name(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Group name must be text")
    name = value.strip()
    if not name or len(name) > 60 or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError("Group name must be 1–60 printable characters")
    if name.casefold() == "all":
        raise ValueError("ALL is reserved for the complete inventory")
    return name


def validate_site_ids(value: object) -> list[int]:
    if not isinstance(value, list) or len(value) > 10000:
        raise ValueError("site_ids must be an array of at most 10000 IDs")
    if any(type(v) is not int or v <= 0 for v in value):
        raise ValueError("site_ids must contain positive integer IDs")
    return list(dict.fromkeys(value))


def validate_group_ids(value: object) -> list[int]:
    if not isinstance(value, list) or len(value) > 1000:
        raise ValueError("group_ids must be an array of at most 1000 IDs")
    if any(type(v) is not int or v <= 0 for v in value):
        raise ValueError("group_ids must contain positive integer IDs")
    return list(dict.fromkeys(value))


def require_existing_ids(con: sqlite3.Connection, table: str, ids: list[int]) -> None:
    # Only these hardcoded table names may be interpolated in SQL.
    assert table in ("sites", "groups")
    if not ids:
        return
    markers = ",".join("?" for _ in ids)
    existing = {r[0] for r in con.execute(f"SELECT id FROM {table} WHERE id IN ({markers})", ids)}
    if len(existing) != len(ids):
        raise ValueError(f"One or more {table} IDs do not exist")


def group_record(row: sqlite3.Row) -> dict:
    return {"id": row["id"], "name": row["name"], "site_count": row["site_count"]}


def group_list(con: sqlite3.Connection) -> list[dict]:
    return [group_record(r) for r in con.execute("""SELECT g.id, g.name,
        COUNT(sg.site_id) AS site_count FROM groups g
        LEFT JOIN site_groups sg ON sg.group_id = g.id
        GROUP BY g.id ORDER BY g.name COLLATE NOCASE, g.id""")]


def resolve_group(con: sqlite3.Connection, path_group_id: int | None = None) -> dict | None:
    """Existing endpoints accept ?group=<id or name>; scoped aliases use numeric IDs."""
    selector = str(path_group_id) if path_group_id is not None else request.args.get("group", "all")
    if selector is None or selector.strip().lower() == "all" or selector == "":
        return None
    if len(selector) > 60:
        raise GroupNotFound("Unknown group")
    if selector.isdecimal():
        row = con.execute("SELECT id, name FROM groups WHERE id=?", (int(selector),)).fetchone()
    else:
        row = con.execute("SELECT id, name FROM groups WHERE name=? COLLATE NOCASE", (selector,)).fetchone()
    if row is None:
        raise GroupNotFound("Unknown group")
    return {"id": row["id"], "name": row["name"]}


def sites_in_group(con: sqlite3.Connection, group: dict | None, order: str = "s.url") -> list[sqlite3.Row]:
    # order is always a hard-coded constant, never supplied by the client.
    assert order in ("s.url", "s.days_left, s.url")
    if group is None:
        return con.execute(f"SELECT s.* FROM sites s ORDER BY {order}").fetchall()
    return con.execute(f"""SELECT s.* FROM sites s
        JOIN site_groups sg ON sg.site_id=s.id WHERE sg.group_id=?
        ORDER BY {order}""", (group["id"],)).fetchall()


def group_memberships(con: sqlite3.Connection) -> dict[int, list[int]]:
    found: dict[int, list[int]] = {}
    for r in con.execute("SELECT site_id, group_id FROM site_groups ORDER BY group_id"):
        found.setdefault(r["site_id"], []).append(r["group_id"])
    return found


@app.get("/api/groups")
def admin_groups():
    with db() as con:
        return jsonify({"groups": group_list(con)})


@app.post("/api/groups")
def create_group():
    body = json_body()
    if body is None:
        return error(400, "Provide a JSON object")
    try:
        name = validate_group_name(body.get("name"))
        site_ids = validate_site_ids(body.get("site_ids", []))
        with db() as con:
            require_existing_ids(con, "sites", site_ids)
            cursor = con.execute("INSERT INTO groups(name, created_at) VALUES (?,?)",
                                 (name, utc_iso(utcnow())))
            group_id = cursor.lastrowid
            con.executemany("INSERT INTO site_groups(site_id, group_id) VALUES (?,?)",
                            ((site_id, group_id) for site_id in site_ids))
        return jsonify({"id": group_id, "name": name, "site_count": len(site_ids)}), 201
    except sqlite3.IntegrityError:
        return error(409, "A group with that name already exists")
    except ValueError as exc:
        return error(400, str(exc))


@app.put("/api/groups/<int:group_id>")
def rename_group(group_id):
    body = json_body()
    if body is None:
        return error(400, "Provide a JSON object")
    try:
        name = validate_group_name(body.get("name"))
        # A single atomic save prevents half-applied edits (rename but not membership).
        site_ids = (validate_site_ids(body["site_ids"]) if "site_ids" in body else None)
        with db() as con:
            if con.execute("SELECT 1 FROM groups WHERE id=?", (group_id,)).fetchone() is None:
                return error(404, "Group not found")
            if site_ids is not None:
                require_existing_ids(con, "sites", site_ids)
            con.execute("UPDATE groups SET name=? WHERE id=?", (name, group_id))
            if site_ids is not None:
                con.execute("DELETE FROM site_groups WHERE group_id=?", (group_id,))
                con.executemany("INSERT INTO site_groups(site_id, group_id) VALUES (?,?)",
                                ((site_id, group_id) for site_id in site_ids))
        return jsonify({"id": group_id, "name": name,
                        "site_count": len(site_ids) if site_ids is not None else None})
    except sqlite3.IntegrityError:
        return error(409, "A group with that name already exists")
    except ValueError as exc:
        return error(400, str(exc))


@app.delete("/api/groups/<int:group_id>")
def remove_group(group_id):
    with db() as con:
        cursor = con.execute("DELETE FROM groups WHERE id=?", (group_id,))
        if not cursor.rowcount:
            return error(404, "Group not found")
    return jsonify({"ok": True, "message": "Group deleted; websites remain monitored"})


@app.put("/api/groups/<int:group_id>/sites")
def set_group_sites(group_id):
    body = json_body()
    if body is None:
        return error(400, "Provide JSON with site_ids")
    try:
        site_ids = validate_site_ids(body.get("site_ids"))
        with db() as con:
            if con.execute("SELECT 1 FROM groups WHERE id=?", (group_id,)).fetchone() is None:
                return error(404, "Group not found")
            require_existing_ids(con, "sites", site_ids)
            con.execute("DELETE FROM site_groups WHERE group_id=?", (group_id,))
            con.executemany("INSERT INTO site_groups(site_id, group_id) VALUES (?,?)",
                            ((site_id, group_id) for site_id in site_ids))
        return jsonify({"ok": True, "group_id": group_id, "site_count": len(site_ids)})
    except ValueError as exc:
        return error(400, str(exc))


@app.put("/api/sites/<int:site_id>/groups")
def set_site_groups(site_id):
    body = json_body()
    if body is None:
        return error(400, "Provide JSON with group_ids")
    try:
        group_ids = validate_group_ids(body.get("group_ids"))
        with db() as con:
            if con.execute("SELECT 1 FROM sites WHERE id=?", (site_id,)).fetchone() is None:
                return error(404, "Site not found")
            require_existing_ids(con, "groups", group_ids)
            con.execute("DELETE FROM site_groups WHERE site_id=?", (site_id,))
            con.executemany("INSERT INTO site_groups(site_id, group_id) VALUES (?,?)",
                            ((site_id, group_id) for group_id in group_ids))
        return jsonify({"ok": True, "site_id": site_id, "group_ids": group_ids})
    except ValueError as exc:
        return error(400, str(exc))


def webhook_targets_public(con: sqlite3.Connection) -> list[dict]:
    result = []
    for cfg in con.execute("SELECT * FROM webhook_targets ORDER BY name COLLATE NOCASE"):
        groups = [r[0] for r in con.execute(
            "SELECT group_id FROM webhook_target_groups WHERE target_id=? ORDER BY group_id", (cfg["id"],))]
        result.append({"id":cfg["id"], "name": cfg["name"], "enabled":bool(cfg["enabled"]),
            "url": cfg["url"],"events":json.loads(cfg["events_json"]),"group_ids":groups,
            "secret_configured":bool(cfg["signing_secret"]),
            "allow_http":bool(cfg["allow_http"]),"allow_private":bool(cfg["allow_private"]),
            "allow_self_signed":bool(cfg["allow_self_signed"]),"updated_at":cfg["updated_at"],
            "all_groups":bool(cfg["all_groups"])})
    return result


def validate_webhook_target(body: dict) -> tuple:
    name = body.get("name")
    if not isinstance(name,str) or not name.strip() or len(name.strip())>80:
        raise ValueError("Name must be 1–80 characters")
    name = name.strip()
    if any(ord(c) < 32 for c in name):
        raise ValueError("Invalid characters in name")
    enabled = body.get("enabled")
    if type(enabled) is not bool:
        raise ValueError("enabled must be boolean")
    events = body.get("events")
    if not isinstance(events,list) or not all(isinstance(e,str) and e in EVENTS for e in events) or len(events)!=len(set(events)):
        raise ValueError("Invalid or duplicate webhook events")
    groups = validate_group_ids(body.get("group_ids",[]))
    opts = [body.get(k,False) for k in ("allow_http","allow_private","allow_self_signed")]
    if any(type(v) is not bool for v in opts):
        raise ValueError("Transport options must be booleans")
    url = body.get("url")
    if not isinstance(url,str):
        raise ValueError("url must be a string")
    normalized = normalize_webhook_url(url.strip(),allow_private=opts[1],allow_http=opts[0]) if url.strip() else ""
    if enabled and (not normalized or not events):
        raise ValueError("Enabled webhook needs a URL and at least one event")
    return name,enabled,normalized,events,groups,opts


@app.post("/api/settings/webhooks")
def create_webhook_target():
    body = json_body()
    if body is None:
        return error(400,"Provide JSON webhook settings")
    try:
        name,enabled,url,events,group_ids,opts = validate_webhook_target(body)
        with db() as con:
            require_existing_ids(con,"groups",group_ids)
            stamp=utc_iso(utcnow())
            secret=secrets.token_urlsafe(32)
            cur=con.execute("""INSERT INTO webhook_targets(name,enabled,url,events_json,signing_secret,
                allow_http,allow_private,allow_self_signed,created_at,updated_at,all_groups)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",(name,int(enabled),url,json.dumps(events),secret,
                *map(int,opts),stamp,stamp,int(not group_ids)))
            con.executemany("INSERT INTO webhook_target_groups(target_id,group_id) VALUES (?,?)",
                [(cur.lastrowid,g) for g in group_ids])
        response=jsonify({"id":cur.lastrowid,"signing_secret":secret})
        response.headers["Cache-Control"]="no-store"
        return response,201
    except sqlite3.IntegrityError:
        return error(409,"Destination name already exists")
    except ValueError as exc:
        return error(400,str(exc))


@app.put("/api/settings/webhooks/<int:target_id>")
def edit_webhook_target(target_id):
    body=json_body()
    if body is None:
        return error(400,"Provide JSON webhook settings")
    try:
        name,enabled,url,events,group_ids,opts=validate_webhook_target(body)
        with db() as con:
            old=con.execute("SELECT * FROM webhook_targets WHERE id=?",(target_id,)).fetchone()
            if old is None: return error(404,"Webhook not found")
            old_groups={r[0] for r in con.execute(
                "SELECT group_id FROM webhook_target_groups WHERE target_id=?",(target_id,))}
            require_existing_ids(con,"groups",group_ids)
            con.execute("""UPDATE webhook_targets SET name=?,enabled=?,url=?,events_json=?,
                allow_http=?,allow_private=?,allow_self_signed=?,updated_at=?,all_groups=? WHERE id=?""",
                (name,int(enabled),url,json.dumps(events),*map(int,opts),utc_iso(utcnow()),int(not group_ids),target_id))
            con.execute("DELETE FROM webhook_target_groups WHERE target_id=?",(target_id,))
            con.executemany("INSERT INTO webhook_target_groups(target_id,group_id) VALUES (?,?)",
                [(target_id,g) for g in group_ids])
            if not enabled or url != old["url"] or set(group_ids)!=old_groups or \
                bool(old["all_groups"])!=bool(not group_ids) or any(bool(old[k])!=v for k,v in zip(
                ("allow_http","allow_private","allow_self_signed"),opts)):
                con.execute("""UPDATE webhook_deliveries SET status='cancelled',next_attempt_at=NULL
                    WHERE status='pending' AND target_id=?""",(target_id,))
        return jsonify({"ok":True})
    except sqlite3.IntegrityError: return error(409,"Destination name already exists")
    except ValueError as exc: return error(400,str(exc))


@app.delete("/api/settings/webhooks/<int:target_id>")
def delete_webhook_target(target_id):
    with db() as con:
        con.execute("""UPDATE webhook_deliveries SET status='cancelled',next_attempt_at=NULL
            WHERE status='pending' AND target_id=?""",(target_id,))
        found=con.execute("DELETE FROM webhook_targets WHERE id=?",(target_id,)).rowcount
    return jsonify({"ok":True}) if found else error(404,"Webhook not found")


@app.post("/api/settings/webhooks/<int:target_id>/rotate-secret")
def rotate_target_secret(target_id):
    secret=secrets.token_urlsafe(32)
    with db() as con:
        if not con.execute("SELECT 1 FROM webhook_targets WHERE id=?",(target_id,)).fetchone():
            return error(404,"Webhook not found")
        con.execute("UPDATE webhook_targets SET signing_secret=?,updated_at=? WHERE id=?",
            (secret,utc_iso(utcnow()),target_id))
        con.execute("""UPDATE webhook_deliveries SET status='cancelled',next_attempt_at=NULL
            WHERE status='pending' AND target_id=?""",(target_id,))
    response=jsonify({"signing_secret":secret})
    response.headers["Cache-Control"]="no-store"
    return response


@app.post("/api/settings/webhooks/<int:target_id>/test")
def test_target_webhook(target_id):
    with db() as con:
        cfg=con.execute("SELECT * FROM webhook_targets WHERE id=?",(target_id,)).fetchone()
        if cfg is None: return error(404,"Webhook not found")
        if not cfg["enabled"] or not cfg["url"]: return error(400,"Enable and save the webhook first")
        event_id=str(uuid.uuid4()); created=utc_iso(utcnow())
        payload=json.dumps({"event_id":event_id,"event":"test","occurred_at":created,"site":None,
            "message":"TLS Watch test delivery"},separators=(",",":"))
        con.execute("""INSERT INTO webhook_deliveries
            (event_id,event,site_id,url,payload,created_at,next_attempt_at,target_id)
            VALUES (?,?,NULL,?,?,?,?,?)""",(event_id,"test",cfg["url"],payload,created,created,target_id))
    return jsonify({"ok":True,"message":"Queued"}),202


# --- TLS Watch remote agents: pull-only orchestration (v4.4) ---
def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def authenticated_agent_id() -> int | None:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:]
    if len(token) < 35 or len(token) > 256:
        return None
    with db() as con:
        row = con.execute("SELECT id FROM monitoring_agents WHERE enabled=1 AND token_hash=?",
                          (token_digest(token),)).fetchone()
    return row["id"] if row else None


def authenticate_agent() -> bool:
    return authenticated_agent_id() is not None


def agent_public_record(row: sqlite3.Row, now: datetime | None = None) -> dict:
    result = {k: row[k] for k in ("id", "name", "enabled", "created_at", "last_seen_at", "version")}
    result["enabled"] = bool(result["enabled"])
    result["status"] = "disabled" if not result["enabled"] else (
        "online" if result["last_seen_at"] and (now or utcnow()) - parse_datetime(result["last_seen_at"]) < timedelta(seconds=90) else "offline")
    return result


@app.get("/api/agents")
def admin_agents():
    with db() as con:
        agents = [agent_public_record(row) for row in con.execute("SELECT * FROM monitoring_agents ORDER BY name")]
        site_counts = {r["agent_id"]: r["n"] for r in con.execute(
            "SELECT agent_id, COUNT(*) n FROM sites WHERE agent_id IS NOT NULL GROUP BY agent_id")}
    for agent in agents:
        agent["site_count"] = site_counts.get(agent["id"], 0)
    return jsonify({"agents": agents})


@app.get("/api/v1/agents")
def public_agent_inventory():
    with db() as con:
        agents = [agent_public_record(row) for row in con.execute("SELECT * FROM monitoring_agents ORDER BY name")]
        counts = {r["agent_id"]:r["n"] for r in con.execute(
            "SELECT agent_id,COUNT(*) n FROM sites WHERE agent_id IS NOT NULL GROUP BY agent_id")}
    for a in agents:
        a["site_count"] = counts.get(a["id"], 0)
    return jsonify({"agents": agents, "count": len(agents), "as_of": utc_iso(utcnow())})


@app.post("/api/agents")
def admin_create_agent():
    body = json_body() or {}
    name = body.get("name")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 70:
        return error(400, "Enter an agent name (1-70 characters)")
    name = name.strip()
    code = "tlsw-enroll-" + secrets.token_urlsafe(32)
    expiry = utc_iso(utcnow() + timedelta(minutes=15))
    try:
        with db() as con:
            cursor = con.execute("INSERT INTO monitoring_agents(name,created_at) VALUES (?,?)",
                                 (name, utc_iso(utcnow())))
            agent_id = cursor.lastrowid
            con.execute("INSERT INTO agent_enrollments(agent_id,code_hash,expires_at) VALUES (?,?,?)",
                        (agent_id, token_digest(code), expiry))
    except sqlite3.IntegrityError:
        return error(409, "Agent name already exists")
    return jsonify({"id": agent_id, "name": name, "enrollment_code": code, "expires_at": expiry}), 201


@app.post("/api/agents/<int:agent_id>/pair")
def admin_pair_agent(agent_id):
    code = "tlsw-enroll-" + secrets.token_urlsafe(32)
    expiry = utc_iso(utcnow() + timedelta(minutes=15))
    with db() as con:
        row = con.execute("SELECT enabled FROM monitoring_agents WHERE id=?", (agent_id,)).fetchone()
        if not row:
            return error(404, "Agent not found")
        if not row["enabled"]:
            return error(400, "Agent is disabled")
        con.execute("DELETE FROM agent_enrollments WHERE agent_id=?", (agent_id,))
        con.execute("INSERT INTO agent_enrollments(agent_id,code_hash,expires_at) VALUES (?,?,?)",
                    (agent_id, token_digest(code), expiry))
    return jsonify({"enrollment_code": code, "expires_at": expiry})


@app.put("/api/agents/<int:agent_id>")
def admin_update_agent(agent_id):
    body = json_body()
    if body is None or not isinstance(body.get("enabled"), bool):
        return error(400, "Supply enabled true or false")
    with db() as con:
        row = con.execute("SELECT id FROM monitoring_agents WHERE id=?", (agent_id,)).fetchone()
        if not row:
            return error(404, "Agent not found")
        con.execute("UPDATE monitoring_agents SET enabled=? WHERE id=?", (int(body["enabled"]), agent_id))
        if not body["enabled"]:
            con.execute("UPDATE sites SET agent_lease=NULL,lease_until=NULL WHERE agent_id=?", (agent_id,))
    return jsonify({"ok": True})


@app.delete("/api/agents/<int:agent_id>")
def admin_delete_agent(agent_id):
    with db() as con:
        if not con.execute("SELECT id FROM monitoring_agents WHERE id=?", (agent_id,)).fetchone():
            return error(404, "Agent not found")
        con.execute("UPDATE sites SET agent_id=NULL,agent_lease=NULL,lease_until=NULL,next_check_at=? WHERE agent_id=?",
                    (utc_iso(utcnow()), agent_id))
        con.execute("DELETE FROM agent_enrollments WHERE agent_id=?", (agent_id,))
        con.execute("DELETE FROM monitoring_agents WHERE id=?", (agent_id,))
    return jsonify({"ok": True, "message": "Affected websites moved back to primary"})


@app.put("/api/sites/<int:site_id>/agent")
def admin_assign_agent(site_id):
    body = json_body()
    if body is None or ("agent_id" not in body):
        return error(400, "Supply agent_id (integer or null for primary)")
    agent_id = body["agent_id"]
    if agent_id is not None and (type(agent_id) is not int or agent_id <= 0):
        return error(400, "agent_id must be an integer or null")
    with db() as con:
        site = con.execute("SELECT id, paused, agent_id FROM sites WHERE id=?", (site_id,)).fetchone()
        if not site:
            return error(404, "Website not found")
        if agent_id is not None and not con.execute(
                "SELECT id FROM monitoring_agents WHERE id=? AND enabled=1", (agent_id,)).fetchone():
            return error(400, "Agent does not exist or is disabled")
        if site["agent_id"] == agent_id:
            return jsonify({"ok": True, "agent_id": agent_id})
        con.execute("UPDATE sites SET agent_id=?,agent_lease=NULL,lease_until=NULL,next_check_at=? WHERE id=?",
                    (agent_id, None if site["paused"] else utc_iso(utcnow()), site_id))
    # A queued local check from the previous assignment can still finish. See run_check owner guard.
    if agent_id is None and not site["paused"]:
        enqueue(site_id)
    return jsonify({"ok": True, "agent_id": agent_id})


@app.post("/agent/v1/enroll")
def agent_enroll():
    body = json_body() or {}
    code = body.get("enrollment_code")
    if not isinstance(code, str) or not 35 <= len(code) <= 160:
        return error(400, "A valid enrollment code is required")
    digest = token_digest(code)
    token = "tlsw-agent-" + secrets.token_urlsafe(36)
    # Atomic consume: one enrollment code cannot create two overlapping sessions.
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("""SELECT e.id AS enrollment_id, e.agent_id, a.name FROM agent_enrollments e
            JOIN monitoring_agents a ON a.id=e.agent_id
            WHERE e.code_hash=? AND e.consumed_at IS NULL AND e.expires_at>? AND a.enabled=1""",
            (digest, utc_iso(utcnow()))).fetchone()
        if not row:
            return error(401, "Enrollment code invalid, expired or already used")
        con.execute("UPDATE agent_enrollments SET consumed_at=? WHERE id=?", (utc_iso(utcnow()), row["enrollment_id"]))
        con.execute("UPDATE monitoring_agents SET token_hash=?,last_seen_at=? WHERE id=?",
                    (token_digest(token), utc_iso(utcnow()), row["agent_id"]))
    return jsonify({"agent_id": row["agent_id"], "agent_name": row["name"], "agent_token": token})


@app.post("/agent/v1/poll")
def agent_poll():
    agent_id = authenticated_agent_id()
    body = json_body() or {}
    version = str(body.get("version", "unknown"))[:50]
    stamp = utc_iso(utcnow())
    capacity = body.get("capacity", 4)
    if type(capacity) is not int or not 0 <= capacity <= 4:
        return error(400, "capacity must be an integer from 0 through 4")
    tasks = []
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        con.execute("UPDATE monitoring_agents SET last_seen_at=?,version=? WHERE id=?", (stamp, version, agent_id))
        due = con.execute("""SELECT id,hostname,port,url FROM sites
           WHERE agent_id=? AND paused=0 AND next_check_at<=?
             AND (agent_lease IS NULL OR lease_until IS NULL OR lease_until<=?)
           ORDER BY next_check_at LIMIT ?""", (agent_id,stamp,stamp,capacity)).fetchall()
        for row in due:
            lease = secrets.token_urlsafe(32)
            until = utc_iso(utcnow() + timedelta(minutes=4))
            con.execute("UPDATE sites SET agent_lease=?,lease_until=? WHERE id=?", (lease, until,row["id"]))
            tasks.append({"site_id":row["id"],"hostname":row["hostname"],"port":row["port"],
                          "url":row["url"],"lease":lease,"lease_until":until})
    return jsonify({"tasks": tasks, "server_time": stamp})


def persist_agent_check(con: sqlite3.Connection, previous: dict, report: dict, checked: datetime) -> None:
    site_id = previous["id"]
    if report.get("success"):
        pem = report.get("certificate_pem")
        if not isinstance(pem, str) or not 100 <= len(pem) <= 40_000:
            raise ValueError("Missing or oversized PEM certificate")
        try:
            cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError("Invalid certificate PEM") from exc
        pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        # Never trust leaf subject / validity fields supplied by the remote agent.
        issuer = issuer_name(cert.issuer)
        issued_at = utc_iso(cert.not_valid_before_utc)
        expires_at = utc_iso(cert.not_valid_after_utc)
        verified = report.get("tls_verified")
        if type(verified) is not bool:
            raise ValueError("tls_verified must be a boolean")
        verify_error = report.get("verify_error")
        if verify_error is not None and not isinstance(verify_error, str):
            raise ValueError("verify_error must be text or null")
        result = {"issuer":issuer,"issued_at":issued_at,"expires_at":expires_at,
                  "certificate_pem":pem,"tls_verified":int(verified),
                  "verify_error":str(verify_error)[:600] if verify_error else None}
        con.execute("""UPDATE sites SET issuer=?,issued_at=?,expires_at=?,days_left=?,
            last_checked_at=?,last_error=NULL,tls_verified=?,verify_error=?,certificate_pem=?,
            certificate_observed_at=?,next_check_at=CASE WHEN paused=1 THEN NULL ELSE ? END,
            last_successful_at=?,stale_notified=0,agent_lease=NULL,lease_until=NULL WHERE id=?""",
            (issuer,issued_at,expires_at,days_remaining(parse_datetime(expires_at),checked),
             utc_iso(checked),result["tls_verified"],result["verify_error"],pem,
             utc_iso(checked),next_random_check(checked),utc_iso(checked),site_id))
        after = dict(con.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone())
        record_certificate_version(con,site_id,previous,after,checked)
        record_check(con,site_id,checked,True,after,previous["agent_id"])
    else:
        reason = report.get("error")
        if not isinstance(reason,str) or not reason.strip():
            raise ValueError("Failure report must include an error message")
        remaining = days_remaining(parse_datetime(previous["expires_at"]),checked) if previous["expires_at"] else None
        con.execute("""UPDATE sites SET last_checked_at=?,last_error=?,days_left=?,
            next_check_at=CASE WHEN paused=1 THEN NULL ELSE ? END,agent_lease=NULL,lease_until=NULL
            WHERE id=?""", (utc_iso(checked),reason[:800],remaining,next_random_check(checked),site_id))
        after = dict(con.execute("SELECT * FROM sites WHERE id=?",(site_id,)).fetchone())
        record_check(con,site_id,checked,False,after,previous["agent_id"])
    queue_events(con,previous,after)


@app.post("/agent/v1/result")
def agent_result():
    agent_id = authenticated_agent_id()
    body = json_body() or {}
    if type(body.get("site_id")) is not int or not isinstance(body.get("lease"),str):
        return error(400,"site_id and lease are required")
    try:
        with db() as con:
            con.execute("BEGIN IMMEDIATE")
            site = con.execute("SELECT * FROM sites WHERE id=? AND agent_id=? AND agent_lease=? AND paused=0",
                               (body["site_id"],agent_id,body["lease"])).fetchone()
            if not site:
                return error(409,"Lease expired, ownership changed, site paused, or result already submitted")
            if not site["lease_until"] or site["lease_until"] <= utc_iso(utcnow()):
                return error(409,"Lease expired; task must be reissued")
            persist_agent_check(con,dict(site),body,utcnow())
            con.execute("UPDATE monitoring_agents SET last_seen_at=? WHERE id=?", (utc_iso(utcnow()),agent_id))
    except ValueError as exc:
        return error(400,str(exc))
    return jsonify({"ok":True})


@app.get("/api/v1/groups")
def public_groups():
    with db() as con:
        groups = group_list(con)
        total = con.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
    resp = jsonify({"groups": [{"id": "all", "name": "ALL", "site_count": total}] + groups,
                    "as_of": utc_iso(utcnow())})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/api/v1/groups/<int:group_id>")
def public_group(group_id):
    with db() as con:
        group = resolve_group(con, path_group_id=group_id)
        row = con.execute("SELECT COUNT(*) FROM site_groups WHERE group_id=?", (group_id,)).fetchone()
    return jsonify({"group": {**group, "site_count": row[0]}})


def valid_api_key(provided: str) -> bool:
    if not provided or len(provided) > 256:
        return False
    digest = hashlib.sha256(provided.encode("utf-8")).hexdigest()
    with db() as con:
        row = con.execute("SELECT key_hash FROM api_keys WHERE id=1").fetchone()
    return row is not None and hmac.compare_digest(digest, row["key_hash"])


def sanitized_certificate(row: sqlite3.Row) -> dict:
    return site_public_record(dict(row))


def response_certificates(rows: list[sqlite3.Row], selection: str,
                          group: dict | None = None) -> Response:
    with db() as con:
        memberships = group_memberships(con)
    certificates = []
    for site in rows:
        item = sanitized_certificate(site)
        item["group_ids"] = memberships.get(site["id"], [])
        certificates.append(item)
    response = jsonify({"certificates": certificates,
                        "count": len(rows), "selection": selection,
                        "group": group or {"id": "all", "name": "ALL"},
                        "as_of": utc_iso(utcnow()),
                        "days_basis": "days remaining at last certificate check"})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/v1/summary")
@app.get("/api/v1/groups/<int:group_id>/summary")
def public_summary(group_id=None):
    with db() as con:
        group = resolve_group(con, group_id)
        rows = [dict(s) for s in sites_in_group(con, group)]
    return jsonify({"as_of": utc_iso(utcnow()), "group": group or {"id": "all", "name": "ALL"},
                    "total": len(rows),
                    "healthy": sum(1 for s in rows if s["days_left"] is not None and s["days_left"] > 90),
                    "expiring_60": sum(1 for s in rows if s["days_left"] is not None and s["days_left"] <= 60),
                    "needs_attention": sum(site_needs_attention(s) for s in rows),
                    "stale_warning": sum(stale_status(s)=="warning" for s in rows),
                    "stale_critical": sum(stale_status(s)=="critical" for s in rows)})


@app.get("/api/v1/certificates")
@app.get("/api/v1/groups/<int:group_id>/certificates")
def public_certificates(group_id=None):
    range_value = request.args.get("range", "all")
    # In query strings a literal + often decodes as a space. Accept both forms.
    if range_value in ("90 ", "90plus", ">90"):
        range_value = "90+"
    if range_value != "all" and range_value not in RANGES:
        return error(400, "Valid ranges: all, expired, 0-30, 31-60, 61-90, 90+")
    with db() as con:
        group = resolve_group(con, group_id)
        rows = sites_in_group(con, group)
    rows = [r for r in rows if (range_value == "all" or
            (r["days_left"] is not None and RANGES[range_value](r["days_left"])))]
    return response_certificates(rows, range_value, group)


@app.get("/api/v1/certificates/expiring")
@app.get("/api/v1/groups/<int:group_id>/certificates/expiring")
def public_expiring(group_id=None):
    raw = request.args.get("within", "30")
    if raw not in ("30", "60", "90"):
        return error(400, "within must be 30, 60, or 90")
    days = int(raw)
    with db() as con:
        group = resolve_group(con, group_id)
        rows = [r for r in sites_in_group(con, group, "s.days_left, s.url")
                if r["days_left"] is not None and r["days_left"] <= days]
    return response_certificates(rows, f"within_{days}", group)


@app.get("/api/v1/certificates/needs-attention")
@app.get("/api/v1/groups/<int:group_id>/certificates/needs-attention")
def public_needs_attention(group_id=None):
    with db() as con:
        group = resolve_group(con, group_id)
        rows = [r for r in sites_in_group(con, group, "s.days_left, s.url")
                if site_needs_attention(dict(r))]
    return response_certificates(rows, "needs_attention", group)


@app.get("/api/v1/certificates/<int:site_id>")
@app.get("/api/v1/groups/<int:group_id>/certificates/<int:site_id>")
def public_certificate(site_id, group_id=None):
    with db() as con:
        group = resolve_group(con, group_id)
        if group is None:
            row = con.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
        else:
            row = con.execute("""SELECT s.* FROM sites s
                JOIN site_groups sg ON sg.site_id=s.id
                WHERE s.id=? AND sg.group_id=?""", (site_id, group["id"])).fetchone()
        group_ids = [r[0] for r in con.execute(
            "SELECT group_id FROM site_groups WHERE site_id=? ORDER BY group_id", (site_id,))]
    if row is None:
        return error(404, "Certificate not found in this group")
    certificate = sanitized_certificate(row)
    certificate["group_ids"] = group_ids
    response = jsonify({"certificate": certificate, "group": group or {"id": "all", "name": "ALL"}})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/settings")
def get_settings():
    with db() as con:
        key = con.execute("SELECT prefix, created_at FROM api_keys WHERE id=1").fetchone()
        cfg = con.execute("SELECT * FROM webhook_config WHERE id=1").fetchone()
        targets = webhook_targets_public(con)
        recent = con.execute("""SELECT id, event, site_id, created_at, status, attempts, target_id,
            delivered_at, response_code, last_error FROM webhook_deliveries
            ORDER BY id DESC LIMIT 30""").fetchall()
    result = {"api_key": {"configured": bool(key),
                         "prefix": key["prefix"] if key else None,
                         "created_at": key["created_at"] if key else None},
              "webhook": {"enabled": bool(cfg["enabled"]), "url": cfg["url"],
                          "allow_http": bool(cfg["allow_http"]),
                          "allow_private": bool(cfg["allow_private"]),
                          "allow_self_signed": bool(cfg["allow_self_signed"]),
                          "events": json.loads(cfg["events_json"]),
                          "secret_configured": bool(cfg["signing_secret"]),
                          "updated_at": cfg["updated_at"]},
              "available_events": list(EVENTS),
              "targets": targets,
              "deliveries": [dict(item) for item in recent]}
    response = jsonify(result)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/settings/api-key")
def rotate_api_key():
    new_key = "tlsw_" + secrets.token_urlsafe(32)
    now = utc_iso(utcnow())
    with db() as con:
        con.execute("""INSERT INTO api_keys (id, key_hash, prefix, created_at)
            VALUES (1,?,?,?) ON CONFLICT(id) DO UPDATE SET key_hash=excluded.key_hash,
            prefix=excluded.prefix, created_at=excluded.created_at""",
            (hashlib.sha256(new_key.encode()).hexdigest(), new_key[:13] + "…", now))
    response = jsonify({"api_key": new_key, "created_at": now,
                        "message": "Save the key now. It will not be shown again."})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.delete("/api/settings/api-key")
def revoke_api_key():
    with db() as con:
        con.execute("DELETE FROM api_keys")
    return jsonify({"ok": True})


@app.put("/api/settings/webhook")
def save_webhook():
    body = json_body()
    if (body is None or type(body.get("enabled")) is not bool or
            not isinstance(body.get("url"), str) or
            not isinstance(body.get("events"), list)):
        return error(400, "Provide enabled, URL and events[]")
    selected = body["events"]
    if len(selected) != len(set(str(e) for e in selected)) or not all(e in EVENTS for e in selected):
        return error(400, "Invalid or duplicate event names")
    # Missing fields are false for backwards compatibility with v4 clients.
    options = {key: body.get(key, False) for key in
               ("allow_http", "allow_private", "allow_self_signed")}
    if any(type(value) is not bool for value in options.values()):
        return error(400, "Webhook transport options must be booleans")
    enabled = body["enabled"]
    raw_url = body["url"].strip()
    try:
        target = normalize_webhook_url(raw_url, allow_private=options["allow_private"],
                                       allow_http=options["allow_http"]) if raw_url else ""
    except ValueError as exc:
        return error(400, str(exc))
    if enabled and (not target or not selected):
        return error(400, "Enable requires a destination URL and at least one event")
    generated = None
    with db() as con:
        config = con.execute("SELECT * FROM webhook_config WHERE id=1").fetchone()
        secret = config["signing_secret"] or secrets.token_urlsafe(32)
        if not config["signing_secret"]:
            generated = secret
        # Cancel any pending events aimed at a previous recipient / when disabling.
        changed_policy = any(bool(config[key]) != value for key, value in options.items())
        if not enabled or target != config["url"] or changed_policy:
            con.execute("""UPDATE webhook_deliveries SET status='cancelled', next_attempt_at=NULL
                WHERE status='pending' AND target_id IS NULL""")
        con.execute("""UPDATE webhook_config SET enabled=?, url=?, events_json=?,
            signing_secret=?, updated_at=?, allow_http=?, allow_private=?,
            allow_self_signed=? WHERE id=1""",
            (int(enabled), target, json.dumps(selected), secret, utc_iso(utcnow()),
             int(options["allow_http"]), int(options["allow_private"]),
             int(options["allow_self_signed"])))
    resp = jsonify({"ok": True, "signing_secret": generated})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post("/api/settings/webhook/rotate-secret")
def rotate_signing_secret():
    secret = secrets.token_urlsafe(32)
    with db() as con:
        con.execute("UPDATE webhook_config SET signing_secret=?, updated_at=? WHERE id=1",
                    (secret, utc_iso(utcnow())))
        # Cancel pending deliveries signed using a prior secret.
        con.execute("""UPDATE webhook_deliveries SET status='cancelled', next_attempt_at=NULL
            WHERE status='pending' AND target_id IS NULL""")
    resp = jsonify({"signing_secret": secret,
                    "message": "Save this secret now. It will not be shown again."})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post("/api/settings/webhook/test")
def test_webhook():
    with db() as con:
        cfg = con.execute("SELECT * FROM webhook_config WHERE id=1").fetchone()
        if not cfg["enabled"] or not cfg["url"]:
            return error(400, "Enable and save a webhook first")
        event_id = str(uuid.uuid4())
        created = utc_iso(utcnow())
        payload = json.dumps({"event_id": event_id, "event": "test", "occurred_at": created,
                              "site": None, "message": "TLS Watch test delivery"}, separators=(",", ":"))
        con.execute("""INSERT INTO webhook_deliveries
            (event_id, event, site_id, url, payload, created_at, next_attempt_at)
            VALUES (?,?,NULL,?,?,?,?)""",
            (event_id, "test", cfg["url"], payload, created, created))
    return jsonify({"ok": True, "message": "Test webhook queued; delivery status appears below."}), 202


@app.get("/")
def home():
    return send_file(BASE / "static" / "index.html")


@app.get("/api/sites")
def get_sites():
    with db() as con:
        rows = con.execute("SELECT * FROM sites ORDER BY paused, url").fetchall()
        agent_names = {r["id"]:r["name"] for r in con.execute("SELECT id,name FROM monitoring_agents")}
        memberships = group_memberships(con)
        groups = group_list(con)
    items = [to_dict(row) for row in rows]
    for site in items:
        site["group_ids"] = memberships.get(site["id"], [])
        site["agent_name"] = agent_names.get(site.get("agent_id"), "Primary server" if site.get("agent_id") is None else "Agent removed")
        site.pop("agent_lease", None)
        site.pop("lease_until", None)
    return jsonify({"sites": items, "groups": groups,
                    "timezone": TZ_NAME, "server_time": utc_iso(utcnow())})


def fetch_site_history(con: sqlite3.Connection,site_id: int) -> dict | None:
    site=con.execute("SELECT url FROM sites WHERE id=?",(site_id,)).fetchone()
    if site is None: return None
    certs=[dict(row) for row in con.execute("""SELECT id, fingerprint,issuer,issued_at,expires_at,
        first_seen_at,last_seen_at FROM certificate_history WHERE site_id=?
        ORDER BY first_seen_at DESC,id DESC LIMIT 250""",(site_id,))]
    for i in range(len(certs)-1):
        current, previous = certs[i], certs[i+1]
        current["issuer_changed"] = current.get("issuer") != previous.get("issuer")
        new_exp, old_exp = current.get("expires_at"), previous.get("expires_at")
        current["expiration_delta_days"] = (round((parse_datetime(new_exp)-parse_datetime(old_exp)).total_seconds()/86400,1)
                                             if new_exp and old_exp else None)
    checks=[dict(row) for row in con.execute("""SELECT checked_at,success,tls_verified,days_left,message,fingerprint
        FROM check_history WHERE site_id=? ORDER BY id DESC LIMIT 150""",(site_id,))]
    for row in checks:
        row["success"]=bool(row["success"])
        row["tls_verified"]=None if row["tls_verified"] is None else bool(row["tls_verified"])
    return {"url":site["url"],"certificates":certs,"checks":checks}


@app.get("/api/sites/<int:site_id>/history")
@app.get("/api/v1/certificates/<int:site_id>/history")
@app.get("/api/v1/groups/<int:group_id>/certificates/<int:site_id>/history")
def site_history(site_id:int,group_id=None):
    with db() as con:
        if group_id is not None:
            resolve_group(con,group_id)
            if not con.execute("SELECT 1 FROM site_groups WHERE site_id=? AND group_id=?",(site_id,group_id)).fetchone():
                return error(404,"Site not found in group")
        result=fetch_site_history(con,site_id)
    if result is None: return error(404,"Site not found")
    response=jsonify(result);response.headers["Cache-Control"]="no-store";return response


@app.get("/api/sites/<int:site_id>/history/<int:certificate_id>.pem")
def history_certificate_pem(site_id:int,certificate_id:int):
    with db() as con:
        found=con.execute("""SELECT certificate_pem FROM certificate_history
            WHERE id=? AND site_id=?""",(certificate_id,site_id)).fetchone()
    if found is None: return error(404,"Certificate not found")
    response=Response(found["certificate_pem"],content_type="application/x-pem-file")
    response.headers["Content-Disposition"]=f'attachment; filename="certificate-{site_id}-{certificate_id}.pem"'
    response.headers["Cache-Control"]="no-store";return response


def certificate_details(pem: str) -> dict:
    """Decode an observed leaf certificate to human-readable X.509 fields."""
    cert = x509.load_pem_x509_certificate(pem.encode("ascii"))

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ip_names = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns_names, ip_names = [], []

    try:
        usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        key_usage = [label for attr, label in (
            ("digital_signature", "Digital Signature"),
            ("content_commitment", "Content Commitment"),
            ("key_encipherment", "Key Encipherment"),
            ("data_encipherment", "Data Encipherment"),
            ("key_agreement", "Key Agreement"),
            ("key_cert_sign", "Certificate Sign"),
            ("crl_sign", "CRL Sign"),
        ) if getattr(usage, attr)]
        if usage.key_agreement:
            if usage.encipher_only:
                key_usage.append("Encipher Only")
            if usage.decipher_only:
                key_usage.append("Decipher Only")
    except x509.ExtensionNotFound:
        key_usage = []

    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        extended_usage = [oid._name if oid._name != 'Unknown OID' else oid.dotted_string for oid in eku]
    except x509.ExtensionNotFound:
        extended_usage = []

    try:
        constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        basic_constraints = ("CA: TRUE" if constraints.ca else "CA: FALSE") + (
            f", path length: {constraints.path_length}" if constraints.path_length is not None else "")
    except x509.ExtensionNotFound:
        basic_constraints = "Not present"

    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key_description = f"RSA ({public_key.key_size} bits)"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key_description = f"Elliptic Curve ({public_key.curve.name}, {public_key.key_size} bits)"
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key_description = f"DSA ({public_key.key_size} bits)"
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key_description = "Ed25519"
    elif isinstance(public_key, ed448.Ed448PublicKey):
        public_key_description = "Ed448"
    else:
        public_key_description = type(public_key).__name__

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "version": cert.version.name.upper(),
        "serial_number": format(cert.serial_number, "X"),
        "issued_at": utc_iso(cert.not_valid_before_utc),
        "expires_at": utc_iso(cert.not_valid_after_utc),
        "dns_names": dns_names,
        "ip_addresses": ip_names,
        "sha256_fingerprint": ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256())),
        "sha1_fingerprint": ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA1())),
        "signature_algorithm": (cert.signature_algorithm_oid._name
                                if cert.signature_algorithm_oid._name not in (None, "Unknown OID")
                                else cert.signature_algorithm_oid.dotted_string),
        "public_key": public_key_description,
        "key_usage": key_usage,
        "extended_key_usage": extended_usage,
        "basic_constraints": basic_constraints,
        "pem": pem,
    }


@app.get("/api/sites/<int:site_id>/certificate")
def get_certificate(site_id: int):
    """Return the saved certificate; opening details does not trigger a new check."""
    site = require_site(site_id)
    if site is None:
        return error(404, "Site not found")
    certificate = None
    if site["certificate_pem"]:
        try:
            certificate = certificate_details(site["certificate_pem"])
        except (ValueError, TypeError) as exc:
            return error(500, f"Could not parse saved certificate: {exc}")
    response = jsonify({
        "url": site["url"],
        "observed_at": site["certificate_observed_at"],
        "last_checked_at": site["last_checked_at"],
        "last_error": site["last_error"],
        "tls_verified": None if site["tls_verified"] is None else bool(site["tls_verified"]),
        "verify_error": site["verify_error"],
        "certificate": certificate,
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/sites/<int:site_id>/certificate.pem")
def download_certificate(site_id: int):
    """Download the observed leaf in standard PEM format (not the private key)."""
    import re
    site = require_site(site_id)
    if site is None:
        return error(404, "Site not found")
    if not site["certificate_pem"]:
        return error(404, "No saved certificate yet. Check this website first.")
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", site["hostname"])[:120] or "certificate"
    response = Response(site["certificate_pem"], content_type="application/x-pem-file")
    response.headers["Content-Disposition"] = f'attachment; filename="{name}.pem"'
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/sites")
def add_sites():
    import re
    body = json_body()
    if body is None or not isinstance(body.get("urls"), str):
        return error(400, "Provide an HTTPS URL or a list of URLs")
    urls = body["urls"]
    if not urls.strip():
        return error(400, "Enter at least one HTTPS address")
    if len(urls) > 40_000:
        return error(400, "URL list is too long")
    inputs = [s.strip() for s in re.split(r"[,;\n\r]+", urls) if s.strip()]
    if len(inputs) > 100:
        return error(400, "Add at most 100 sites at a time")
    try:
        group_ids = validate_group_ids(body.get("group_ids", []))
        with db() as con:
            require_existing_ids(con, "groups", group_ids)
    except ValueError as exc:
        return error(400, str(exc))
    agent_choice = body.get("agent_id")
    if agent_choice is not None:
        if type(agent_choice) is not int or agent_choice < 1:
            return error(400, "agent_id must be a positive integer or null")
        with db() as con:
            agent = con.execute("SELECT enabled FROM monitoring_agents WHERE id=?", (agent_choice,)).fetchone()
        if agent is None or not agent["enabled"]:
            return error(400, "Select an active monitoring agent")
    added, duplicates, errors = [], [], []
    seen = set()
    for item in inputs:
        try:
            url, hostname, port = normalize_url(item)
            if url in seen:
                duplicates.append(url)
                continue
            seen.add(url)
            with db() as con:
                cursor = con.execute("""INSERT OR IGNORE INTO sites
                    (url, hostname, port, created_at, next_check_at,agent_id) VALUES (?,?,?,?,?,?)""",
                    (url, hostname, port, utc_iso(utcnow()), next_random_check(), agent_choice))
                if cursor.rowcount:
                    con.executemany("INSERT INTO site_groups(site_id, group_id) VALUES (?,?)",
                                    ((cursor.lastrowid, gid) for gid in group_ids))
                    added.append((cursor.lastrowid, url))
                else:
                    duplicates.append(url)
        except ValueError as exc:
            errors.append({"url": item, "error": str(exc)})
    for site_id, _ in added:
        enqueue(site_id)
    return jsonify({"added": [url for _, url in added],
                    "duplicates": duplicates, "errors": errors}), 201


def require_site(site_id: int) -> sqlite3.Row | None:
    with db() as con:
        return con.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()


@app.post("/api/sites/<int:site_id>/pause")
def pause_site(site_id: int):
    if require_site(site_id) is None:
        return error(404, "Site not found")
    body = json_body()
    if body is None or not isinstance(body.get("paused"), bool):
        return error(400, "Provide boolean 'paused' value")
    paused = body["paused"]
    with db() as con:
        con.execute("UPDATE sites SET paused=?, next_check_at=?, agent_lease=NULL, lease_until=NULL WHERE id=?",
                    (int(paused), None if paused else next_random_check(), site_id))
    if not paused:
        enqueue(site_id)
    return jsonify({"ok": True, "paused": paused})


@app.post("/api/sites/<int:site_id>/check")
def check_site(site_id: int):
    if require_site(site_id) is None:
        return error(404, "Site not found")
    started = enqueue(site_id)
    return jsonify({"ok": True, "message": "Check started" if started else "Check already in progress"})


@app.delete("/api/sites/<int:site_id>")
def delete_site(site_id: int):
    if require_site(site_id) is None:
        return error(404, "Site not found")
    with db() as con:
        con.execute("DELETE FROM sites WHERE id=?", (site_id,))
    return jsonify({"ok": True})


def read_import_records(fmt: str, text: str) -> tuple[list[dict],list[str]]:
    text = text.lstrip("\ufeff")
    if fmt=="csv":
        table=csv.DictReader(io.StringIO(text))
        if not table.fieldnames or "url" not in {h.strip().lower() for h in table.fieldnames}:
            raise ValueError("CSV must contain a URL column")
        rows=[]
        for row in table:
            data={str(k).strip().lower():v for k,v in row.items() if k is not None}
            paused=str(data.get("paused", "false")).strip().lower()
            if paused not in ("true","false","1","0","yes","no",""):
                raise ValueError("Paused must be true or false")
            groups=[g.strip() for g in str(data.get("groups") or "").split(";") if g.strip()]
            rows.append({"url":data.get("url"),"groups":groups,"paused":paused in ("true","1","yes")})
        return rows,[]
    if fmt!="json":raise ValueError("format must be csv or json")
    obj=json.loads(text)
    existing_groups=[]
    if isinstance(obj,dict):
        existing_groups=obj.get("groups",[])
        obj=obj.get("websites",obj.get("sites",[]))
    if not isinstance(obj,list): raise ValueError("JSON requires a websites list")
    rows=[]
    for item in obj:
        if isinstance(item,str): item={"url":item}
        if not isinstance(item,dict):raise ValueError("Each website must be a JSON object")
        g=item.get("groups",[])
        if not isinstance(g,list) or not all(isinstance(v,str) for v in g):
            raise ValueError("groups must be an array of names")
        pause=item.get("paused",False)
        if type(pause) is not bool: raise ValueError("paused must be boolean")
        rows.append({"url":item.get("url"),"groups":g,"paused":pause})
    if not isinstance(existing_groups,list): raise ValueError("groups must be a list")
    if not all(isinstance(g,str) for g in existing_groups): raise ValueError("Group names must be text")
    return rows,existing_groups


@app.post("/api/import")
def import_inventory():
    body=json_body()
    if body is None or not isinstance(body.get("content"),str):
        return error(400,"Supply format and file content")
    content=body["content"]
    if len(content.encode("utf-8")) > 2_000_000:return error(413,"File exceeds 2MB")
    try:
        rows,declared=read_import_records(body.get("format",""),content)
        if len(rows)>1500:raise ValueError("At most 1500 websites per import")
        parsed=[]
        all_group_names={}
        for name in declared:
            name=validate_group_name(name);all_group_names[name.casefold()]=name
        for item in rows:
            if not isinstance(item["url"],str): raise ValueError("Website URL must be text")
            url,host,port=normalize_url(item["url"])
            names=[]
            for group in item["groups"]:
                name=validate_group_name(group);all_group_names[name.casefold()]=name;names.append(name.casefold())
            parsed.append((url,host,port,item["paused"],names))
        new=[]; created_count=0; updated=0
        with db() as con:
            existing={row["name"].casefold():row["id"] for row in con.execute("SELECT id,name FROM groups")}
            for key,name in all_group_names.items():
                if key not in existing:
                    cur=con.execute("INSERT INTO groups(name,created_at) VALUES (?,?)",(name,utc_iso(utcnow())))
                    existing[key]=cur.lastrowid
            for url,host,port,paused,names in parsed:
                row=con.execute("SELECT id FROM sites WHERE url=?",(url,)).fetchone()
                if row:
                    site_id=row["id"];updated+=1
                    # Import may change pause state intentionally but never reset data.
                    con.execute("""UPDATE sites SET paused=?,next_check_at=CASE
                        WHEN ? THEN NULL WHEN paused=1 THEN ? ELSE next_check_at END WHERE id=?""",
                        (int(paused),int(paused),utc_iso(utcnow()),site_id))
                else:
                    cur=con.execute("""INSERT INTO sites
                        (url,hostname,port,paused,created_at,next_check_at) VALUES (?,?,?,?,?,?)""",
                        (url,host,port,int(paused),utc_iso(utcnow()),None if paused else utc_iso(utcnow())))
                    site_id=cur.lastrowid
                    created_count += 1
                    if not paused:new.append(site_id)
                for group_key in names:
                    con.execute("INSERT OR IGNORE INTO site_groups(site_id,group_id) VALUES (?,?)",
                        (site_id,existing[group_key]))
        for site_id in new[:MAX_WORKERS * 2]:enqueue(site_id)
        return jsonify({"ok":True,"created":created_count,"updated":updated,
                        "groups":len(all_group_names),"message":"Imported; existing group memberships merged"})
    except (ValueError,UnicodeError,json.JSONDecodeError,csv.Error,sqlite3.IntegrityError) as exc:
        return error(400,str(exc))


@app.get("/api/export.json")
def export_json():
    with db() as con:
        groups=group_list(con);members=group_memberships(con)
        rows=con.execute("SELECT id,url,paused,agent_id FROM sites ORDER BY url").fetchall()
        agent_names={r["id"]:r["name"] for r in con.execute("SELECT id,name FROM monitoring_agents")}
    names={g["id"]:g["name"] for g in groups}
    payload={"format":"tls-watch-v4.4","exported_at":utc_iso(utcnow()),
             "groups":[g["name"] for g in groups],
             "websites":[{"url":r["url"],"paused":bool(r["paused"]),
                 "groups":[names[g] for g in members.get(r["id"],[]) if g in names],
                 "monitoring_agent": agent_names.get(r["agent_id"], "Primary server")} for r in rows]}
    response=Response(json.dumps(payload,indent=2),mimetype="application/json")
    response.headers["Content-Disposition"]='attachment; filename="tls-watch-backup.json"'
    response.headers["Cache-Control"]="no-store"
    return response


@app.get("/api/export-inventory.csv")
def export_inventory_csv():
    with db() as con:
        rows=con.execute("SELECT id,url,paused,agent_id FROM sites ORDER BY url").fetchall()
        memberships=group_memberships(con)
        names={r["id"]:r["name"] for r in con.execute("SELECT id,name FROM groups")}
        agent_names={r["id"]:r["name"] for r in con.execute("SELECT id,name FROM monitoring_agents")}
    result=io.StringIO();writer=csv.writer(result)
    writer.writerow(["URL","Groups","Paused","Monitoring Agent"])
    for row in rows:
        writer.writerow([row["url"],";".join(names[g] for g in memberships.get(row["id"],[]) if g in names),
            str(bool(row["paused"])),agent_names.get(row["agent_id"], "Primary server")])
    response=Response(result.getvalue(),mimetype="text/csv")
    response.headers["Content-Disposition"]='attachment; filename="tls-watch-inventory.csv"'
    response.headers["Cache-Control"]="no-store";return response


@app.get("/api/export.csv")
def export_csv():
    import csv
    import io
    with db() as con:
        rows = con.execute("""SELECT url, paused, issuer, issued_at, expires_at,
            days_left, last_checked_at, next_check_at, last_error, tls_verified
            FROM sites ORDER BY url""").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["URL", "Paused", "Issuer", "Issued At (UTC)", "Expires At (UTC)",
                     "Days Left at Last Check", "Last Check (UTC)", "Next Check (UTC)",
                     "Last Error", "TLS Trusted"])
    for row in rows:
        writer.writerow(tuple(row))
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="tls-watch.csv"'})


if __name__ == "__main__":
    start_scheduler()
    host = os.getenv("BIND_HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8080"))
    print(f"TLS Watch is ready at http://{host}:{port}", flush=True)
    try:
        # Do NOT use the Flask reloader: it launches another process and scheduler.
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    finally:
        stop_scheduler.set()
        if scheduler_thread is not None:
            scheduler_thread.join(timeout=2)
        executor.shutdown(wait=False, cancel_futures=True)
        webhook_executor.shutdown(wait=False, cancel_futures=True)
