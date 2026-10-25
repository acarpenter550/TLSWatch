"""Read-only API helpers, event transitions and restricted webhook transport.

No third-party dependencies. Used by TLS Watch's existing Flask app.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

EVENTS = (
    "expiration_90", "expiration_60", "expiration_30", "certificate_expired",
    "tls_invalid", "check_failed", "recovered", "certificate_changed",
    "needs_attention", "attention_cleared", "certificate_renewed",
    "certificate_issuer_changed", "certificate_expiration_shortened",
    "monitoring_stale_warning", "monitoring_stale_critical",
)

RANGES = {
    "expired": lambda d: d < 0,
    "0-30": lambda d: 0 <= d <= 30,
    "31-60": lambda d: 31 <= d <= 60,
    "61-90": lambda d: 61 <= d <= 90,
    "90+": lambda d: d > 90,
}


def needs_attention(site: dict) -> bool:
    """Same conditions as the Overview's Needs Attention card and filter."""
    d = site.get("days_left")
    return bool(site.get("last_error") or site.get("tls_verified") == 0 or (d is not None and d <= 30))


def classify_events(before: dict, after: dict) -> list[str]:
    """Emit only transitions. Each check can produce several distinct event types.

    A first observation uses its most urgent threshold instead of emitting every
    threshold simultaneously. Consecutive failures/untrusted checks do not repeat.
    """
    events: list[str] = []

    def finalize():
        if not needs_attention(before) and needs_attention(after):
            events.append("needs_attention")
        elif needs_attention(before) and not needs_attention(after):
            events.append("attention_cleared")
        return events
    earlier = before.get("days_left")
    later = after.get("days_left")
    old_pem = before.get("certificate_pem")
    new_pem = after.get("certificate_pem")
    changed = bool(old_pem and new_pem and old_pem != new_pem)
    new_certificate = not old_pem or changed or not before.get("expires_at")

    if after.get("last_error"):
        if not before.get("last_error"):
            events.append("check_failed")
        # The previous certificate's expiry remains known on a DNS/connection
        # failure. A crossing should not disappear just because we cannot
        # currently reach the site. We intentionally never invent an expiry
        # threshold when no previous certificate has been observed.
        if earlier is not None and later is not None:
            if earlier >= 0 > later:
                events.append("certificate_expired")
            elif later >= 0:
                for threshold, label in ((30, "expiration_30"),
                                         (60, "expiration_60"),
                                         (90, "expiration_90")):
                    if earlier > threshold >= later:
                        events.append(label)
        return finalize()

    if after.get("tls_verified") == 0 and before.get("tls_verified") != 0:
        events.append("tls_invalid")
    if (after.get("tls_verified") == 1 and
            (bool(before.get("last_error")) or before.get("tls_verified") == 0)):
        events.append("recovered")
    if changed:
        events.append("certificate_changed")

    if later is None:
        return finalize()
    if later < 0:
        if new_certificate or earlier is None or earlier >= 0:
            events.append("certificate_expired")
        return finalize()
    thresholds = ((30, "expiration_30"), (60, "expiration_60"), (90, "expiration_90"))
    if new_certificate or earlier is None:
        for threshold, label in thresholds:
            if later <= threshold:
                events.append(label)
                break
    else:
        # When several thresholds were crossed between checks, report each
        # crossing independently, allowing subscribers to select their alerts.
        for threshold, label in thresholds:
            if earlier > threshold >= later:
                events.append(label)
    return finalize()


def normalize_webhook_url(raw: str, allow_private: bool = False,
                          allow_http: bool = False) -> str:
    """Validate webhook destination. Security-sensitive schemes/address ranges opt in.

    IP allowlisting for DNS names is enforced again *at connection time* by the
    caller's vetted resolver. This check rejects non-public literal IPs early.
    """
    if not isinstance(raw, str) or not (1 <= len(raw.strip()) <= 2048):
        raise ValueError("Enter a webhook URL (up to 2048 characters)")
    if any(ord(ch) <= 32 or ord(ch) == 127 for ch in raw):
        raise ValueError("Webhook URL must not contain whitespace or control characters")
    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("Webhook URL must start with http:// or https:// and include a hostname")
        if scheme == "http" and not allow_http:
            raise ValueError("HTTP webhooks are disabled; enable Allow HTTP destination")
        if parts.username is not None or parts.password is not None or parts.fragment:
            raise ValueError("Webhook URL cannot contain credentials or a fragment")
        port = parts.port or (443 if scheme == "https" else 80)
        host = parts.hostname.encode("idna").decode("ascii").rstrip(".").lower()
        if not (1 <= port <= 65535) or not host or len(host) > 253:
            raise ValueError("Invalid webhook hostname or port")
        # URL parsing does not replace a strict hostname validation.
        if any(c in host for c in ("/", "\\", "@", "#", "%")):
            raise ValueError("Invalid webhook hostname")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if not allow_private and not address.is_global:
                raise ValueError("Private/local webhook destinations are disabled; enable Allow local/private destinations")
        host_part = f"[{host}]" if ":" in host else host
        default_port = 443 if scheme == "https" else 80
        return f"{scheme}://{host_part}{(':' + str(port)) if port != default_port else ''}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")
    except (ValueError, UnicodeError) as exc:
        raise ValueError(str(exc) or "Invalid webhook URL") from exc


def send_webhook(url: str, raw_json: str, secret: str, event: str, event_id: str,
                 resolve_target, timeout: float = 7.0, allow_private: bool = False,
                 allow_http: bool = False, allow_self_signed: bool = False) -> int:
    """Send signed JSON to a pinned vetted-IP destination; no redirects.

    TLS verification is enabled unless the administrator explicitly chooses
    allow_self_signed (which also disables hostname verification). Plain HTTP
    is likewise an explicit opt-in. The same HMAC signature is used in both.
    """
    url = normalize_webhook_url(url, allow_private=allow_private, allow_http=allow_http)
    parsed = urlsplit(url)
    host = parsed.hostname
    https = parsed.scheme == "https"
    port = parsed.port or (443 if https else 80)
    destination = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    body = raw_json.encode("utf-8")
    if len(body) > 100_000:
        raise ValueError("Webhook payload too large")
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json", "Accept": "application/json",
        "User-Agent": "TLS-Watch/4.3", "X-TLSWatch-Event": event,
        "X-TLSWatch-Delivery": str(event_id), "X-TLSWatch-Timestamp": stamp,
        "X-TLSWatch-Signature": f"sha256={signature}",
    }
    addresses = resolve_target(host, port)
    last_exc = None
    for family, sockaddr in addresses:
        sock = None
        conn = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            if https:
                context = ssl.create_default_context()
                if allow_self_signed:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                tls = context.wrap_socket(sock, server_hostname=host)
                sock = None  # TLS object takes ownership.
                conn = http.client.HTTPSConnection(host, port, timeout=timeout)
                conn.sock = tls
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
                conn.sock = sock
                sock = None  # HTTPConnection takes ownership.
            conn.request("POST", destination, body=body, headers=headers)
            response = conn.getresponse()
            response.read(4096)
            if not (200 <= response.status < 300):
                raise RuntimeError(f"Webhook returned HTTP {response.status}")
            return response.status
        except (socket.error, ssl.SSLError, http.client.HTTPException) as exc:
            last_exc = exc
        finally:
            if conn is not None:
                conn.close()
            if sock is not None:
                sock.close()
    if last_exc:
        raise last_exc
    raise RuntimeError("No allowed webhook destination address")
