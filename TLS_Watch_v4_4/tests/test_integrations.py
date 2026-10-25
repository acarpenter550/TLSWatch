"""Pure integration helper tests. They run without Flask installed."""
import hashlib
import hmac
import http.server
import json
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest

from integrations import (
    RANGES, EVENTS, classify_events, needs_attention,
    normalize_webhook_url, send_webhook,
)


def site(days=150, error=None, verified=1, pem="cert-v1"):
    return {"days_left": days, "last_error": error, "tls_verified": verified,
            "certificate_pem": pem, "expires_at": "2026-01-01T00:00:00Z"}


def test_ranges_and_needs_attention_match_dashboard():
    assert sum(RANGES["90+"](d) for d in (0,30,60,90,91,100)) == 2
    assert RANGES["expired"](-1)
    assert not RANGES["expired"](0)
    assert RANGES["61-90"](90)
    assert RANGES["0-30"](0)
    assert needs_attention(site(25))
    assert needs_attention(site(180, verified=0))
    assert needs_attention(site(180, error="DNS failure"))
    assert not needs_attention(site(180))


def test_first_check_emits_most_urgent_event_only():
    blank = {"days_left": None, "last_error": None, "tls_verified": None,
             "certificate_pem": None, "expires_at": None}
    assert classify_events(blank, site(20)) == ["expiration_30", "needs_attention"]
    assert classify_events(blank, site(50)) == ["expiration_60"]
    assert classify_events(blank, site(80)) == ["expiration_90"]
    assert classify_events(blank, site(120)) == []
    assert classify_events(blank, site(-3)) == ["certificate_expired", "needs_attention"]
    assert classify_events(blank, site(50, verified=0)) == ["tls_invalid", "expiration_60", "needs_attention"]
    assert classify_events(blank, site(None, error="bad url", pem=None)) == ["check_failed", "needs_attention"]


def test_only_crossing_events_fire_not_daily_duplicates():
    assert classify_events(site(100), site(89)) == ["expiration_90"]
    assert classify_events(site(89), site(59)) == ["expiration_60"]
    assert classify_events(site(59), site(29)) == ["expiration_30", "needs_attention"]
    assert classify_events(site(30), site(29)) == []
    assert classify_events(site(110), site(25)) == ["expiration_30", "expiration_60", "expiration_90", "needs_attention"]
    assert classify_events(site(1), site(-1)) == ["certificate_expired"]
    assert classify_events(site(-1), site(-2)) == []
    assert classify_events(site(170, error="fail"), site(170, error="fail")) == []
    assert classify_events(site(31), site(30, error="DNS")) == ["check_failed", "expiration_30", "needs_attention"]
    assert classify_events(site(2, error="DNS"), site(-1, error="DNS")) == ["certificate_expired"]
    assert classify_events(site(170, error="fail"), site(170)) == ["recovered", "attention_cleared"]
    assert classify_events(site(170, verified=0), site(170, verified=1)) == ["recovered", "attention_cleared"]
    assert classify_events(site(170), site(170, pem="new-cert")) == ["certificate_changed"]


def test_webhook_requires_https_no_credentials_fragments_or_local_by_default():
    assert normalize_webhook_url("https://EXAMPLE.com:443/events?a=1") == "https://example.com/events?a=1"
    for bad in ("http://example.com", "https://user:pass@example.com/",
                "https://example.com/#frag", "https://127.0.0.1/test", "https://[::1]/",
                "", "https:///missing-host"):
        with pytest.raises(ValueError):
            normalize_webhook_url(bad)
    assert normalize_webhook_url("https://127.0.0.1/hooks", allow_private=True) == "https://127.0.0.1/hooks"


def test_https_webhook_signature_and_json_delivery(monkeypatch, tmp_path):
    """End-to-end signed POST against a localhost TLS server (no internet)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    crt = tmp_path / "localhost.pem"
    ky = tmp_path / "localhost.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ky.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.TraditionalOpenSSL,
                                     serialization.NoEncryption()))
    received = {}
    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            received["body"] = self.rfile.read(length)
            received["signature"] = self.headers["X-TLSWatch-Signature"]
            received["event"] = self.headers["X-TLSWatch-Event"]
            received["path"] = self.path
            self.send_response(204)
            self.end_headers()
        def log_message(self, *args):
            pass
    server = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(ky))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    original_context = ssl.create_default_context
    def trusted_context():
        result = original_context()
        result.load_verify_locations(cafile=str(crt))
        return result
    monkeypatch.setattr(ssl, "create_default_context", trusted_context)
    def resolve(host, port):
        assert host == "localhost"
        return [(socket.AF_INET, ("127.0.0.1", port))]
    body = '{"event":"expiration_30","site":{"id":1}}'
    try:
        code = send_webhook(f"https://localhost:{server.server_port}/tls-event",
                            body, "test-secret", "expiration_30", "delivery-1", resolve,
                            allow_private=True)
        assert code == 204
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert received["body"].decode() == body
    assert received["path"] == "/tls-event"
    assert received["event"] == "expiration_30"
    expected = hmac.new(b"test-secret", body.encode(), hashlib.sha256).hexdigest()
    assert received["signature"] == f"sha256={expected}"


def test_explicit_http_and_private_options_require_both_opt_ins():
    with pytest.raises(ValueError, match="HTTP webhooks are disabled"):
        normalize_webhook_url("http://127.0.0.1:8888/webhook")
    with pytest.raises(ValueError, match="Private/local"):
        normalize_webhook_url("http://127.0.0.1:8888/webhook", allow_http=True)
    with pytest.raises(ValueError, match="HTTP webhooks are disabled"):
        normalize_webhook_url("http://127.0.0.1:8888/webhook", allow_private=True)
    assert normalize_webhook_url("http://127.0.0.1:8888/webhook", allow_http=True,
                                 allow_private=True) == "http://127.0.0.1:8888/webhook"
    assert normalize_webhook_url("https://127.0.0.1/webhook", allow_private=True) == "https://127.0.0.1/webhook"
    with pytest.raises(ValueError):
        normalize_webhook_url("http://user:pass@localhost:8888/a", allow_http=True, allow_private=True)


def test_http_local_webhook_signed_end_to_end():
    got = {}
    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            got["payload"] = self.rfile.read(int(self.headers["Content-Length"]))
            got["signature"] = self.headers["X-TLSWatch-Signature"]
            got["path"] = self.path
            self.send_response(200)
            self.end_headers()
        def log_message(self, *args): pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    def resolve(host, port):
        assert host == "127.0.0.1"
        return [(socket.AF_INET, (host, port))]
    body = '{"event":"test","site":null}'
    try:
        assert send_webhook(f"http://127.0.0.1:{srv.server_port}/webhook", body,
                            "shared-key", "test", "test-id", resolve,
                            allow_http=True, allow_private=True) == 200
    finally:
        srv.shutdown();srv.server_close();th.join(timeout=2)
    assert got["path"] == "/webhook"
    assert got["payload"] == body.encode()
    assert got["signature"] == "sha256=" + hmac.new(b"shared-key", body.encode(), hashlib.sha256).hexdigest()


def test_untrusted_https_requires_explicit_self_signed_opt_in(tmp_path):
    """Without toggle, self-signed cert fails. With toggle, signed JSON succeeds."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=3))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    crt, ky = tmp_path / "crt.pem", tmp_path / "key.pem"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ky.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
    got = []
    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            got.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()
        def log_message(self,*args): pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(ky))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    def resolve(host, port):
        return [(socket.AF_INET, ("127.0.0.1", port))]
    try:
        with pytest.raises(ssl.SSLError):
            send_webhook(f"https://localhost:{srv.server_port}/webhook", '{}',
                         "secret", "test", "a", resolve, allow_private=True)
        assert send_webhook(f"https://localhost:{srv.server_port}/webhook", '{}',
                            "secret", "test", "b", resolve,
                            allow_private=True, allow_self_signed=True) == 200
    finally:
        srv.shutdown();srv.server_close();th.join(timeout=2)
    assert got == [b'{}']
