"""API, settings and webhook integration tests (requires Flask as in requirements.txt)."""

import json

import pytest
import app as monitor


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(monitor, "DB_PATH", tmp_path / "certificates.sqlite3")
    monkeypatch.setattr(monitor, "AUTH_USER", "")
    monkeypatch.setattr(monitor, "AUTH_PASSWORD", "")
    monkeypatch.setattr(monitor, "ALLOW_PRIVATE", False)
    monitor.init_db()
    with monitor.db() as con:
        now = monitor.utc_iso(monitor.utcnow())
        for host, days, verified, problem in (
            ("healthy.example.com", 120, 1, None),
            ("invalid.example.com", 180, 0, None),
            ("warning.example.com", 45, 1, None),
            ("critical.example.com", 18, 1, None),
            ("outage.example.com", 140, 1, "DNS failure"),
            ("expired.example.com", -5, 0, None),
        ):
            con.execute("""INSERT INTO sites (url, hostname, port, created_at,
                last_checked_at, days_left, tls_verified, last_error)
                VALUES (?,?,?,?,?,?,?,?)""",
                ("https://" + host, host, 443, now, now, days, verified, problem))
    return monitor.app.test_client()


def test_api_key_required_and_read_only(isolated):
    client = isolated
    assert client.get("/api/v1/certificates").status_code == 401
    assert client.get("/api/v1/certificates", headers={"X-API-Key": "invalid"}).status_code == 401
    fresh = client.post("/api/settings/api-key")
    assert fresh.status_code == 200
    key = fresh.json["api_key"]
    assert key.startswith("tlsw_")
    read = {"X-API-Key": key}
    assert client.get("/api/v1/certificates", headers=read).json["count"] == 6
    assert client.get("/api/v1/certificates", headers={"Authorization": f"Bearer {key}"}).status_code == 200
    assert client.post("/api/v1/certificates", headers=read, json={}).status_code == 405
    assert client.get("/api/settings").json["api_key"]["configured"]
    assert "api_key" not in client.get("/api/settings").json["api_key"]
    new_key = client.post("/api/settings/api-key").json["api_key"]
    assert client.get("/api/v1/certificates", headers=read).status_code == 401
    assert client.get("/api/v1/certificates", headers={"X-API-Key": new_key}).status_code == 200
    assert client.delete("/api/settings/api-key").status_code == 200
    assert client.get("/api/v1/certificates", headers={"X-API-Key": new_key}).status_code == 401


def test_ranges_and_attention_match_overview(isolated):
    client = isolated
    key = client.post("/api/settings/api-key").json["api_key"]
    headers = {"X-API-Key": key}
    def get(path):
        response = client.get(path, headers=headers)
        assert response.status_code == 200
        return response.json
    assert get("/api/v1/certificates?range=90%2B")["count"] == 3
    assert get("/api/v1/certificates?range=90+")["count"] == 3
    assert get("/api/v1/certificates?range=31-60")["count"] == 1
    assert get("/api/v1/certificates?range=0-30")["count"] == 1
    assert get("/api/v1/certificates?range=expired")["count"] == 1
    assert get("/api/v1/certificates/expiring?within=30")["count"] == 2
    assert get("/api/v1/certificates/expiring?within=60")["count"] == 3
    assert get("/api/v1/certificates/expiring?within=90")["count"] == 3
    assert get("/api/v1/certificates/needs-attention")["count"] == 4
    summary = get("/api/v1/summary")
    assert summary["total"] == 6
    assert summary["healthy"] == 3
    assert summary["needs_attention"] == 4
    assert client.get("/api/v1/certificates?range=19-30", headers=headers).status_code == 400
    assert client.get("/api/v1/certificates/expiring?within=42", headers=headers).status_code == 400


def test_admin_remote_requires_auth_without_basic(isolated):
    assert isolated.get("/api/settings", environ_overrides={"REMOTE_ADDR": "10.1.2.3"}).status_code == 403
    key = isolated.post("/api/settings/api-key").json["api_key"]
    assert isolated.get("/api/v1/summary", headers={"X-API-Key": key},
                        environ_overrides={"REMOTE_ADDR": "10.1.2.3"}).status_code == 200


def test_webhook_filter_delivery_and_retries(monkeypatch, isolated):
    client = isolated
    enabled = client.put("/api/settings/webhook", json={
        "enabled": True, "url": "https://hooks.example.com/tls-watch",
        "events": ["expiration_30", "check_failed", "recovered"]})
    assert enabled.status_code == 200
    assert len(enabled.json["signing_secret"]) >= 32
    # Secret never appears in GET.
    assert "signing_secret" not in client.get("/api/settings").json["webhook"]
    assert client.post("/api/settings/webhook/test").status_code == 202
    ids = []
    def fake_send(url, payload, secret, event, event_id, resolver, **kwargs):
        assert url == "https://hooks.example.com/tls-watch"
        assert len(secret) >= 32
        ids.append(event_id)
        return 204
    monkeypatch.setattr(monitor, "send_webhook", fake_send)
    monitor.process_webhook_delivery()
    status = client.get("/api/settings").json["deliveries"][0]
    assert status["status"] == "delivered"
    assert status["response_code"] == 204
    assert len(ids) == 1

    test_again = client.post("/api/settings/webhook/test")
    assert test_again.status_code == 202
    def rejected(*args, **kwargs):
        raise RuntimeError("Webhook returned HTTP 503")
    monkeypatch.setattr(monitor, "send_webhook", rejected)
    monitor.process_webhook_delivery()
    with monitor.db() as con:
        row = con.execute("SELECT status, attempts FROM webhook_deliveries ORDER BY id DESC LIMIT 1").fetchone()
    assert row["status"] == "pending" and row["attempts"] == 1
    # A URL change cancels future attempts targeting the old URL.
    client.put("/api/settings/webhook", json={
        "enabled": True, "url": "https://other.example.com/hook", "events": ["check_failed"]})
    with monitor.db() as con:
        row = con.execute("SELECT status FROM webhook_deliveries ORDER BY id DESC LIMIT 1").fetchone()
    assert row["status"] == "cancelled"


def test_new_event_is_queued_only_when_selected(monkeypatch, isolated):
    client = isolated
    client.put("/api/settings/webhook", json={
        "enabled": True, "url": "https://hooks.example.com/monitor",
        "events": ["expiration_30"]})
    with monitor.db() as con:
        target = con.execute("SELECT id FROM sites WHERE hostname='healthy.example.com'").fetchone()[0]
    def new_certificate(*args):
        return {"issuer": "Test CA", "issued_at": "2026-01-01T00:00:00Z",
                "expires_at": monitor.utc_iso(monitor.utcnow() + monitor.timedelta(days=20)),
                "tls_verified": 1, "verify_error": None, "certificate_pem": "pem-test"}
    monkeypatch.setattr(monitor, "inspect_certificate", new_certificate)
    monitor.run_check(target)
    monitor.run_check(target)
    with monitor.db() as con:
        rows = con.execute("SELECT event,payload FROM webhook_deliveries").fetchall()
    assert len(rows) == 1
    assert rows[0]["event"] == "expiration_30"
    record = json.loads(rows[0]["payload"])
    assert record["site"]["id"] == target
    assert record["site"]["days_left"] <= 30


def test_webhook_transport_options_persist_independently_of_site_monitor(monkeypatch, isolated):
    client = isolated
    local_url = "http://127.0.0.1:8888/webhook"
    body = {"enabled": True, "url": local_url, "events": ["expiration_30"]}
    assert client.put("/api/settings/webhook", json=body).status_code == 400
    body["allow_http"] = True
    assert client.put("/api/settings/webhook", json=body).status_code == 400
    body["allow_private"] = True
    body["allow_self_signed"] = True
    assert client.put("/api/settings/webhook", json=body).status_code == 200
    saved = client.get("/api/settings").json["webhook"]
    assert saved["url"] == local_url
    assert saved["allow_http"] and saved["allow_private"] and saved["allow_self_signed"]
    assert monitor.ALLOW_PRIVATE is False  # Does NOT enable private certificate sites.

    # Worker actually uses the newly saved options, even if ALLOW_PRIVATE is false.
    assert client.post("/api/settings/webhook/test").status_code == 202
    observed = {}
    def fake_send(url, payload, secret, event, event_id, resolver, **kwargs):
        observed.update(kwargs)
        monkeypatch.setattr(monitor.socket, "getaddrinfo", lambda host, port, type:
                            [(monitor.socket.AF_INET, monitor.socket.SOCK_STREAM, 0, "", ("127.0.0.1", port))])
        assert resolver("localhost", 8888)[0][1] == ("127.0.0.1", 8888)
        return 200
    monkeypatch.setattr(monitor, "send_webhook", fake_send)
    monitor.process_webhook_delivery()
    assert observed["allow_http"] is True
    assert observed["allow_private"] is True
    assert observed["allow_self_signed"] is True


def test_webhook_rejects_non_boolean_flags(isolated):
    result = isolated.put('/api/settings/webhook', json={
        'enabled': True, 'url': 'https://hooks.example.com/a',
        'events': ['check_failed'], 'allow_http': 'yes'})
    assert result.status_code == 400
