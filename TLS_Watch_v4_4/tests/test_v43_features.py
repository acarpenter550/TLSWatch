"""TLS Watch v4.3 regression coverage. Run: python -m pytest tests -q."""
import json
from datetime import timedelta

import pytest
import app as monitor


@pytest.fixture
def monitor_client(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor, "DB_PATH", tmp_path / "test-v43.sqlite3")
    monkeypatch.setattr(monitor, "AUTH_USER", "")
    monkeypatch.setattr(monitor, "AUTH_PASSWORD", "")
    monitor.init_db()
    with monitor.db() as con:
        now = monitor.utc_iso(monitor.utcnow())
        for host in ("first.example.com", "second.example.com"):
            con.execute("INSERT INTO sites(url,hostname,port,created_at) VALUES(?,?,443,?)",
                        (f"https://{host}", host, now))
    return monitor.app.test_client()


def test_history_keeps_versions_and_failures(monkeypatch, monitor_client):
    cert = {"issuer": "Initial CA", "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2027-01-01T00:00:00Z", "tls_verified": 1,
            "verify_error": None, "certificate_pem": "FIRST PEM"}
    monkeypatch.setattr(monitor, "inspect_certificate", lambda *args: dict(cert))
    monitor.run_check(1)
    monitor.run_check(1)
    assert len(monitor_client.get("/api/sites/1/history").json["certificates"]) == 1
    cert.update({"issuer": "Replacement CA", "expires_at": "2028-01-01T00:00:00Z",
                 "certificate_pem": "SECOND PEM"})
    monitor.run_check(1)
    history = monitor_client.get("/api/sites/1/history").json
    assert len(history["certificates"]) == 2
    assert history["certificates"][0]["issuer_changed"]
    assert history["certificates"][0]["expiration_delta_days"] > 0
    assert len(history["checks"]) == 3
    monkeypatch.setattr(monitor, "inspect_certificate", lambda *args: (_ for _ in ()).throw(OSError("server unavailable")))
    monitor.run_check(1)
    history = monitor_client.get("/api/sites/1/history").json
    assert len(history["certificates"]) == 2
    assert history["checks"][0]["success"] is False
    assert "server unavailable" in history["checks"][0]["message"]
    with monitor.db() as con:
        row = con.execute("SELECT last_successful_at, last_checked_at FROM sites WHERE id=1").fetchone()
        assert row["last_successful_at"] is not None
    key = monitor_client.post("/api/settings/api-key").json["api_key"]
    assert monitor_client.get("/api/v1/certificates/1/history",headers={"X-API-Key":key}).status_code == 200
    assert monitor_client.get("/api/v1/certificates/1/history").status_code == 401


def test_json_csv_import_and_backup(monitor_client):
    payload = {"groups": ["Unassigned"], "websites": [
        {"url":"https://first.example.com", "paused":False, "groups":["Production","Private"]},
        {"url":"https://third.example.com:9443", "paused":True, "groups":["Private"]}]}
    r=monitor_client.post("/api/import",json={"format":"json","content":json.dumps(payload)})
    assert r.status_code==200, r.json
    assert r.json["created"]==1  # Newly imported paused website is included in created count


def test_csv_import_round_trip(monitor_client):
    csv_text="URL,Groups,Paused\nhttps://first.example.com,Production;Internal,false\nhttps://new.example,Internal,true\n"
    r=monitor_client.post("/api/import",json={"format":"csv","content":csv_text})
    assert r.status_code==200, r.json
    out=monitor_client.get("/api/export.json")
    assert out.status_code==200
    backup=json.loads(out.data)
    assert {g for g in backup["groups"]}=={"Production","Internal"}
    assert len(backup["websites"])==3
    assert "api_key" not in out.get_data(as_text=True)
    assert monitor_client.get("/api/export-inventory.csv").status_code==200


def test_group_webhook_delivery_scope_and_secret(monkeypatch, monitor_client):
    with monitor.db() as con:
        con.execute("INSERT INTO groups(name,created_at) VALUES('Production',?)",
                    (monitor.utc_iso(monitor.utcnow()),))
        con.execute("INSERT INTO site_groups(site_id,group_id) VALUES(1,1)")
    body={"name":"Production","enabled":True,"url":"http://127.0.0.1:8888/webhook",
          "group_ids":[1],"events":["check_failed"],"allow_http":True,"allow_private":True}
    r=monitor_client.post("/api/settings/webhooks",json=body)
    assert r.status_code==201,r.json
    assert "signing_secret" in r.json
    settings=monitor_client.get("/api/settings").json
    assert "signing_secret" not in str(settings)
    def bad(*args): raise OSError("unreachable")
    monkeypatch.setattr(monitor,"inspect_certificate",bad)
    monitor.run_check(1);monitor.run_check(2)
    with monitor.db() as con:
        rows=con.execute("SELECT site_id,target_id FROM webhook_deliveries").fetchall()
        assert [(r["site_id"],r["target_id"]) for r in rows]==[(1,r.json["id"])]
    assert monitor_client.post(f'/api/settings/webhooks/{r.json["id"]}/test').status_code==202


def test_deleting_last_group_does_not_broaden_scope(monkeypatch,monitor_client):
    with monitor.db() as con:
        con.execute("INSERT INTO groups(name,created_at) VALUES('Customer A',?)",
                    (monitor.utc_iso(monitor.utcnow()),))
        con.execute("INSERT INTO site_groups(site_id,group_id) VALUES(1,1)")
    body={"name":"Customer A hook","enabled":True,"url":"http://127.0.0.1:8888/webhook",
          "group_ids":[1],"events":["check_failed"],"allow_http":True,"allow_private":True}
    assert monitor_client.post("/api/settings/webhooks",json=body).status_code==201
    assert monitor_client.delete("/api/groups/1").status_code==200
    def bad(*args): raise OSError("down")
    monkeypatch.setattr(monitor,"inspect_certificate",bad)
    monitor.run_check(2)
    with monitor.db() as con:
        assert con.execute("SELECT COUNT(*) FROM webhook_deliveries").fetchone()[0]==0


def test_stale_needs_attention(monkeypatch, monitor_client):
    old=monitor.utc_iso(monitor.utcnow()-timedelta(hours=49))
    with monitor.db() as con:
        con.execute("UPDATE sites SET last_successful_at=?,tls_verified=1,days_left=150 WHERE id=1",(old,))
    key=monitor_client.post("/api/settings/api-key").json["api_key"]
    headers={"X-API-Key":key}
    summary=monitor_client.get("/api/v1/summary",headers=headers).json
    assert summary["stale_critical"]==1
    assert summary["needs_attention"]==1
    matching=monitor_client.get("/api/v1/certificates/needs-attention",headers=headers).json
    assert matching["count"]==1
    assert matching["certificates"][0]["stale_status"]=="critical"
