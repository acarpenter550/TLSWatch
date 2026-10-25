"""Distributed agent regression: primary enrollment, task authorization, result ingest, assignment."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import app as monitor


@pytest.fixture
def c(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor, "DB_PATH", tmp_path / "agents.db")
    monkeypatch.setattr(monitor, "AUTH_USER", "")
    monkeypatch.setattr(monitor, "AUTH_PASSWORD", "")
    monitor.init_db()
    return monitor.app.test_client()


def self_signed():
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "internal.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=160))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def setup_agent(client):
    agent = client.post("/api/agents", json={"name": "Branch"})
    assert agent.status_code == 201, agent.json
    code = agent.json["enrollment_code"]
    token_resp = client.post("/agent/v1/enroll", json={"enrollment_code": code})
    assert token_resp.status_code == 200, token_resp.json
    assert client.post("/agent/v1/enroll", json={"enrollment_code": code}).status_code == 401
    agent_id = agent.json["id"]
    token = token_resp.json["agent_token"]
    return agent_id, {"Authorization": "Bearer " + token}


def test_pair_schedule_and_result(c, monkeypatch):
    agent_id, headers = setup_agent(c)
    assert c.post("/agent/v1/poll",json={"capacity":1}).status_code == 401
    site = c.post("/api/sites",json={"urls":"https://internal.example", "agent_id":agent_id})
    assert site.status_code == 201, site.json
    rows=c.get("/api/sites").json["sites"]
    assert len(rows)==1 and rows[0]["agent_id"] == agent_id
    site_id=rows[0]["id"]
    poll = c.post("/agent/v1/poll",json={"capacity": 1,"version":"test"},headers=headers)
    assert poll.status_code == 200, poll.json
    task=poll.json["tasks"][0]
    assert task["hostname"] == "internal.example"
    assert c.post("/agent/v1/poll",json={"capacity":1},headers=headers).json["tasks"] == []
    pem = self_signed()
    result = c.post("/agent/v1/result", json={"site_id":site_id,"lease":task["lease"],
       "success":True,"certificate_pem":pem,"tls_verified":False,"verify_error":"Untrusted CA"},headers=headers)
    assert result.status_code == 200, result.json
    assert c.post("/agent/v1/result", json={"site_id":site_id,"lease":task["lease"],
        "success":False,"error":"duplicate"},headers=headers).status_code == 409
    updated = c.get("/api/sites").json["sites"][0]
    assert updated["tls_verified"] is False and "160" in str(updated["days_left"])
    assert updated["agent_name"] == "Branch"
    assert c.get(f"/api/sites/{site_id}/history").json["checks"][0]["success"] is True
    assert c.put(f"/api/sites/{site_id}/agent",json={"agent_id":None}).status_code == 200


def test_agent_pause_delete(c):
    agent_id, headers = setup_agent(c)
    site = c.post("/api/sites",json={"urls":"https://branch.example", "agent_id":agent_id})
    assert site.status_code == 201
    site_id=c.get("/api/sites").json["sites"][0]["id"]
    assert c.post(f"/api/sites/{site_id}/pause",json={"paused":True}).status_code==200
    assert c.post("/agent/v1/poll",json={"capacity":2},headers=headers).json["tasks"] == []
    assert c.delete(f"/api/agents/{agent_id}").status_code == 200
    assert c.get("/api/sites").json["sites"][0]["agent_id"] is None
    assert c.post("/agent/v1/poll",json={"capacity":2},headers=headers).status_code == 401


def test_agent_isolated_ownership(c):
    first, h1 = setup_agent(c)
    second = c.post('/api/agents',json={'name':'Office 2'}).json
    h2 = {'Authorization': 'Bearer ' + c.post('/agent/v1/enroll',json={
        'enrollment_code':second['enrollment_code']}).json['agent_token']}
    c.post('/api/sites',json={'urls':'https://local.example','agent_id':first})
    task = c.post('/agent/v1/poll',json={'capacity':1},headers=h1).json['tasks'][0]
    forged = c.post('/agent/v1/result',headers=h2,json={
        'site_id':task['site_id'], 'lease':task['lease'],'success':False,'error':'forged'})
    assert forged.status_code == 409
    assert c.post('/agent/v1/result',headers=h1,json={
        'site_id':task['site_id'], 'lease':task['lease'],'success':False,'error':'unable'}).status_code == 200
