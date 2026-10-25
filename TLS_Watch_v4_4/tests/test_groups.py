"""v4.2 persistent multi-group membership, filtered API and backwards compatibility."""
import sqlite3

import pytest
import app as monitor


@pytest.fixture
def seeded(monkeypatch, tmp_path):
    monkeypatch.setattr(monitor, 'DB_PATH', tmp_path / 'upgrade.sqlite3')
    monkeypatch.setattr(monitor, 'AUTH_USER', '')
    monkeypatch.setattr(monitor, 'AUTH_PASSWORD', '')
    monkeypatch.setattr(monitor, 'enqueue', lambda site_id: True)
    # Simulate the database from v4.1: no groups or site_groups tables.
    with sqlite3.connect(monitor.DB_PATH) as con:
        con.executescript(monitor.SQL_SCHEMA.split('CREATE TABLE IF NOT EXISTS groups')[0])
        con.execute("""CREATE TABLE webhook_config (id INTEGER PRIMARY KEY CHECK(id=1),
            enabled INTEGER NOT NULL DEFAULT 0, url TEXT NOT NULL DEFAULT '',
            events_json TEXT NOT NULL DEFAULT '[]', signing_secret TEXT NOT NULL DEFAULT '',
            updated_at TEXT, allow_http INTEGER NOT NULL DEFAULT 0,
            allow_private INTEGER NOT NULL DEFAULT 0, allow_self_signed INTEGER NOT NULL DEFAULT 0)""")
        con.execute("""CREATE TABLE api_keys (id INTEGER PRIMARY KEY CHECK(id=1),
            key_hash TEXT NOT NULL, prefix TEXT NOT NULL, created_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE webhook_deliveries (id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE, event TEXT NOT NULL, site_id INTEGER, url TEXT NOT NULL,
            payload TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT, delivered_at TEXT,
            response_code INTEGER, last_error TEXT)""")
        con.execute("""INSERT INTO sites(url,hostname,port,created_at,days_left,tls_verified)
            VALUES ('https://prod.example','prod.example',443,'2026-01-01T00:00:00Z',120,1)""")
        con.execute("""INSERT INTO sites(url,hostname,port,created_at,days_left,tls_verified)
            VALUES ('https://shared.example','shared.example',443,'2026-01-01T00:00:00Z',24,1)""")
        con.execute("""INSERT INTO sites(url,hostname,port,created_at,days_left,tls_verified,last_error)
            VALUES ('https://dev.example','dev.example',443,'2026-01-01T00:00:00Z',150,0,'bad trust')""")
    monitor.init_db()
    # v4.3 flags never-successful sites older than 24 hours as stale;
    # keep these v4.2 grouping fixtures recent to isolate group semantics.
    with monitor.db() as con:
        con.execute("UPDATE sites SET created_at=? WHERE last_checked_at IS NULL",
                    (monitor.utc_iso(monitor.utcnow()),))
    client = monitor.app.test_client()
    key = client.post('/api/settings/api-key').json['api_key']
    return client, {'X-API-Key': key}


def test_all_tab_and_multigroup_membership_survive_restart(seeded):
    client, auth = seeded
    assert client.get('/api/sites').json['groups'] == []
    assert client.get('/api/v1/groups', headers=auth).json['groups'][0]['name'] == 'ALL'
    ids = {s['hostname']: s['id'] for s in client.get('/api/sites').json['sites']}
    production = client.post('/api/groups', json={
        'name': 'Production', 'site_ids': [ids['prod.example'], ids['shared.example']]})
    assert production.status_code == 201
    g1 = production.json['id']
    internal = client.post('/api/groups', json={
        'name': 'Internal', 'site_ids': [ids['shared.example'], ids['dev.example']]})
    assert internal.status_code == 201
    g2 = internal.json['id']
    sites = {s['hostname']: s for s in client.get('/api/sites').json['sites']}
    assert sorted(sites['shared.example']['group_ids']) == sorted([g1,g2])
    assert client.get('/api/v1/certificates', headers=auth).json['count'] == 3
    assert client.get(f'/api/v1/certificates?group={g1}', headers=auth).json['count'] == 2
    assert client.get(f'/api/v1/summary?group={g2}', headers=auth).json['total'] == 2
    monitor.init_db()  # same database survives restart
    assert client.get(f'/api/v1/groups/{g1}', headers=auth).json['group']['site_count'] == 2
    assert client.get('/api/v1/groups', headers=auth).json['groups'][0]['site_count'] == 3


def test_all_expiration_and_attention_queries_scoped(seeded):
    client, auth = seeded
    ids = {s['hostname']: s['id'] for s in client.get('/api/sites').json['sites']}
    g1 = client.post('/api/groups', json={
        'name':'Critical', 'site_ids':[ids['prod.example'], ids['shared.example']]}).json['id']
    g2 = client.post('/api/groups', json={
        'name':'Other', 'site_ids':[ids['shared.example'], ids['dev.example']]}).json['id']
    get = lambda path: client.get(path, headers=auth)
    assert get(f'/api/v1/certificates?group={g1}&range=90%2B').json['count'] == 1
    assert get(f'/api/v1/certificates?group={g1}&range=0-30').json['count'] == 1
    assert get(f'/api/v1/certificates/expiring?within=60&group={g1}').json['count'] == 1
    assert get(f'/api/v1/certificates/needs-attention?group={g1}').json['count'] == 1
    assert get(f'/api/v1/certificates/needs-attention?group={g2}').json['count'] == 2
    assert get(f'/api/v1/summary?group={g2}').json['healthy'] == 1
    assert get(f'/api/v1/groups/{g2}/summary').json['needs_attention'] == 2
    assert get(f'/api/v1/groups/{g2}/certificates/needs-attention').json['count'] == 2
    assert get(f'/api/v1/groups/{g1}/certificates?range=0-30').json['count'] == 1
    assert get(f'/api/v1/certificates/{ids["prod.example"]}?group={g2}').status_code == 404
    assert get(f'/api/v1/certificates/{ids["prod.example"]}?group={g1}').status_code == 200
    assert get('/api/v1/certificates?group=not-here').status_code == 404
    assert get('/api/v1/summary?group=999999').status_code == 404
    assert get('/api/v1/groups/999999/certificates').status_code == 404


def test_edit_replace_delete_group_preserves_sites(seeded):
    client, auth = seeded
    sites = client.get('/api/sites').json['sites']
    ids = [s['id'] for s in sites]
    g1 = client.post('/api/groups', json={'name': 'Alpha', 'site_ids': ids[:2]}).json['id']
    g2 = client.post('/api/groups', json={'name': 'Beta', 'site_ids': ids}).json['id']
    assert client.put(f'/api/groups/{g1}', json={'name':'New Alpha', 'site_ids': ids[1:]}).status_code == 200
    assert client.put(f'/api/groups/{g1}/sites', json={'site_ids': ids[1:]}).json['site_count'] == 2
    assert client.put(f'/api/sites/{ids[1]}/groups', json={'group_ids':[g1, g2]}).status_code == 200
    assert client.put(f'/api/sites/{ids[0]}/groups', json={'group_ids':[]}).status_code == 200
    assert client.get('/api/v1/certificates?group=New%20Alpha', headers=auth).json['count'] == 2
    assert client.delete(f'/api/groups/{g1}').status_code == 200
    assert client.get('/api/sites').json['sites'][0]['group_ids'] != [g1]
    assert client.get('/api/v1/certificates', headers=auth).json['count'] == 3
    assert client.get(f'/api/v1/certificates?group={g1}', headers=auth).status_code == 404
    assert client.get(f'/api/v1/groups/{g2}', headers=auth).json['group']['site_count'] == 2
    assert client.delete(f'/api/sites/{ids[1]}').status_code == 200
    assert client.get(f'/api/v1/groups/{g2}', headers=auth).json['group']['site_count'] == 1


def test_names_ids_and_atomic_assignment_validation(seeded):
    client, _ = seeded
    ids = [s['id'] for s in client.get('/api/sites').json['sites']]
    assert client.post('/api/groups', json={'name':'ALL'}).status_code == 400
    assert client.post('/api/groups', json={'name':'  '}).status_code == 400
    assert client.post('/api/groups', json={'name':'Bad', 'site_ids':[ids[0],999999]}).status_code == 400
    assert client.get('/api/groups').json['groups'] == []
    a = client.post('/api/groups', json={'name':'Production'}).json['id']
    assert client.post('/api/groups', json={'name':'production'}).status_code == 409
    assert client.put(f'/api/groups/{a}/sites', json={'site_ids':[ids[0],999999]}).status_code == 400
    assert client.get('/api/groups').json['groups'][0]['site_count'] == 0
    assert client.put(f'/api/sites/{ids[0]}/groups', json={'group_ids':[a,999999]}).status_code == 400
    assert client.post('/api/sites', json={'urls':'https://new.example','group_ids':[999999]}).status_code == 400
    assert len(client.get('/api/sites').json['sites']) == 3
    # Only dashboard-authorized users may alter groups; API keys are GET-only.
    assert client.post('/api/v1/groups', json={}).status_code == 405


def test_adding_with_group_ids(seeded):
    client, auth = seeded
    gid = client.post('/api/groups', json={'name':'New sites'}).json['id']
    response = client.post('/api/sites', json={'urls':'https://newly-added.test','group_ids':[gid]})
    assert response.status_code == 201
    assert response.json['added'] == ['https://newly-added.test']
    assert client.get(f'/api/v1/certificates?group={gid}', headers=auth).json['count'] == 1
    assert client.get('/api/v1/certificates', headers=auth).json['count'] == 4
