"""Postman collection integrity: no third-party modules required."""
import json
from pathlib import Path


def test_postman_collection_has_all_api_endpoints():
    obj = json.loads((Path(__file__).resolve().parent.parent / 'TLS_Watch_v4_3.postman_collection.json').read_text())
    assert obj['info']['schema'].endswith('/collection/v2.1.0/collection.json')
    read_folder = obj['item'][0]
    assert read_folder['auth']['type'] == 'apikey'
    assert all(item['request']['method'] == 'GET' for item in read_folder['item'])
    paths = [item['request']['url'] for item in read_folder['item']]
    for path in ('/api/v1/summary', '/api/v1/certificates',
                 '?range=0-30', '?range=31-60', '?range=61-90',
                 '?range=90%2B', '/api/v1/certificates/needs-attention',
                 '/api/v1/certificates/expiring?within=30',
                 '/api/v1/certificates/expiring?within=60',
                 '/api/v1/certificates/expiring?within=90'):
        assert any(path in url for url in paths), path
    assert len(read_folder['item']) >= 27
    assert any('/api/v1/groups' in url for url in paths)
    assert any('group={{groupId}}' in url and 'needs-attention' in url for url in paths)
    admin_folder = obj['item'][1]
    assert admin_folder['auth']['type'] == 'basic'
    assert any('/api/settings/webhook' in req['request']['url'] for req in admin_folder['item'])
    vars = {var['key']: var['value'] for var in obj['variable']}
    assert vars['baseUrl'] == 'http://127.0.0.1:8080'
    assert vars['apiKey'] == ''
    assert vars['groupId'] == '1'
    assert vars['adminPassword'] == ''
    assert 'signingSecret' not in vars
    assert all(not v.startswith('tlsw_') for v in (str(x) for x in vars.values()))


def test_v43_history_backup_and_multiple_destinations():
    obj=json.loads((Path(__file__).resolve().parent.parent / 'TLS_Watch_v4_3.postman_collection.json').read_text())
    read=[r['request']['url'] for r in obj['item'][0]['item']]
    admin=[r['request']['url'] for r in obj['item'][1]['item']]
    assert any('/certificates/{{siteId}}/history' in r for r in read)
    assert any('/api/export.json' in r for r in admin)
    assert any('/api/import' in r for r in admin)
    assert any('/api/settings/webhooks/{{targetId}}/test' in r for r in admin)
