"""Run after installing requirements and pytest: python -m pytest -q."""
from datetime import datetime, timezone

import pytest

import app as monitor


def test_normalize_domain_port():
    assert monitor.normalize_url('WWW.Example.COM/some/page?q=abc') == ('https://www.example.com', 'www.example.com', 443)
    assert monitor.normalize_url('https://example.com:8443/path') == ('https://example.com:8443', 'example.com', 8443)
    with pytest.raises(ValueError):
        monitor.normalize_url('http://example.com')
    with pytest.raises(ValueError):
        monitor.normalize_url('https://user:password@example.com')


def test_days_remaining():
    checked = datetime(2026, 10, 23, tzinfo=timezone.utc)
    assert monitor.days_remaining(checked, checked) == 0
    assert monitor.days_remaining(checked.replace(day=24), checked) == 1
    assert monitor.days_remaining(checked.replace(day=24, hour=1), checked) == 2
    assert monitor.days_remaining(checked.replace(hour=23), checked.replace(day=24)) == -1


def test_schedule_uses_next_local_calendar_day():
    current = datetime(2026, 11, 1, 4, 0, tzinfo=timezone.utc)
    next_date = current.astimezone(monitor.LOCAL_TZ).date() + monitor.timedelta(days=1)
    for _ in range(30):
        scheduled = monitor.parse_datetime(monitor.next_random_check(current))
        assert scheduled.astimezone(monitor.LOCAL_TZ).date() == next_date


def test_flask_api_and_persistence(monkeypatch, tmp_path):
    monkeypatch.setattr(monitor, 'DB_PATH', tmp_path / 'sites.sqlite3')
    monitor.init_db()
    calls = []
    monkeypatch.setattr(monitor, 'enqueue', lambda site_id: calls.append(site_id) or True)
    client = monitor.app.test_client()
    response = client.post('/api/sites', json={'urls': 'https://example.com/path\nexample.org\nhttp://invalid.site'})
    assert response.status_code == 201
    assert len(response.json['added']) == 2
    assert len(response.json['errors']) == 1
    sites = client.get('/api/sites').json['sites']
    assert len(sites) == 2
    assert len(calls) == 2
    site_id = sites[0]['id']
    assert client.post(f'/api/sites/{site_id}/pause', json={'paused': True}).json['paused'] is True
    assert next(s for s in client.get('/api/sites').json['sites'] if s['id'] == site_id)['paused'] is True
    assert client.post(f'/api/sites/{site_id}/pause', json={'paused': False}).json['paused'] is False
    assert client.post(f'/api/sites/{site_id}/check').status_code == 200
    assert client.get('/api/export.csv').status_code == 200
    assert client.delete(f'/api/sites/{site_id}').status_code == 200
    assert len(client.get('/api/sites').json['sites']) == 1
    assert client.get('/').status_code == 200


def test_certificate_metadata_saved(monkeypatch, tmp_path):
    monkeypatch.setattr(monitor, 'DB_PATH', tmp_path / 'sites.sqlite3')
    monitor.init_db()
    with monitor.db() as con:
        cur = con.execute('INSERT INTO sites (url, hostname, port, created_at) VALUES (?,?,?,?)',
                          ('https://example.com', 'example.com', 443, monitor.utc_iso(monitor.utcnow())))
        site_id = cur.lastrowid

    def fake_cert(_host, _port):
        return {'issuer': 'Example CA', 'issued_at': '2026-01-01T00:00:00Z',
                'expires_at': '2027-12-01T00:00:00Z', 'tls_verified': 1, 'verify_error': None}

    monkeypatch.setattr(monitor, 'inspect_certificate', fake_cert)
    monitor.run_check(site_id)
    with monitor.db() as con:
        row = con.execute('SELECT * FROM sites WHERE id=?', (site_id,)).fetchone()
    assert row['issuer'] == 'Example CA'
    assert row['last_checked_at']
    assert row['next_check_at']
    assert row['days_left'] > 0


def test_block_private_targets(monkeypatch):
    monkeypatch.setattr(monitor, 'ALLOW_PRIVATE', False)
    with pytest.raises(OSError, match='blocked'):
        monitor.resolve_target('127.0.0.1', 443)


def test_local_tls_handshake(monkeypatch, tmp_path):
    import socket
    import ssl
    import threading
    from datetime import timedelta
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'TLS Watch Test CA')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=1))
                   .not_valid_after(now + timedelta(days=100))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                   .sign(key, hashes.SHA256()))
    certfile, keyfile = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    listener.listen(4)
    listener.settimeout(5)
    port = listener.getsockname()[1]

    def server():
        try:
            for _ in range(2):
                client, _ = listener.accept()
                try:
                    with ctx.wrap_socket(client, server_side=True):
                        pass
                except ssl.SSLError:
                    pass
        finally:
            listener.close()

    worker = threading.Thread(target=server, daemon=True)
    worker.start()
    monkeypatch.setattr(monitor, 'ALLOW_PRIVATE', True)
    result = monitor.inspect_certificate('localhost', port)
    worker.join(timeout=5)
    assert result['issuer'] == 'TLS Watch Test CA'
    assert result['tls_verified'] == 0
    assert result['verify_error']
    assert monitor.parse_datetime(result['expires_at']) > now


def test_existing_database_migrates_without_losing_sites(monkeypatch, tmp_path):
    import sqlite3
    database = tmp_path / 'legacy.sqlite3'
    old_schema = monitor.SQL_SCHEMA.replace(
        ' created_at TEXT NOT NULL,\n certificate_pem TEXT,\n certificate_observed_at TEXT\n',
        ' created_at TEXT NOT NULL\n'
    )
    with sqlite3.connect(database) as con:
        con.executescript(old_schema)
        con.execute('''INSERT INTO sites (url, hostname, port, paused, last_checked_at,
            next_check_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)''',
            ('https://example.com', 'example.com', 443, 0,
             '2026-10-23T00:00:00Z', '2026-10-30T00:00:00Z', '2026-10-23T00:00:00Z'))
    monkeypatch.setattr(monitor, 'DB_PATH', database)
    monitor.init_db()
    with monitor.db() as con:
        row = con.execute('SELECT * FROM sites WHERE id=1').fetchone()
        assert row['url'] == 'https://example.com'
        assert row['certificate_pem'] is None
        assert row['certificate_observed_at'] is None
        # Existing active certificates will be refreshed once when upgrading.
        assert monitor.parse_datetime(row['next_check_at']) <= monitor.utcnow()
    # Reinitializing must not repeatedly reschedule the existing site.
    with monitor.db() as con:
        con.execute('UPDATE sites SET next_check_at=? WHERE id=1', ('2026-10-30T00:00:00Z',))
    monitor.init_db()
    with monitor.db() as con:
        assert con.execute('SELECT next_check_at FROM sites WHERE id=1').fetchone()[0] == '2026-10-30T00:00:00Z'


def test_full_certificate_details_saved_and_downloadable(monkeypatch, tmp_path):
    from datetime import timedelta
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

    monkeypatch.setattr(monitor, 'DB_PATH', tmp_path / 'certs.sqlite3')
    monitor.init_db()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=100))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('example.com'),
                                                        x509.DNSName('www.example.com')]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode('ascii')
    with monitor.db() as con:
        site_id = con.execute('INSERT INTO sites (url, hostname, port, created_at) VALUES (?,?,?,?)',
                              ('https://example.com', 'example.com', 443,
                               monitor.utc_iso(now))).lastrowid
    client = monitor.app.test_client()
    assert client.get(f'/api/sites/{site_id}/certificate').json['certificate'] is None
    assert client.get(f'/api/sites/{site_id}/certificate.pem').status_code == 404
    monkeypatch.setattr(monitor, 'inspect_certificate', lambda host, port: {
        'issuer': 'Example CA', 'issued_at': monitor.utc_iso(cert.not_valid_before_utc),
        'expires_at': monitor.utc_iso(cert.not_valid_after_utc), 'tls_verified': 0,
        'verify_error': 'self-signed', 'certificate_pem': pem,
    })
    monitor.run_check(site_id)
    overview = client.get('/api/sites').json['sites'][0]
    assert overview['has_certificate'] is True
    assert 'certificate_pem' not in overview
    result = client.get(f'/api/sites/{site_id}/certificate')
    assert result.status_code == 200
    info = result.json['certificate']
    assert info['subject'] == 'CN=example.com'
    assert 'www.example.com' in info['dns_names']
    assert info['public_key'] == 'RSA (2048 bits)'
    assert info['sha256_fingerprint']
    assert info['pem'] == pem
    assert result.json['tls_verified'] is False
    pem_download = client.get(f'/api/sites/{site_id}/certificate.pem')
    assert pem_download.status_code == 200
    assert pem_download.data.decode('ascii') == pem
    assert 'example.com.pem' in pem_download.headers['Content-Disposition']
    # Details remain inspectable even if a later connection attempt fails.
    def connection_failed(host, port):
        raise ConnectionError('Disconnected')
    monkeypatch.setattr(monitor, 'inspect_certificate', connection_failed)
    monitor.run_check(site_id)
    result_after_error = client.get(f'/api/sites/{site_id}/certificate').json
    assert result_after_error['certificate']['pem'] == pem
    assert 'Disconnected' in result_after_error['last_error']
