# TLS Watch v4.3 — REST API and outbound webhook reference

TLS Watch is a locally hosted Flask/SQLite HTTPS-certificate monitor. Its optional **read-only API** lets other tools query the monitored certificates, and its optional **outbound webhooks** send selected change events to a receiving HTTP or HTTPS service (HTTP requires an explicit opt-in).

**Base address (on the monitoring PC):** `http://127.0.0.1:8080`. For access from other devices, see [Remote access and security](#remote-access-and-security) below. An API key authenticates a request; it does not by itself make a local-only server reachable over the network.

## 1. Enabling an API key

1. Open TLS Watch's dashboard and expand **API access & outbound webhooks** below Certificate Overview.
2. Under **Remote API access**, click **Generate / rotate API key**.
3. Copy the generated key immediately and store it securely. **The full key is shown only once.** TLS Watch persists its SHA-256 hash, not the cleartext key.
4. Use either header in requests to `/api/v1/`:

   ```http
   X-API-Key: tlsw_YOUR_GENERATED_KEY
   ```

   or

   ```http
   Authorization: Bearer tlsw_YOUR_GENERATED_KEY
   ```

5. **Generate / rotate** invalidates the previous key immediately. **Revoke** removes the current key, disabling authenticated API access until a new key is generated. This release supports one active key at a time.

All `/api/v1` operations are `GET` only. The API key **cannot** add, pause, delete, or check a website; view the saved PEM; generate/rotate keys; or manage webhooks. Browser management routes remain separate and are controlled by local access / optional dashboard login.

### Authentication examples

PowerShell (Windows):

```powershell
$base = 'http://127.0.0.1:8080'
$headers = @{ 'X-API-Key' = 'tlsw_YOUR_GENERATED_KEY' }
Invoke-RestMethod -Uri "$base/api/v1/summary" -Headers $headers
Invoke-RestMethod -Uri "$base/api/v1/certificates/needs-attention" -Headers $headers
Invoke-RestMethod -Uri "$base/api/v1/certificates?range=90%2B" -Headers $headers
```

cURL (Linux, macOS, recent Windows installations):

```bash
curl -H 'X-API-Key: tlsw_YOUR_GENERATED_KEY' \
  'http://127.0.0.1:8080/api/v1/certificates/expiring?within=60'
```

**Security:** These loopback examples use HTTP because they run on the same computer. Use **HTTPS** for any request that traverses a network, through an authenticated/restricted reverse proxy; never send API keys over a public plaintext HTTP connection.

### Postman import and setup

This release ships an importable **Postman Collection v2.1** file named [`TLS_Watch_v4_3.postman_collection.json`](TLS_Watch_v4_3.postman_collection.json). In Postman select **Import → Files**, then choose that JSON file. It has two folders:

- **Read-only monitoring API — X-API-Key**: all GET endpoints, with automatic `X-API-Key` authentication from the `apiKey` collection variable.
- **Local dashboard administration — optional**: settings, API-key creation/revocation, webhook configuration, signing-secret rotation and test delivery. This is **not** part of the API-key-authorized read-only remote API. Admin endpoints use local/dashboard access or optional Basic authentication. Some admin requests revoke credentials; use intentionally.

In the collection's **Variables** tab set `baseUrl` (`http://127.0.0.1:8080` locally, or the HTTPS reverse proxy URL remotely), `apiKey` (the one-time value copied from the UI), and optionally `siteId` (e.g., `1`). To use optional administration requests, set `adminUsername`, `adminPassword`, and `webhookUrl` as needed. Postman may synchronize variable values; do not export or share credentials in a collection.

The **Healthy expiry >90 days** request is already written as `?range=90%2B`, so Postman sends a literal `+` value correctly. See the API endpoint table below.

## 2. Read-only API endpoints

Every endpoint in the table requires a valid API key. Results are UTF-8 JSON and timestamps use **UTC ISO 8601**, e.g. `2026-10-24T12:00:00Z`.

| Method | Endpoint | Returns |
| --- | --- | --- |
| `GET` | `/api/v1/summary` | Certificate overview counters |
| `GET` | `/api/v1/certificates` | All monitored sites |
| `GET` | `/api/v1/certificates?range=expired` | Expired certificates (`days_left < 0`) |
| `GET` | `/api/v1/certificates?range=0-30` | 0–30 days remaining, inclusive |
| `GET` | `/api/v1/certificates?range=31-60` | 31–60 days remaining, inclusive |
| `GET` | `/api/v1/certificates?range=61-90` | 61–90 days remaining, inclusive |
| `GET` | `/api/v1/certificates?range=90%2B` | More than 90 days remaining (the dashboard's **green** category) |
| `GET` | `/api/v1/certificates/expiring?within=30` | Any certificate with **≤30 days**, including expired certificates |
| `GET` | `/api/v1/certificates/expiring?within=60` | Any certificate with **≤60 days**, including expired certificates |
| `GET` | `/api/v1/certificates/expiring?within=90` | Any certificate with **≤90 days**, including expired certificates |
| `GET` | `/api/v1/certificates/needs-attention` | All sites that need attention (definition below) |
| `GET` | `/api/v1/certificates/123` | Monitored site whose numeric ID is `123`; HTTP 404 if absent |

`90%2B` is the URL-encoded spelling of `90+`. The server also tolerates `90plus`, `>90`, or a literal `+` interpreted as a space in a query string. Prefer `90%2B` in automation.

**Expiration ranges:** All filters use `days_left` **as calculated at the most recent check** rather than an independently updating clock. A site that has never successfully exposed a certificate has `days_left: null` and is absent from range selections. Paused websites remain in API results and counts; they are not silently excluded.

**Needs Attention:** A site is included when **any** of these conditions holds:

- The latest check failed (`last_error` is not `null`/empty), e.g., a DNS, TCP, or TLS connection error.
- The last certificate inspection produced `tls_verified: false` (trust-chain, expiry, or hostname validation failed).
- Its last measured `days_left` is **30 or less**, including negative values for expired certificates.
- **NEW v4.3:** The website is active and has not had a successful certificate retrieval in **over 24 hours**. Above 48 hours the stale severity is critical.

The last-known certificate metadata is preserved when a later check fails. Accordingly a certificate with 120 days remaining but a new DNS error can be **both green/healthy by expiration** and **Needs Attention** due to the connection error. A website with no successful check enters Needs Attention if no certificate is retrieved more than 24 hours after it is added. Paused websites are excluded from the stale threshold.

### Response example: summary

```json
{
  "as_of": "2026-10-24T12:00:00Z",
  "total": 5,
  "healthy": 3,
  "expiring_60": 2,
  "needs_attention": 2
}
```

Counts follow the dashboard: `healthy` counts `days_left > 90` without suppressing independently detected errors; `expiring_60` includes expired certificates; `needs_attention` uses the rules above. Counters are not necessarily mutually exclusive.

### Response example: certificate collection

```json
{
  "as_of": "2026-10-24T12:00:00Z",
  "selection": "within_30",
  "days_basis": "days remaining at last certificate check",
  "count": 1,
  "certificates": [
    {
      "id": 3,
      "url": "https://customer.example.com",
      "hostname": "customer.example.com",
      "port": 443,
      "paused": false,
      "issuer": "Example Certificate Authority",
      "issued_at": "2026-08-01T00:00:00Z",
      "expires_at": "2026-11-15T00:00:00Z",
      "days_left": 22,
      "last_checked_at": "2026-10-24T12:00:00Z",
      "next_check_at": "2026-10-25T18:45:13Z",
      "certificate_observed_at": "2026-10-24T12:00:00Z",
      "last_error": null,
      "tls_verified": true,
      "verify_error": null,
      "needs_attention": true
    }
  ]
}
```

`GET /api/v1/certificates/{id}` instead returns the object under the single `certificate` property. The API does **not** return stored PEM, private keys, API key hashes, webhook settings, or signing secrets.

### API response codes

| Code | Meaning |
| --- | --- |
| `200` | Success |
| `400` | Unsupported `range`/`within` value |
| `401` | API key missing, revoked or incorrect |
| `404` | Certificate or group ID not found |
| `405` | Non-GET request to the read-only API |

Error responses are JSON such as `{"detail":"Valid API key required (X-API-Key or Bearer)"}`. Requests to API endpoints should include the key even if the browser dashboard is already authenticated. Sensitive API responses are marked `Cache-Control: no-store`.

## 2A. Inventory groups and scoped API (v4.2)

**ALL** is a virtual, permanent inventory tab; it contains every website. Named groups are stored persistently in SQLite with a many-to-many relationship to monitored sites. A website can be assigned to zero, one, or many groups without duplicating monitoring, checks, certificates, or webhooks. Deleting a group **only** removes its memberships, not monitored sites. Group names are unique without regard to case; `ALL` is reserved. Numeric group IDs are stable even when groups are renamed.

### Read-only group discovery

| GET request | Result |
|---|---|
| `/api/v1/groups` | `groups` array with virtual `ALL` first and named groups with `{id,name,site_count}`. Same `X-API-Key` as other GET endpoints. |
| `/api/v1/groups/2` | Group record and membership count; 404 if not found. |

Example `GET /api/v1/groups` response:

```json
{"groups":[{"id":"all","name":"ALL","site_count":7},{"id":2,"name":"Production","site_count":3},{"id":4,"name":"Internal","site_count":2}],"as_of":"2026-10-24T12:00:00Z"}
```

### Apply a group to **any** existing certificate GET

Add `group=<group ID>` or `group=<group name>` to the existing endpoint. URLs with spaces or special characters in group names must be URL-encoded. **Prefer IDs for stable automation**, because names may be renamed.

| GET request | Result |
|---|---|
| `/api/v1/summary?group=2` | Healthy, expiring and Needs Attention counts **only within group 2** |
| `/api/v1/certificates?group=2` | Every certificate in group 2 |
| `/api/v1/certificates?group=2&range=expired` | Expired certificates in group 2 |
| `/api/v1/certificates?group=2&range=0-30` | Group 2, 0–30 days left |
| `/api/v1/certificates?group=2&range=31-60` | Group 2, 31–60 days left |
| `/api/v1/certificates?group=2&range=61-90` | Group 2, 61–90 days left |
| `/api/v1/certificates?group=2&range=90%2B` | Group 2, >90 days left |
| `/api/v1/certificates/expiring?within=30&group=2` | Group 2, ≤30 days incl. expired |
| `/api/v1/certificates/expiring?within=60&group=2` | Group 2, ≤60 days incl. expired |
| `/api/v1/certificates/expiring?within=90&group=2` | Group 2, ≤90 days incl. expired |
| `/api/v1/certificates/needs-attention?group=2` | **Needs Attention** certificates in group 2 |
| `/api/v1/certificates/123?group=2` | Certificate 123, **only if it belongs to group 2**; otherwise 404 |

Equivalent, discoverable group-scoped aliases are available for each call:

```http
GET /api/v1/groups/2/summary
GET /api/v1/groups/2/certificates?range=0-30
GET /api/v1/groups/2/certificates/expiring?within=60
GET /api/v1/groups/2/certificates/needs-attention
GET /api/v1/groups/2/certificates/123
```

Both approaches are equivalent and require the same valid **read-only API key**. A `group` response field identifies the selected group (or `{ "id": "all", "name": "ALL" }`). Certificate list items also include `group_ids`, an array of numeric groups the site belongs to. Unknown groups return `404`. A group with zero sites returns an empty collection and zero summary counters. The virtual `ALL` scope is available by omitting `group` or using `?group=all`.

### Local-only group administration (not authorized by read-only API key)

These use the same dashboard/local access rules as the v4.1 `/api/sites` and `/api/settings` management endpoints:

| Method | Endpoint | Body | Purpose |
|---|---|---|---|
| `GET` | `/api/groups` | — | List named groups, their IDs and counts |
| `POST` | `/api/groups` | `{"name":"Production","site_ids":[1,2]}` | Create group and optionally assign websites in one operation |
| `PUT` | `/api/groups/2` | `{"name":"Renamed","site_ids":[1,2]}` | Rename group and optionally atomically replace its membership; `site_ids` is optional |
| `DELETE` | `/api/groups/2` | — | Delete group and group memberships, **keep all websites** |
| `PUT` | `/api/groups/2/sites` | `{"site_ids":[1,3]}` | **Replace** group 2's memberships with exactly the listed websites |
| `PUT` | `/api/sites/1/groups` | `{"group_ids":[2,4]}` | **Replace** website 1's memberships across groups |
| `POST` | `/api/sites` | `{"urls":"https://host.example","group_ids":[2]}` | Add website(s) directly into selected group(s); `group_ids` is optional |

`site_ids` / `group_ids` must be lists of existing positive integer IDs. Empty lists clear memberships. An unknown ID returns 400 and does not partially change memberships. Names are 1–60 printable characters, unique case-insensitively; `ALL` is reserved. These routes cannot be written with the read-only API key. The Postman collection includes optional local administration group examples; **do not execute edits unintentionally**.

### Search and group tabs

The Live Inventory opens with **ALL** first, followed by named group tabs and their counts. Group tabs default to the **This Group** search scope. The scope dropdown also offers **All Websites** to search the complete site inventory regardless of the active group tab. Status filtering (active, paused, Needs Attention) and sorting apply to the selected search scope. **Edit group** lists all monitored websites with checkboxes to add or remove any website; individual website **Groups** action lets you select multiple groups for one site. These preferences control only the browser table; the top summary cards still show ALL websites.

## 3. Configure outbound webhooks

TLS Watch retains the **original/default webhook destination** (applies to ALL) and additionally supports **multiple independent group-filtered webhook destinations** (HTTP or HTTPS URLs), each with configurable event types. It sends JSON **POST** requests to your receiver. Configuration is in the same **API access & outbound webhooks** accordion.

1. Enter the receiver URL under **Webhook destination** (for local testing: `http://127.0.0.1:8888/webhook`; production example: `https://hooks.example.org/tls-watch`).
2. For local HTTP testing, enable **Allow HTTP destinations** and **Allow localhost and private network addresses**. For an HTTPS receiver with a self-signed certificate, enable **Accept self-signed / untrusted HTTPS certificates** if you cannot install a trusted certificate. Each option is saved per webhook and defaults to OFF.
3. These exceptions affect only the **outbound webhook**. They do not disable certificate validation when TLS Watch checks monitored websites.
4. Select the events to send using the checkboxes below the URL.
5. To provision your receiver safely, **save with the Enable box unchecked first**. This generates the shared HMAC-SHA256 signing secret. Copy it **immediately** and configure it on the receiver. The secret will not be displayed on later visits.
6. Then enable **Webhook delivery** and click **Save webhook** again.
7. Click **Send test** to queue a test delivery; check **Recent webhook deliveries** for status, HTTP response or last error. `test` is always permitted when explicitly requested, independent of your selected subscriptions.
8. Use **Rotate signing secret** to change the secret; update the receiver at the same time. Pending deliveries are cancelled to avoid deliveries signed with the wrong secret.

Disabling delivery, changing the URL, or changing security options cancels *pending* deliveries to the previous endpoint. Already-sending requests cannot always be cancelled. TLS Watch keeps a recent status list in the dashboard and stores the full delivery records in SQLite. A URL is never opened in a browser and no HTTP redirects are followed.

### Available webhook events

| Event | When emitted |
| --- | --- |
| `expiration_90` | Certificate first observed at ≤90 days, or subsequently crosses 90-day threshold |
| `expiration_60` | Certificate first observed at ≤60 days, or subsequently crosses 60-day threshold |
| `expiration_30` | Certificate first observed at ≤30 days, or subsequently crosses 30-day threshold |
| `certificate_expired` | Certificate first observed expired, or crosses from unexpired to expired |
| `tls_invalid` | TLS validation first fails after previously passing / being unknown |
| `check_failed` | Network/DNS/inspection check newly fails |
| `recovered` | A previously failed/untrusted endpoint successfully validates |
| `certificate_changed` | The saved leaf certificate's PEM changes between successful inspections |
| `needs_attention` | Site newly enters the Needs Attention condition |
| `attention_cleared` | Site leaves the Needs Attention condition |

The checks are **transition-based** to prevent firing the same warning every day. A first observation issues only the **most severe applicable expiration threshold** (for example, 20 days yields `expiration_30` rather than 30+60+90). When an *existing* certificate crosses multiple thresholds between checks, one event per crossed threshold can be generated, depending on subscriptions. Different event types for the same check can be delivered separately. On an expired certificate, the `certificate_expired` event supersedes threshold alerts. Certificate renewals/changes can generate a new threshold alert for the new certificate.

**Note:** HTTPS TLS validity and certificate expiry are separate dimensions. For example, TLS can be untrusted for a non-expiry issue even if `days_left` is high. A failed check may retain old certificate details; the fresh error is exposed in `last_error`.

### Webhook request format

Each queued event is delivered as `POST <configured-webhook-url>` with headers:

```http
Content-Type: application/json
Accept: application/json
X-TLSWatch-Event: expiration_30
X-TLSWatch-Delivery: 849c4a7c-8d7e-49e0-9160-ef0c2ac8a5b9
X-TLSWatch-Timestamp: 2026-10-24T12:00:04Z
X-TLSWatch-Signature: sha256=<lowercase-hex-hmac>
```

Example JSON payload (`site` contains the full public certificate fields as described above):

```json
{
  "event_id": "849c4a7c-8d7e-49e0-9160-ef0c2ac8a5b9",
  "event": "expiration_30",
  "occurred_at": "2026-10-24T12:00:00Z",
  "site": {
    "id": 3,
    "url": "https://customer.example.com",
    "hostname": "customer.example.com",
    "port": 443,
    "paused": false,
    "issuer": "Example Certificate Authority",
    "issued_at": "2026-08-01T00:00:00Z",
    "expires_at": "2026-11-15T00:00:00Z",
    "days_left": 22,
    "last_checked_at": "2026-10-24T12:00:00Z",
    "next_check_at": "2026-10-25T18:45:13Z",
    "last_error": null,
    "tls_verified": true,
    "verify_error": null,
    "certificate_observed_at": "2026-10-24T12:00:00Z",
    "needs_attention": true
  },
  "previous": {
    "days_left": 31,
    "last_error": null,
    "tls_verified": true
  }
}
```

For an explicit `test` event, the `site` field is `null` and the JSON also contains `"message":"TLS Watch test delivery"`.

### Webhook receiver: verify the signature

Compute `HMAC-SHA256(key = signing_secret, message = **exact raw HTTP request-body bytes**)`, hex encode it, and compare it in constant time to `X-TLSWatch-Signature` after the `sha256=` prefix. **Do not reserialize JSON before verifying.** Use `X-TLSWatch-Delivery` as a deduplication key because retries deliver the same event ID/payload.

Python / Flask receiver example (illustrative; run this **separately** from TLS Watch with an HTTPS reverse proxy):

```python
import hashlib
import hmac
import os
from flask import Flask, abort, request

receiver = Flask(__name__)
SIGNING_SECRET = os.environ["TLS_WATCH_WEBHOOK_SECRET"]

@receiver.post("/tls-watch")
def receive_tls_watch():
    body = request.get_data()  # raw bytes; do not parse/re-encode first
    supplied = request.headers.get("X-TLSWatch-Signature", "")
    expected = "sha256=" + hmac.new(
        SIGNING_SECRET.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        abort(401)
    event = request.get_json()  # signature now verified
    event_id = request.headers.get("X-TLSWatch-Delivery", "")
    # Production: durably deduplicate event_id before processing.
    print("Valid event", event_id, event["event"])
    return "", 204
```

The HMAC covers the body but **does not cover the timestamp header**. A production receiver should also de-duplicate delivery IDs and can check `X-TLSWatch-Timestamp` against an acceptable time window to reduce replay exposure.

### Delivery and retry behavior

- Events are queued persistently in `data/certificates.sqlite3`; sending runs on the Flask server even with the browser closed.
- The background worker polls for deliveries about every **10 seconds** and handles them one at a time; the server must remain running.
- HTTP `2xx` means success; HTTP `3xx`, `4xx`, `5xx`, DNS, timeout and TLS validation errors are failures. Redirects are **not** followed.
- Up to **3 delivery attempts**: initial, then ~60 seconds after the first error, then ~300 seconds after the second error. On the third failure it is marked `failed`; there is no automatic retry beyond that.
- Statuses: `pending`, `sending`, `delivered`, `failed`, `cancelled`. The dashboard lists the 15 most recent deliveries (with attempt counts, last errors and success status); the complete log is retained in SQLite.
- The same `event_id` and JSON payload are reused for retries. Event delivery is **at-least-once**, not exactly-once: a server might receive the event but fail to acknowledge it in time, causing a retry.
- **Default security**: only HTTPS, public addresses, normal CA and hostname verification. No HTTP redirects are followed.
- **Allow HTTP destinations** (`allow_http`): permits `http://` endpoints. HTTP payloads and headers are **not encrypted** (but the HMAC still signs the JSON); use only on trusted networks for testing.
- **Allow localhost and private network addresses** (`allow_private`): permits loopback/private/link-local webhook targets, including `127.0.0.1:8888`. DNS results are checked at connection time and connected by pinned IP, reducing DNS-rebinding risk. This does *not* change the `ALLOW_PRIVATE_TARGETS` setting for monitored certificate endpoints.
- **Accept self-signed certificates** (`allow_self_signed`): for **HTTPS** webhook destinations only. Disables TLS certificate-chain and hostname validation for this outbound webhook. Traffic remains encrypted, but an impersonating server cannot be detected by certificate verification. Avoid on untrusted networks.
- These three boolean options are independent, opt-in, and persisted in the SQLite webhook configuration. Turning one off or changing it cancels pending deliveries.

## 4. Local administrative endpoints

These endpoints power the integrations accordion and are provided in the **optional Postman admin folder**. They are **not accessible with `X-API-Key` or Bearer API-key authentication**. Without `APP_USERNAME` and `APP_PASSWORD`, access to the dashboard/admin API is restricted to local client addresses. With Basic authentication configured, use those credentials and restrict access behind HTTPS and an authentication-enforcing reverse proxy.

| Method | Path | Purpose | Request body |
| --- | --- | --- | --- |
| `GET` | `/api/settings` | API key prefix/status, default webhook, additional targets (no secrets), 30 latest deliveries | none |
| `POST` | `/api/settings/api-key` | Generate/rotate the single API key and return it *once* | `{}` optional |
| `DELETE` | `/api/settings/api-key` | Revoke the active API key | none |
| `PUT` | `/api/settings/webhook` | Configure event subscriptions and enable/disable deliveries | JSON example below |
| `POST` | `/api/settings/webhook/test` | Queue a `test` webhook (requires enabled destination); HTTP 202 | `{}` optional |
| `POST` | `/api/settings/webhook/rotate-secret` | Generate/rotate the webhook signing secret and return it *once* | `{}` optional |

Example body for `PUT /api/settings/webhook`:

```json
{
  "enabled": false,
  "url": "https://hooks.example.com/tls-watch",
  "events": ["expiration_30", "certificate_expired", "tls_invalid", "check_failed", "recovered", "needs_attention"],
  "allow_http": false,
  "allow_private": false,
  "allow_self_signed": false
}
```

When first saving a webhook, the response includes `signing_secret` to copy to the receiver. Future GETs show only whether the secret is configured. The secret is never retrievable again; rotation generates a new secret. For a safe initial receiver setup, save with `enabled: false`, install the returned secret on the receiver, then enable the webhook.

## 5. Remote access and security

TLS Watch's Flask app listens on `127.0.0.1:8080` by default. To query it from another PC, make it reachable with an **HTTPS reverse proxy** or secure VPN, firewall access restrictions, and preferably a production WSGI server instead of exposing Flask's development server.

- API keys are **bearer secrets**. Store securely; rotate if exposed; do not put them in URLs or application logs.
- **Dashboard/admin access is distinct from API access.** By default, remote UI/admin requests are denied unless both `APP_USERNAME` and `APP_PASSWORD` are configured; the `/api/v1` endpoints accept a valid API key from remote callers, subject to network reachability. If you use a reverse proxy, enforce authentication and access controls **at the proxy** as well, because proxied traffic may appear as `127.0.0.1` to Flask.
- Use **TLS/HTTPS** at the network boundary. API keys and browser Basic credentials must never traverse an untrusted network in plaintext.
- `BIND_HOST=0.0.0.0` exposes the built-in application to your LAN and is **not** recommended on an untrusted network. Use a secure reverse proxy instead.
- The default `ALLOW_PRIVATE_TARGETS=true` setting permits **certificate monitoring** for internal HTTPS sites. The webhook's separate **Allow localhost/private** checkbox controls webhook delivery and does not require setting `ALLOW_PRIVATE_TARGETS`.
- Local webhook testing: run the separate **TLS Webhook Viewer** at `127.0.0.1:8888`, configure HTTP and localhost options in TLS Watch, then send a test. The viewer is a separate application, not bundled into TLS Watch's Flask server.
- Restrict filesystem access to `data/certificates.sqlite3`. It contains the monitored endpoint list, the **hashed API key**, webhook **signing secret in cleartext** (needed to sign outgoing requests), queued payloads, and delivery history.
- **No inbound webhook receiver** is implemented in TLS Watch; the webhooks feature only sends events to your configured receiver.
- This is a read-only remote API. Existing local dashboard endpoints, including `/api/settings`, `/api/sites` and PEM download, are intentionally **not** API-key accessible.

## 6. Administration and persistence

Your existing monitored sites, API keys, webhook configuration, and certificate history are retained when upgrading to TLS Watch v4.3. Unzip over the existing folder without deleting `data/` or `.venv/`. Database tables for keys, webhook settings, and deliveries are created automatically at startup. The original site entries are not replaced.

API keys, webhook configuration and queued/delivered events survive application restarts because they live in SQLite. The app must remain running for daily checks and webhook processing. Make sure only **one** TLS Watch instance points to a given database: the in-process daily scheduler is not designed for multiple Flask processes.

For general setup/Windows startup see [`README.md`](README.md).

## 7. Local HTTP receiver example

With the separate Flask viewer running, set the outbound webhook config to:

```json
{
  "enabled": true,
  "url": "http://127.0.0.1:8888/webhook",
  "events": ["expiration_30", "tls_invalid", "check_failed", "needs_attention"],
  "allow_http": true,
  "allow_private": true,
  "allow_self_signed": false
}
```

View deliveries at `http://127.0.0.1:8888/`. Click **Send test** in TLS Watch. A test webhook uses event type `test`, even when not selected in subscriptions. If you configure the viewer with `WEBHOOK_SIGNING_SECRET`, it verifies the HMAC and rejects invalid signatures.


---

## 5. New features in v4.3

### Certificate and connection history

Each website has a **History** button in the Actions column. Open it to see recorded certificate versions (and issuer/expiration differences), last-seen dates, past leaf certificate downloads, and recent connection checks. Versions are deduplicated by SHA-256 fingerprint of the stored PEM and kept as long as the site exists. The last **1,000** individual checks per website are retained. Checks prior to upgrading to v4.3 were not previously stored; migration adds the last certificate snapshot only.

| Method | Path | Access | Description |
|---|---|---|---|
| GET | `/api/sites/{siteId}/history` | Dashboard/admin | All saved certificate versions (up to 250 returned) and latest 150 checks |
| GET | `/api/sites/{siteId}/history/{certificateId}.pem` | Dashboard/admin | Download historical leaf PEM |
| GET | `/api/v1/certificates/{siteId}/history` | **API key** | JSON history, never PEM |
| GET | `/api/v1/groups/{groupId}/certificates/{siteId}/history` | **API key** | Same, only for sites belonging to the named group |

Sample:

```http
GET /api/v1/certificates/15/history
X-API-Key: tlsw_YOUR_GENERATED_KEY
```

The JSON body contains `url`, `certificates[]` and `checks[]`. Each version includes `fingerprint`, `issuer`, `issued_at`, `expires_at`, `first_seen_at`, `last_seen_at`, `issuer_changed` and `expiration_delta_days` (where there is an older version for comparison). Each check includes `checked_at`, `success`, `tls_verified`, `days_left`, `message` and `fingerprint`.

The API does not return PEMs, encryption keys, signing secrets or authentication credentials.

### Stale monitoring checks

The most recent successful **certificate retrieval** (even if the returned certificate is untrusted) is stored in `last_successful_at`, separate from `last_checked_at` (which includes failures). An active website is classified `fresh` up through 24 hours, `warning` when **over 24h**, and `critical` when **over 48h** without a successful retrieval; a paused site is `paused`. A newly added site which has never passed a check uses its creation time until a certificate is retrieved.

`GET /api/v1/summary` now also returns `stale_warning` and `stale_critical`, and `GET /api/v1/certificates/needs-attention` includes stale sites. All existing `?group=` filters and group-scoped paths work with the same logic. `healthy` still means *expiry greater than 90 days*, independent of TLS trust, connection issues, and staleness. Counts can overlap.

Stale status is based on **current UTC time**, whereas `days_left` is computed at the last check. A daily randomized schedule can legitimately go more than 24 hours between runs; use 48h critical status in conjunction with check history to distinguish schedule variation from extended failures.

New optional events: `certificate_renewed`, `certificate_issuer_changed`, `certificate_expiration_shortened`, `monitoring_stale_warning`, `monitoring_stale_critical`. Stale sites also enter Needs Attention, and a later successful check clears this state unless an independent problem remains. The warning/critical events fire once per stale episode/severity, not every scheduler tick. Webhook certificate-change payloads also contain `previous.issuer`, `previous.expires_at`, `group_ids`, and `groups`.

### Bulk import/export

| Method | Path | Body | Description |
|---|---|---|---|
| GET | `/api/export-inventory.csv` | — | Download website inventory and group membership as `URL,Groups,Paused` CSV |
| GET | `/api/export.json` | — | Download portable JSON backup of website URLs, groups and pause status (no secrets) |
| POST | `/api/import` | `{"format":"csv"|"json", "content":"file as UTF-8 text"}` | Import up to 1,500 entries and 2 MB of text; names/URLs validated and changes committed atomically |

These three management routes use dashboard/local Basic authentication, **not the read-only API key**.

CSV input example:

```csv
URL,Groups,Paused
https://example.com,Production;Customer A,false
https://api.example.com:8443,Production;Internal,false
https://dev.example.net,Development,true
```

JSON input example:

```json
{
  "groups": ["Production", "Development", "Customer A"],
  "websites": [
    {"url": "https://example.com", "groups": ["Production", "Customer A"], "paused": false},
    {"url": "https://dev.example.net", "groups": ["Development"], "paused": true}
  ]
}
```

**Import semantics:** Existing sites are matched by normalized HTTPS host/port and are never duplicated. Their current certificate snapshots, history, and existing group memberships are kept. Imported group membership is *merged*; imported `paused` values are applied. Missing groups are created. New active websites are queued for initial checks; large imports are admitted through the normal capped scheduler. There is no API-key-authorized import/export of administrative configuration. JSON backup intentionally excludes API keys, webhook signing secrets and delivery history; keep the actual SQLite database backed up separately when you need a disaster-recovery snapshot.

### Multiple webhook destinations with independent group selections

The existing `PUT /api/settings/webhook`, `POST /api/settings/webhook/test` and `POST /api/settings/webhook/rotate-secret` continue working exactly as before as the **Default** (all-sites) webhook. In addition, the dashboard shows **Additional group-specific webhooks**.

| Method | Path | Description |
|---|---|---|
| POST | `/api/settings/webhooks` | Create an additional destination; displays its signing secret once |
| PUT | `/api/settings/webhooks/{id}` | Rename, enable/disable, change URL, events, groups, or transport options |
| DELETE | `/api/settings/webhooks/{id}` | Remove destination; queued pending deliveries for that destination are cancelled |
| POST | `/api/settings/webhooks/{id}/test` | Queue signed test delivery for that destination |
| POST | `/api/settings/webhooks/{id}/rotate-secret` | Rotate signing secret, cancel pending sends; displays new secret once |
| GET | `/api/settings` | Existing settings response now includes `targets[]` (non-secret additional destinations), and delivery records have `target_id` (`null` means Default) |

Create example:

```http
POST /api/settings/webhooks
Content-Type: application/json

{
  "name": "Production monitoring",
  "enabled": true,
  "url": "http://127.0.0.1:8888/webhook",
  "events": ["expiration_30", "certificate_renewed", "check_failed", "monitoring_stale_critical"],
  "group_ids": [2, 5],
  "allow_http": true,
  "allow_private": true,
  "allow_self_signed": false
}
```

`group_ids: []` means **ALL websites**. Otherwise the event is delivered only when the website belongs to at least one selected group. A website in two matched groups still generates **one delivery per webhook destination**. A destination may use its own HTTP/private/self-signed opt-in settings; all exceptions are **off by default**. Signature header `X-TLSWatch-Signature: sha256=<hex>` is generated from the **exact raw JSON POST body** using the destination-specific secret. Each queued event uses the existing 3-attempt retry policy. If the last selected group is deleted, the webhook is left with no matched groups and delivers to **no sites**, rather than silently becoming an ALL webhook. Edit it to select valid groups or explicitly clear its selection to opt into ALL.

The secret cannot be retrieved later via GET. Protect the SQLite database as it stores webhook signing secrets to sign outgoing requests. All webhook management operations use dashboard/local access; API-key clients remain strictly read-only.

---

# v4.4 — Monitoring agents and distributed certificate checks

All v4.3 monitoring GET, history, group, and webhook endpoints remain in place. The `agent_id` property on certificates is `null` for primary-local sites, or a numeric remote agent ID. The local dashboard inventory additionally includes `agent_name`. Agents generate the **same central certificate history, statuses, Needs Attention results and group webhooks** as locally checked sites.

## Read-only authenticated API

`GET /api/v1/agents` — requires the existing `X-API-Key`/Bearer monitoring API key. Lists agent `id`, `name`, `enabled`, `status` (`online`/`offline`/`disabled`), `last_seen_at`, `version`, and `site_count`. No tokens or pairing codes are returned.

## Dashboard administration API

These endpoints require dashboard administrative access. They do **not** accept read-only API keys:

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/agents` | List agents, heartbeat status and assigned website counts |
| `POST` | `/api/agents` | Create agent; JSON `{"name":"Branch A"}`; returns single-use `enrollment_code` and `expires_at` |
| `POST` | `/api/agents/{id}/pair` | Issue another single-use enrollment code valid 15 minutes |
| `PUT` | `/api/agents/{id}` | `{"enabled":false}` disables remote polling; `true` re-enables |
| `DELETE` | `/api/agents/{id}` | Delete an agent; its sites move to the primary |
| `PUT` | `/api/sites/{id}/agent` | `{"agent_id":3}` assigns agent 3; `{"agent_id":null}` assigns primary |
| `POST` | `/api/sites` | Existing request now optionally accepts `agent_id` (integer or null) |

Only the agent pairing flow discloses an enrollment code. No raw authentication token is returned from an admin listing.

## Agent-only protocol (not for general client applications)

These endpoints are intended solely for the Docker/Python agent. Agent bearer credentials are separate from the existing user API key and never authorize dashboard actions.

`POST /agent/v1/enroll`: JSON `{"enrollment_code":"tlsw-enroll-..."}`. If the one-time code is valid, returns `agent_id`, `agent_name`, and a new `agent_token`. The primary stores **only a SHA-256 hash** of the token. The token is returned only once and replaces any previous token assigned to the same agent.

`POST /agent/v1/poll`: Header `Authorization: Bearer tlsw-agent-...`; JSON `{"version":"4.4.0","capacity":3}`. Returns up to `capacity` due tasks with `site_id`, `hostname`, `port`, `url`, `lease`, and `lease_until` (UTC). A capacity of zero is allowed to send only a heartbeat. Tasks are atomically leased for four minutes and are only offered to the assigned, enabled agent.

`POST /agent/v1/result`: same Authorization header, with JSON:

```json
{
  "site_id": 42,
  "lease": "the-task-lease-token",
  "success": true,
  "certificate_pem": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\\n",
  "tls_verified": true,
  "verify_error": null
}
```

For failures: `{"site_id":42,"lease":"...","success":false,"error":"DNS lookup failed"}`. The primary rejects results from the wrong agent, an expired/replaced lease, paused/deleted sites or an old owner (`409`). It derives validity, issuer and expiration dates directly from PEM (not from agent-claimed dates), records certificate and check history, and schedules the next check at a randomized time the following local calendar day. Agent status/heartbeat is available from the dashboard and `/api/v1/agents`.

**Trust and security:** Use HTTPS between agent and primary in deployment (custom root CA supported on the agent). The agent will not follow HTTP redirects during authenticated requests. HTTP between agent and primary can only be enabled explicitly in the agent setup for isolated testing. Secure the setup UI and protect any reachable admin routes. Avoid logging or sharing enrollment codes/agent tokens.
