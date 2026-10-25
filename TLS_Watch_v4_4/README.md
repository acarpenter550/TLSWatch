# TLS Watch v4.3 — Flask certificate monitoring with API & webhooks

**Python 3.11+ · Flask · SQLite · no Docker required.** This version is an in-place update of the **v4.2** certificate monitor. It retains the certificate details viewer, daily randomized checks, persistent site list, pause/delete controls, CSV export, and the corrected Healthy Certificates count.

## Windows installation / upgrade

1. If TLS Watch is currently running, stop it using `Ctrl+C`.
2. Extract the ZIP contents into your existing `F:\Code\TLS_Watch_Flask\` directory, replacing files. **Do not delete `.venv` or `data/`.** The site's database and certificate history stay in `data/certificates.sqlite3`.
3. Double-click `START_TLS_WATCH.bat` to run. If this is a new install, the batch file creates a virtual environment and installs requirements. If an existing `.venv` already works, it will reuse it.
4. Open <http://127.0.0.1:8080/>. The **Live Inventory** now has group tabs (beginning with **ALL**), a **+ New group** button, and a **This Group / All Websites** search-scope selector. Expand **API access & outbound webhooks** for integration settings.
5. Leave the Python window open for periodic certificate checks and scheduled webhook sends. Closing the browser does not stop the service.

For manual startup, activate your Python venv, `python -m pip install -r requirements.txt`, then `python app.py`.

## New in v4.3: history, bulk inventory import/export, multi-destination webhooks and stale monitoring

**These changes build on v4.2 without replacing your existing database, API key, website list, groups, or configured default webhook.** The migration runs automatically when you restart TLS Watch. Take a backup of `data/certificates.sqlite3` before upgrading.

- **Certificate history:** Each different observed leaf certificate is retained (issuer, issue/expiration, first/last observed and original PEM). Select **History** in a website's Actions column to compare historical versions and download past PEMs. A renewal can generate `certificate_renewed`, `certificate_issuer_changed`, or `certificate_expiration_shortened` events. On startup, v4.3 captures the most recent v4.2 certificate as the first historical snapshot; older versions that v4.2 did not store cannot be reconstructed.
- **Check history:** Saves each successful/failed TLS attempt including timestamp, trust verification and errors. The 1,000 most recent checks per website are retained. This begins when v4.3 is installed; earlier individual checks are not recoverable.
- **Bulk import/backup:** Use **Import CSV/JSON** or export **Inventory CSV** / **Backup JSON** from the Live Inventory panel. CSV header: `URL,Groups,Paused`; separate multiple groups with semicolons. JSON uses `{"groups":["Production"], "websites":[{"url":"https://example.com","paused":false,"groups":["Production"]}]}`. Import creates new groups/sites, merges imported memberships into existing sites, applies the imported paused state and preserves existing certificate/history records. Export deliberately **excludes credentials and private secrets**.
- **Multiple webhook destinations:** The existing webhook stays the **Default webhook** for all sites, unchanged. Under **Additional group-specific webhooks** add/edit/delete independent destinations, each with its own URL, events, signing secret, TLS transport exceptions, and optional group selections. No groups selected means ALL. Each event is sent once per matching destination; multiple memberships do not duplicate delivery. A deleted group's scoped webhook **fails closed** rather than reverting to ALL.
- **Stale monitoring detection:** An active website without a successful **certificate retrieval** for more than 24h is flagged WARNING; more than 48h is CRITICAL. Paused sites are excluded. Stale sites enter **Needs Attention** independently of certificate expiry and appear on the API with `stale_status` and `last_successful_at`. Two new webhook events are `monitoring_stale_warning` and `monitoring_stale_critical`. The configured daily randomized scheduler sometimes produces intervals longer than 24 hours even when working correctly, so a 24h stale warning alone is not proof of a system failure.
- **Read-only API:** `GET /api/v1/certificates/{siteId}/history` and scoped `GET /api/v1/groups/{groupId}/certificates/{siteId}/history`; `/api/v1/summary` adds `stale_warning` and `stale_critical` counters. Existing group/expiry queries continue working.
- **Private certificate targets remain ON by default** (`ALLOW_PRIVATE_TARGETS=true`). The outbound webhook HTTP/private/self-signed exceptions remain independent and disabled by default per destination.

See [`api.md`](api.md) and [`TLS_Watch_v4_3.postman_collection.json`](TLS_Watch_v4_3.postman_collection.json) for the complete API and webhook reference.

## New in v4.2: persistent inventory groups

- **ALL** is the permanent first tab, containing every monitored website; it cannot be renamed or deleted.
- Click **+ New group**, enter a name, then check any websites from the **entire ALL inventory**. A site may belong to **multiple groups** simultaneously (e.g. `Production`, `Customer A`, and `Renewals`). Group assignments are stored in the existing SQLite database.
- On any group tab, click **Edit group** to rename it, select/deselect any websites, or delete the group. Deleting a **group never deletes the websites** or alters their certificate check schedules.
- In the **Actions** column, click the new grid/groups icon on a website to add/remove membership in **multiple groups** at once.
- The search-scope selector beside the search field provides **All Websites** and **This Group**. Choosing a group tab defaults the scope to **This Group**, but you can choose All Websites without changing the current tab. The separate status filter still offers active, paused, and Needs Attention.
- Adding a new URL while viewing a group automatically assigns that new URL to the visible group. The website still appears in ALL, and automatic certificate checks are shared across groups.
- Group membership does not change the global dashboard counters or duplicate automatic checks. In v4.3, group membership **does** determine which additional group-scoped webhooks can receive events.

### Group-aware API

All existing `/api/v1/...` GET endpoints keep working and now accept `?group=<id>` (or the group name, case-insensitively). The group listing reports stable numeric IDs and per-group site counts. A missing/deleted group returns HTTP **404**, rather than silently defaulting to ALL.

```http
GET /api/v1/groups
GET /api/v1/summary?group=2
GET /api/v1/certificates?group=2&range=0-30
GET /api/v1/certificates/expiring?group=2&within=60
GET /api/v1/certificates/needs-attention?group=2
GET /api/v1/certificates/123?group=2
```

There are also equivalent group-scoped paths, e.g. `GET /api/v1/groups/2/certificates?range=90%2B` and `GET /api/v1/groups/2/certificates/needs-attention`. Group API requests require the **same read-only API key**, and return only the same certificates as the equivalent all-sites API intersected with the group's membership. The Postman collection includes the new requests and a `groupId` variable. See [api.md](api.md).

**Security change:** Monitored private/internal HTTPS targets are **enabled by default** (`ALLOW_PRIVATE_TARGETS=true`). Only run TLS Watch in trusted environments; allowing private targets increases the reach of server-initiated network connections. Outbound webhook HTTP/private/self-signed allowances remain separate opt-ins and are unchanged.

### API key (read-only)

Open the integrations accordion and click **Generate / rotate API key**. Copy the key when shown: TLS Watch stores **only its SHA-256 hash**, and the actual key is not retrievable later. Rotating immediately invalidates the previous key; **Revoke** disables remote queries. The key permits **GET only** on `/api/v1/...` routes. It cannot edit websites, settings, or webhook configuration.

Supply either HTTP header:

```http
X-API-Key: tlsw_PASTE_YOUR_KEY
```

or:

```http
Authorization: Bearer tlsw_PASTE_YOUR_KEY
```

#### API endpoints

| Method and path | Result |
|---|---|
| `GET /api/v1/summary` | Summary counters: total, healthy (>90 days), expiring ≤60, needs attention |
| `GET /api/v1/certificates` | All certificate/site records |
| `GET /api/v1/certificates?range=expired` | Certificates that have expired (`days_left < 0`) |
| `GET /api/v1/certificates?range=0-30` | 0–30 days remaining |
| `GET /api/v1/certificates?range=31-60` | 31–60 days remaining |
| `GET /api/v1/certificates?range=61-90` | 61–90 days remaining |
| `GET /api/v1/certificates?range=90%2B` | More than 90 days remaining (green/healthy) |
| `GET /api/v1/certificates/expiring?within=30` | All certificates with `days_left ≤ 30`, including expired |
| `GET /api/v1/certificates/expiring?within=60` | All certificates with `days_left ≤ 60`, including expired |
| `GET /api/v1/certificates/expiring?within=90` | All certificates with `days_left ≤ 90`, including expired |
| `GET /api/v1/certificates/needs-attention` | Sites with **check failure**, **TLS trust/hostname verification failure**, **≤30 days** remaining, or **>24 hours without a successful certificate retrieval** |
| `GET /api/v1/certificates/123` | Certificate/site record by database ID |

**Healthy and Needs Attention can overlap**, exactly as in the dashboard: e.g., a certificate expiring in 150 days but failing trust verification is counted as healthy by **expiration** and also needs attention for **validation**.

Day ranges use **days remaining at the last check**, not a constantly recalculated countdown. Records expose issuer, issued/expiry dates, days remaining, check timestamps, paused status, TLS validation and latest errors. PEM and secrets are **not** returned by these endpoints.

Windows PowerShell example:

```powershell
$headers = @{ 'X-API-Key' = 'tlsw_PASTE_YOUR_KEY' }
Invoke-RestMethod -Headers $headers -Uri 'http://127.0.0.1:8080/api/v1/certificates/needs-attention'
Invoke-RestMethod -Headers $headers -Uri 'http://127.0.0.1:8080/api/v1/certificates?range=90%2B'
```

The `90+` filter is URL-encoded `%2B` above; the API also accepts a literal plus sign as a convenience.

### Outbound webhooks

Expand the same integrations accordion:

1. Enter a webhook URL (HTTPS by default, or HTTP for local testing). For the included standalone **TLS Webhook Viewer** on the same PC, use `http://127.0.0.1:8888/webhook`.
2. Local HTTP: check **Allow HTTP destinations** and **Allow localhost and private network addresses**. Self-signed HTTPS: check **Accept self-signed / untrusted HTTPS certificates**. All three opt-ins default to off and apply only to outbound webhooks.
3. Select which events should be sent; set **Enable webhook delivery**.
4. Click **Save webhook**. On the first save, TLS Watch generates an HMAC signing secret and displays it **once**. Copy it to the receiving service. You can rotate the signing secret, which invalidates the previous one.
5. Click **Send test** and examine **Recent webhook deliveries**. A test event is delivered even if the `test` type is not selected in your event preferences.

Webhook triggers (checkboxes):

| Event name | When it occurs |
|---|---|
| `expiration_90` | Observed crossing to ≤90 days |
| `expiration_60` | Observed crossing to ≤60 days |
| `expiration_30` | Observed crossing to ≤30 days |
| `certificate_expired` | Observed crossing from unexpired to expired |
| `tls_invalid` | Trust/hostname validation first fails |
| `check_failed` | First failure after a working/unknown check |
| `recovered` | Prior failed/untrusted check succeeds and validates |
| `certificate_changed` | Leaf certificate PEM differs from the previously captured certificate |
| `needs_attention` | Site newly enters Needs Attention state (including stale >24h) |
| `attention_cleared` | Site leaves Needs Attention (valid TLS, no check error, and >30 days) |

Events are **transition-based**, rather than sent every day for the same condition. On an initial observation, only the most urgent applicable expiration threshold is emitted. If multiple thresholds are crossed between subsequent checks, each crossed threshold is emitted (according to selected event types). Failures that prevent retrieval of a new certificate preserve the previously observed certificate.

Every webhook is a JSON `POST` with headers:

```http
Content-Type: application/json
X-TLSWatch-Event: expiration_30
X-TLSWatch-Delivery: <unique-event-id>
X-TLSWatch-Timestamp: 2026-10-24T12:00:00Z
X-TLSWatch-Signature: sha256=<64-character-hex-digest>
```

Example body:

```json
{
  "event_id": "849c4a7c-8d7e-49e0-9160-ef0c2ac8a5b9",
  "event": "expiration_30",
  "occurred_at": "2026-10-24T12:00:00Z",
  "site": {
    "id": 3,
    "url": "https://example.com",
    "hostname": "example.com",
    "port": 443,
    "issuer": "Example CA",
    "issued_at": "2026-08-01T00:00:00Z",
    "expires_at": "2026-11-15T00:00:00Z",
    "days_left": 22,
    "last_checked_at": "2026-10-24T12:00:00Z",
    "tls_verified": true,
    "needs_attention": true
  },
  "previous": {"days_left": 31, "last_error": null, "tls_verified": true}
}
```

The actual `site` object also includes the other standard certificate fields. Verify the signature by computing **HMAC-SHA256(signing_secret, exact UTF-8 request body bytes)** and comparing to the hex digest after `sha256=` with a constant-time comparison. Keep delivery IDs to ignore duplicates. The event ID is stable across retries.

Delivery details:

- The event payload and delivery state are stored in SQLite, surviving Python restarts.
- Delivery is attempted automatically by the in-process scheduler (about every 10 seconds).
- A successful delivery requires HTTP **2xx**. Other responses / TLS / network errors are retried twice (after about 1 minute and then 5 minutes); after three attempts it is marked failed.
- Failed attempts appear in **Recent webhook deliveries** with the error. Sending to a new URL or disabling webhooks cancels pending deliveries to the former destination. Delivery history is retained.
- Outbound URLs default to **HTTPS, public addresses, and standard CA/hostname verification**. HTTP, private/localhost destinations, and self-signed/untrusted HTTPS certificates each require a separate explicit opt-in. Redirects are never followed and target IPs are vetted and pinned. Self-signed mode disables outbound webhook TLS identity checks; HTTP transmits payloads in cleartext.
- These webhook transport settings are **independent** of `ALLOW_PRIVATE_TARGETS`, which still controls monitored HTTPS certificate sites only.
- A rotated signing secret or target URL can invalidate already-in-progress requests; rotate receiver secrets carefully.

### Postman collection (ready to import)

The package includes **[`TLS_Watch_v4.postman_collection.json`](TLS_Watch_v4.postman_collection.json)**, a Postman Collection v2.1 with every read-only API endpoint (including 30/60/90-day expiration filters and **Needs Attention**) and an **optional** folder for local administrative requests and webhook testing.

1. In Postman select **Import → Files** and choose `TLS_Watch_v4.postman_collection.json`.
2. In the imported collection's **Variables**, keep `baseUrl` as `http://127.0.0.1:8080` for checks on this PC, or change to your secure HTTPS endpoint for remote access.
3. Copy the API key generated in the dashboard into the `apiKey` variable. Set `siteId` from a record returned by **All certificates**.
4. Run the requests in **Read-only monitoring API — X-API-Key**. The `90+` request already URL-encodes its plus sign as `%2B`.
5. **Optional admin folder**: only for local/dashboard-authorized access; it does *not* accept the API key. Fill `adminUsername` / `adminPassword` if dashboard Basic authentication is configured, and `webhookUrl` for webhook requests. Avoid invoking the destructive **Revoke** or **Rotate** operations unintentionally.

The collection intentionally ships with **no active API keys, usernames, passwords, or webhook signing secrets**. Keep those values private when sharing or exporting Postman collections.

**Detailed API and webhook specification:** See [`api.md`](api.md) for the Postman setup, request/response schemas, filter boundaries, HMAC validation examples, event semantics, retry behavior, and remote-access guidance.

## Network and security

By default TLS Watch binds **only** to `127.0.0.1:8080`. API keys authenticate `/api/v1` but cannot make the service reachable over the network by themselves. For remote use, configure a trusted reverse proxy providing **HTTPS** and firewall rules; the reverse proxy can forward to `127.0.0.1:8080`. The built-in Flask development server should **not** be published directly to the Internet.

If using the application from another PC on your LAN, set `APP_USERNAME` and `APP_PASSWORD` and use a proper HTTPS reverse proxy and production WSGI hosting. When no UI credentials are configured, **non-local dashboard/admin requests are denied**; the read-only v1 API continues to accept valid API keys remotely, subject to your network routing and firewall. Do not send Basic credentials or API keys over plain public HTTP.

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `BIND_HOST` | `127.0.0.1` | Listen address (keep loopback behind a proxy) |
| `APP_USERNAME` / `APP_PASSWORD` | unset | Optional HTTP Basic credentials for dashboard/admin |
| `APP_TIMEZONE` | `America/New_York` | Timezone for per-site randomized checks |
| `DB_PATH` | `data/certificates.sqlite3` | Database path (also stores API-key hash and webhook settings/events) |
| `TLS_TIMEOUT_SECONDS` | `7` | TLS connection timeout |
| `MAX_CHECK_WORKERS` | `6` | Max concurrent certificate checks |
| `ALLOW_PRIVATE_TARGETS` | `true` | Allow internal monitored HTTPS sites; webhook options are configured separately in the UI |

Keep **one Python process** running. Each active site gets its first certificate check when added, then a new independently randomized time on the following local calendar day; overdue checks run after restart. Paused sites skip scheduled checks. The browser can be closed without stopping the server.

## Validation

Run automated tests once Flask is installed:

```bash
python -m pip install pytest
python -m pytest -q
```

The pure helper tests also exercise signed webhook POST delivery against a local TLS listener, URL validation, thresholds, and event deduplication. The existing certificate-monitoring suite and JavaScript dashboard count tests are included.

## TLS Watch v4.3 local HTTP webhook test

Run the separate `TLS_Webhook_Viewer` Flask app on `127.0.0.1:8888`. In TLS Watch, save:

- URL: `http://127.0.0.1:8888/webhook`
- **Allow HTTP destinations:** ON
- **Allow localhost and private network addresses:** ON
- **Accept self-signed / untrusted HTTPS certificates:** OFF (not needed for HTTP)

Then click **Send test** and open `http://127.0.0.1:8888/`. The full API and transport documentation is in `api.md`.

---

# TLS Watch v4.4 — Distributed Remote Agents

v4.4 extends the existing Python/Flask primary with **outbound-only remote agents**. The central primary continues to own the SQLite database, website groups, randomized daily schedule, X.509 history, GET APIs, webhooks, and alerts. Sites are monitored once per day, **from the chosen execution location**.

## How remote checks work

- A remote agent makes **outbound** HTTPS requests to the primary; it needs no inbound network exposure on the branch/customer LAN.
- The primary authenticates each agent with a separate, randomly generated bearer token. Pairing uses a one-time code valid for 15 minutes. Agents do **not** receive the primary API key or webhook secrets.
- An agent polls approximately every 15 seconds for due work, makes the TLS connection **from its own LAN**, and sends the observed PEM and verification status back to the primary.
- The primary parses certificate issuer/validity from the returned PEM, calculates days remaining, records check/certificate history and triggers existing event webhooks.
- Leases prevent concurrent delivery; failed or interrupted tasks are retried after a four-minute lease timeout. Late or duplicate results are rejected. If an agent is offline, assigned websites remain pending; the primary will *not* silently check them from another network.
- Reassign a website to `Primary server (local)` from its new Actions > monitoring agent button to run checks on the primary again.

## Primary installation (Windows/Python; no Docker needed)

Update the primary exactly as prior versions: stop it, **back up `data/certificates.sqlite3`**, extract these files over your existing TLS Watch directory, **preserve `data/` and `.venv/`**, then run `START_TLS_WATCH.bat`. Open `http://localhost:8080`.

Open **Monitoring agents**, expand the accordion, choose a descriptive name (e.g. `Branch-A`), click **Create & generate pairing code**, and copy the code shown. To add websites, select the remote agent from **Check using**. For an existing website, click the new **monitoring agent** icon under Actions.

v4.4 retains `ALLOW_PRIVATE_TARGETS=true` by default, and retains all v4.3 feature behavior for centrally monitored sites.

## Remote installation (Docker)

Copy the **agent/** folder to the machine on the other LAN and run:

```sh
cd agent
docker compose up -d --build
```

Open **http://localhost:8899** *on the Docker host*. The Compose file binds the setup UI to **127.0.0.1 only**, to prevent external users from taking control of it. Enter:

- **Primary URL**: The primary's externally reachable HTTPS origin, e.g. `https://tlswatch.example.net` (not `localhost:8080` unless the container itself hosts the primary).
- **One-time pairing code**: The code created in the primary UI.
- **Optional custom primary CA**: Paste the signing CA PEM if your *primary's HTTPS endpoint* uses a private PKI. HTTPS verification remains on. For a trusted test lab only, HTTP can be explicitly enabled.

Click **Connect to primary**. Within 15–30 seconds its status should show ONLINE at the primary. An assigned site receives its first check almost immediately, assuming the remote LAN can resolve and reach it.

### Connectivity and security

The **remote agent must reach the primary's HTTPS URL** through an authenticated VPN/reverse proxy, a private routed network, or a securely published HTTPS service. Do **not** expose Flask's development server directly to the Internet. A TLS-terminating reverse proxy should forward `/agent/v1/` to the Flask app and pass its `Authorization: Bearer ...` header without replacing it. Other dashboard routes should remain restricted or protected with `APP_USERNAME` + `APP_PASSWORD`.

The agent connects to internal hosts on their configured TLS ports using the **agent container's DNS/network**. A hostname like `192.168.1.20` works when the agent can route to that address; `127.0.0.1` inside Docker refers to the **container**, not the Docker host. The certificate is validated against the hostname entered in TLS Watch; self-signed/untrusted server certificates can still be inspected but are flagged as untrusted (the agent does not globally disable their verification).

The agent saves its pairing token in a Docker-managed persistent volume (`tlswatch-agent-data`), with file permissions 0600 where supported. Back up the primary SQLite database separately. Do not publish the agent's setup UI beyond localhost without adding authentication. Agent token revocation: **Disable** or **Delete** the agent from the primary; reconnecting requires a fresh pairing code. The primary list marks agents offline after ~90 seconds without a heartbeat.

Note: To deploy the agent on a Linux/Windows host **without** Docker, install Flask and run `python agent.py` with `AGENT_DATA_DIR` set to a writable directory. Its UI listens on 8899; protect/bind its exposure appropriately.

## Testing and deployment notes

Use `python -m pytest tests/test_agents.py -q` in the primary's Python environment to test pairing, authorization, leased tasks, certificate/result storage, and reassignment. Existing test files remain included. This is a single-primary-process SQLite design; keep `use_reloader=False` and do not run multiple scheduler-enabled Flask workers against the same database.

**Backup scope note:** JSON/CSV inventory exports now include the *name* of each assigned monitoring agent for reference. They intentionally do not include agent bearer credentials or pairing codes. Importing a backup does not automatically re-pair agents or reassign websites to potentially unrelated agents on a different primary; create/pair agents and assign sites in the dashboard after restore.
