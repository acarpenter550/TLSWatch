# TLS Watch v4.4 — Remote LAN Agent (Docker)

This lightweight Flask/Docker service polls a central TLS Watch v4.4 primary over HTTPS and checks the certificates of assigned internal HTTPS targets from its **own LAN**. It does not require inbound connectivity from the primary.

## Install

```bash
docker compose up -d --build
```

Open `http://localhost:8899` **on the Docker host**, then paste the **Primary HTTPS URL** and the **single-use pairing code** generated in the primary's **Monitoring agents** accordion. Pairing codes expire after 15 minutes. A CA certificate can be pasted when the primary's HTTPS endpoint is signed by your private PKI; this is safer than skipping TLS verification. HTTP is disabled unless explicitly enabled for isolated lab testing.

The primary must be reachable from the agent's Docker container (over VPN, private network, or properly protected HTTPS reverse proxy). Avoid using `127.0.0.1` as the primary URL: localhost inside Docker points to the agent itself. There is no need to forward the agent's port 8899 from the Internet.

The agent polls approximately every 15 seconds. Its current status, last contact time and most recent check are displayed on the local setup page. The agent credential is persisted in the named `tlswatch-agent-data` volume. Disable or delete the agent from the primary to revoke access; disconnecting only removes the local copy of credentials.

## Optional configuration

Change the environment variables in `compose.yaml`: `POLL_SECONDS` (5–60), `AGENT_WORKERS` (1–4), and `TLS_TIMEOUT_SECONDS` (3–30). The setup UI is bound to the Docker host's `127.0.0.1:8899` for security. Do not publish it to the network without suitable authentication.

### Troubleshooting

```bash
docker compose logs -f tls-watch-agent
```

If the status shows connection errors, verify routing/DNS **from inside the container** and that your proxy forwards `/agent/v1/*` and the agent's `Authorization: Bearer` header. The primary must be v4.4 or newer. Certificates from self-signed/private servers are still collected; TLS trust failures appear as Needs Attention in the primary. If the target name is `localhost`, the agent will probe its own container. Use a routable LAN hostname/IP instead.
