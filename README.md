# Square × UniFi Protect Integration

Link **Square POS transactions** to **UniFi Protect camera footage** — the same
experience UniFi Protect's native Shopify integration provides, for Square.

Every Square payment shows up in the integration's feed with its timestamp,
amount, card details, and a **thumbnail captured from the camera watching your
POS at the exact moment of the sale**. Clicking the thumbnail opens the UniFi
Protect timeline at that timestamp, so you can review the footage of any
transaction in one click.

## Features (parity with the Shopify ⇄ Protect integration, for Square)

- **Connect your Square account** — enter a Square access token (production or
  sandbox); the integration verifies it against the Square API before saving.
- **Connect your UniFi Protect console** — local-account credentials for your
  UniFi OS console (Dream Machine, NVR, etc.), verified on save.
- **Trigger Protect alarms for completed sales (optional)** — use a Protect API
  key and matching Alarm Manager webhook trigger ID to run notifications or
  Protect automations whenever Square marks a payment completed.
- **Choose the POS camera** — for each Square location, pick which Protect
  camera watches the register, with a live snapshot preview.
- **Transaction feed** — payments appear with timestamp, amount, card last-4,
  status, and a thumbnail pulled from the POS camera's recording at the
  transaction's timestamp.
- **Click through to footage** — clicking a thumbnail opens the UniFi Protect
  timeline for that camera at the moment of the transaction.
- **Real-time + backfill** — a Square webhook receiver ingests payments the
  moment they happen (HMAC-SHA256 signature verified), and a background poller
  backfills/refreshes via the Square Payments API.

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/uvicorn app.main:app --factory --host 0.0.0.0 --port 8000
```

Open `http://<host>:8000`, then:

1. **Create the admin password** (first run only).
2. **Settings → UniFi Protect console** — host/IP of your console plus a local
   Protect user's credentials (a dedicated view-only local user is recommended).
   To trigger an alarm for completed sales, also create a key under UniFi Site
   Manager → Settings → API Keys and enter it with the ID of a matching Alarm
   Manager webhook trigger. The key is verified against Protect's official local
   integration API before it is saved. Leave alarm fields blank to retain saved
   values, or use the disable button to remove them locally even when the
   Protect console is unavailable.
3. **Settings → Square account** — a Square access token
   (Developer Dashboard → your application → Credentials). Optionally add your
   webhook signature key and notification URL for real-time ingestion
   (subscribe the webhook to `payment.updated` pointing at
   `https://<your-host>/webhooks/square`).
4. **Settings → POS camera** — pick the camera that watches each location's
   register.
5. Open **Transactions** — press *Sync now* for an immediate backfill; the
   poller (`SPI_POLL_INTERVAL`, default 60 s) keeps it current thereafter.

## Configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `SPI_DATA_DIR` | `./data` | SQLite DB, encryption key, thumbnails |
| `SPI_POLL_INTERVAL` | `60` | Seconds between Square polls |
| `SPI_DISABLE_POLLER` | `0` | Set `1` to disable background polling |
| `SPI_COOKIE_SECURE` | `0` | Set `1` when serving over HTTPS |
| `SPI_ENCRYPTION_KEY` | — | Fernet key overriding the on-disk key file |

The deep-link URL format can be adjusted for your Protect version by setting
the `deep_link_template` key in the settings table; the default is
`https://{host}/protect/timeline/{camera_id}?ts={ts_ms}`.

> **Note on historical thumbnails:** recent UniFi Protect versions serve a
> recorded frame when the snapshot endpoint is called with a `ts` parameter;
> older versions ignore it and return a live frame. Webhook-ingested
> transactions are captured within seconds of the sale either way.

> **Alarm delivery semantics:** each completed transaction is atomically claimed
> and marked delivered after Protect accepts the trigger. Failed requests are
> released for retry by the next poll or duplicate webhook. On startup and retry
> scans, expired in-progress claims are also released. If a request times out or the
> process crashes after Protect accepts a trigger but before delivery state is
> saved, that sale can trigger the alarm again; the Protect endpoint does not
> provide an idempotency key. Completed sales already stored when alarms are first
> enabled are marked handled rather than replayed as a historical burst.

## Security

- **Secrets encrypted at rest** — the Square access token, webhook signature
  key, Protect password, and Protect API key are Fernet-encrypted in SQLite;
  the key file is created `0600`.
- **Admin password** hashed with scrypt; login is throttled after repeated
  failures; sessions are random 256-bit tokens in `HttpOnly`/`SameSite` cookies.
- **Webhooks verified** — Square's `x-square-hmacsha256-signature` is checked
  with a constant-time comparison; unsigned or forged deliveries are rejected,
  and the endpoint is disabled until a signature key is configured.
- **Input validation** — Protect host and camera ids are strictly validated
  (no URL/path injection), thumbnail serving is confined to the thumbnail
  directory, and the frontend renders all server data as text, never markup.

Serve the integration over HTTPS (reverse proxy) and set `SPI_COOKIE_SECURE=1`
in production. The webhook endpoint is the only route that must be reachable
from the internet; everything else can stay LAN-only.

## Development

```bash
.venv/bin/python -m pytest
```

Tests run against mocked Square and UniFi Protect APIs — no hardware or Square
account needed.

## License

MIT — see [LICENSE](LICENSE).
