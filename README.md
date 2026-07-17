# Square × UniFi Protect Integration

This standalone companion app links **Square POS transactions** to **UniFi
Protect camera footage**. It approximates the transaction-to-video workflow of
UniFi Protect's native Shopify integration, but it does not install a Square
settings page or transaction feed inside the Protect application.

Every Square payment shows up in the companion feed with its timestamp, amount,
card details, and a thumbnail requested from the camera watching the POS.
Clicking the thumbnail uses a version-dependent deep link to open the Protect
timeline near that timestamp.

## Implemented companion features

- **Connect your Square account** — enter a Square access token in the companion
  app (production or sandbox); the integration verifies it against the Square
  API before saving.
- **Connect your UniFi Protect console** — local-account credentials for your
  UniFi OS console (Dream Machine, NVR, etc.), verified on save.
- **Choose the POS camera per register** — map each observed Square POS device
  to its own Protect camera, with per-location fallbacks and a live snapshot
  preview. Multi-register stores get the right footage for each terminal.
- **Trigger Protect alarms for completed sales (optional)** — use a Protect API
  key and matching Alarm Manager webhook trigger ID to run notifications or
  Protect automations whenever Square marks a payment completed. Delivery is
  at-least-once with durable state; sales completed before the feature is
  enabled are never replayed.
- **Transaction feed** — payments appear in the companion app with timestamp,
  tip-inclusive amount, card last-4, status, and a camera thumbnail; the feed
  auto-refreshes while visible.
- **Click through to footage** — clicking a thumbnail uses the configured URL
  template to open the Protect timeline near the transaction timestamp.
- **Real-time + backfill** — a Square webhook receiver acknowledges deliveries
  immediately (HMAC-SHA256 signature verified) and captures footage
  asynchronously, while a background poller reconciles every Square location
  by update time. Missed thumbnails persist in a durable retry queue with
  backoff, so a Protect outage never permanently loses evidence.

## Protect integration boundary

As of July 2026, the [documented UniFi Protect API](https://developer.ui.com/protect)
does not expose a way for third-party applications to add a retail transaction
feed or credential screen inside Protect. Native Shopify-style placement would
therefore require a separate Ubiquiti partner/private integration contract.
Square credentials and transactions in this repository live in the companion
web app. The sale-alarm feature uses the official integration API
(`X-API-Key` + Alarm Manager webhook triggers) and is the supported way to
surface sale events inside Protect itself.

The repository's local-account login, recording-snapshot query, and playback
deep link are undocumented Protect interfaces. They have been verified against
a UNVR G2 on Protect 7.1.87 (a dedicated view-only local account is
sufficient for all of them), but they can change across Protect releases —
re-verify after major console updates. The default deep link matches the
URL Protect's own event links use on that version:
`https://{host}/protect/timelapse/{camera_id}?start={ts_ms}`.

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
   `https://<your-host>/webhooks/square`). Existing installations must reconnect
   Square once after upgrading so webhook events can be bound to that merchant.
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
the `deep_link_template` key in the settings table; the default (verified on
Protect 7.1.87) is
`https://{host}/protect/timelapse/{camera_id}?start={ts_ms}`.

> **Note on historical thumbnails:** verified against a UNVR G2 running
> Protect 7.1.87 — historical frames come from the `recording-snapshot`
> endpoint (the live `snapshot` endpoint silently ignores `ts` on this
> firmware). Recorded frames become available roughly ten seconds behind
> live; a sale ingested in real time gets its thumbnail on the first retry
> pass rather than a wrong-time live frame. On older firmware without
> `recording-snapshot`, the integration falls back to the legacy `snapshot?ts`
> query, which some of those versions honored.

> **Alarm delivery semantics:** each completed transaction is atomically claimed
> and marked delivered after Protect accepts the trigger. Failed requests are
> released for retry by a later poll or duplicate webhook. On startup and retry
> scans, expired in-progress claims are also released. If a request times out or the
> process crashes after Protect accepts a trigger but before delivery state is
> saved, that sale can trigger the alarm again; the Protect endpoint does not
> provide an idempotency key. Completed sales already stored when alarms are first
> enabled, plus sales imported later whose transaction time predates activation,
> are marked handled rather than replayed as a historical burst. Automatic retry
> uses the Square poller; when `SPI_DISABLE_POLLER=1`, pending deliveries require
> a duplicate webhook or manual **Sync now**.

## Security

- **Secrets encrypted at rest** — the Square access token, webhook signature
  key, Protect password, and Protect API key are Fernet-encrypted in SQLite;
  the key file is created `0600`.
- **Admin password** hashed with scrypt; login is throttled after repeated
  failures; sessions are random 256-bit tokens in `HttpOnly`/`SameSite` cookies.
- **Webhooks verified** — Square's `x-square-hmacsha256-signature` is checked
  with a constant-time comparison; unsigned or forged deliveries are rejected,
  request bodies are capped at 1 MiB, and the endpoint is disabled until a
  signature key is configured.
- **Input validation** — Protect host and camera ids are strictly validated
  (no URL/path injection), thumbnail serving is confined to the thumbnail
  directory, and the frontend renders all server data as text, never markup.
- **Protect TLS** — certificate verification is off by default for local
  self-signed consoles. Install/trust the console certificate and enable
  **Verify TLS certificate** whenever possible; otherwise local credentials
  and the Protect API key rely on the LAN being trusted.

Serve the integration over HTTPS (reverse proxy) and set `SPI_COOKIE_SECURE=1`
in production. The webhook endpoint is the only route that must be reachable
from the internet; everything else can stay LAN-only.

## Development

```bash
.venv/bin/python -m pytest        # functional + security tests
```

Tests run against mocked Square and UniFi Protect APIs. Passing tests do not
validate firmware-specific snapshot or timeline behavior on real hardware.

## License

MIT — see [LICENSE](LICENSE).
