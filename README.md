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
- **Choose the POS camera** — for each Square location, pick which Protect
  camera watches the register, with a live snapshot preview.
- **Transaction feed** — payments appear in the companion app with timestamp,
  amount, card last-4, status, and a camera thumbnail.
- **Click through to footage** — clicking a thumbnail uses the configured URL
  template to open the Protect timeline near the transaction timestamp.
- **Real-time + backfill** — a Square webhook receiver ingests payments the
  moment they happen (HMAC-SHA256 signature verified), and a background poller
  backfills/refreshes via the Square Payments API.

## Protect integration boundary

As of July 2026, the [documented UniFi Protect API](https://developer.ui.com/protect)
does not expose a way for third-party applications to add a retail transaction
feed or credential screen inside Protect. Native Shopify-style placement would
therefore require a separate Ubiquiti partner/private integration contract.
Square credentials and transactions in this repository live in the companion
web app.

The repository's local-account login, historical `ts` snapshot query, and
timeline URL are legacy/undocumented Protect interfaces. They can change across
Protect releases and must be tested against the target console and firmware.

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/uvicorn app.main:app --factory --host 0.0.0.0 --port 8000
```

Open `http://<host>:8000`, then:

1. **Create the admin password** (first run only).
2. **Settings → UniFi Protect console** — host/IP of your console plus a local
   Protect user's credentials (a dedicated view-only local user is recommended).
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

> **Note on historical thumbnails:** the documented snapshot API does not
> include a timestamp parameter. A console may ignore the legacy `ts` query and
> return a live frame. Verify thumbnail timing and the deep link on real target
> hardware before relying on either as transaction evidence.

## Security

- **Secrets encrypted at rest** — the Square access token, webhook signature
  key, and Protect password are Fernet-encrypted in SQLite; the key file is
  created `0600`.
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
.venv/bin/python -m pytest        # 91 functional + security tests
```

Tests run against mocked Square and UniFi Protect APIs. Passing tests do not
validate firmware-specific snapshot or timeline behavior on real hardware.

## License

MIT — see [LICENSE](LICENSE).
