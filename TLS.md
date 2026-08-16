# Protect Event Delivery and TLS Trust

Status: architecture decision; current webhook root cause unconfirmed

This document separates four different concerns:

- receiving motion events from UniFi Protect;
- authenticating the Square Protect HTTPS listener;
- authenticating each motion event;
- signing and notarizing the macOS application.

Passing one trust check does not imply that another passed.

## Decision summary

1. The product target is an app-initiated subscription to Protect's official
   local event WebSocket. Each installation connects to its own NVR with its
   own API key and selected camera. This avoids an inbound motion listener,
   app-host DNS, and app-side certificate issuance.
2. Keep the existing custom webhook receiver as a compatibility fallback until
   the event stream has been validated against supported Protect versions and
   real motion events.
3. Do not make one shared hostname, certificate, private key, or relay endpoint
   a requirement for every installation.
4. Apple Developer ID signing and notarization remain release tasks. They do
   not establish network trust between Protect and the app.

The preferred event-stream design is not implemented yet. The current release
still receives motion through a Protect custom webhook.

## Delivery choices

| Mode | Connection direction | Per-install app DNS/certificate | Product role |
| --- | --- | --- | --- |
| Local Protect event stream | App to its own NVR | No | Recommended target after hardware validation |
| LAN HTTP webhook | NVR to app | No | Possible fallback only if supported firmware accepts an `http://` URL |
| LAN HTTPS webhook | NVR to app | Yes | Current secure fallback |
| Hosted relay | NVR to relay, relay to app | Relay owns public TLS | Optional future service, not required for local installs |

The local event stream scales naturally: ten stores create ten independent
connections to ten independently configured NVRs. No event is routed to a
particular developer machine or another customer's installation.

## What is known and what is not

Ubiquiti documents these relevant interfaces:

- Protect custom webhooks send GET or POST requests and GET actions support
  custom headers.
- Protect's local Integration API exposes
  `/proxy/protect/integration/v1/subscribe/events` as an authenticated WebSocket
  that broadcasts Protect events.
- The event WebSocket requires a direct local connection and is not supported
  through the UniFi Cloud Connector.

The existing opt-in provider tests do not make Protect send a webhook. They
verify camera discovery against a live console, then inject a request directly
into the app's in-process router. They therefore prove neither TLS success nor
TLS failure.

A generated self-signed certificate is not automatically trusted by an
unattended client. That makes certificate rejection a credible hypothesis, but
the absence of an HTTP receipt does not identify the failed layer. DNS,
routing, firewall rules, TCP reachability, TLS validation, method selection,
headers, token authentication, and payload handling are separate failure
points.

Therefore certificate validation must not be described as the confirmed root
cause without a Protect error or a controlled comparison that changes only the
certificate.

## Required root-cause test

Run this after the app host and NVR are on working routed networks:

1. Resolve the configured app hostname from the NVR's DNS environment.
2. Confirm that the NVR can reach the listener's exact address and port.
3. Observe bounded connection metadata at the app host:
   - no connection attempt points to alarm configuration, DNS, or routing;
   - TCP without a completed TLS handshake points to TLS or transport;
   - an HTTP rejection proves TLS completed and identifies the HTTP layer;
   - HTTP `204` plus a new ledger row proves end-to-end delivery.
4. Send a local request with the valid method and token, then an invalid token.
   The valid request must return `204`; the invalid request must reach HTTP and
   be rejected without logging the token.
5. Compare the generated certificate and a valid public-CA certificate on the
   same hostname, address, port, route, alarm, method, and header. A result that
   changes only with the certificate confirms the TLS hypothesis.

Do not log credentials, webhook tokens, raw headers, private keys, or complete
event bodies while diagnosing the connection.

## Recommended product design: local event subscription

Add a resilient client for:

```text
wss://<protect-host>/proxy/protect/integration/v1/subscribe/events
Accept: application/json
X-API-Key: <per-installation key>
```

Implementation requirements:

1. Reuse the installation's configured Protect host, certificate-verification
   policy, and narrowly scoped Integration API key. Never ship a shared key.
2. Filter events by the configured camera identifier and supported event type.
   Validate the exact event types and timestamps against real hardware before
   declaring a compatibility range.
3. Deduplicate by stable event identity and preserve the existing motion
   correlation and retention behavior.
4. Reconnect with bounded exponential backoff and jitter. Surface connected,
   reconnecting, authentication-failed, certificate-failed, and unsupported
   payload states without revealing secrets.
5. Treat malformed or unexpectedly large messages as untrusted input. Bound
   frame size, nesting, strings, and retained diagnostic metadata.
6. Record stream gaps so operators know when motion events may have been
   missed. Do not imply delivery completeness after a disconnect.
7. Keep the current webhook path available during migration. Prevent duplicate
   alerts when both sources report the same event.
8. Test reconnects, duplicate events, reordered updates, wrong-camera events,
   credential rotation, and shutdown behavior with synthetic fixtures.
9. Run an explicit hardware acceptance test for every documented Protect
   compatibility range.

This changes the app from an inbound server, for motion purposes, into a client
of the NVR already configured by the installer. The dashboard may still use
local HTTPS, and Square webhooks may still require an internet-reachable URL;
those are independent of Protect motion delivery.

## LAN HTTP fallback

Ubiquiti calls the actions HTTP GET and HTTP POST, but its public help article
does not explicitly guarantee that every supported Protect version accepts an
`http://` URL scheme. Test that behavior on each supported firmware line before
offering it in setup.

If supported, a dedicated LAN-only HTTP motion listener can remove certificate
management. It must not expose the admin UI or authenticated application APIs.
Use all of these controls:

- a separate listener or narrowly isolated route;
- a random per-installation webhook token;
- a firewall allowlist for the NVR address or VLAN;
- request-size, rate, method, and content-type limits;
- no cookies, setup routes, admin routes, or secret-bearing responses;
- a warning that the token and event metadata are plaintext to anyone able to
  observe that network segment.

This is simpler than TLS, but weaker. It is suitable only for a controlled LAN
whose threat model accepts that tradeoff.

## LAN HTTPS webhook fallback

The server already supports an administrator-managed pair:

```text
SPI_TLS=1
SPI_TLS_CERTFILE=/absolute/path/to/fullchain.pem
SPI_TLS_KEYFILE=/absolute/path/to/privkey.pem
```

Only installations choosing inbound HTTPS motion webhooks need app-side server
certificates. Give each such installation its own hostname and private key. A
split-horizon record can resolve that hostname directly to the local app host;
it does not forward other customers' traffic to that host.

An advanced deployment can:

1. Reserve a unique hostname such as
   `store-random-id.square-protect.example.com`.
2. Resolve it from that site's NVR to the site's app host.
3. Issue a public-CA certificate with DNS-01 validation so no WAN listener must
   be opened.
4. Generate and retain the private key on that installation only.
5. install the full chain and key outside the repository with private file
   permissions.
6. Restart the app only after the replacement pair validates.
7. confirm hostname, chain, HTTP `204`, and a new motion-ledger event.

Do not distribute a wildcard private key to installations. If a future hosted
service brokers DNS-01 challenges, it should authorize a unique hostname while
the leaf private key remains local.

## Optional hosted relay

A relay can provide a unique public webhook URL for each installation while the
local app maintains an outbound authenticated connection. This removes local
DNS and inbound firewall work, but introduces an operated service, recurring
cost, internet dependency, privacy obligations, tenant isolation, replay
protection, and outage handling. It should be optional rather than the only way
to install the app.

## macOS signing is separate

Developer ID signing and Apple notarization authenticate the downloaded app to
Gatekeeper. They cannot be reused as a TLS server identity and cannot make a
Protect console trust the app's listener.

Never include the Developer ID private key, a reusable TLS private key, DNS
credentials, or notarization credentials in the app bundle, disk image,
repository, pull-request jobs, or release artifacts.

The release path should eventually sign nested Mach-O files and the app,
create and sign the disk image, submit it to `notarytool`, staple the accepted
ticket, and validate the final artifact. That work can ship independently of
the motion delivery design.

## Product acceptance criteria

- Each installer enters only that store's Protect address, API key, and camera
  selection for motion delivery.
- The default motion path needs no project-owned domain, inbound port, app-side
  public certificate, or shared relay.
- Event reconnect, deduplication, compatibility, and observable gap tests pass.
- A real-hardware test proves that a configured camera's motion event reaches
  correlation through the official event stream.
- Webhook fallback diagnostics identify the failed network or HTTP layer
  without logging secrets.
- Any HTTPS webhook uses a unique per-installation hostname and locally held
  private key.
- Public fixtures and documentation contain no real deployment identifiers.

## Proposed pull-request order

1. Event-stream spike with captured synthetic fixtures and a live compatibility
   report; do not change the product default yet.
2. Production event client, reconnect state, deduplication, and diagnostics.
3. Migration UI that makes the event stream default and keeps webhook fallback.
4. Optional LAN HTTP compatibility mode if supported firmware accepts it.
5. Optional per-install HTTPS automation or hosted relay.
6. Signed and notarized macOS release pipeline.

## Authoritative references

- [Ubiquiti: Send UniFi Protect alerts using webhooks](https://help.ui.com/hc/en-us/articles/25478744592023-Send-UniFi-Protect-Alerts-to-Web-Services-using-Webhooks)
- [Ubiquiti Protect API: event WebSocket](https://developer.ui.com/protect/v7.0.107/get-v1subscribeevents)
- [Ubiquiti Protect API](https://developer.ui.com/protect)
- [Apple: Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/)
- [Apple: Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Let's Encrypt: challenge types](https://letsencrypt.org/docs/challenge-types/)
