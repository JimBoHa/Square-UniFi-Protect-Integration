# TLS Trust and macOS Distribution Plan

Status: proposed implementation plan

This document separates macOS distribution trust from HTTPS server trust and
defines the work required for a compiled `SquareProtect.dmg` to receive UniFi
Protect webhooks without disabling certificate verification.

## Decision

Use two independent certificate systems:

1. Sign the app and disk image with an Apple-issued **Developer ID
   Application** certificate, submit the disk image to Apple's notary service,
   and staple the returned ticket. This lets macOS Gatekeeper authenticate the
   publisher and assess the downloaded application.
2. Give each installation its own hostname, private key, and Web PKI TLS server
   certificate. The Square Protect server presents this certificate to UniFi
   Protect on TCP port `3546`.

An Apple Developer ID certificate cannot be reused as the HTTPS server
certificate. It is a code-signing identity evaluated by macOS Gatekeeper, not a
TLS server identity trusted by the Protect NVR. Apple also does not code-sign a
disk image on the developer's behalf: the release publisher signs it with an
Apple-issued identity, and Apple's separate notary service returns a ticket
after automated analysis.

Never include either the Developer ID private key or a reusable TLS private key
in the app bundle, disk image, repository, or CI artifacts.

## The three trust decisions

| Consumer | Artifact or connection | Trust material | Purpose |
| --- | --- | --- | --- |
| macOS Gatekeeper | `Square Protect.app` and `SquareProtect.dmg` | Developer ID Application signature plus an Apple notarization ticket | Authenticates the publisher, detects modification, and records Apple's malware analysis |
| UniFi Protect | `https://<app-hostname>:3546` | Publicly trusted TLS certificate whose Subject Alternative Name contains `<app-hostname>` | Authenticates the webhook server during the TLS handshake |
| Square Protect | Motion webhook request | Per-installation `X-SPI-Webhook-Token` | Authenticates the request after TLS succeeds |

Passing one check does not imply either of the others passed. In particular,
Protect can trigger an alarm action while closing the connection before HTTP if
it rejects the server certificate.

## Current repository behavior

The server already supports an administrator-managed certificate pair:

```text
SPI_TLS=1
SPI_TLS_CERTFILE=/absolute/path/to/fullchain.pem
SPI_TLS_KEYFILE=/absolute/path/to/privkey.pem
```

At startup it checks the PEM files, certificate validity, and private-key file
permissions before opening the listener. It refuses to silently fall back to a
self-signed certificate when a configured custom pair is invalid.

Two gaps remain for the DMG experience:

- `scripts/macos/build_dmg.sh` signs the nested binaries and app bundle, but it
  does not yet sign the completed disk image or run notarization and stapling as
  one guarded release operation.
- `square-protect-menubar` currently binds the child server to `127.0.0.1` and
  does not forward `SPI_TLS_CERTFILE` or `SPI_TLS_KEYFILE`. A Finder-launched
  DMG installation therefore cannot receive a LAN webhook merely because the
  bundle was signed.

The generated self-signed certificate remains useful for local development and
interactive browser setup. It is not a reliable production choice for an
unattended Protect webhook client.

## Immediate deployment with the existing server

An operator can solve TLS trust today for the service/headless package without
waiting for DMG configuration UI:

1. Reserve a stable hostname such as `square-protect.example.com`.
2. Make that hostname resolve, from the NVR's DNS resolver, to the app host's
   stable LAN address.
3. Obtain a public-CA certificate for that hostname. DNS-01 ACME validation is
   recommended because the app can remain LAN-only and no WAN port needs to be
   opened. Use a DNS credential restricted to the validation record or zone.
4. Install the complete PEM certificate chain and its per-installation private
   key outside the repository. Make the key readable only by the service user.
5. Set `SPI_TLS`, `SPI_TLS_CERTFILE`, and `SPI_TLS_KEYFILE` in the service
   definition, then restart only Square Protect.
6. Configure the Protect action as:

   ```text
   https://square-protect.example.com:3546/webhooks/protect/motion
   ```

   Use the documented GET method with the displayed
   `X-SPI-Webhook-Token` header for the most compatible configuration.
7. Confirm that the hostname resolves correctly on the NVR, the TLS chain and
   hostname validate, Protect receives HTTP `204`, and the motion event appears
   in the app.

Certificate renewal must replace the two PEM files atomically and restart the
service only after the new pair has passed validation. Keep the previous valid
pair until the restart succeeds.

## Proposed product implementation

### Workstream A: produce a signed and notarized DMG

Keep pull-request CI able to create an ad-hoc-signed test DMG. Add a separate
release mode that fails closed unless the release identity and notarization
profile are available.

The release path should:

1. Build both locked release binaries.
2. Reject non-portable dynamic-library paths and run the existing bundle and
   smoke validation.
3. Sign each nested Mach-O file, then the app bundle, with a Developer ID
   Application identity, hardened runtime, and a secure timestamp.
4. Verify the app signature with `codesign --verify --deep --strict --verbose=2`
   and assess the app with `spctl`.
5. Create the UDIF disk image, sign the completed `.dmg` with the same Developer
   ID Application identity, and verify that signature.
6. Submit the disk image with `xcrun notarytool submit --wait`, fail on any
   rejected or non-accepted result, and retain the notary log for diagnosis.
7. Staple and validate the ticket with `xcrun stapler`.
8. Mount the final disk image on a clean test account and run the bundled smoke
   check before publishing it.

Use a Developer ID **Installer** certificate only if distribution later changes
to a signed installer package (`.pkg`). It is not the identity for this `.app`
and `.dmg` workflow.

Suggested build interface:

```text
MACOS_SIGNING_IDENTITY="Developer ID Application: Example (TEAMID)"
MACOS_NOTARY_PROFILE="square-protect-release"
scripts/macos/build_dmg.sh
```

The notary credentials belong in a Keychain profile created with
`notarytool store-credentials`. Release CI should use a protected environment
and short-lived or narrowly scoped secrets; pull-request jobs must never receive
the signing private key or notarization credentials.

### Workstream B: make a trusted certificate usable from the DMG

Add a menubar-owned runtime configuration under
`~/Library/Application Support/SquareProtect/`. The configuration should store
only non-secret settings and paths, for example:

- LAN listener enabled or disabled;
- stable hostname;
- TLS mode (`generated` or `managed-files`);
- managed certificate and key paths.

Implement a **Configure LAN HTTPS** action that:

1. Lets an administrator select a full-chain PEM and matching unencrypted PEM
   private key.
2. Copies them into an app-owned directory using atomic writes, directory mode
   `0700`, and private-key mode `0600`. Do not continue to depend on files in
   Downloads or a mounted disk image.
3. Validates the key pair, validity interval, server-auth usage, full chain,
   and Subject Alternative Name for the configured hostname before changing
   the active configuration.
4. Preserves the last working pair until the replacement server is listening.
5. Restarts only the embedded server with `SPI_HOST=0.0.0.0`, `SPI_TLS=1`,
   `SPI_TLS_CERTFILE`, and `SPI_TLS_KEYFILE`; the menu-bar parent should remain
   running and report a failed rollback clearly.
6. Shows certificate source, issuer, hostname, expiration, listener address,
   and renewal status without exposing private-key material.

Changing from loopback to a LAN listener is a security boundary. Require an
administrator confirmation, keep first-run bootstrap protection, and do not
infer LAN exposure merely from the presence of a certificate.

### Workstream C: automate public certificate issuance and renewal

After managed-file import works, add ACME as another certificate source rather
than coupling certificate issuance to code signing.

Recommended ACME design:

1. Ask for a hostname and DNS provider, not a public inbound port.
2. Generate the TLS private key locally for each installation.
3. Use DNS-01 validation so `_acme-challenge` can be public while the app's A/AAAA
   record is private or split-horizon DNS.
4. Store the narrowly scoped DNS API credential in macOS Keychain. Never write
   it to SQLite, the runtime configuration, logs, crash reports, or command-line
   arguments.
5. Support delegation of `_acme-challenge` to a validation-only DNS zone so the
   app does not require broad credentials for the primary domain.
6. Write renewed certificate generations atomically, validate them with the
   same path used at startup, reload or restart the embedded server, then retire
   the previous generation.
7. Schedule renewal from the certificate's advertised validity and ACME renewal
   guidance rather than assuming every certificate lasts 90 days. Apply bounded
   backoff and preserve the current valid certificate when issuance fails.
8. Warn well before expiration and make renewal failure visible in both the
   dashboard and menu-bar status.

Provider-specific DNS clients can be added incrementally behind one interface.
The first implementation should also support an external certificate manager
writing the managed files, so users are not blocked on a particular DNS
provider.

### Workstream D: make delivery failures observable

Add diagnostics that distinguish:

- DNS resolution failure;
- TCP refusal or timeout;
- TLS trust, hostname, expiry, or incomplete-chain failure;
- missing or incorrect webhook token;
- invalid HTTP method, content type, or payload;
- accepted and deduplicated delivery.

The receiver should record bounded metadata for rejected attempts when HTTP was
reached, but never record the webhook token or raw credentials. The UI should
state that Protect's successful alarm execution status is not proof of an HTTP
receipt. A successful end-to-end test requires both HTTP `204` and a new event
in the motion ledger.

## Security constraints

- Do not extract, export, or embed the Developer ID private key for runtime use.
- Do not ship one TLS private key or certificate shared by all installations.
- Do not disable Protect's server-certificate verification as a product fix.
- Do not expose the webhook receiver to the public internet merely to complete
  certificate issuance; DNS-01 avoids that requirement.
- Do not store DNS provider credentials, Square credentials, Protect
  credentials, webhook tokens, or private keys in source control or PR logs.
- Keep port `3546` stable unless every inbound URL and deployment definition is
  deliberately migrated together.
- Keep the app's token authentication even after a trusted TLS certificate is
  installed. TLS authenticates the server; the token authenticates the caller.

## Acceptance criteria

### macOS release

- A clean machine accepts the app and disk image under default Gatekeeper
  policy without right-click overrides.
- `codesign` verifies all nested code, the app bundle, and the disk image.
- `notarytool` reports an accepted submission, and `stapler validate` succeeds
  without relying on a live lookup.
- The unsigned/ad-hoc CI path remains available but cannot be mistaken for a
  public release artifact.

### HTTPS listener

- The DMG-installed menu-bar app can intentionally enable a LAN listener and
  persists its non-secret runtime configuration across restarts.
- The server presents a complete public chain for the configured hostname on
  port `3546`.
- A normal TLS client validates the chain and hostname without an insecure
  bypass flag.
- Protect's GET webhook with the custom token receives HTTP `204` and creates a
  motion-ledger event.
- An invalid token is rejected without being logged, and a certificate mismatch
  fails before HTTP as expected.
- A forced renewal test proves atomic replacement and rollback to the previous
  valid pair.

## Suggested pull-request sequence

1. **Release hardening:** sign the DMG, add explicit secure timestamps, automate
   notarization/stapling behind release-only inputs, and test the script's
   fail-closed modes.
2. **Menubar runtime configuration:** persist LAN/TLS settings and forward the
   existing custom-certificate variables to the embedded server.
3. **Managed certificate import:** add secure copy, validation, status, restart,
   and rollback behavior.
4. **Delivery diagnostics:** expose certificate and webhook receipt state
   without logging secrets.
5. **ACME DNS-01:** add provider-neutral issuance/renewal orchestration, then
   individual DNS providers.

Keeping these changes separate makes it possible to ship a correctly signed
and notarized DMG before automated TLS issuance is complete, while ensuring the
release artifact never falsely claims that Apple notarization solves webhook
server trust.

## Authoritative references

- [Apple: Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/)
- [Apple: Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Apple: Resolving common notarization issues](https://developer.apple.com/documentation/security/resolving-common-notarization-issues)
- [Let's Encrypt: Challenge types](https://letsencrypt.org/docs/challenge-types/)
- [Let's Encrypt: Certificate profiles](https://letsencrypt.org/docs/profiles/)
- [Ubiquiti: Send UniFi Protect alerts using webhooks](https://help.ui.com/hc/en-us/articles/25478744592023-Send-UniFi-Protect-Alerts-to-Web-Services-using-Webhooks)
