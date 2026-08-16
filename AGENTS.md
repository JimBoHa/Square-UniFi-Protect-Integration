# Repository agent rules

These rules apply to the entire repository and every coding agent.

## Never publish deployment data

- Never commit, paste into issues or pull requests, or print in logs any real
  password, access token, API key, webhook token, DNS credential, encryption
  key, session, private key, runtime database, merchant data, camera name, site
  hostname, or site network address.
- Never use real deployment values in source, tests, fixtures, screenshots, or
  examples. Use `example.com`, `.invalid`, and the RFC 5737 documentation
  networks `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`.
- A TLS certificate and its public chain are public information, but still do
  not commit per-installation certificate files. A TLS private key is always a
  secret and must never enter Git.
- Keep runtime state in the ignored `data/` directory. Keep certificate keys,
  ACME account material, DNS tokens, and local environment files outside the
  repository in an OS credential store or a root-only path.

## Required checks

- Run `./scripts/check-secrets.sh` before committing or publishing changes.
- Treat every finding as real until verified. Never add an allowlist merely to
  make CI pass. A fingerprint exemption is allowed only for a deterministic,
  clearly fake test value after human review.
- Review `git diff --cached` for deployment identifiers as well as credentials;
  scanners cannot recognize every password or private address.

## Suspected disclosure

Stop publishing. Do not repeat the value in discussion or logs. Revoke or
rotate the exposed credential or private key first, then audit Git history,
GitHub Actions logs and artifacts, issues, pull requests, releases, packages,
forks, and clones. Deleting a file or making the repository private does not
revoke a leaked secret and does not remove it from existing history or clones.
