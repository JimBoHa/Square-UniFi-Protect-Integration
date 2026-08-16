# Security policy

## Public-repository boundary

This repository contains application source and generic examples only. It must
not contain deployment credentials, private keys, runtime state, customer or
merchant data, camera/site identifiers, or real network topology.

Public certificate chains are not authentication secrets. TLS private keys,
ACME account keys, DNS-provider tokens, Square and Protect credentials, webhook
tokens, encryption keys, session data, and the application database are
secrets. Store them outside the repository using the operating system's
credential store, a dedicated secrets manager, or a root-only file required by
the service. Do not pass secrets in command-line arguments or write them to CI
logs.

Tests and documentation must use `.example`/`.invalid` names and RFC 5737
documentation addresses. See [AGENTS.md](AGENTS.md) for mandatory rules that
apply to coding agents.

## Before publishing a change

Install [Gitleaks](https://github.com/gitleaks/gitleaks), then run:

```bash
./scripts/check-secrets.sh
git diff --cached
```

The script scans all reachable Git history plus every current tracked or
non-ignored untracked file. GitHub push protection and the repository workflow
provide additional checks, but no scanner replaces manual review.

## If a secret may have been exposed

1. Stop publishing and do not repeat the value in an issue or pull request.
2. Revoke or rotate the credential or private key immediately.
3. Audit Git history, forks and clones, Actions logs and artifacts, issues,
   pull requests, releases, and packages.
4. Remove the value from current code. Rewrite history only after assessing the
   disruption and coordinating with every clone and fork.

Deleting the current file, closing a pull request, or changing repository
visibility does not invalidate a credential and does not erase existing copies.

## Reporting a vulnerability

Do not open a public issue containing exploit details or deployment data. Use
GitHub's private vulnerability reporting for this repository.
