# Legacy diagnostics archive

These are exact copies of one-off utilities used for the August 2026 Square
Sandbox load test and UniFi frame-timestamp investigation. They are preserved
for auditability only and are not part of the production runtime or native Rust
test suite.

The utilities retrieve credentials from macOS Keychain and contain no embedded
credentials. One script retains the historical private-LAN endpoint used during
the test so its archived source remains byte-for-byte identical.

Do not run these utilities against a live system without reviewing their fixed
load-test parameters and endpoints first.
