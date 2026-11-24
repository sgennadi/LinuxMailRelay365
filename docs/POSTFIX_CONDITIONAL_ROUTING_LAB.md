# Isolated Postfix conditional-routing acceptance

This CI-only fixture uses a disposable Ubuntu 24.04 Docker container with
`--network none`. Only loopback interfaces exist. All mail has synthetic .invalid
addresses; no credentials, tenants, real recipients, or host Postfix are used.

Real Postfix is exercised with hash maps, using the key/value shapes shown in
the RC13 wizard. The fixture checks exact envelope sender vs. @sender-domain,
recipient transport precedence over both, unaffected local delivery, fallback on
no match, and delivery after byte-for-byte baseline rollback and map removal.
Each modeled next hop uses a different explicit TCP port and the test verifies
SMTP envelope, DATA marker, queue drain, and absence of duplicate/wrong-port
receipt. The listener stays on loopback TCP/25.

This lab verifies Postfix routing behavior only, not an application Apply or
rollback implementation. It does not validate other map backends, TLS, AUTH,
external delivery, 200% Windows DPI, or any production migration. The workflow
does not publish or modify any release.
