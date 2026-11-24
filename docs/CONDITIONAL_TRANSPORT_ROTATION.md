# Credential rotation core (development)

A single existing password-authenticated sender transport can be selected by
its validated plan index. The library requires an exact owned installed
record, a fresh caller-supplied review, verified native candidate bytes and
exclusive stopped-host maintenance. It replaces only that SASL DB, preserving
both configuration files and all other map identities. Normal Restore can
remove the rotated DB after checking the current ownership overlay.

An atomic, root-only current overlay records new private map hashes and file
identities; it binds to the original immutable publication journal. A durable
pending marker is written before replacement and records the prepared inode
identity before rename. Ordinary discovery, restore and further rotation
refuse a pending marker. The old DB is held in process memory for immediate
rollback on verified failures before commit. No persistent duplicate password
DB is created. If the process is killed, or overlay publication has uncertain
outcome, explicit recovery may be required; keep Postfix stopped. Guarded post-crash reconciliation is implemented at library level. Do not delete a pending marker or
assume the old credentials are recoverable. Private hashes/identity records
must not be exported or logged. No authentication or mail delivery is
claimed. The library does not expose a production CLI or GUI. Native
candidate compilation, pending-recovery workflow and real host acceptance
remain gates.

## Interrupted rotation reconciliation

A separate stopped-host library reconciles a proven retained map after fresh
native verification. It recognizes the original inode, a durably prepared
replacement inode, or a durably prepared rollback inode. It does not rewrite
credentials or Postfix configuration, recreate a lost password, or start a
service. A matching already-committed overlay is accepted only when its
transaction generation and reconstructed prior record match. Unknown inodes,
configuration drift, orphan scratch files and native verification failures
block reconciliation. Recovery requires separate typed approval and exclusive
maintenance. Inventory reports credential_rotation_pending; this status does
not authorize recovery or restart. CLI/GUI and actual native acceptance are
still required. Do not remove a pending marker manually.

## Native single-map preparation (library only)

The single-account preparation helper uses the existing native compiler in
private scratch with exactly one selected sender rule and credential slot.
It verifies the callback's rule, plan, backend, CA bundle and receipt; only
that SASL database returns in memory. The native retained-map helper queries
one exact map under the Postfix account, checks directory and inode identity,
requires exactly one expected endpoint, checks a positive and negative lookup,
and optionally compares the submitted new credential. Errors are redacted.
No other account is read, no credential is returned by the verifier, and no
SMTP authentication or service control is performed. The caller still must
prove the exclusive maintenance guard and native effective-policy checks.
Full repository CI and real native integration are required before exposing
these helpers through the CLI or Windows GUI.
