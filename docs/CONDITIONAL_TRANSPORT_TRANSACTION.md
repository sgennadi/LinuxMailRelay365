# Multi-provider transport transactions (development)

The snapshot library and new transaction library implement the file-level
first-install / rollback path for disjoint sender-specific SMTP services.
They are not exposed by a production CLI or GUI. Existing explicit routing
assignments and map/service collisions are refused, including empty explicit
assignments. A mandatory caller-supplied exclusive maintenance guard and
native verification are required; neither has a permissive default.

The native compiler can pass verified database bytes to an internal callback
while its private temporary directory still exists. The normal CLI is
unchanged. The caller must supply the exact verified map set. The transaction
uses an opaque random recovery revision, saves both original/proposed configs
and a private journal of database hashes and individual durable publication
receipts. It never backs up a second copy of the SASL databases. The journal
and snapshots are private, not suitable for export or telemetry. Original
configuration itself can contain sensitive values.

Maps are created exclusively with 0640 root:postfix-equivalent metadata
(the caller supplies the validated group), then master.cf and main.cf are
replaced individually. This is not a two-file atomic swap: exclusive stopped
maintenance is essential. Rollback disconnects routes by restoring main.cf
before master.cf, checks original native policy via the caller, and removes
only maps with a matching publication receipt, file identity, content and
metadata. Unknown/replaced files, unrelated edits and missing receipts block
automatic deletion. No service, queue, inbound listener or existing foreign
map is changed automatically. A failed rollback returns an opaque recovery ID
and leaves the operator to inspect the host. Unencrypted SASL DBs still contain
readable credentials; no claim of encrypted at-rest storage or secure erasure
is made. SELinux/ACL configurations are refused by this new path.

Tests cover the exact file transaction, snapshot compatibility, no credential
DB duplication, injected failure before main publication, failed verification,
idempotent restore, foreign-map collisions and unknown publication identity.
Actual native runtime maintenance, end-to-end SMTP routing/AUTH isolation,
credential rotation, replacement of existing sets, recipient routing,
SELinux and GUI integration remain separate gates.
