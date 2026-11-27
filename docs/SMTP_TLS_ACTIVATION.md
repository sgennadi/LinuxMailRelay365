# SMTP TLS activation primitive

The generation pointer helper is internal only. It must not be invoked by a GUI
or timer until a deployment transaction supplies an exclusive lock, certificate
revalidation, a durable recovery journal, Postfix configuration verification,
reload and delivery checks. A pointer swap alone does not guarantee that two
separate opens of certificate and key see the same generation. Prefer a single
combined PEM via smtp_tls_chain_files where supported, or a controlled offline
transition. No production configuration is changed by this module.

## Reviewed Windows rotation (experimental)

The SMTP TLS wizard now lists staged generations and reviews certificate/key/chain, the current active generation, main.cf and master.cf SHA-256, terminal journal state, client TLS settings and CA trust. Initial setup remains preview-only; no first-time pointer bootstrap or config write is offered. Rotation requires an existing managed Postfix, a locally valid previous certificate for the same DNS identity, and SELinux disabled or not detected. An explicit confirmation is followed by a fresh SHA review inside the existing deployment lock before the existing durable activation transaction checks and reloads Postfix. Local failure attempts rollback; uncertain outcomes require manual journal review. External editors must be excluded separately. The new GUI does not change main.cf, master.cf, ports, inbound SMTP, routing or Exchange configuration. Enforcing, physical delivery and interrupted-process recovery through this GUI remain unverified. Expired previous material and nonstandard configuration require manual recovery or a separate future deployment workflow.

## Reviewed initial deployment

The reviewed deployment dialog now also permits initial managed TLS setup for Postfix >= 3.4 with no conflicting existing SMTP client certificate settings or unfinished journals, on systems with SELinux disabled/not detected. It previews exact original/candidate main.cf hashes and the unchanged SMTP TLS security level. The existing initial transaction writes its durable backup and prepared journal before switching the generation pointer, then atomically replaces only the smtp_tls_chain_files setting and verifies/reloads Postfix. Rollback restores main.cf and reloads it; the protected generation/pointer can remain staged but unused, and only a recorded same-generation retained pointer is eligible for a reviewed retry. The compatible v1 journal records bootstrap_generation; the updated recovery entry point preserves this field. Old installed recovery helpers may omit it, requiring manual review before retry. Interrupted operations are recoverable from the existing journal, but automatic boot recovery requires a separately installed recovery service. The setting is global for outbound SMTP, not confined to the Microsoft 365 destination. No port, listener, inbound TLS, relayhost, queue or Exchange configuration changes are made. Live delivery remains unverified.
