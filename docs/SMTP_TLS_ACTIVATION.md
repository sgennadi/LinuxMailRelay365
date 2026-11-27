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
