# SMTP TLS activation primitive

The generation pointer helper is internal only. It must not be invoked by a GUI
or timer until a deployment transaction supplies an exclusive lock, certificate
revalidation, a durable recovery journal, Postfix configuration verification,
reload and delivery checks. A pointer swap alone does not guarantee that two
separate opens of certificate and key see the same generation. Prefer a single
combined PEM via smtp_tls_chain_files where supported, or a controlled offline
transition. No production configuration is changed by this module.
