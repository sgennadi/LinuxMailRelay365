# SMTP Relay certificate lifecycle

Separate SMTP client TLS certificates from Entra OAuth signing certificates.
Linux hostname and selected Exchange Accepted Domain are independent.
Support existing PEM, imported PFX and ACME providers only after verifying client TLS suitability. Do not assume Let's Encrypt is eligible.

The initial read-only checker validates expiration, local CA chain and OpenSSL sslclient purpose. It deliberately does not authorize deployment. Name matching, key matching, Exchange acceptance, trusted CA selection and DNS provider credentials still require implementation.

Renewal design: Linux-native scheduler, restricted DNS credentials, staged certificate and key, validate chain/name/purpose/key, atomic activation, Postfix reload, delivery verification and rollback. Manual DNS challenges must not be labeled automatic renewal. Preserve local delivery and existing listeners. Never modify inbound TLS when configuring outbound TLS.
