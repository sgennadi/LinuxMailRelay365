# SMTP Relay certificate lifecycle

Separate SMTP client TLS certificates from Entra OAuth signing certificates.
Linux hostname and selected Exchange Accepted Domain are independent.
Support existing PEM, imported PFX and ACME providers only after verifying client TLS suitability. Do not assume Let's Encrypt is eligible.

The read-only checker validates expiration, local CA chain, DNS name, key match and OpenSSL sslclient purpose. It deliberately does not authorize deployment or prove Exchange acceptance.

The Windows import action ships its own checker, stager and receiver through an isolated Python launcher. On a connected Postfix host with Python 3, OpenSSL and root or passwordless sudo, no previous LinuxMailRelay365 helper installation is required. Only public helper code and the DNS name travel in command arguments; the certificate package travels through SSH stdin. The temporary helper directory under `/run` is private and removed after normal completion or handled failure. Validated certificates are staged under `/etc/postfix/lmr365-smtp-tls`, without modifying active Postfix settings or Exchange connectors. Password-based sudo, production SELinux acceptance, ACME issuance and renewal, and end-to-end Exchange delivery still require separate work.

Renewal design: Linux-native scheduler, restricted DNS credentials, staged certificate and key, validate chain/name/purpose/key, atomic activation, Postfix reload, delivery verification and rollback. Manual DNS challenges must not be labeled automatic renewal. Preserve local delivery and existing listeners. Never modify inbound TLS when configuring outbound TLS.

## ACME DNS-01 readiness (read-only)

The Windows SMTP certificate wizard opens a separate DNS-01 plan for the manually selected Exchange domain and independent certificate DNS name. The connected Linux host uses its configured resolver through `dig`, if available, to inspect TXT, CNAME, direct CAA and selected-domain NS answers. Only answer states are returned; TXT contents are not exported. Missing tools, NXDOMAIN, resolver errors and empty answers remain distinct. Certbot executable detection is not a plugin or credentials check. The plan SHA covers inputs only, not DNS observations. Effective CAA (including inheritance and aliases), public DNS propagation, domain ownership, Exchange acceptance and certificate client TLS eligibility remain unverified. No Certbot invocation, issuance, credential collection, DNS update, renewal or Postfix activation is performed.
