# SMTP Relay certificate lifecycle

Separate SMTP client TLS certificates from Entra OAuth signing certificates.
Linux hostname and selected Exchange Accepted Domain are independent.
Support existing PEM, imported PFX and ACME providers only after verifying client TLS suitability. Do not assume Let's Encrypt is eligible.

The read-only checker validates expiration, local CA chain, DNS name, key match and OpenSSL sslclient purpose. It deliberately does not authorize deployment or prove Exchange acceptance.

The Windows import action ships its own checker, stager and receiver through an isolated Python launcher. On a connected Postfix host with Python 3, OpenSSL and root or passwordless sudo, no previous LinuxMailRelay365 helper installation is required. Only public helper code and the DNS name travel in command arguments; the certificate package travels through SSH stdin. The temporary helper directory under `/run` is private and removed after normal completion or handled failure. Validated certificates are staged under `/etc/postfix/lmr365-smtp-tls`, without modifying active Postfix settings or Exchange connectors. Password-based sudo, production SELinux acceptance, ACME issuance and renewal, and end-to-end Exchange delivery still require separate work.

Renewal design: Linux-native scheduler, restricted DNS credentials, staged certificate and key, validate chain/name/purpose/key, atomic activation, Postfix reload, delivery verification and rollback. Manual DNS challenges must not be labeled automatic renewal. Preserve local delivery and existing listeners. Never modify inbound TLS when configuring outbound TLS.

## ACME DNS-01 readiness (read-only)

The Windows SMTP certificate wizard opens a separate DNS-01 plan for the manually selected Exchange domain and independent certificate DNS name. The connected Linux host uses its configured resolver through `dig`, if available, to inspect TXT, CNAME, direct CAA and selected-domain NS answers. Only answer states are returned; TXT contents are not exported. Missing tools, NXDOMAIN, resolver errors and empty answers remain distinct. Certbot executable detection is not a plugin or credentials check. The plan SHA covers inputs only, not DNS observations. Effective CAA (including inheritance and aliases), public DNS propagation, domain ownership, Exchange acceptance and certificate client TLS eligibility remain unverified. No Certbot invocation, issuance, credential collection, DNS update, renewal or Postfix activation is performed.

## Renewal inventory (read-only)

The SMTP TLS wizard inspects standard Certbot and isolated LinuxMailRelay365 renewal configurations, the presence of a protected (not validated) renewal profile, and five systemd timer/service states. Configuration and hook contents, DNS credentials and private keys are not exported. Unsafe paths, missing configurations, ambiguous settings and systemd failures remain distinct. An active timer does not prove successful renewal. The existing managed service may activate renewed material; the inventory does not invoke or enable that service, run Certbot, execute hooks or reload Postfix. Dry-run, credential verification and actual activation remain separate actions.

## Reviewed staging renewal test

The renewal inventory now offers a separate Review and test renewal action for an existing isolated managed profile. It ships the read-only review and dry-run helper plus its dependencies, requires a single matching certificate DNS SAN, private root-owned configuration and credential files, supported DNS authenticator, known Let's Encrypt directory and no configured hooks, custom global configuration or unsupported options. A fresh plan SHA is checked again under the managed renewal lock after explicit approval. The test uses the staging CA and `--dry-run` only; temporary DNS TXT updates and local Certbot state/logs are possible. It never invokes live renewal, forced renewal, activation or Postfix reload. Failed/uncertain tests must be investigated before retry. Custom CA and unsupported configuration remain manual. Staging acceptance is not evidence of production CA, client TLS or Exchange delivery acceptance.
