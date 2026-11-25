# Microsoft 365 SMTP readiness — development after RC19

The Objects Manager adds a read-only audit for the selected XOAUTH2 primary
mailbox when native Graph inventory has found its exact Enterprise Application.
Existing connector-only inventory and the local Verify checkpoint remain intact.
No new Graph permissions are requested.

The existing Exchange PowerShell session revalidates its tenant and checks
Get-TransportConfig, exact primary address via Get-Mailbox, Get-CASMailbox,
and the Exchange principal's AppId/ObjectId against Graph. The selected
mailbox is evaluated with Test-ServicePrincipalAuthorization for the exact
Application SMTP.SendAsApp role. Missing permissions or unexpected values
are unverified. A genuine null mailbox flag inherits the organization flag;
explicit mailbox values override it. In-scope Exchange RBAC does not cover
separate Entra grants, Security Defaults, Conditional Access, certificate
trust, token acquisition, SMTP AUTH or real delivery.

The Windows receipt is bound to tenant, Client ID, mailbox and Enterprise
Application. CONFIG OK is a configuration observation only. No settings,
grants, certificates, passwords or mail are changed. Tests are offline;
actual tenant acceptance is still required. Next: correlate Postfix
sender routing and Linux public certificate with the same cloud identity.

References:
- https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission
- https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac

## Configured active certificate correlation (pending CI)

In Microsoft 365 Objects, select Primary Postfix or Isolated Postfix / Sidecar
under Linux / Entra certificate match, then Compare active certificate.
The read-only helper samples the fixed app.json and its referenced public
certificate twice. It does not assume the old app.crt is still active,
require a staged rotation or read a private key. The receipt binds tenant,
client, selected mailbox and explicit source. Native Graph records SHA-256
only when an actual public X.509 key is returned; missing bytes are unverified,
not a mismatch. A matching credential must also be within both validity
windows. The comparison uses the cloud inventory in the open dialog, and
is not proof of key possession, effective routing, SMTP AUTH or delivery.
No new cloud permissions, provider changes, or mail sending are introduced.

## Postfix XOAUTH2 pipe configuration correlation (pending CI)

The certificate comparison now includes a separate read-only inspection
of the fixed primary or sidecar configuration directory. It checks
postconf default_transport, relay_transport, recipient limit, presence of
transport/sender-dependent maps and relayhost, the exact expected managed
m365xoauth2 pipe command, and presence of master.cf service overrides.
The two configuration snapshots must match around the public certificate
sample; root-owned configuration hashes are checked before and after
postconf reads. Only coded findings leave Linux. Unavailable or changed
configuration becomes unverified; the certificate result remains separate.
Local/virtual recipient address classes, actual map-key lookups, live
process state, signer operation, SMTP authorization and delivery are NOT
proved. The green indication requires both an in-validity public certificate
match and the expected default/relay pipe configuration, and is not a
permission to apply or send. See https://www.postfix.org/postconf.5.html
and https://www.postfix.org/postconf.1.html for precedence and readback.

## Installed Postfix route lookup (development)

The advanced routing page includes Inspect installed Postfix route. Choose
the discovered primary instance or sidecar and enter a non-null envelope
sender and recipient. Expanded postconf readback and actual postmap -q
queries against private snapshots of allowlisted, single local hash/LMDB
routing databases identify matching key shapes. Recipient transport keys
are checked before sender-dependent default transports; sender-dependent
relayhost is a next-hop fallback, not a universal transport override.
Literal local, virtual and relay classes are distinguished. Unsupported
maps, rewriting, service overrides, malformed values and snapshot drift
produce a review/unverified result, not an assumed route. Only a validated
single SMTP host/port is shown, never arbitrary map values or credentials.
No live database is queried or rebuilt, no message is submitted, no
service is changed, and no configuration or TLS/authentication acceptance
is implied. The candidate describes a sampled configuration only.

Reference: https://www.postfix.org/transport.5.html and
https://www.postfix.org/postconf.5.html (address classes and lookup precedence).
