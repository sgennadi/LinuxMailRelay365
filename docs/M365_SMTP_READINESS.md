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
