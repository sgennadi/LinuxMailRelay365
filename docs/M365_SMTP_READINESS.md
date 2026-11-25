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
