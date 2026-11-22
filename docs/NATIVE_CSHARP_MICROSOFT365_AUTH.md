# Microsoft 365 authentication architecture — C# first (RC2)

The WinForms host references a reusable .NET 10 class library at
`src/Microsoft365Auth/Microsoft365Auth.csproj`. It uses Microsoft.Identity.Client
(MSAL.NET) for delegated Device Code / MFA; sign-in is displayed in a HiDPI-aware
window adapted from BitKeyBridge's UX. This is a separate module suitable for
further reuse by BitKeyBridge (the original project's source is not modified).

## What now runs in native C#

| Action | Client | Requested delegated permissions | Side effects |
| --- | --- | --- | --- |
| Identify the signed-in tenant | Microsoft Graph /organization | User.Read | Read-only |
| List accessible tenant directories (advanced) | Azure Resource Manager /tenants | ARM user_impersonation | Read-only |
| Inspect an exact App Registration, Enterprise Application and its public certificate metadata | Microsoft Graph | Application.Read.All | Read-only |

The default public sign-in application is the same Microsoft Graph Command
Line Tools application used by BitKeyBridge
(`14d82eec-204b-4c2f-b7e8-296a70dab67e`). Microsoft Entra tenant policy
may block or require consent for this first-party app. The GUI accepts a
different **organization-approved public client ID**. Listing multiple
directories with ARM explicitly requires such an approved public client ID;
the program does not silently impersonate an administrator or install Azure
CLI.

An access token is kept only inside the process by MSAL.NET and is not written
to a JSON file, command line, log or PowerShell environment. The app obtains
Graph and ARM tokens for separate resources with separate, minimal scopes.
No tenant mutations occur during either discovery or inventory. Cloud
authentication is tenant-bound and API redirects are disabled.

The Graph App Registration inspection must be an **exact Client ID**, never a
display-name search. Certificate *metadata* is displayed without exporting
private or public key bytes. If Graph returns an ambiguous/denied response, the
UI does not claim that the object is absent.

## RC3: native C# Entra Graph write provisioning (test-only)

With explicit operator confirmation, Microsoft365Auth now requests delegated
`Application.ReadWrite.All` using an exact tenant MSAL session. It creates an
App Registration with ONLY the Linux public certificate, or reads an existing
App Registration by **exact Client ID** and appends the public certificate if
not present. It reads back the complete keyCredential bytes and checks for
concurrent drift before a PATCH; if Graph omits existing key bytes or the
postcheck does not preserve every old key, it fails closed. A concurrent
Entra write is still possible, and a drift guard is not a distributed lock.
A new/reused Enterprise Application must be verified by app ID and object ID.
No private Linux key, Graph Mail.Send, password or client secret is uploaded.

The GUI checks `pwsh` and `ExchangeOnlineManagement` availability **before**
Graph changes, then warns explicitly that if Exchange RBAC later fails the
Entra objects may already have changed; it never automatically deletes them.
Only nonsecret IDs, the mailbox and public cert SHA/date are passed to
the remaining Exchange-only PS1. Tenant identity is separately rechecked
by `Get-ConnectionInformation` before any Exchange mutation.

This is a candidate pending real administrator consent, Entra API and
Exchange RBAC acceptance, including app reuse with multiple public keys.

## What still needs Exchange Online PowerShell

- Exchange Online scoped `Application SMTP.SendAsApp` RBAC, recipient
  management scope, CAS mailbox SMTP AUTH settings, and verification
- Exchange Online Inbound Connectors and management roles/inventory
- Entra app/certificate Graph **write** provisioning is now in C# (RC3).

The Cloud Objects inspector and the Exchange RBAC provisioning PowerShell are now **Exchange-only** and does not
load `Microsoft.Graph.Authentication`. The tenant discovery script using
`Az.Accounts` has been removed entirely.

## Required real acceptance

This code can pass offline CI without proving live Entra sign-in. Test with an
approved client app in a real tenant: Device Code + MFA, ARM permission denial,
multi-tenant selection, exact tenant enforcement, application read permissions,
and Exchange's independent tenant verification. Never describe CI as proof of
live Microsoft 365 authorization or real external mail delivery.
