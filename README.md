# LinuxMailRelay365

Linux Mail Relay for Microsoft 365 — Windows 10/11/Server GUI wizard, Linux Postfix outbound transport and scoped Exchange Online application identity. **Preview 0.1.0-preview.4 — source only, not a verified production release.**

## Intended workflow

1. Connect to an Ubuntu/Debian or RHEL/Oracle Linux server using SSH private key/agent or user password; verify SSH host key. A separate `sudo` password is optional. Passwords exist in the live wizard session only, are not persisted, and are never passed as process command-line arguments.
2. **Optional security check**: read-only inventory of TPM 2.0, `tpm2-tools`, PKCS#11/HSM hints; optionally run read-only Entra policy/log access diagnostic. Nothing is enabled or installed by these checks. All three optional protection choices are **OFF by default**.
3. Click **Connect to Microsoft 365 and discover tenants**: a delegated interactive Az.Accounts sign-in lists accessible Entra directories. With exactly one tenant, Tenant ID is automatically filled; with multiple tenants, a dropdown requires an explicit choice. If Azure tenant enumeration is unavailable, switch to manual GUID entry. Nothing is provisioned during discovery. Then set mailbox, Entra application display name, optional existing Client ID for a shared app, and certificate validity 1–365 days. Generate an RSA signing key on Linux. Only its public X.509 certificate is transferred to Windows.
4. Perform interactive Entra + Exchange Online provisioning. Grant mailbox-scoped `Application SMTP.SendAsApp`, without Exchange Connector, Direct Send, mailbox password, client secret or refresh token.
5. Back up existing Postfix configuration and install dedicated Linux Python XOAUTH2 pipe transport. Existing Sendmail/Exim MTA is detected and **not silently replaced**. Run token check, queue check and test email.
6. Open **Security Center** again from the diagnostics step for future checks and opt-in planning.

## Multiple Linux servers and sender mailboxes

Each Linux host can use a **different primary Microsoft 365 sender mailbox** and its
own **certificate**, while sharing the same Entra Application (Client ID). The
Exchange provisioner now derives a **separate mailbox-specific RBAC management scope
and assignment** for each sender, instead of reusing one app-wide management scope.
Adding another host does not retag or modify previously configured mailboxes.
Previously installed single-mailbox app-wide scopes are preserved for the matching
mailbox only. If CustomAttribute15 is already assigned for another purpose, the
wizard fails closed and does not overwrite the attribute.

**Security limitation:** every valid certificate on a shared app can use **the union
of all mailbox scopes**. These assignments do not bind an individual certificate
to an individual mailbox. For strong per-host isolation, create one Entra app per
Linux host. Windows state and protection preferences are scoped per SSH endpoint;
one host is configured with one sender mailbox in this preview.

On Exchange Online the installer changes only the selected mailbox
(`Set-CASMailbox -SmtpClientAuthenticationDisabled $false` and its free
`CustomAttribute15`) and creates/verifies the minimum
`Application SMTP.SendAsApp` role. It does **not** change global SMTP AUTH,
Entra Security Defaults, Conditional Access, SPF, DKIM, DMARC or connectors.
Existing tenant policies may still block submission.

## Security Center: precisely what works today

| Mechanism | Discovery | Default | Activation in this preview |
|---|---|---|---|
| TPM 2.0, TPM2 tools | Read-only device, sysfs and command probe | Off | **Manual only, not automatically provisioned**. A detected TPM is not proof of a compatible nonexportable signing key. |
| HSM/PKCS#11 | Read-only tools and token-slot hints | Off | **Manual only, not automatically provisioned**. Hardware signing is not wired to the PEM-based transport yet. |
| Entra workload identity IP Conditional Access | Explicit read-only admin sign-in, Graph policy API accessibility check | Off | Operator configures a **Report-only** policy in Entra, checks results, then enables it manually. No automatic CA mutations. Requires Workload ID Premium. |
| Entra sign-in logs | Explicit read-only Graph audit endpoint check | Off | Operator configures alerting manually. Reading logs does not enable alerts. |

Selected checkboxes are **preferences / plans, not active configuration**. A separate JSON plan, all values initially `false`, is saved per SSH host+port+username under `%LOCALAPPDATA%/LinuxMailRelay365`. No secrets are stored in that plan. A shared Entra app has a shared permissions and public-IP policy: one certificate cannot be IP-restricted separately within the same app. For per-host IP policies, register separate applications.

**Security limits:** The PEM signing key on Linux is accessible to privileged operators; root can use it. Obfuscating or encrypting it with a local unattended unlocker is not a root defense. TPM/HSM can prevent key export but not necessarily key *use* by compromised root. If root must not obtain any Microsoft 365 credential, move credential issuance and message submission to a separately controlled service.

## Build source on Windows (PowerShell 7, .NET 10 SDK)

```powershell
pwsh -File ./scripts/restore-modules.ps1

dotnet publish ./src/LinuxMailRelay365/LinuxMailRelay365.csproj `
  -c Release -r win-x64 --self-contained true
```

The app **can build without access to the private UniversalUpdater** module: public CI uses a small read-only GitHub Releases checker. If you restore the user's pinned `UniversalUpdater` module from `MODULES.lock`, the full shared release-verification code is compiled instead. The app uses `SSH.NET` v2026.0.0 via NuGet. No Windows binaries have been built or visually verified in this development environment.

## Linux-only probe (zero changes)

```bash
bash linux/probe-linux.sh
```

## Offline tests

```bash
python3 -m unittest discover -v -s tests
bash -n linux/probe-linux.sh linux/install-postfix-m365-xoauth2.sh
```

Public Windows CI builds **single EXE** self-contained preview artifacts for **win-x64 and win-arm64** without private GitHub secrets and runs `LinuxMailRelay365.exe --self-test` on Windows x64. The optional shared updater is used when restored on the developer's Windows machine. The fallback only checks releases: it does not download or install updates.

## Windows interface (Preview 4)

- Original multi-size `.ico` embedded in the application and shown in its main window.
- Unified compact HiDPI-aware outlined buttons with vector glyphs (SSH, cloud, shield, upload, diagnostics, refresh).
- Five-step wizard; one selected Microsoft 365 tenant, password/key-based SSH, optional sudo password.
- **Diagnostics Journal**: allowlisted operation status events only. `Copy privacy-safe diagnostic report` and `Save privacy-safe JSON report` on the Diagnostics step. Raw activity is only local and is redacted before display.
- No automatic update installer, no stable production release yet.


## GitHub

The repository exists at [sgennadi/LinuxMailRelay365](https://github.com/sgennadi/LinuxMailRelay365). The source package contains no GitHub tokens. Public CI builds self-contained executables after the sources are pushed; downloading a CI artifact is not the same as installing a signed stable release.

## Known preview limitations

- Real SMTP/Entra tenant and SSH hosts have not been exercised; verify in a dedicated test tenant and server before production.
- Existing Sendmail remains untouched; automatic Sendmail migration is not yet supported.
- Hardware-backed OAuth signing and automatic Conditional Access enforcement are not implemented. Do not treat planned options as enabled.
- Microsoft Entra tenant discovery uses `Az.Accounts` (installed for CurrentUser when absent) and `Get-AzTenant`. Azure APIs might not enumerate all external/guest tenants. User can enter the correct Tenant GUID manually. Discovery and actual Graph/Exchange provisioning are separate administrative sign-ins in this preview. Exchange tenant identity is independently checked using `Get-ConnectionInformation` before any changes.
- The wizard uses PowerShell 7 for Microsoft 365 provisioning. The operator must consent with an authorized administrative account.
- A certificate renewal feature exists in the Linux CLI (`--rotate-only` / `--activate-only`), but the complete managed GUI rotation workflow is not yet finished.
- Password mode and MTA setup need a Windows/.NET build and server integration test before a stable release.

## Sources

- [Microsoft Conditional Access for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity)
- [Microsoft Graph permission model for Exchange Application RBAC](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
- [SSH.NET documentation](https://sshnet.github.io/SSH.NET/examples.html)
