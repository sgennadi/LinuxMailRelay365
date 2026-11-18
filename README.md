# LinuxMailRelay365

Linux Mail Relay for Microsoft 365 — Windows 10/11/Server GUI wizard, Linux Postfix outbound transport and scoped Exchange Online application identity. **Preview 0.1.0-preview.15 — source and GitHub Actions builds; not a verified production release.**

## New functionality in development branch (not Stable)

See [final acceptance checklist](docs/FINAL_ACCEPTANCE.md) for the complete
end-of-project test plan. These features are checked by GitHub Actions, **not
yet verified on the user's real RHEL + SELinux Enforcing host or production
Microsoft 365 tenant**. The application remains an unsigned Draft preview.

- Custom private inbound SMTP TCP port (1024–65535; 2525 is only a default),
  independent of outbound 587 (XOAUTH2) or outbound 25 (Direct Send/Connector).
- Separate Postfix queue, Dovecot 2.3/2.4 private SMTP AUTH and mandatory
  STARTTLS with 1–64 app-specific hashed accounts. Optional Add/Rotate/Revoke
  account management now has Linux source + Windows Wizard UI, guarded by a
  root-only hash source, SHA state check, explicit confirmation, backup and
  local Dovecot restart. This account manager needs a full live integration
  exercise before Stable.
- Verified local SMTP certificate identity and opt-in isolated TLS certificate
  rotation with a root-only recovery archive and local rollback. **Local
  Linux trust is not a substitute for actual client trust validation.**
- Read-only queue/deferred/oldest-age, disk and certificate-expiry health
  diagnostics; optional 15-minute systemd timer writes to local journald only.
  Opt-in HTTPS webhook alerts are available separately on the existing local
  timer, with a root-only Linux configuration and no host or message identities.
  Real notification delivery has not been independently accepted.
- Root-only pre-reboot configuration snapshot and an explicit post-reboot
  service/configuration comparison that refuses to pass without a changed
  kernel boot ID. GitHub Actions stop/start tests are not a real OS reboot.
- Read-only RHEL-family SELinux Enforcing acceptance report: TCP port type,
  queue/auth socket and file/process labels. This **does NOT automatically
  install SELinux policy or remove existing Enforcing safety blocks**.
- Optional read-only MX/SPF/DMARC/DKIM public DNS analysis (no raw TXT values,
  no tenant authorization claims and no DNS mutations).
- Microsoft 365 Direct Send/Connector preflight and **guarded outbound route
  switching on an already installed isolated Postfix**; no tenant-side
  Connector provisioning or verified real delivery. Direct Send is
  internal-recipient-only; public inbound SMTP is a separate guarded expert-only action.

## Direct Send / Connector — guarded sidecar outbound route (Preview)

The new **Advanced SMTP → Preview / Apply / Restore EOP route** workflow
configures an **already installed private isolated Postfix** sidecar, using its
existing custom input TCP port (1024–65535). The EOP destination is always
outbound port 25 with mandatory TLS and certificate hostname validation.
**The primary Postfix (port 25), original queue, and existing application
settings are never modified by this route manager.**

- **Direct Send**: permits SMTP RCPT TO only for explicitly declared accepted
  internal domains and rejects external recipients at the Linux sidecar
  before DATA. Source MAIL FROM must be within the approved domain and
  Postfix rewrites the envelope and From header to the single fixed sender.
  Direct Send does not support external recipient relay.
- **Connector**: supports an external-recipient route only after an operator
  has verified a tenant-approved pre-existing Inbound Connector with static
  unshared public egress IP or the declared client TLS certificate. This
  application **does not create or modify Exchange Online connectors**.
  It also fixes the sender to one permitted address, not arbitrary From.
- Both modes require the installed port match, exact reviewed
  SHA-256, validated SMTP allowlists, root-only recovery archive, a separate
  typed confirmation and verified outbound EOP STARTTLS. The **Restore**
  action requires the unchanged applied-route fingerprint and restores the
  original isolated XOAUTH2 configuration.
- The operator must re-acknowledge tenant accepted domain/Connector after
  changing inputs. These acknowledgements are never saved as authorization.
- A NEW private Direct Send sidecar can now be installed without an Entra
  application, XOAUTH2 certificate or mailbox-scoped role. It requires an
  existing primary Postfix, the chosen private custom SMTP port, one fixed
  declared sender, an operator-verified tenant domain and an EOP TLS preflight.
  Direct Send rejects non-tenant recipients before mail DATA; no actual tenant
  delivery has yet been tested.
- The separate Preview/Apply/Restore switch for an existing XOAUTH2 sidecar
  refuses to change routes while its dedicated queue contains messages.
  Pause applications and drain messages before switching.
- Real Ubuntu CI tests the Direct Send local SMTP MAIL/RCPT allowlist and
  checked Restore **without sending MAIL DATA**. This does not prove an
  accepted M365 Connector, a verified tenant domain, sender entitlement or
  real recipient delivery. Keep production use blocked until those checks.

## Development branch: cross-distro custom SMTP port and SELinux checks (not released)

This branch adds a **read-only** Windows Wizard action in step 4:
**Check Linux / SELinux for the selected SMTP port**. It uses the port entered in
the **Isolated SMTP port** field, **not a hard-coded TCP 2525**. TCP 2525 remains
the default; supported custom isolated ports are **1024 through 65535**.
Ports 25 and 587 remain intentionally excluded for the isolated instance to
avoid collision with standard mail services. Port availability and active
firewall rules are checked separately via **Check ports 443/587, SMTP and
firewall**.

The Python platform probe reads `/etc/os-release` as data (not as a shell
script) and identifies **RHEL 8/9/10, Oracle Linux 8/9/10, Rocky Linux
8/9/10, AlmaLinux 8/9/10, CentOS Stream 9/10**, plus Ubuntu 20/22/24/26
and Debian 11/12/13 as *candidate platforms*. Detection does **not** mean
an isolated SMTP gateway has been integration-tested on that release.
The probe checks whether Postfix and Dovecot exist, identifies Dovecot
2.3 or 2.4 (using separate validated auth-only syntax), while other
unrecognized versions fail closed, and detects
Postfix's Dovecot SASL capability, queries SELinux status and evaluates
the **actual selected port's** SELinux TCP type when `semanage` is installed.
It never installs packages, invokes `semanage port -a/-m`, runs `restorecon`,
disables SELinux, opens a firewall, or edits the existing mail server.

If an enforcing RHEL-compatible host reports `SELINUX_SMTP_PORT=unmapped`,
`conflict` or `unknown_no_semanage`, **do not assume SMTP will work**.
Review `semanage port -l`, `ss -ltn`, journald/AVC denials, the actual
Postfix instance and queue/socket file labels, and any existing service
using the selected port. Relabeling a port or a queue is a separate privileged
change requiring backup, operator confirmation and rollback support; this
branch does not automatically apply it. Custom port availability is not
equivalent to internet reachability. The existing Preserve mode's client
SMTP AUTH and TLS limitations, and its prohibition on internet exposure,
remain in force **for default, unhardened sidecar installations**. An
optional private-sidecar AUTH/STARTTLS upgrade is available below.

## Microsoft 365 tenant-side read-only readiness check

An optional standalone PowerShell 7 script under
windows/Test-LinuxMailRelay365OutboundMode.ps1 inspects the currently
authenticated Exchange Online session. It reports only aggregate accepted
domain and inbound Connector candidates, without modifying tenant objects.
Connect interactively to the correct test tenant first, then run the script
from the same session. It never creates connectors, grants app permissions,
changes mail routes or verifies message delivery. Details and sample commands
are in docs/FINAL_ACCEPTANCE.md. This is **separate** from the Linux MX TCP25
preflight and is not an automatic Connector deployment.

## Optional private SMTP AUTH + mandatory STARTTLS (development preview)

This branch adds a separate **opt-in hardening step** for an **already installed**
Preserve Existing Mail isolated Postfix. The initial isolated relay still
defaults to trusted-network-only, unauthenticated SMTP, to avoid silently
breaking existing clients. When explicitly activated, the upgrade:

- Uses the actual installed **custom TCP port (1024–65535, default 2525)**,
  not a fixed port, while preserving the same private IP listener and trusted
  CIDR restrictions.
- Starts an **independent, auth-only Dovecot 2.3 or 2.4** instance with a socket
  inside the separate Postfix queue; does not modify a host Dovecot or the
  primary Postfix service, configuration, port 25, or queue.
- Makes STARTTLS mandatory before SMTP AUTH and message submission. Refuses
  unencrypted mail submission and does not advertise AUTH before TLS.
- Supports **1–64 distinct SMTP client usernames**, each with a separate
  salted SHA512-CRYPT password hash. A single, root-owned, mode `0600`
  plaintext file contains only `username:{SHA512-CRYPT}$6$...` hash lines,
  not passwords; input is prepared **on Linux**, never copied to Windows.
- Keeps the fixed Microsoft 365 XOAUTH2 sender mailbox and existing outbound
  transport. **Different SMTP usernames do NOT grant different Microsoft
  365 sender identities**; each authorized internal client is permitted to
  submit through the same configured mailbox. Use separate Linux instances
  and/or separate Entra applications for stronger sender isolation.
- Performs a **read-only Check Only preflight** followed by an explicitly
  typed confirmation before changes. On errors it attempts to restore only
  the isolated Postfix main.cf and removes the newly created auth service.
  If restoration fails it preserves the original snapshot for manual recovery.
- Never opens a public port, changes firewall rules or disables SELinux.

**Prepare securely on the Linux server** (example *file paths only*):

```bash
sudo install -d -o root -g root -m 0700 /etc/linuxmailrelay365/auth-source
sudo install -o root -g root -m 0600 /dev/null /etc/linuxmailrelay365/auth-source/users
sudo doveadm pw -s SHA512-CRYPT
# Enter a strong password at the interactive prompt.
# Copy ONLY the resulting {SHA512-CRYPT}... value into the file.
sudoedit /etc/linuxmailrelay365/auth-source/users
# Add one unique line per application:
# app01:{SHA512-CRYPT}$6$...
# app02:{SHA512-CRYPT}$6$...
sudo chmod 0600 /etc/linuxmailrelay365/auth-source/users
```

Provision a TLS certificate and matching private key on the Linux server,
using an exact DNS SAN matching the SMTP hostname used by applications,
with a trusted issuer for the connecting clients. The Linux source private
key must be root-owned mode `0600`. The certificate must have **at least
7 days before expiry** at installation time. The installer copies the
certificate and key to a separate root-controlled directory; **certificate
renewal, account updates and rotation of an active configuration are not
automated yet**. Keep recovery material secure.

In Wizard step 4 enter the SMTP DNS name and **Linux file paths** to the
certificate, private key and hash file; click **Check SMTP AUTH/STARTTLS
prerequisites**, then **Enable SMTP AUTH + STARTTLS** and type the required
confirmation. Only the path strings cross SSH; private key contents and
hash contents remain on Linux. Afterwards configure each participating
application with the selected SMTP DNS hostname, custom port, **STARTTLS
required**, its unique SMTP username and password, and full server certificate
chain / DNS verification. Existing clients using that port without SMTP AUTH
will stop submitting until reconfigured. Apps on the original Postfix route
continue using their existing settings.

**SELinux Enforcing (RHEL family):** the hardening installer refuses to
activate until a separately verified labeling design for the independent
Postfix queue, TLS material and Dovecot SASL socket is implemented. Do not
disable SELinux as a workaround. Platform discovery and custom-port SELinux
inspection do run read-only on RHEL/Oracle/Rocky/AlmaLinux. Full RHEL/Oracle
Postfix+Dovecot+SELinux Enforcing activation is **not yet integration-tested**.
The installer and restore utility also block RHEL-family hosts reporting
**SELinux Permissive** or **unknown SELinux mode**: permissive mode is
not proof that file/queue/socket policy will work after enforcement
is enabled. Where `getenforce` is unavailable, the kernel's
`/sys/fs/selinux/enforce` status is checked and unverified RHEL
states are not treated as disabled. This protection does not change
the SELinux enforcement mode or relabel anything.
Dovecot 2.4 now uses separate config/storage version directives, named
passwd-file passdb and static userdb filters, and an explicitly typed
UNIX listener. Integration tests execute both Dovecot **2.3 (Ubuntu
24.04)** and **2.4 (current ubuntu-latest)** against real isolated
Postfix services: TLS handshake,
wrong/correct SMTP AUTH credentials, no mail transfer and unchanged primary
Postfix. No end-to-end Exchange Online delivery is claimed.

## Verified local SMTP STARTTLS certificate identity (Preview 12)

On Wizard step 4, enter the **SMTP server DNS name** that clients will
actually use, along with an optional Linux CA bundle path. Leave the
optional CA path blank to use the **Linux system trust store**. If using
a private or self-signed enterprise CA for your internal SMTP clients,
supply an administrator-approved CA certificate/bundle path already on
Linux. The optional CA file is **not** a private key and is never copied
to Windows.

When **Audit installed SMTP** or **Check SMTP AUTH/STARTTLS prerequisites**
detects that the installed isolated Postfix already uses mandatory
STARTTLS and SMTP AUTH, the wizard can perform an additional **read-only**
local TLS identity check against the actual installed custom port
(default 2525, but not hardcoded). The Python 3.6+ script
`linux/verify-sidecar-tls-identity.py` always opens the TCP socket to
`127.0.0.1`, while presenting the entered DNS hostname as SNI and
enforcing **both CA chain trust and exact certificate DNS identity**.
It checks that AUTH is not offered until TLS is established and that
TLS 1.2+ is negotiated. It performs **no SMTP login or message
submission**, does not read SMTP passwords/hashes or private keys,
and does not open firewall rules. If verification fails, the status
is **not verified**, never silently accepted.

Real Ubuntu CI now checks a test-trusted certificate, rejects a wrong
DNS name with the same CA, rejects a self-signed certificate without
its explicit trust anchor, and refuses a mismatched custom port.
The results explicitly distinguish a **verified local Linux
certificate chain and DNS identity** from unverified trust on actual
Windows/Mac/mobile/application clients, external network access or
Microsoft 365 delivery. The verification does not override a client's
TLS trust or DNS rules; those must be separately tested from the client.

## Opt-in restore of isolated SMTP AUTH + TLS (security downgrade)

A separate **Restore previous private SMTP without AUTH/STARTTLS** action is
available in Wizard step 4. It is intended for reverting the private sidecar
to the **original trusted-network-only Postfix policy**, e.g. after an
application compatibility issue. **It does NOT remove the sidecar or clear
its mail queue**, and never changes the primary system Postfix or Microsoft
365 application identity. The custom port is always discovered and verified
against the actual Linux installation; **2525 is not hard-coded**.

The restore is an intentional **security downgrade**. After confirmation,
applications on approved private CIDRs can submit without per-client
credentials or mandatory TLS. **Never expose this restored listener to the
public internet or a broad/untrusted network.** Update affected applications
explicitly; do not silently change their SMTP settings.

Safety checks before any changes: live sidecar and auth service, exact
custom port, non-public IPv4 listener, RFC1918-only trusted networks, strict
original Postfix client/relay/recipient policies, root-owned pre-auth
snapshot, activation-time SHA-256 fingerprints of `main.cf` and
`master.cf`, and an exact current SHA-256 supplied by the Wizard after
its read-only preflight. Conflicting changes, missing manifests, unknown
relay rules and unsupported SELinux Enforcing state cause a **fail-closed**
refusal. The operator must type **RESTORE TRUSTED SMTP** in the GUI.

The root-side script uses an exclusive lock shared with the AUTH/TLS
activation operation and makes a **new root-only recovery archive before
modification** under `/var/lib/linuxmailrelay365-sidecar-auth-recovery`.
The archive contains the original active AUTH config, its TLS key and
**password hashes**. It must be retained securely, protected from backup
exposure and retired under an approved retention policy. After a verified
restore, the separate auth-only Dovecot service and its active files are
removed; Postfix is reloaded in place, not restarted globally. Failure
after reload attempts to restore the previous authenticated Postfix
configuration and Dovecot service. If this verification fails, the archive
remains available for **manual recovery** and the Wizard reports failure.

**Compatibility limitation:** AUTH installations from development builds
before the activation SHA-256 manifest was introduced cannot be restored
automatically. First inspect and back them up manually; never fabricate
or retroactively assign a fingerprint. The automated restore remains
blocked for RHEL-family SELinux Enforcing, Permissive or unknown states
until the complete queue/socket/file-context behavior has been
integration-tested. No tool silently disables or relabels SELinux.

No successful local restore test guarantees real Exchange Online delivery;
verify token authorization, queue state and a final delivered test message
after the maintenance change.

## Read-only SMTP AUTH recovery archive verification (development preview)

The existing **Audit installed SMTP** and **Restore AUTH/STARTTLS** steps now
automatically include a read-only recovery-archive report. No new popup or
separate button is required. The Linux audit inspects
`/var/lib/linuxmailrelay365-sidecar-auth-recovery`, never sends email,
opens firewall ports, modifies backup files, or returns secrets to Windows.

It reports only aggregate status codes, the number of inspected archives,
and that **retention remains a manual administrator responsibility**.
For each `recovery.XXXXXXXX` entry it verifies the archive and parent
directories are root-owned and mode 0700, that required backups exist
without symlinks or unsafe permissions, and that archived `main.cf`
and `master.cf` match their activation-time SHA-256 manifests. TLS
private-key contents and client password hashes are **never read or
included in the report**.

Possible statuses are `not_created`, `empty`, `verified_root_only`,
`incomplete_or_tampered`, `unsafe_root_directory`, or a manual-review
status for unexpected entries or excessive archive counts. A successful
integrity report does **not** prove recoverability after a disk or OS
failure, nor does it guarantee backups are encrypted off-host.
There is **no automatic pruning**, because archived credentials and keys
must follow the organization's explicitly approved retention policy.

The Ubuntu integration smoke additionally checks controlled systemd
cold-start of both isolated services on the actual selected TCP 2529,
revalidates SMTP AUTH after STARTTLS and confirms the primary MTA remains
unchanged. This is a service-stop/start simulation, **not a full VM reboot**.

## Read-only audit of the installed custom SMTP port (development)

The **Audit installed SMTP: AUTH/TLS, port, SELinux (read-only)** button in
Wizard step 4 checks the **port already installed on the Linux server**.
If the value typed into the Wizard differs from the installed port, the
button explains the mismatch and audits the actual live configuration.
It does not silently change the listener or install anything.

This audit verifies the private IPv4 binding and Postfix `mynetworks`,
compares the port file against the isolated `master.cf`, checks active
systemd units and the Postfix relay / recipient / client restrictions,
and looks for insecure SMTP authentication settings. When AUTH + mandatory
STARTTLS is configured, it performs a loopback-only SMTP feature handshake
before and after STARTTLS, without sending credentials, `MAIL FROM`,
`RCPT TO`, `DATA` or a message. It also checks restrictive ownership
and permission **metadata** on the private key/hash files, without reading
their contents.

On RHEL/Oracle/Rocky/AlmaLinux hosts with SELinux enabled, it inspects
the custom TCP port's SELinux type and the existence and labeling of the
isolated Postfix queue, AUTH socket and credentials. **A label being present
is not proof that the SELinux policy permits those operations.** The audit
never changes policy, runs `setenforce`, installs dependencies or opens
firewall ports. In SELinux Enforcing mode the final security result
remains **needs_manual_review** until an actual enforcing integration
test of process, queue and socket access is supported.

The output contains only status codes, the selected TCP port and explicit
`MICROSOFT365_DELIVERY_VERIFIED=no` and
`PUBLIC_INTERNET_ACCESS_VERIFIED=no`. It does not reveal internal
addresses, SMTP client usernames, salted hashes, private keys, mail
contents or tokens. A passing local STARTTLS probe does **not** verify
the SMTP certificate against an actual client DNS name and trusted
certificate authority; complete that test from a client separately.
The report distinguishes authenticated local SMTP, private but
unauthenticated SMTP, and states requiring manual review.

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

## Optional internal SMTP clients

The installed Postfix listens on **loopback only by default**. For programs on
other machines, the Wizard can explicitly set a local RFC1918 IPv4 listener
and one or more trusted RFC1918 client CIDRs. These values are checked before
installation; wildcards and public client networks are rejected. This does not
provision a firewall or grant internet access. Existing Postfix still requires
a separately approved override, and the default **Preserve Existing Mail**
mode refuses modifications to an existing MTA.

Example for a fresh Linux relay: listener `192.168.50.10`, trusted client
network `192.168.50.0/24`. SMTP is **not authenticated per client** in this
mode; every authorized client in a trusted network can submit mail as the
configured mailbox. Use narrow subnets and host firewall rules, and do not
forward public SMTP traffic to this port. SMTP submission from a trusted LAN
remains unencrypted until separate TLS listener support is implemented.

## Live Preserve Existing Mail diagram and existing public SMTP audit (Preview 10)

In step **4 — Configure Postfix**, choose **Preserve Existing Mail** (on by
default). Before installation click **Inspect existing MTA and routing**. This
performs a *read-only* Linux MTA scan **and** an audit of existing SMTP listener
bindings, Postfix `postconf` relay/recipient restrictions, `mynetworks`,
per-service master.cf overrides, SASL authentication and inbound TLS. The
auditor produces only structured status codes, not raw configuration,
credentials or messages. It does not send mail.

**Public SMTP listener is NOT equivalent to open relay.** A listener on
`0.0.0.0:25` may legitimately accept inbound mail while
`reject_unauth_destination` blocks forwarding. The audit distinguishes
*potentially public bind*, *restricted relay rules*, *suspected unsafe relay*,
*unknown*, and *no matching active listener*. This is a configuration
heuristic, **not** proof of an open relay or actual internet reachability:
NAT, firewall, externally sourced SMTP and permitted recipient tests are not
performed. Unknown or inconclusive findings require manual verification.

When Preserve is selected, an in-Wizard **live route diagram** draws both
independent flows from the *actual entered values*, with no invented host,
mailbox, Tenant, subnet or port:

- **Old applications → existing Postfix → existing routes and queue**.
  Existing applications stay on their original SMTP port and destination.
- **New applications → separate Linux SMTP listener at the selected port →
  isolated Postfix queue → Microsoft 365 XOAUTH2 → original recipient**.
  The sender `From` and SMTP envelope sender are rewritten to the
  selected and Exchange-authorized Microsoft 365 mailbox.
- The diagram updates as the user edits Linux host, selected listener IP,
  port, sender mailbox, Tenant, verified domain, trusted CIDRs, transport and
  public-Internet plan. Missing inputs are shown as *not selected*.
  **Advanced Connector/Direct Send routes are not assumed deployed** until
  the operator performs the separate guarded Apply action and verification;
  Connector sender preservation and subdomain masquerade require separate review and Apply.
- A read-only, translated **client SMTP setup guide** (RU/EN/HE) below the
  diagram can be copied with one button, without copying credentials or
  private keys and without resetting the Wizard scroll position.

**Client configuration after successful deployment**: point only the *new*
programs to the configured private Linux IPv4 and custom port (default 2525).
If the listener IP is omitted, use `127.0.0.1` **only from applications running
on that same Linux host**. On remote programs, use the Linux private IPv4,
an explicitly allowed trusted CIDR and a matching local firewall rule. The base sidecar uses a trusted private network; optional Dovecot
SMTP AUTH with mandatory STARTTLS can be enabled in Advanced SMTP. Neither
mode is certified for public Internet exposure. Before switching programs, send a test
message and verify actual Microsoft 365 delivery.

## SMTP firewall and optional public internet exposure

Preview 9 adds a read-only wizard network preflight for outbound Entra HTTPS
**TCP 443**, Exchange Online client submission **TCP 587**, the custom
SMTP port, and firewall identification (UFW, firewalld, other/ambiguous).
Only active UFW/firewalld instances can receive firewall rules, after the
operator enters `OPEN TRUSTED SMTP` in a confirmation dialog. Rules restrict
the source CIDR **and destination private IPv4 and destination port**. This
does **not** enable disabled firewalls or automatically forward router ports.
Testing local TCP connectivity cannot verify remote client reachability.

**Public Internet SMTP is off by default and requires a separate expert-only
Preview / Apply / Restore operation (Preview 14).** Checking the host-scoped
plan does not change Postfix, firewall or NAT. The ordinary
`network-firewall.sh` continues to block every
`--public-internet --apply` request. Only the dedicated
`linux/manage-public-smtp.py` can expose the selected local RFC1918 IPv4
and custom port to all IPv4 sources after prerequisites: mandatory STARTTLS
and Dovecot SMTP AUTH, verified system CA and exact DNS/SNI, fixed XOAUTH2
sender policy, Postfix rate limits, active systemd health timer, active
Fail2ban jails, reviewed SHA-256 and typed risk confirmation. It does not
enable a disabled firewall or modify the NAT/router.

An Internet-facing listener is **not** an open relay if authenticated relay
restrictions reject unauthorized RCPT, but public submission is inherently
higher risk: compromised SMTP credentials, password guessing, spam,
traffic exhaustion, reputation loss and Microsoft 365 blocks.
Fail2ban jail existence alone does not prove it captures the isolated
Postfix/Dovecot service's logs. Operators MUST run a real ban drill,
check monitoring, external client CA trust and tenant mail delivery.
Successful local preflight/apply does NOT establish public reachability or
abuse resistance. RHEL SELinux Enforcing activation remains blocked until
real server acceptance.

Restore first removes the exact public firewall rule and then restores
the SHA-guarded private Postfix configuration, retaining a root-only
archive for each activation. AUTH/TLS downgrade, certificate rotation and
EOP re-routing refuse to operate while public submission remains active.
**No Stable release is implied.**

## Generate a strong per-application SMTP password (Preview 15)

Advanced SMTP now provides a one-time password generation action.
After checking a safe account login and obtaining separate confirmation,
Linux uses a cryptographic random generator and OpenSSL SHA512-CRYPT with
a random salt. It creates only root-owned, mode 0600, hash-only and
login:hash files under /etc/linuxmailrelay365/generated-accounts/ (0700).
No plaintext password file is created.

The one-time plaintext travels back over the administrator's verified SSH
connection to a dedicated masked Windows dialog. This value is not written
to diagnostics, wizard state or a mail configuration. The admin must copy
it securely before closing the dialog. Clipboard copying is an explicit
button action and leaves a clipboard copy under the admin's control.
Abandoned hash files need deliberate root-only cleanup; the generator
refuses to overwrite existing files. Password generation alone does not
create a Dovecot account or change Microsoft 365. The usual Preview/Apply
flow for Add/Rotate is still required.

Do not run the standalone generate command using tee, transcript recording
or an unattended job: it intentionally emits a ONE-TIME password to stdout.
The Windows Wizard consumes that sensitive line without logging it.

## RHEL SELinux Enforcing live SMTP handshake test (Preview 15)

A separate expert-only read-only live test checks an ALREADY-installed isolated
Postfix on the selected custom loopback TCP port, with SELinux truly Enforcing.
It requires Postfix, Dovecot and the verified smtp_port_t mapping, checks
installed SASL and mandatory STARTTLS policy, validates relevant file/socket
SELinux labels, and negotiates CA-trusted TLS 1.2/1.3 with the configured
certificate DNS name. SMTP AUTH must remain hidden before TLS and be advertised
after TLS. No credentials, MAIL FROM, RCPT TO or DATA are sent. If any check
fails, the tool refuses rather than disabling SELinux or changing policies.

This local test is an additional acceptance gate, NOT a production signoff.
A successful TLS/AUTH advertisement does not prove that the Linux kernel
allows actual Dovecot password lookup, Postfix queue processing, network
clients after reboot or Exchange Online delivery. Review AVC denials and
run real authorized end-to-end tests separately.

## Optional Microsoft 365 tenant Connector creation (Preview 15)

Advanced SMTP includes Preview NEW tenant Connector and Create NEW reviewed
tenant Connector actions. PowerShell 7 and ExchangeOnlineManagement prompt
for an administrator Device Code and verify that the Exchange Online
session belongs to the selected tenant GUID. The accepted mail domain must
already exist in that tenant. Preview only reads the Connector inventory,
checks duplicates and returns an SHA-256 that is rechecked before Apply.
Sensitive object IDs, account addresses, IPs, client secrets and raw cloud
metadata are not printed in the status report.

Creation requires explicit typed approval and EXACTLY ONE declared identity:
a static exclusive public egress IPv4 or a certificate DNS name matching the
sending Linux host's accepted-domain certificate. Only a NEW enabled
OnPremises inbound Connector is created. No existing Connector, tenant
permissions, mailbox, DNS record, Security Defaults or local Postfix
configuration is modified. The new object is queried after creation, but
the actual Connector authorization, source IP ownership, TLS identity and
recipient delivery still require real test-tenant acceptance. Reuse an
existing properly verified Connector rather than creating a duplicate.
Emergency cloud revocation requires manually disabling that NEW Connector
in Exchange Admin Center under approved change control.

### Sidecar detection safeguard

Direct Send and new Connector sidecars have no OAuth app.json identity.
The Wizard therefore detects an installed sidecar from its dedicated
Postfix main.cf, master.cf and custom smtp-port marker, rather than
requiring OAuth credentials. A previously installed fresh sidecar must
be recognized and must block a second install/overwrite. The legacy
XOAUTH2 route-switch manager still does not support converting a
fresh non-OAuth gateway into XOAUTH2; do not assume that Restore does.

## Fresh independent Connector without OAuth (Preview 15)

The Advanced SMTP Wizard now provides a separate Preview/Install for a NEW,
fixed-sender Microsoft 365 Connector gateway when the host already has a
primary Postfix but has no isolated SMTP sidecar. No Entra application,
XOAUTH2 certificate or SMTP AUTH credentials are required for outbound
Connector delivery. The installation creates only a dedicated Postfix config,
service and queue, using the chosen private inbound TCP port (1024-65535)
and selected RFC1918 listener/client networks. Existing primary mail
configuration, port 25 and queue remain untouched.

The selected EOP MX is reached on outbound TCP 25 with mandatory verified TLS.
The operator must separately verify that an existing inbound Connector in
the exact Microsoft 365 tenant authorizes the actual public egress IP or
validated certificate and that the declared sending domain is accepted.
A certificate is only read from the root-controlled Linux path and must be
matching, unexpired and readable by the Postfix process. Public SMTP
ingress is never opened and DNS/MX/Exchange objects are not modified.
Unlike Direct Send, an authorized tenant Connector may relay to external
recipients, which increases the importance of limiting private submitters.
The fresh installer uses a fixed sender only; Connector sender preservation
and login maps require a separately reviewed existing-sidecar migration.
Real tenant recipient acceptance and full rollback still need host testing.

## Optional HTTPS health notifications (Preview 15)

The 15-minute systemd health timer remains local by default. A separate,
opt-in HTTPS webhook adds confidential alert delivery without altering
the primary Postfix, mail queue, NAT or firewall. A root-owned 0600
configuration file at /etc/linuxmailrelay365/health-alerts.json contains
the webhook URL. Never type a real webhook URL, token or secret into
the Windows Wizard.

Example configuration for a NONFUNCTIONAL documentation endpoint:

```json
{
  "url": "https://hooks.example.org/health-event",
  "timeout_seconds": 8,
  "repeat_hours": 24
}
```

After securely creating this file on Linux, choose Advanced SMTP > Enable
HTTPS SMTP health alerts. The Wizard previews SHA-256 and requires typed
confirmation. It adds a reversible systemd ExecStartPost drop-in to the
existing timer and does not send anything during preview. Only aggregate
severity, alert codes and numeric queue/disk/certificate metrics are sent,
not hostnames, addresses, credentials or message bodies. Incident/recovery
transitions are deduplicated, with a configurable periodic reminder.

The sender checks all DNS addresses are public, pins the HTTPS connection
to an approved IP, verifies original-hostname SNI/CA, ignores proxies and
refuses redirects. It never prints the private webhook URL or response body.
Disabling alerts removes only the owned drop-in; local monitoring continues.
The root-only URL file is retained for administrator review. Live incident
delivery and receiver routing must still be tested before production.

## Real Ubuntu/Postfix sidecar smoke test (Preview 11)

GitHub Actions now provisions an **ephemeral Ubuntu runner** with real Postfix,
creates a temporary certificate (no Entra tenant access), and starts an
**independent Postfix instance on TCP 2529**. It verifies an actual SMTP
greeting, separate queue/data directories, unchanged existing
`/etc/postfix/main.cf` and `master.cf`, unchanged primary service
and queue path, and rejects an attempt to reinstall the already-present
secondary instance. The test never submits a message to Microsoft 365
or contacts any mailbox; it verifies the local SMTP listener only.

CI must report the `ubuntu-postfix-smoke` job as passing before this
functionality can be considered locally integration-tested. This
**does not confirm real OAuth2 app authorization, Microsoft 365 SMTP
submission, recipient delivery, multi-distribution compatibility,
certificate rotation, or live production readiness**.

## Preserve Existing Mail: isolated Postfix channel (Preview 9)

When the read-only Linux inspection finds **existing Postfix**, the default
**Preserve Existing Mail** setting now configures an independent Postfix instance
with its own configuration, queue and systemd unit. The only submission port is
**TCP 2525 by default**, configurable per Linux (1024–65535);
its default listener is **127.0.0.1 only**. Optional remote
submission requires an explicit local RFC1918 IPv4 and trusted RFC1918 CIDR.
This is an unauthenticated/trusted-network-only listener, with no inbound TLS
yet: restrict it to localhost unless the network is isolated and trusted.

- Existing Postfix `/etc/postfix/main.cf`, `master.cf`, port 25, queue
  and `postfix.service` are not modified, reloaded or restarted.
- Sidecar configuration: `/etc/linuxmailrelay365/sidecar-postfix/`; identity:
  `/etc/linuxmailrelay365/sidecar-identity/`.
- Sidecar queue: `/var/spool/linuxmailrelay365-sidecar/`;
  sidecar service: `linuxmailrelay365-sidecar.service`.
- The XOAUTH2 transport enforces its own app mailbox and private certificate.
  It does **not** preserve arbitrary input `From:` headers.
- Diagnostics and test-mail submission read the installed port from the Linux
  sidecar (not a stale Windows preference) and use the
  isolated queue when a sidecar installation is detected.
- Existing sidecar installations are never overwritten silently. Failed new
  installations remove their new service/configuration while retaining the
  separate queue for inspection. This is *not* a full restore of all packages.
- Only existing Postfix is supported by this mode in Preview 9.
  Existing Sendmail/Exim are protected; their sidecars are not implemented.

**Deployment limitation:** the installer has not yet been exercised against
a real running Postfix service and Microsoft 365 tenant. Perform the first
end-to-end test in a disposable VM before using production systems.
No production guarantee is implied by CI builds and source tests.

## Force Replace, Backup & Restore (Preview)

**Preview 7 improvement:** the read-only MTA inspection computes a SHA-256
fingerprint of `main.cf` and `master.cf`. Force Replace is not offered
unless both files are readable and the fingerprint is valid. The wizard checks
that nothing changed since inspection; the Linux installer independently
rechecks the fingerprint before the backup and after its verification.
A mismatch aborts without changing mail settings. This does not cover
every external Postfix map, database or referenced TLS key, so a verified
full-tree snapshot and operator confirmation remain mandatory.


Force Replace is **hidden until the Wizard reads the Linux MTA state**.
Only an existing Postfix unlocks the option. It is OFF by default, and
Preserve Existing Mail remains ON. Existing Sendmail/Exim, partially detected
MTA states, and changed Postfix routes are blocked.

To replace an existing Postfix, the operator must turn off Preserve Existing
Mail, check Force Replace, and type **REPLACE POSTFIX** in a warning dialog.
The Linux installer independently requires
`--force-replace --confirm-force-replace REPLACE_POSTFIX_CONFIG`.
It creates a root-only snapshot of the full `/etc/postfix` directory
(including keys, if present), the M365 transport and recorded service state
under `/var/backups/linuxmailrelay365`. The tar.gz SHA-256 is verified
before the installer changes any settings. Snapshot IDs, never archives or
configuration contents, return to Windows.

A failing forced installation attempts an automatic restore; a failed
restore is reported as critical rather than silently declaring success.
The Wizard also provides **Create verified backup**, **List verified
backups** and **Restore selected configuration**. Restore requires typing
**RESTORE POSTFIX**, creates a separate pre-restore safety snapshot and
verifies the selected snapshot. Linux packages, firewall rules, external
mail routing, DNS records and external files referenced by Postfix
are **not** included in the snapshot or rolled back; test on a nonproduction
server before using Force Replace.

## Domain, sender rewriting and existing mail safety

The Wizard supports **XOAUTH2 fixed mailbox** and a separate guarded
**Advanced SMTP Direct Send/Connector outbound route** on an already installed
isolated Postfix. It stores nonsecret per-host preferences, but tenant
domain/Connector approval checkboxes are never persisted. Connector-only accepted-domain sender preservation and subdomain masquerade have a reviewed per-SMTP-login envelope MAIL FROM ownership map, SHA-verified Apply and separate Restore. RFC5322 From headers are NOT validated by this Postfix map; a reviewed Milter or fixed-header policy is required. The app never provisions tenant Connectors or changes MX,
SPF, DKIM, DMARC or Exchange accepted domains automatically.

**Safe default for existing Linux:** Preserve Existing Mail is ON. Before
applying any Postfix changes, the wizard runs a read-only Linux MTA probe.
Existing Postfix is left untouched in Preserve mode. Sendmail and Exim are
always left untouched. The recommended separate-sidecar mode **preserves the primary Postfix
configuration, port and original queue**; intentional Force Replace is
different and requires its own explicit high-risk warning and backup.
Changing existing primary Postfix routes is not a hidden prerequisite for
Direct Send or Connector on the isolated sidecar.

**XOAUTH2** uses one Exchange-authorized sender mailbox per server; the
transport rewrites the message From and envelope sender to the authorized
mailbox. No extra Postfix domain masquerading is required. The guarded private
**Connector route** configures EOP TCP25 with fixed sender, accepted-domain
preservation or restricted subdomain masquerade. It requires an already
verified tenant Connector and explicit attestation, **not** automatic
Exchange authorization. Per-SMTP-account MAIL FROM ownership is checked against a
root-only Linux source file and existing Dovecot logins. RFC5322 From header
identity and Exchange Online Send As permissions remain separate checks.

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

The app **can build without access to the private UniversalUpdater** module: public CI uses a small read-only GitHub Releases checker. If you restore the user's pinned `UniversalUpdater` module from `MODULES.lock`, the full shared release-verification code is compiled instead. The app uses `SSH.NET` v2026.0.0 via NuGet. GitHub Actions builds preview Windows x64/ARM64 executables; physical UI testing
and code signing are still outstanding.

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

## Windows interface (Preview 5)

- Original multi-size `.ico` embedded in the application and shown in its main window.
- Unified compact HiDPI-aware outlined buttons with vector glyphs (SSH, cloud, shield, upload, diagnostics, refresh).
- Five-step wizard; one selected Microsoft 365 tenant, password/key-based SSH, optional sudo password.
- **Diagnostics Journal**: allowlisted operation status events only. `Copy privacy-safe diagnostic report` and `Save privacy-safe JSON report` on the Diagnostics step. Raw activity is only local and is redacted before display.
- No automatic update installer, no stable production release yet.


## GitHub

The repository exists at [sgennadi/LinuxMailRelay365](https://github.com/sgennadi/LinuxMailRelay365). The source package contains no GitHub tokens. Public CI builds self-contained executables after the sources are pushed; downloading a CI artifact is not the same as installing a signed stable release.

## Known preview limitations

- Real SMTP/Entra tenant and SSH hosts have not been exercised; verify in a dedicated test tenant and server before production.
- Existing Sendmail/Exim remain untouched; automatic migration and isolated sidecars for them are not yet supported.
- Hardware-backed OAuth signing and automatic Conditional Access enforcement are not implemented. Do not treat planned options as enabled.
- Microsoft Entra tenant discovery uses `Az.Accounts` (installed for CurrentUser when absent) and `Get-AzTenant`. Azure APIs might not enumerate all external/guest tenants. User can enter the correct Tenant GUID manually. Discovery and actual Graph/Exchange provisioning are separate administrative sign-ins in this preview. Exchange tenant identity is independently checked using `Get-ConnectionInformation` before any changes.
- The wizard uses PowerShell 7 for Microsoft 365 provisioning. The operator must consent with an authorized administrative account.
- XOAUTH2 application signing certificate renewal exists in the Linux CLI
  (--rotate-only/--activate-only); the Entra-verified, mailbox-scoped managed
  GUI rotation workflow remains incomplete. Incoming SMTP TLS certificate
  rotation is separately implemented for the private sidecar.
- Password mode and MTA setup need a Windows/.NET build and server integration test before a stable release.

## Sources

- [Microsoft Conditional Access for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity)
- [Microsoft Graph permission model for Exchange Application RBAC](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
- [SSH.NET documentation](https://sshnet.github.io/SSH.NET/examples.html)

### Connector sender policy (Preview 13)

In Advanced SMTP, the isolated existing XOAUTH2 sidecar route can be switched to an explicitly verified Microsoft 365 Inbound Connector. The sender policy is selected independently:

- **Fixed mailbox:** rewrite to one approved sender (also mandatory for Direct Send).
- **Preserve accepted domain:** permit the accepted-domain envelope sender unchanged; other envelope domains are rejected.
- **Masquerade subdomain:** rewrite an approved subdomain envelope/header sender to the accepted domain using a scoped Postfix regexp map; unrelated domains are rejected.

This is not an Exchange Online Send As grant, does not validate header ownership in Microsoft 365 and does not change an existing primary Postfix or queue. Automatic route changes require an empty isolated queue, reviewed SHA-256, explicit tenant attestation and an archived rollback. Public Internet SMTP and unverified RHEL SELinux Enforcing installation remain intentionally blocked.



For non-fixed Connector sender modes (preserve domain or subdomain masquerade),
prepare a root:root 0600 Linux-only sender owner file with 1–64 lines,
using exactly one address and one existing Dovecot SMTP login per line.
For example: alerts@example.org smtp-app01
The Wizard reads only the absolute path; the root-side route manager verifies
SMTP AUTH + mandatory STARTTLS, that each login exists, every address is
within the tenant-accepted domain or an approved subdomain, and the file's
SHA-256 has not changed since Preview. Postfix enforces
reject_authenticated_sender_login_mismatch BEFORE the domain allowlist;
a successful domain allowlist must never bypass sender-login ownership.
This checks envelope MAIL FROM; it does NOT compare RFC5322 From headers.
Use a separately reviewed header-enforcement Milter or fixed sender policy
where header-level anti-spoofing is required. All client applications need
an individual authorization and live delivery test.

### RHEL-family custom SMTP port label (Preview 13)

The Wizard's Advanced SMTP section can check, explicitly add, and restore a missing `smtp_port_t` SELinux port assignment using `semanage port`. Operations require a reviewed policy SHA-256, an unclaimed port, typed confirmation, a root-only rollback record and an empty TCP listener for restoration. RHEL, Oracle Linux, Rocky, AlmaLinux 8/9/10 and CentOS Stream 9/10 are identified without disabling SELinux. SELinux Enforcing installation, file/queue/socket label policy and real SMTP verification are **not** automatically approved by this preparatory action.
