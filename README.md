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
  before DATA. Fixed-mailbox MAIL FROM must match the exact approved sender
  address (not merely another address in the same domain); Postfix then
  canonicalizes envelope and sender headers to that address, with
  `local_header_rewrite_clients = static:all` for remote SMTP submissions.
  This is not an RFC5322 parser or proof that duplicate/malformed header
  variants and tenant Send As authorization are safely handled.
  Direct Send does not support external recipient relay.
- **Connector**: supports an external-recipient route only after an operator
  has verified a tenant-approved pre-existing Inbound Connector with static
  unshared public egress IP or the declared client TLS certificate. This
  separate tenant Connector provisioner **can create a new Connector after
  its independent guarded Preview and explicit administrator confirmation**;
  this EOP route operation itself never creates or modifies tenant objects.
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
2. **Optional security check**: read-only inventory of TPM 2.0, `tpm2-tools`, PKCS#11/HSM hints; optionally run read-only Entra policy/log access diagnostic. All three protection choices are **OFF by default**. When a TPM 2.0 node is detected on RHEL/Oracle/Rocky/Alma 8–10, the Wizard additionally offers a **separate reviewed RPM dependencies Preview** and a **typed-confirmation DNF install** action. The initial scan never installs anything; the optional package operation does not enable OAuth hardware signing, change TPM keys, start `tpm2-abrmd`, adjust SELinux or modify Postfix.
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
credentials or messages. It does not send mail. Detection now prioritizes the
**active MTA service**, not merely a `postconf` binary: Exim or Sendmail may
be active even when Postfix is installed. Mixed, unverified and inactive
service states trigger manual review instead of a false Postfix security
assessment. `SMTP_STANDARD_PORT_SOCKETS` reports observed 25/465/587
listener binds separately, without claiming the process owning those ports.

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

## Multi-sender RFC5322 From ownership guard — isolated Milter (Preview / opt-in)

A Connector with sender-policy **preserve-domain** or **masquerade** can
have multiple SMTP application identities. The existing
`reject_authenticated_sender_login_mismatch` Postfix map protects SMTP
`MAIL FROM`, but **does not validate the message's RFC5322 `From:` header**.
A private Sendmail-protocol Milter is now staged for that gap:

- `linux/sidecar-from-owner-milter.py` inspects SASL `auth_authen` and
  `auth_type` macros, the exact SMTP envelope sender, **exactly one** `From:`,
  optional `Sender:`, duplicate/ambiguous headers and headers after aborts.
  Strict Preview policy requires `From:` = SMTP `MAIL FROM` = an address
  owned by the authenticated application login. Resent headers are rejected.
- `linux/install-sidecar-from-guard.sh` stages a **separate**, unprivileged
  systemd service and private Unix socket; it requires SHA-reviewed, root-owned
  policy/script inputs and a typed confirmation. It installs no packages and
  changes **no** primary Postfix/Exim/Sendmail settings or queues.
- For those multi-sender Connector policies, the EOP route refuses Preview
  and Apply without this **running, policy-pinned** guard. When approved it
  attaches the filter to the *isolated* Postfix with
  `milter_default_action = tempfail` and explicit authenticated mail macros.
  Local `sendmail/postdrop` submissions are disabled for this mode, as they
  cannot supply trusted SMTP SASL macros.
- Fixed-sender Direct Send and Connector routes **do not require** the new
  filter and keep their existing sender canonical header rewriting.
- The guard is independently scanned and archived by isolated configuration
  Backup/Restore. It does **not** restore systemd users, runtime socket files,
  Linux/SELinux labels, host packages or tenant configuration.

Example **disposable VM only**, *before* configuring the multi-sender EOP
route (replace paths, SHA values and custom port with approved ones):

```bash
# Prepare a trusted root-only source and reviewed policy first.
sudo install -o root -g root -m 0755 linux/sidecar-from-owner-milter.py \
  /root/linuxmailrelay365-from-guard.py
# Prepare /root/sender-owners.txt manually, mode 0600, lines:
# alice@example.org smtp-app01
# billing@example.org smtp-app02
sudo bash linux/install-sidecar-from-guard.sh --check-only \
  --smtp-port 46500 --owner-file /root/sender-owners.txt \
  --engine-file /root/linuxmailrelay365-from-guard.py
# Review FROM_GUARD_OWNER_SHA256 and FROM_GUARD_ENGINE_SHA256.
sudo bash linux/install-sidecar-from-guard.sh --apply \
  --smtp-port 46500 --owner-file /root/sender-owners.txt \
  --engine-file /root/linuxmailrelay365-from-guard.py \
  --expect-owner-sha256 REVIEWED_OWNER_SHA256 \
  --expect-engine-sha256 REVIEWED_ENGINE_SHA256 \
  --confirm ACTIVATE_PRIVATE_FROM_OWNER_GUARD
```

The installed private service is not itself a mail route. It becomes active
for SMTP submissions **only** with a separately approved Connector EOP route
Apply, using the exact same reviewed owners file. If the service disappears,
Postfix must tempfail and never silently accept a spoofed sender. This
feature is **Preview** pending successful exact-commit CI socket/SMTP tests,
a real recipient negative test and RHEL SELinux Enforcing validation; do not
equate a successfully negotiated socket with proven final delivery.

## Signed Stable release gate (Preview 15, manual acceptance required)

The repository includes a guarded PowerShell 7 release check:
scripts/Test-LinuxMailRelay365SignedRelease.ps1. Before anyone can
claim a Stable artifact, it must inspect BOTH x64 and ARM64 EXEs, verify
their actual PE architecture headers, require the SAME numeric stable
ProductVersion, check valid trusted Authenticode signatures and compare
the signer certificate to an explicit pinned publisher thumbprint.
Only then can it create a new (never-overwritten) SHA256 JSON manifest.
It does not itself sign, publish or install anything and cannot replace
real Microsoft 365/RHEL test acceptance.

The Windows CI pipeline generates a separate SHA256 file for its
UNSIGNED PREVIEW executables. A preview digest is not a publisher
signature and does not make it a Stable release. Production signing
requires the organization's actual trusted code-signing certificate and
independent verification of its thumbprint. Never turn off certificate
validation to force a Stable release.

## Existing Sendmail / Exim / Postfix coexistence (guarded preview)

The Advanced SMTP Wizard now includes an entirely read-only MTA coexistence
audit. It detects which native mail services are currently active (including
Sendmail and Exim), whether Postfix CLI/configuration is already installed,
whether the dedicated LinuxMailRelay365 sidecar exists, and whether the custom
port is currently occupied. It deliberately refuses to claim a safe
installation if two native MTA services are active or systemd cannot establish
service state.

On a host with active Exim or Sendmail, the **fresh fixed-sender Direct Send and
Connector sidecar installers** also accept an explicitly opted-in foreign-MTA
preservation mode. The only SMTP listener added is on the selected private custom
port. The guard refuses installation if native MTA service identity, running
PID, current TCP 25 listener set, or a bounded root-owned configuration inventory
cannot be verified. It records an SHA-256 baseline before installing the sidecar
and checks it again after startup; on failure the new independent service and
configuration are rolled back. Exim/Sendmail, their queues and packages are
NEVER stopped, restarted, replaced, removed or silently modified.

The foreign-MTA path requires Postfix binaries to be **preinstalled** (no package
manager operation), a manually entered sidecar **FQDN** and explicit
`PRESERVE_EXISTING_EXIM` or `PRESERVE_EXISTING_SENDMAIL` confirmation. The
Windows Wizard sends the guard as a bundled resource when this mode is selected
after inspecting the primary MTA. For direct CLI use, keep
`guard-foreign-mta.py` in the same directory as the install script. Example:

```bash
# Input validation only: this never inspects production MTA services.
bash linux/install-direct-send-sidecar.sh --check-only   --smtp-port 46500 --mx-host example-com.mail.protection.outlook.com   --accepted-domain example.com --fixed-sender alerts@example.com   --preserve-primary-mta exim --sidecar-hostname relay.example.com

# Only after an operator-approved disposable-VM review and tenant acceptance:
sudo bash linux/install-direct-send-sidecar.sh --apply   --smtp-port 46500 --mx-host example-com.mail.protection.outlook.com   --accepted-domain example.com --fixed-sender alerts@example.com   --preserve-primary-mta exim --sidecar-hostname relay.example.com   --confirm-accepted-domain TENANT_DOMAIN_CHECKED   --confirm-preserve-primary-mta PRESERVE_EXISTING_EXIM
```

This is a **guarded preview**, not a verified migration or production-safe
coexistence claim. Live Exim/Sendmail + Postfix package/service, queue and
reboot testing is still required. The RHEL-family SELinux Enforcing install
remains explicitly blocked and must NOT be bypassed.

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
The fresh Direct Send and Connector installers accept only the exact
fixed MAIL FROM sender, not another local-part in the same domain. Their
private Postfix receiver canonicalizes sender headers, but it does not prove
tenant Send As authorization or validate all RFC5322 From edge cases.
Connector sender preservation and login maps require a separately reviewed
existing-sidecar migration.
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
- The XOAUTH2 sidecar installer still requires a primary Postfix. For a primary
  Exim/Sendmail, only the separate fixed-sender Direct Send/Connector guarded
  installer is currently offered; see the coexistence section. No mail queue
  migration or automatic MTA package replacement is supported.

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
verifies the selected snapshot. The Linux recovery CLI itself now separately
refuses manual `--restore ID` unless the administrator explicitly passes
`--confirm RESTORE_POSTFIX_CONFIGURATION`; failure-rollback uses a distinct
`AUTO_ROLLBACK_AFTER_FAILED_INSTALL` marker so automatic recovery remains
available. These markers are confirmations, not authentication mechanisms.
Linux packages, firewall rules, external
mail routing, DNS records and external files referenced by Postfix
are **not** included in the snapshot or rolled back; test on a nonproduction
server before using Force Replace.

### Manual authenticated SMTP client verification (Preview 15)

Once private Dovecot SMTP AUTH and the exact DNS/TLS certificate are installed,
run **on the Linux host** from an interactive terminal:

    python3 linux/verify-sidecar-auth-client.py --smtp-port 46500 --server-name smtp.example.org --login smtp-app01 --ca-file /etc/ssl/certs/approved-ca.pem

The program only connects to loopback on the chosen inbound custom port. It
verifies the server's CA chain and DNS identity with TLS 1.2+ **before**
prompting for a hidden SMTP app password, then authenticates and quits. No
email, recipient or message DATA is transmitted; no password is passed via
command-line argument or written to disk. A successful local AUTH does not
prove Microsoft 365 Connector authorization, permission, queue I/O or mail
delivery. Ubuntu CI uses disposable credentials against real local Postfix
and Dovecot; never automate this manual command with live credentials.

### Verified isolated SMTP Relay configuration backup and offline recovery (Preview)

**This is not the primary Postfix backup**. New
`linux/sidecar-config-recovery.py` provides a separate root-only, SHA-verified
snapshot of the LinuxMailRelay365 configuration, isolated systemd service/timer
units, local transport and monitoring scripts, and owned recovery-state
directories (if present). It also includes local SMTP AUTH credential hashes and
sidecar-specific keys **under `/etc/linuxmailrelay365`**. Backups never leave
Linux via the Wizard. They are sensitive and are stored under
`/var/backups/linuxmailrelay365-sidecar` (0700), with archive files mode 0600.
Backup reads fail closed on symlinks, untrusted ownership/permissions,
oversized trees or concurrent writes. Verification checks the manifest,
the archive checksum and **every** member SHA-256/type/path/ownership.

```bash
sudo python3 linux/sidecar-config-recovery.py --backup
sudo python3 linux/sidecar-config-recovery.py --list
sudo python3 linux/sidecar-config-recovery.py --verify BACKUP_ID
sudo python3 linux/sidecar-config-recovery.py --preview-restore BACKUP_ID
```

The Wizard exposes the same actions separately from primary MTA Restore under
**Advanced SMTP / Preserve Existing Mail**. Preview prints a hash of the
*current* isolated configuration. A deliberate restore requires the exact
selected archive, the reviewed current SHA and both Windows and Linux typed
confirmation:

```bash
# Only on an approved disposable test server with its own VM snapshot:
# Manually STOP the isolated sidecar, SMTP AUTH, health service and timer.
# Verify the independent queue is empty. Never purge a live mail queue.
sudo python3 linux/sidecar-config-recovery.py --restore BACKUP_ID \
  --expect-current-sha256 REVIEWED_CURRENT_SHA256 \
  --confirm RESTORE_ISOLATED_RELAY_CONFIGURATION
```

Restore verifies a **stopped isolated stack**, an empty sidecar queue, an
**unbound custom SMTP listener** (including manually started daemons) and
matching configured SMTP port; it creates a new emergency backup of the current
configuration before any file replacement. It stages only allowlisted
application-owned paths, validates the restored Postfix config and reloads
systemd's unit cache. If validation fails, it attempts a filesystem rollback
of the original isolated files. **It never starts, stops or restarts a primary
Postfix, Exim or Sendmail service**; the isolated services remain offline and
must be started separately **only after live revalidation**.

The archived scope **does include** private TLS certificates/keys, Dovecot
`smtp-auth/dovecot.conf` and salted SMTP AUTH password hashes when those files
are inside `/etc/linuxmailrelay365`. It does **not** include an external CA,
trusted root store, secret file or key referenced from another path. The
Ubuntu CI now also exercises a real private Dovecot AUTH/TLS snapshot after
credential rotation, stops independent SMTP/Auth/monitoring units, restores
verified files offline and manually checks a rotated account's real TLS login.
This is not a production DR test, and must not be marked accepted until the
**exact GitHub Actions commit** passes all jobs.

This is **configuration recovery**, not whole-machine disaster recovery:
neither primary MTA nor queued mail, external TLS keys/certificates,
OS trust store, package versions, external systemd dependencies, tenant
Connectors, Entra identities, firewall/NAT, DNS nor Microsoft 365 messages are
backed up or re-created. If a public SMTP exposure is active, the restore is
refused until the public mode/firewall is safely reverted separately. Only
unit tests and synthetic file-system rollback have been performed; actual
power-loss recovery and RHEL SELinux enforcing labels remain unverified.

### Read-only recovery scope inventory (Preview 15)

Run `sudo python3 linux/recovery-scope-audit.py --smtp-port 46500`
(on the target server, replacing the sample port). This Python 3.6+
checker reports only statuses/counts for primary Postfix, a separate sidecar,
Dovecot, systemd, queue, Sendmail/Exim coexistence and external configuration
references. It never prints certificate paths or secret material, never
sends SMTP and never changes a service. Candidate backup directory counts
are intentionally **unverified**, not proof that restoration works. A complete
external-system backup/restore, package recovery, queued-message recovery and
live reboot acceptance are still mandatory before Stable.

## Domain, sender rewriting and existing mail safety

The Wizard supports **XOAUTH2 fixed mailbox** and a separate guarded
**Advanced SMTP Direct Send/Connector outbound route** on an already installed
isolated Postfix. It stores nonsecret per-host preferences, but tenant
domain/Connector approval checkboxes are never persisted. Connector-only accepted-domain sender preservation and subdomain masquerade have a reviewed per-SMTP-login envelope MAIL FROM ownership map, SHA-verified Apply and separate Restore. RFC5322 From headers are NOT validated by this Postfix map; a reviewed Milter or fixed-header policy is required. The EOP route action itself never provisions tenant Connectors. The separate
Windows Wizard Connector provisioning action can Preview and Create a NEW
tenant Connector only with exact-tenant checks and explicit administrator
approval. Neither action changes MX, SPF, DKIM, DMARC or Exchange accepted
domains automatically.

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
| TPM 2.0, TPM2 tools | Read-only device, sysfs and command probe; separate SHA-reviewed RPM inventory (RHEL family) | Off | **Preview** and explicitly approved DNF installation of missing packages, only when TPM2 hardware and signed repository prerequisites are present. No key provisioning or background package install. |
| HSM/PKCS#11 | Read-only tools and token-slot hints | Off | Preview signer supports an explicitly staged protected OpenSSL 3 TPM2/PKCS#11 provider with PS256 and public-certificate verification; **no automatic provisioning or tenant activation**. RHEL 9 source provider builds are manual; RHEL 10 native RPM is selected separately. |
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
- Exim/Sendmail automatic migration is not supported; their fixed-sender Direct Send/Connector isolated sidecar requires an already-installed Postfix, separate FQDN, guarded service/config fingerprint and explicit approval. Real mixed-MTA acceptance remains outstanding.
- Hardware-signing helper and guarded RHEL-family TPM2 package dependency installation are implemented in Preview, but **no actual non-exportable key provisioning, GUI activation, real TPM signer acceptance, tenant delivery or automatic Conditional Access enforcement is verified**. Do not treat staged/configured options as active.
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


## RHEL-family TPM2 RPM preparation (Preview; dedicated package approval)

On RHEL/Oracle/Rocky/Alma Linux 8–10 with a detected TPM 2.0 device,
Security Center offers a dedicated read-only dependency plan (runtime,
build prerequisites, PKCS#11 on OpenSSL 3, or native provider on RHEL 10).
Use the Windows Wizard or the Linux CLI. **The default command never modifies the system:**

```bash
sudo python3 linux/manage-tpm-dependencies.py --profile runtime
sudo python3 linux/manage-tpm-dependencies.py --profile build-prereqs
```

For RHEL 9, the native `tpm2-openssl` RPM is not assumed; choose PKCS#11
with an approved OpenSSL 3 PKCS#11 provider where available, or build the
native provider from reviewed upstream sources **outside the automatic installer**.
For RHEL 10 only, `--profile native-provider` requests the packaged native
provider. Availability is determined by the signed configured DNF repositories.
On Rocky 8, `tpm2-tools` can be sourced from the official BaseOS repository;
do not enable Devel just to obtain it. Some development headers on RHEL 8/9
need their distribution's approved development repository already enabled.

After reviewing the current plan and its exact `TPM_DEPS_PLAN_SHA256`, and
only on an authorized disposable or approved machine, an administrator may
run the explicit installation command with the SHA from **that same host and
profile**. This can install or update RPM dependencies, but does not activate
hardware-based OAuth or change keys:

```bash
sudo python3 linux/manage-tpm-dependencies.py --profile runtime \
  --apply --approve-sha256 <SHA_FROM_PREVIEW> \
  --confirm INSTALL_TPM2_DEPENDENCIES
```

A mismatched plan/device/OS/package set, missing TPM 2.0, missing privilege,
missing RPM dependencies or unapproved profile blocks the operation. It never
adds repositories, bypasses package signatures, builds code from GitHub,
enables tpm2-abrmd, modifies a mail service or provisions a TPM key.
RHEL 8 uses an older default OpenSSL API; its TPM packages alone do not make
OpenSSL 3-provider signing available. Provider loading and offline signing
must be separately verified before any real Microsoft 365 tenant test.


## Offline hardware OAuth signing diagnostics (Preview)

Windows Wizard / Optional security checks now has two separate actions:

- **Inspect hardware OAuth configuration (read-only)**: checks the four fixed root-managed active/staged identity paths, file permissions and provider selection. No signing, key creation, Entra or SMTP calls.
- **Verify existing TPM/HSM PS256 signing offline**: after operator approval, invokes the installed transport's `--signing-check` as the restricted `m365mailer` account. Verifies signature against the public certificate. No mail, token or tenant change.

On a disposable Linux test host use:

    sudo python3 linux/verify-hardware-oauth.py --inventory-only
    sudo python3 linux/verify-hardware-oauth.py

The Windows executable embeds the same diagnostic script and stages it in a root-only temporary directory, removing it after use. The diagnostic checks only fixed installed paths; it accepts no custom identity, private key or module path. Results include only non-secret status codes.

**Interpretation:** `provider_ps256_certificate_match_verified` proves that the configured provider produced a signature matching the certificate. It does **not** independently prove hardware provenance, nonexportability, persistence over reboot, device attestation, Entra acceptance or Microsoft 365 mail delivery. A staged identity never becomes active through the diagnostic. Existing PEM identities remain unchanged.

**Remaining for Stable:** guarded key provisioning and key-origin verification, actual TPM/HSM signing on a target RHEL/Ubuntu host, restart continuity, stage-to-active approval and rollback, authorized Microsoft 365 tenant test and final signed desktop build.


## Guarded staged hardware OAuth cutover (Draft / Preview)

An installed XOAUTH2 transport can switch from its existing OAuth signing identity to an **already prepared** TPM2/PKCS#11 identity without replacing the primary MTA, changing SMTP routes, downloading private keys or restarting Postfix. The implementation is deliberately separate from package installation and TPM key provisioning.

**Prerequisites:** provision a hardware-backed RSA key through a locally approved provider; prepare a matching certificate and register its public certificate on the existing Entra application; configure a root-owned `hardware-staged.json` in the same identity directory; keep the previous PEM key/certificate and service user access intact. The staged identity may only change the signing provider, key reference and certificate: tenant ID, client ID and sender mailbox must match the active identity. The staged JSON must be mode `0640`, owner `root:m365mailer`, and provider configuration/key blobs must meet the same root-only policy. The software transport already supports `--candidate-config` for signing/token checks but never for mail delivery.

Wizard / Optional security checks:

1. Choose **Isolated sidecar** (recommended) or **Primary Postfix**.
2. **Review hardware OAuth cutover**: read-only SHA256 plan includes the two identity contents, public certificate, provider configuration, TSS2 blob where used, installed transport and signing helper. There are no mail, token, Entra or MTA changes in preview.
3. **Approve and activate hardware OAuth**: a separate typed confirmation is required. The manager revalidates the exact SHA plan, locally verifies PS256 signature with the staged key and obtains an application token from **real Entra**, before changing `app.json`. It writes a root-only integrity-checked snapshot of the prior identity, atomically replaces `app.json` and repeats signing + token verification against the active config. If post-validation fails, it attempts an automatic restoration of the original identity and returns failure. The old private key and certificates remain on disk for rollback.
4. **List hardware OAuth rollback snapshots** and **Restore selected backup** are separate explicitly approved actions. Restore refuses if the active identity does not match the recorded deployed SHA (to avoid overwriting unrelated changes). Rollback restores only `app.json`; it does not undo changes in Entra or delete other keys.

CLI on the *approved test host* (does not accept arbitrary config paths):

    sudo python3 linux/manage-hardware-oauth-cutover.py --target sidecar --plan
    sudo python3 linux/manage-hardware-oauth-cutover.py --target sidecar --apply --approve-sha256 <reviewed-64hex-plan> --confirm ACTIVATE_HARDWARE_OAUTH
    sudo python3 linux/manage-hardware-oauth-cutover.py --target sidecar --list
    sudo python3 linux/manage-hardware-oauth-cutover.py --target sidecar --rollback <backup-ID> --confirm ROLLBACK_HARDWARE_OAUTH

Use `--target primary` only when the installed primary Postfix uses the XOAUTH2 pipe transport and a separately approved maintenance window exists. Backups are kept under `/var/backups/linuxmailrelay365-hardware-oauth/{sidecar,primary}` with root-only directory/file permissions. Status output contains no tokens, PINs, private keys, assertions or mailbox addresses.

**Safety limitation:** an atomic JSON switch protects against torn configuration writes, but simultaneous in-flight mail jobs may use either old or new identity until the switch is complete. Use an operator-approved maintenance window for production. A token check confirms Entra application token issuance, **not** Exchange Online SMTP authorization or delivered mail. Device attestation/provenance, real RHEL SELinux Enforcing, physical hardware signing, reboot recovery and signed Stable QA remain release gates.


## Hardware OAuth candidate staging (Preview)

The Wizard can now build `hardware-staged.json` without manual JSON editing. Select `sidecar` or `primary`, choose **TPM2** or **PKCS#11**, enter the reference for an **already provisioned** hardware key, review a read-only SHA256 plan and separately confirm creation. No TPM key, private PEM, HSM PIN, Entra app, Postfix service or message is created or modified.

**Prerequisites on the selected Linux host:**

- An existing `app.json` with a recoverable root-owned key and certificate, and an installed XOAUTH2 transport and signing helper.
- A matching *public* `hardware-app.crt` inside the selected root-owned identity directory, with mode `0644` or `0640`, verified by the operator against the real hardware key.
- A root-owned `tpm2.cnf` or `pkcs11.cnf` inside that same directory, group `m365mailer`, mode `0640`; the config is the approved place to load hardware provider modules. PINs and module paths must never be entered in the Wizard key reference.
- A hardware key reference: `handle:0x81000001` or the fixed `/etc/.../tpm2-app.key` TSS2-wrapped blob for TPM2, or a PIN-free `pkcs11:object=...;type=private` / PKCS#11 `id=` URI.

The output is a separate root-owned `hardware-staged.json`, group `m365mailer`, mode `0640`. The generator copies the *tenant ID, app client ID and mailbox* from the existing active identity, forbids PEM fallback, binds its plan SHA to the existing identity and the public certificate/provider/transport bytes, refuses any pre-existing staged file, and verifies offline PS256 signature matching the hardware public certificate. A failed signature or dependency check removes only the newly published candidate; unexpected external edits are fail-closed and reported. The active identity remains unchanged.

### CLI for the same staging mechanism

Preview (does not access Entra or sign):

    sudo python3 linux/manage-hardware-oauth-cutover.py --target sidecar --stage-plan --stage-provider tpm2 --stage-key-ref handle:0x81000001

Apply the reviewed SHA256, then locally sign and verify without mail or Entra:

    sudo python3 linux/manage-hardware-oauth-cutover.py --target sidecar --stage-apply --stage-provider tpm2 --stage-key-ref handle:0x81000001 --approve-sha256 <exact-64-character-sha> --confirm STAGE_HARDWARE_OAUTH

Alternatively an experienced Linux administrator can create a root-owned `hardware-request.json` containing exactly `provider`, `key_ref`, and `provider_config` under the identity directory; `--stage-plan` without `--stage-provider` will inspect that request. No arbitrary identity paths are accepted.

**Then** register the candidate public certificate with the existing Entra application using a separately approved tenant workflow; only afterwards review the distinct **hardware cutover** SHA plan and explicitly approve its live token preflight and rollback-protected activation.

**Scope updated in later Preview sections:** guarded TPM2 RSA key creation, provider-config generation, certificate staging and Entra Graph addKey registration now have separate review/approval flows. Physical TPM provenance, Entra authorization and Exchange Online SMTP delivery are still NOT proven by CI.


## TPM2 RSA OAuth key provisioning (Preview)

The Windows Wizard / Optional security checks now offers an **explicit reviewed TPM2 key creation** workflow, distinct from package preparation, candidate staging and live OAuth cutover. It provisions a **new** RSA-2048 signing primary object in TPM2 owner persistent NV at a user-reviewed free `0x8101xxxx` handle. The key is never exported to a software private PEM. The same operation creates the matching public, self-signed X.509 certificate and a fixed TPM2 OpenSSL provider configuration in the selected root-managed identity directory.

**Prerequisites:** TPM 2.0 accessible through `/dev/tpmrm0`; TPM2 sysfs reports major `2`; TPM2 command-line tools and an OpenSSL **3+** `tpm2` provider already installed from a trusted source; an existing root:m365mailer `app.json`; `m365mailer` service account with device access; a free selected persistent handle and an owner hierarchy authorized for this command. The provisioning tool **never** installs packages, resets/clears a TPM, evicts existing objects, changes the owner password, upgrades system OpenSSL, or builds a provider from source. RHEL 8 defaults to OpenSSL 1.1; no automatic provider activation or system OpenSSL upgrade is attempted.

1. Use **Review TPM2 key provisioning**. The read-only root preflight checks device, executable availability, OpenSSL 3/provider, installed identity and its SHA, the current persistent handle inventory and that `hardware-app.crt`, `tpm2.cnf`, `hardware-staged.json` do not already exist. It outputs a reproducible plan SHA256 without modifying the TPM.
2. Separately **Approve TPM2 key and certificate creation**. The manager rechecks the exact plan SHA, obtains the cross-workflow file lock, creates an RSA-2048 sign-only TPM primary with fresh unique input and makes its transient context persistent only at the reviewed free owner handle. `tpm2_evictcontrol` is invoked **only with the transient context file**; it is never invoked with an existing persistent object to delete one. It checks public key identity before and after persistence, creates root-managed `tpm2.cnf` and public `hardware-app.crt`, and demands a local PS256 signature as the restricted `m365mailer` account matching the public certificate.
3. After success, the Wizard fills in the `handle:0x8101xxxx` reference for the separate staged hardware OAuth candidate workflow. **Nothing becomes active automatically**. The public certificate must still be registered in the existing Entra application before the separate live token test, guarded cutover and rollback.

Approved/test-host CLI:

    sudo python3 linux/manage-tpm-oauth-key.py --target sidecar --handle 0x81010001 --plan

    sudo python3 linux/manage-tpm-oauth-key.py --target sidecar --handle 0x81010001 --apply --approve-sha256 <exact-reviewed-64-hex> --confirm CREATE_TPM2_OAUTH_KEY

Both `sidecar` and `primary` targets are supported but the primary identity requires an explicit change window and separate approval. File ownership is root:m365mailer; the provider config is mode `0640` and public certificate mode `0644`. All SHA manifests and console status are secretless.

**Recovery/safety:** TPM key persistence consumes scarce TPM NV resources. A failure **after** key creation may leave a persistent handle or partial certificate/configuration; the tool refuses to delete TPM objects or overwrite any pre-existing key/cert/config. Inspect and resolve the partial state manually. This provisioning is supported only for owner hierarchies that do not require an interactive/secret owner authorization; otherwise it fails closed. No TPM provenance attestation, reboot-continuity evidence, actual Microsoft 365 delivery, or runtime SELinux Enforcing acceptance is claimed by mocked CI. Live disposable host testing remains required before Stable.


## Entra add-only public hardware OAuth certificate registration (Preview)

The Wizard now supports public TPM2/PKCS#11 X.509 registration in the **existing** Entra app, using the Microsoft Graph v1.0 **application addKey** endpoint. It never calls PATCH keyCredentials, removeKey, changes the app's permissions, creates a new app, or deletes any previous certificate. The Linux TPM/HSM key and existing software PEM private key remain only on the Linux machine.

### Preparation and identity limits

- Stage a verified `hardware-staged.json` identity with a matching root-managed public `hardware-app.crt`; keep the active `app.json` and its existing PEM private key/certificate untouched.
- In the Wizard, select the exact tenant GUID and enter the installed existing **Application (Client) ID**. The same tenant/client/mailbox must be present in both installed Linux identities. A Graph application lookup must return precisely that client and at least one valid current certificate with the SHA-1 public thumbprint of the active Linux certificate.
- Requires PowerShell 7 and official `Microsoft.Graph.Authentication`; no automatic module installation, silent login, tenant credential capture or persistence. Preview signs in using delegated `Application.Read.All` and `-ContextScope Process`; Apply requires delegated `Application.ReadWrite.All` and an account authorized to manage this application. The account and tenant are verified in each session.
- Apply works only when the **active identity uses the existing root-managed PEM key** for the Graph addKey proof-of-possession signature. A hardware-only active signer, an expired/missing Entra certificate, or a mismatched tenant/client/credential is refused (no automatic fallback to PATCH).

### Read-only Preview

The Wizard obtains the two **public DER certificates only** through SSH, verifies their SHA256 fingerprints and current/staged identity hashes, checks the live Graph app, existing credential IDs, certificate dates and that the candidate is not yet registered, then returns a review SHA256 and the exact Entra Application Object ID. The public certificate is not activated and no Graph tenant change is made.

### Explicit Apply

After typed confirmation, the Wizard re-reads Linux identity/certificate evidence. Linux generates a fresh short-lived RS256 JWT proof-of-possession signed by its **existing** private key, bound to the reviewed active/staged hashes and Graph Object ID. The private key never leaves Linux. Windows creates a per-user ACL-restricted temporary input and deletes it at the start of the Graph operation. The proof is never printed, logged, or passed on command-line arguments. Graph revalidates the application inventory SHA and the proof's audience, issuer, 10-minute lifetime, active certificate thumbprint and RSA signature.

The only Graph write is POST to `/v1.0/applications/{objectId}/addKey` containing `AsymmetricX509Cert` / `Verify` and the candidate public DER. Afterward the Wizard checks that the new credential appears and **every existing key ID, type, usage, fingerprint and validity window is unchanged**. If Graph does not return a verified result, inspect the app's certificates before retrying: the addKey request may already have completed, and the tool never auto-removes keys.

**After success** perform a separate reviewed Linux staged-to-active cutover, which checks real Entra OAuth token acquisition before and after switching and can roll back `app.json`. Public certificate registration **does not prove** that Exchange Online accepts SMTP XOAUTH2 or delivered a test message. Do not merge Stable until tested on an authorized tenant/physical TPM.


## Separate staged TPM/HSM Entra application token check (Preview)

After a new TPM2/PKCS#11 public certificate is registered in the existing Entra application, the Wizard provides a **separate staged-key token preflight**. It runs before the operator performs any active OAuth identity switch.

1. Review the exact staged hardware OAuth cutover SHA256 plan (`--target sidecar --plan` or `--target primary --plan`). The plan binds the active identity, hardware-staged.json, certificate, provider config and installed transport/signing module.
2. Select **Verify staged TPM/HSM Entra token without switching** and approve a real Entra token request. The root-owned manager takes the hardware OAuth lock, confirms the reviewed SHA, runs existing `--signing-check --candidate-config` and `--token-check --candidate-config` as `m365mailer`, and rechecks the complete plan after the network request.
3. It outputs non-secret statuses: `HARDWARE_CUTOVER_STAGED_ONLY=yes`, `HARDWARE_CUTOVER_LOCAL_SIGNING_VERIFIED=yes`, `HARDWARE_CUTOVER_ENTRA_TOKEN_VERIFIED=yes`, `HARDWARE_CUTOVER_ACTIVE_OAUTH_CHANGED=no`, `HARDWARE_CUTOVER_MAIL_SENT=no`, `HARDWARE_CUTOVER_TOKEN_PRINTED=no`.

Equivalent CLI for an explicitly authorized test host:

    sudo python3 linux/manage-hardware-oauth-cutover.py --target sidecar --plan
    sudo python3 linux/manage-hardware-oauth-cutover.py --target sidecar --token-preflight --approve-sha256 <reviewed-plan-sha256> --confirm VERIFY_STAGED_ENTRA_TOKEN

**No token is printed or saved.** An unsuccessful signature, invalid Entra certificate, network error or changed plan returns non-success without changing `app.json`. This preflight **does not** confirm Exchange Online SMTP authorization, mailbox permissions or recipient delivery. The later guarded activation repeats both checks with a fresh token, so a previously passing result cannot bypass current validation. Current physical TPM acceptance and live tenant SMTP delivery remain mandatory before Stable.


## Pre-cutover Exchange Online SMTP AUTH validation (no mail sent)

Even if a staged TPM/HSM signing key gets an Entra token, Microsoft 365 SMTP may still reject the app due to missing Exchange service-principal permission, SMTP AUTH being disabled or a mailbox mapping issue. The Wizard therefore offers **Test Exchange SMTP AUTH XOAUTH2 (no mail sent)** separately from the staged Entra token check and the active OAuth cutover.

The operator first reviews the unchanged `hardware-staged.json` cutover SHA plan. A second approval connects to `smtp.office365.com:587` using TLS with standard server certificate verification, negotiates STARTTLS, confirms `AUTH XOAUTH2` is offered, and authenticates as the configured fixed mailbox using a fresh Entra token signed by the hardware key. The SMTP session then closes. It explicitly does **not** issue MAIL FROM, RCPT TO or DATA, submit any message or alter `app.json`, Postfix, queues or tenant application registration. It never prints or stores the access token, SASL exchange or SMTP challenge.

Equivalent CLI, on a separately approved test host:

    sudo python3 linux/manage-hardware-oauth-cutover.py --target sidecar --plan
    sudo python3 linux/manage-hardware-oauth-cutover.py --target sidecar --smtp-auth-preflight --approve-sha256 <reviewed-64hex-sha> --confirm VERIFY_STAGED_SMTP_AUTH

Success returns `HARDWARE_CUTOVER_SMTP_STARTTLS_VERIFIED=yes`, `HARDWARE_CUTOVER_SMTP_AUTH_XOAUTH2_VERIFIED=yes`, `HARDWARE_CUTOVER_MAIL_FROM_RCPT_DATA_SENT=no`, `HARDWARE_CUTOVER_ACTIVE_OAUTH_CHANGED=no`, `HARDWARE_CUTOVER_TOKEN_PRINTED=no` and `HARDWARE_CUTOVER_APPLIED=no`. The manager rechecks the exact SHA plan after network validation and refuses any drift.

This preflight establishes a real authenticated SMTP session, **not** the ability to send or deliver mail to a specific internal/external recipient. SMTP RCPT/DATA, queue processing, Exchange policy and recipient acceptance still require a separately approved end-to-end delivery acceptance test. Real tenant and TPM tests remain prerequisites for Stable.


## Mandatory Exchange SMTP AUTH gates during TPM/HSM activation

The approved hardware-OAuth **activation** step now repeats the Exchange Online SMTP STARTTLS/XOAUTH2 check **twice**: once using `hardware-staged.json` *before touching* active `app.json`, and once using newly activated `app.json` *after* the atomic swap. The earlier independent SMTP AUTH preflight remains available for troubleshooting and is not trusted as a permanent authorization grant.

Order under the cross-workflow hardware OAuth lock:

1. Recompute reviewed SHA256 plan and validate current/staged identity, signer, public cert, package and runtime dependencies.
2. Sign with staged TPM/HSM key and obtain a real Entra access token; authenticate to Exchange Online with STARTTLS + XOAUTH2 as the staged sender. No MAIL FROM, RCPT TO, DATA, message or queue mutation.
3. Recompute SHA256 plan; keep root-only original identity backup; atomically publish the staged identity to active `app.json`.
4. Re-run signing + Entra token + Exchange SMTP AUTH using the **new active configuration**.
5. If any post-activation verification fails, restore the exact previous identity by SHA under the same lock. If a third party changed active identity unexpectedly, refuse to overwrite it and report manual recovery from the root-only backup.

Success requires `HARDWARE_CUTOVER_SMTP_STARTTLS_VERIFIED=yes`, `HARDWARE_CUTOVER_SMTP_AUTH_XOAUTH2_VERIFIED=yes`, `HARDWARE_CUTOVER_MAIL_FROM_RCPT_DATA_SENT=no`, and `HARDWARE_CUTOVER_APPLIED=yes`. This does NOT verify recipients, queues, actual delivered mail, host-reboot continuity, TPM hardware provenance or real production tenant policy; those need separately approved acceptance tests. The GUI uses a longer bounded timeout because each Exchange authentication check may need a fresh Entra token.


## Two-recipient Microsoft 365 OAuth SMTP delivery acceptance (Preview)

The Windows Wizard now offers a separate **operator-approved test of two real SMTP messages** after the TPM2/PKCS#11 identity is already active. This is not part of automatic hardware cutover. It does not create new tenants, register certificates, alter Postfix, or bypass SMTP AUTH.

**Review-only step:** choose the installed active sidecar/primary OAuth transport and specify two consented test inboxes. For the initial guarded acceptance, the internal recipient must have the same domain as the fixed active sender, and the external recipient a different domain; this is a **simple domain comparison**, not authoritative proof of Exchange accepted-domain membership. The Wizard allocates a unique 128-bit trace ID and reads the active root-managed hardware identity and installed transport. It returns a SHA256 plan with recipient hashes, identity/transport fingerprints and explicit `MAIL_SENT=no`. No mailbox addresses are emitted into the diagnostic status.

**Explicit apply:** a separate typed confirmation `SEND_TWO_ACCEPTANCE_TESTS` is required. The Linux script takes the same exclusive hardware OAuth lock as cutover, rechecks the plan and reserves the trace ID in a root-only single-use ledger (`/var/lib/linuxmailrelay365-acceptance/<trace>.jsonl`, mode 0600). The script invokes the installed active transport as `m365mailer` for a fixed short ASCII message to the internal address and then the external address. Neither recipient is passed as an OS command argument; addresses travel only on encrypted SSH stdin into the authorized delivery process. The signed hardware assertion obtains the Entra token; Exchange Online STARTTLS + XOAUTH2, SMTP RCPT and DATA are then used for actual submission.

The manager writes an attempt record and fsyncs it **before** each SMTP operation, and records `smtp_accepted_not_inbox_verified` only after a successful SMTP submission. If SSH disconnects, transport times out or only one message succeeds, this trace ID can **never be reused for automatic retry**. Inspect the ledger, Exchange Message Trace and both destination mailboxes before deciding whether to initiate another separately reviewed test with a new ID. No original key, Postfix configuration, mail queue or Entra certificate is modified.

The Wizard reports `SMTP_ACCEPTANCE_TWO_SMTP_SUBMISSIONS_ACCEPTED=yes` only when both SMTP submissions succeeded; it always reports `SMTP_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED=no` because SMTP 250 acceptance does not prove final inbox arrival. The operator must inspect both test inboxes/Message Trace using the trace ID and confirm or investigate independently. Bounces, security filtering, throttling, transport rules, quarantine and end-user delivery still need separate acceptance evidence.

CLI for an **authorized disposable test host**, with a JSON request provided through standard input rather than command arguments:

    printf '%s' '{"internal":"internal@example.org","external":"external@outside.net","run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' | sudo python3 linux/manage-m365-delivery-acceptance.py --target sidecar --plan

    printf '%s' '{"internal":"internal@example.org","external":"external@outside.net","run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' | sudo python3 linux/manage-m365-delivery-acceptance.py --target sidecar --apply --approve-sha256 <exact-reviewed-64hex-sha> --confirm SEND_TWO_ACCEPTANCE_TESTS

**Important:** these CLI commands use illustrative addresses only. Replace them with operator-controlled, authorized inboxes. The delivered test is direct from the installed XOAUTH2 transport to Exchange Online and **does not yet validate the local Postfix inbound listener, SASL, queue or application-to-relay mail path**. That full-system delivery acceptance and physical TPM/SELinux Enforcing deployment remain pending before Stable.


## TPM2 package and provider diagnostics (Draft)

On RHEL/Oracle/Rocky/Alma 8–10, the Windows Wizard offers a default
read-only **Automatic TPM2 RPM profile** and a separately approved DNF
installation from already-configured repositories. It now also offers
**Inspect OpenSSL 3 and m365mailer TPM access**. This second step loads
the OpenSSL `tpm2` and `pkcs11` providers in a restricted environment and
checks the existing TPM resource manager with a read-only
`tpm2_getcap properties-fixed` command under the service account.

Provider inspection cannot run together with package installation. No
hardware key is generated, no OAuth signature is made and no mail or
Entra request is sent. A provider being loadable is **not** proof that
a configured key works: separate offline PS256 signing, tenant tests,
SELinux Enforcing and reboot acceptance are required before Stable.


## Manual Postfix pre-DATA SMTP envelope acceptance (Draft)

`linux/verify-sidecar-envelope.py` is a separate, opt-in interactive CLI
probe for an **installed isolated Postfix sidecar** (not the primary MTA).
It connects only to local 127.0.0.1 at the chosen *custom inbound port*,
verifies the configured TLS hostname and certificate CA, performs STARTTLS
and SMTP AUTH PLAIN with an app-specific client password, then sends exactly
MAIL FROM and RCPT TO before resetting the session (RSET) and quitting.
**It never sends DATA or queues a message.** Sender, recipient and password
are prompted on a terminal without echo and do not enter command arguments,
stdout or diagnostic logs.

    python3 linux/verify-sidecar-envelope.py --smtp-port 46500 \
      --server-name relay.example.org --login smtp-app01 \
      --ca-file /path/to/trusted-ca.pem

Test the approved internal recipient first. In Direct Send mode, optionally
run a second check with `--expect-reject` and a non-tenant recipient, to
require a permanent SMTP 5xx refusal before DATA. Always use an approved
disposable host and real trusted TLS identity. This proves only **local
pre-DATA SMTP policy**, not successful delivery to Exchange Online, correct
Postfix queue and retries, tenant Connector permissions or recipient inbox.

The true end-to-end internal+external two-recipient acceptance using actual
Postfix DATA/queue remains blocked until a real, approved test tenant, secure
client credential handling and independently reviewed recipients are available.


## Full-message Postfix delivery on an offline CI fixture (Draft)

Ubuntu 24.04 and ubuntu-latest CI now test more than SMTP EHLO/RCPT:
after installing independent private Connector **and Direct Send** fixtures, the tests send
one synthetic **DATA** message into its real Postfix inbound listener, which
queues and forwards the message to a loopback-only SMTP sink. It asserts
exact sender, recipient, headers and body, requires the independent queue
to drain, and restores the byte-identical sidecar configuration. The
original system Postfix configuration, service and queue remain unchanged.

No message goes to Microsoft 365: the test temporarily stops the isolated
Postfix, replaces all outbound routes with [127.0.0.1]:46601, disables
fallback routing, and uses a deliberately private test recipient. A
failure with a non-empty queue leaves the sidecar stopped with its
loopback-only routing rather than restoring a real external destination.
The helper refuses execution outside a disposable GitHub Actions runner.

The **full system path to Exchange Online and actual inbox delivery**
remains unverified. Production delivery requires separately reviewed
real-tenant internal and external tests, TPM hardware signing acceptance
and Linux host-specific verification. See `docs/FINAL_ACCEPTANCE.md`.

## Universal delivery Wizard — route, sender and mail-flow preview

The Windows GUI now separates three independent decisions rather than
conflating them in a single Postfix install button:

1. **Outbound delivery**: XOAUTH2 via Microsoft 365 SMTP AUTH on 587,
   Exchange Online Inbound Connector through tenant MX on TCP 25, or Direct
   Send through the tenant MX on TCP 25 (tenant-internal recipients only).
2. **Sender handling**: for XOAUTH2, a single approved mailbox that
   **rewrites RFC5322 From and envelope sender**; the multi-mailbox preserve
   mode can be selected as an **intent-only, non-deployable plan**. For
   Connector, choose a fixed sender, preserved approved-domain senders, or
   reviewed subdomain masquerading. Multi-sender Connector requires
   SMTP AUTH/STARTTLS, a root-only sender login ownership map and a running
   RFC5322 From Guard.
3. **Existing mail**: Preserve Existing Mail remains the safe default with
   its own independent Postfix listener and queue, configurable input port
   1024–65535, optional private listener and trusted CIDRs.

**The flowchart and copyable proposed SMTP-client instructions now change
immediately based on the operator's entered values and choices**. The route
explanation includes separate input and output ports, required credentials,
recipient scope, sender rewriting, and whether the existing MTA is preserved.
RU / EN / HE delivery and sender options are supported. The diagram is a
preview, **never proof of deployment or real Exchange delivery**.

The Microsoft 365/Entra wizard step is automatically explained as optional
for Connector and Direct Send; only XOAUTH2 needs an Entra application and
mailbox. The main Postfix page exposes preflight and initial installation
of a fixed-sender Connector or internal-only Direct Send without requiring
the Advanced section. Migrating an already installed sidecar to a different
EOP route stays in Advanced and remains SHA-reviewed with backup/restore.

The normal test-mail button is currently **XOAUTH2 only**. It will not
silently submit Connector or Direct Send mail with XOAUTH2 credentials.
Approval-gated real EOP mailbox delivery remains a separate acceptance
gate. Preserve-multiple-mailbox XOAUTH2 cannot be installed or used yet;
a future implementation must verify the incoming authenticated SMTP login,
both envelope and RFC5322 From ownership, the chosen M365 mailbox mapping,
and Exchange Online app Send As permissions before enabling delivery.

## Multi-sender XOAUTH2 planning audit (read-only)

The Windows Wizard now lets you choose the outgoing method on the Microsoft
365 step, **before** any Entra app setup. Connector and Direct Send skip
OAuth-related prompts. XOAUTH2 still supports only one approved mailbox
for live sending; it rewrites the sender as that mailbox.

Selecting *Multiple authorized mailboxes — preserve From (plan only)*
exposes a root-controlled Linux TSV map path and a separate **read-only**
permission-structure audit. It checks distinct login/envelope/mailbox
entries and associated root-owned OAuth identity JSON, returning anonymous
counts and a SHA256. It neither enables a transport nor grants access.

The planned multi-mailbox mode remains blocked in Postfix Apply and Test
Send until SMTP AUTH login ownership, secure From header guard, per-mailbox
OAuth and Exchange authorization, recovery and real delivery are verified.
See `docs/FINAL_ACCEPTANCE.md` for the exact TSV column format and
permission rules.

## Read-only spoofing simulation for multi-mailbox XOAUTH2

The sender map audit also runs offline positive/negative checks: it compares
each configured SMTP login, envelope sender, intended Exchange Online mailbox,
and single RFC5322 From/Sender, rejecting cross-account and duplicate-header
spoof attempts. Only synthetic messages are parsed; no user mail or tokens are
read, nothing is delivered. The GUI reports the number of tests and explicitly
labels them **offline simulation only**. Live sender-ownership enforcement and
multi-mailbox SMTP sending are still disabled.

## Multi-mailbox: current From Guard account limit

The audit also shows whether a planned sender map fits the current 64-entry
From Guard / SMTP account capacity. This does NOT verify that the Milter is
actually running, bound to authenticated SMTP submissions or authorized in
Exchange Online. Maps beyond that limit stay plan-only; the program never
truncates sender mappings or silently changes to a less secure mode.

## Live configuration comparison without activation (multi-mailbox XOAUTH2)

On the XOAUTH2 sender-policy page the Wizard now has two independent
read-only actions: **Audit sender/mailbox mapping** and **Compare against
installed SMTP AUTH and From Guard**. The second check scans
root-controlled login/From ownership files, Postfix configuration,
Dovecot and From Guard service status, with sanitized results.

Even a result labelled `ingress_config_consistent_not_live_verified`
means only that a local ingress configuration appears consistent. It
does NOT mean any real SMTP login, RFC5322 From filtering, Exchange
Send As, multi-mailbox selection or external mail delivery is working.
All multi-mailbox Apply/Send buttons remain disabled. See
`docs/FINAL_ACCEPTANCE.md` for precise evidence and limitations.

## Read-only exact owner rule matching

The ingress comparison now checks both the literal Postfix sender-owner
regexp rules and the From Guard service's SHA256-pinned root policy.
Extra/wildcard map rules, wrong owners or a mismatched service pin are
reported as **not ready**. These are still only static checks: real
SMTP login/From rejection, multi-mailbox XOAUTH2 and tenant delivery
remain disabled until live tests and operator approval.
