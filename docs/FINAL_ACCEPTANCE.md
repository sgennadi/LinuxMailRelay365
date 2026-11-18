# Final acceptance plan — LinuxMailRelay365

**Development preview only. Do not merge, deploy to production or publish Stable without the evidence below.** The user will run the final acceptance checks after the development work is complete.

## What is implemented vs blocked

| Feature | State | Acceptance evidence still needed |
| --- | --- | --- |
| Private isolated Postfix, user-selected TCP port 1024–65535 | Implemented | Run on each production-target OS |
| Independent Dovecot SMTP AUTH with mandatory STARTTLS | Ubuntu integration-tested | Real client password, CA chain and DNS test on RHEL family |
| Per-client salted hash Add/Rotate/Revoke | Preview | Live independent client/rollback exercise |
| SMTP certificate rotation and archived rollback | Preview | Live certificate renewal and client trust |
| Read-only queue/service/cert health | Preview | Real queue, disk and expiry thresholds |
| Signed x64/ARM64 Stable release gate | Manual Authenticode trusted signer + pinned publisher + arch/version verification | Real signing credentials, signed binary QA and tenant acceptance needed |
| Sendmail/Exim/Postfix coexistence guard | Read-only MTA inventory plus explicit fixed-sender Direct Send/Connector install path with preinstalled Postfix, FQDN, native service PID/config/port-25 SHA baseline and post-start rollback guard | Live Exim/Sendmail + Postfix package/service/queue/reboot tests on each target OS; RHEL enforcing still blocked |
| Strong per-app SMTP password generator | Root-only SHA512-CRYPT files and one-time masked GUI reveal | Verify actual Dovecot login, clipboard handling and client configuration |
| RHEL SELinux Enforcing local SMTP STARTTLS/AUTH probe | Read-only host runtime handshake and label/status checks | Successful SASL login, queue I/O, AVC audit, reboot and M365 delivery still needed |
| Opt-in 15-min local journald systemd timer | Preview | Verify after real OS reboot |
| Optional HTTPS webhook health alerts | Preview 15, root-only Linux config | Live incident/recovery delivery, external TLS and receiver alert routing |
| Root-only real reboot baseline and verification | Implemented | Controlled actual Linux reboot |
| RHEL 8/9/10, Oracle, Rocky, Alma SELinux port/file/process context audit | Read-only | Real Enforcing process AVC allow/deny integration |
| RHEL SELinux custom smtp_port_t label preparation and rollback | Implemented with reviewed SHA and explicit confirmation | Verify `semanage port` change/rollback on a real disposable enforcing host; not a full service acceptance |
| Microsoft 365 XOAUTH2 sender transport | Preview | Live Entra tenant + Exchange scoped mailbox + delivered test |
| Microsoft 365 Direct Send | Fresh isolated installation without Entra/OAuth, or guarded route switch of an existing XOAUTH2 sidecar; exact fixed MAIL FROM required | Approved accepted domain, root-owned map/postmap negative tests, real internal recipient receipt |
| Microsoft 365 Connector | New isolated fixed-sender sidecar with exact fixed MAIL FROM or guarded switch of existing XOAUTH2 route | Verified tenant Connector authorization, exact-sender negative tests, real host install, external recipient receipt |
| New Exchange Online tenant Inbound Connector | Guarded PowerShell 7 read-only Preview and separate Create with exact tenant, accepted domain and inventory SHA | Real authorized creation, exclusive IP/certificate, anti-abuse and message delivery on a test tenant |
| Public-domain DNS MX/SPF/DMARC/DKIM report | Read-only evidence | Verify records against actual Exchange/tenant configuration, DKIM enabled state and recipients |
| Connector sender preserve accepted domain / masquerade subdomains | Authenticated MAIL FROM account owner map required, reviewed SHA, isolated EOP route | Real Postfix account ownership/negative tests, RFC5322 From header protection and tenant delivery |
| Internet-wide SMTP listener | Guarded opt-in manager, not production-approved | Real Fail2ban ban drill, external client TLS trust, firewall/NAT, abuse controls and rollback on disposable test host |
| Primary Postfix backup restore confirmation | Linux `--restore ID` requires explicit confirmation; installer rollback has distinct marker | Restore/rollback after fault injection on disposable VM, validate external dependencies and queue durability |
| Independent Relay config backup and offline restore | Root-only allowlisted application configuration, archive SHA+per-member hashes, pre-restore emergency snapshot, stopped isolated units + empty queue required, reviewed current SHA and explicit confirmation; no auto service start | Live disposable-VM recovery, actual systemd/SMTP AUTH/TLS, external cert/key dependencies, queue durability and RHEL SELinux labels |
| Signed Stable Windows EXE | Not released | Signing provenance, GUI / x64 / ARM64 production QA |

The incoming Linux custom port is separate from Microsoft 365 outbound 587 (XOAUTH2) or 25 (Direct Send / Connector). Direct Send is restricted to recipients in the Microsoft 365 organization.

## 1. Prepare a disposable test server

Take a recoverable VM snapshot; baseline primary Postfix service, port 25, queue, configuration and existing programs. Choose an available custom private inbound port, for example 46500. Allow only loopback or explicit trusted RFC1918 client CIDRs by default. Do NOT disable SELinux or expose the listener to the public Internet without an explicitly approved, isolated public-submission acceptance test.

Prepare an approved test Tenant, authorized mailbox and an exact DNS SAN TLS certificate. Keep passwords, TLS private keys and OAuth credentials only in approved protected local storage. Never attach them to bug reports.

## 2. Read-only Linux diagnostics

On a test machine with a copy of the project branch, run the following commands (replace 46500 with the chosen installed private port).

    python3 linux/audit-existing-smtp.py
    sudo python3 linux/mta-coexistence-doctor.py --smtp-port 46500
    python3 linux/guard-foreign-mta.py --self-test
    sudo python3 linux/platform-compat.py --smtp-port 46500
    sudo python3 linux/rhel-selinux-doctor.py --smtp-port 46500
    sudo python3 linux/manage-rhel-selinux-port.py --check-only --smtp-port 46500
    sudo python3 linux/installed-sidecar-audit.py --smtp-port 46500
    sudo python3 linux/recovery-scope-audit.py --smtp-port 46500
    sudo python3 linux/sidecar-config-recovery.py --self-test

For a **disposable VM whose active primary MTA is Exim or Sendmail**,
review the root-only inventory output and separate sidecar FQDN. Only if Postfix
binaries are *already installed*, verify the native service and TCP 25 baseline
under root (no configuration is changed by this command):

    sudo python3 linux/guard-foreign-mta.py --mta exim --hostname relay.example.org

Then run the private fixed-sender Direct Send or Connector installer with
`--preserve-primary-mta exim`, `--sidecar-hostname relay.example.org`,
and `--confirm-preserve-primary-mta PRESERVE_EXISTING_EXIM` (or the Sendmail
equivalent), plus the usual domain/Connector approvals. The installer checks
the primary MTA fingerprint again after starting only the independent sidecar.
On guard failure it attempts removal of the new sidecar service/config, but
preserves its queue for forensic inspection. Verify separately that the
original MTA PID, TCP25 listener, queue state, active routing and DNS MX are
unchanged; send a real pre/post test through the existing MTA and a separate
client test through the new private port. Unknown or mixed active MTA state
must block the operation. This has **not** been verified on a real
Exim/Sendmail server, and enforcing SELinux is still blocked.

For an already installed independent Relay, verify separate root-only
configuration backup and offline restore on a **disposable VM** only:

    sudo python3 linux/sidecar-config-recovery.py --backup
    sudo python3 linux/sidecar-config-recovery.py --list
    sudo python3 linux/sidecar-config-recovery.py --verify BACKUP_ID
    sudo python3 linux/sidecar-config-recovery.py --preview-restore BACKUP_ID

Save the reviewed current SHA from Preview. Stop ONLY the isolated Relay,
SMTP AUTH and health services/timer, verify its queue is empty and its
custom TCP listener unbound using `ss`, and confirm
the baseline of the PRIMARY MTA remains unchanged. Only then execute:

    sudo python3 linux/sidecar-config-recovery.py --restore BACKUP_ID --expect-current-sha256 REVIEWED_SHA256 --confirm RESTORE_ISOLATED_RELAY_CONFIGURATION

Verify the emergency safety snapshot ID, restored configuration, service
units, certificate references and read-only Postfix `postconf -c ... -n/-M/-h`
checks **before** manually starting isolated services. The restore deliberately
avoids `postfix check`, which could create missing spool directories. Do not claim queue recovery, external TLS private
key restore, package rollback or M365 tenant message delivery. Separate
public SMTP exposure must be reverted before restoring any old configuration.
Run induced corrupt-archive and failed-Postfix-check rollback tests. The
new CLI does **not** stop or start services and does not touch primary
Postfix, Exim or Sendmail; do not use live production mail for this exercise.

The optional real SMTP client-authentication acceptance test must run at a
trusted interactive terminal on an authorized TEST host (never in automation
with a production password). After installing the dedicated Postfix/Dovecot
AUTH/TLS service and the correct CA chain, run:

    python3 linux/verify-sidecar-auth-client.py --smtp-port 46500 --server-name smtp.example.org --login smtp-app01 --ca-file /etc/ssl/certs/approved-ca.pem

The program prompts for the app-specific password without echo, validates the
TLS CA chain and exact DNS hostname **before requesting the password**, then
performs only an AUTH login and QUIT. It sends no MAIL, RCPT or DATA, does not
modify Linux configuration, and never claims tenant or recipient delivery.
Run one successful and one intentionally wrong-password test using only
approved disposable test credentials. It requires a real interactive tty.
    sudo python3 linux/relay-health.py --smtp-port 46500
    sudo python3 linux/audit-sidecar-auth-archives.py

Inspect all non-success codes. The read-only accepted-domain DNS action inspects public MX, SPF, DKIM selector CNAME and DMARC status without exposing raw TXT data or changing DNS; a matching MX/SPF is NOT Exchange tenant authorization. A SELinux smtp_port_t mapping and present socket labels do NOT mean a policy actually authorizes access. On Enforcing machines, collect a redacted AVC report and verify permissions on a disposable test host with approved policy changes. Automatic SMTP AUTH installation remains blocked on unverified RHEL Enforcing/Permissive/unknown modes.


The Wizard can optionally add a missing, unclaimed `smtp_port_t` TCP mapping on
RHEL-family systems after SHA-verified preflight and typed approval. This
changes only the SELinux port type; it does **not** change `setenforce`,
firewall, queue files, domains, process types or Dovecot socket policy.
A matching root-only rollback record supports removal only with the listener
stopped and the SELinux policy unchanged. A port label alone never establishes
functional SELinux Enforcing support or safe SMTP AUTH. Real host acceptance is
still required before Enforcing deployment is unlocked.

## 3. Private SMTP acceptance

Use Wizard step 4 to check installed configuration. Choose SMTP server DNS name, current custom TCP port, trusted client CIDRs and Linux paths to TLS cert/key/hash source. Create salted hashes interactively on Linux via "doveadm pw -s SHA512-CRYPT", and protect secrets root-only. Enable only after preflight and typed confirmation.

From an approved client test that TLS 1.2+, CA trust and exact DNS name match; AUTH is not available before STARTTLS; correct password succeeds and incorrect or revoked password fails. Add and rotate one account without invalidating other clients. Verify the primary Postfix service, main/master configuration, port 25 and queue remain unchanged.

Optional read-only Linux TLS identity check:

    sudo python3 linux/verify-sidecar-tls-identity.py --smtp-port 46500 --server-name smtp-relay.example.org

The local TLS probe is not evidence that a Windows/client application trusts the cert.

## 4. Health and real OS reboot

The optional health monitor writes local anonymized status to journald every 15 minutes. A separate opt-in HTTPS webhook mode sends anonymized aggregate incident/recovery events, but email/SMS and receiver routing are not provisioned. Verify actual queue thresholds, disk headroom, service readiness and certificate alerts. Inspect:

    sudo systemctl status linuxmailrelay365-sidecar.service
    sudo systemctl status linuxmailrelay365-smtp-auth.service
    sudo systemctl status linuxmailrelay365-health.timer
    sudo journalctl -u linuxmailrelay365-health.service --no-pager -n 30

Record a reboot baseline from the Wizard or the following command:

    sudo python3 linux/verify-reboot-continuity.py --record-baseline --smtp-port 46500

After a controlled ACTUAL Linux reboot (not a mere systemctl restart), execute:

    sudo python3 linux/verify-reboot-continuity.py --verify-after-reboot --smtp-port 46500

Only "REBOOT_CONTINUITY_RESULT=local_services_continuity_verified" combined with the new kernel boot ID confirms local continuity. Continue with live TLS clients and external delivery. The baseline cannot be silently overwritten.

Rehearse root-only recovery archives with no production credentials. Inspect restored certificate/trust and Postfix policies. If the rollback verification fails, manually restore from the approved VM snapshot.

For EOP route maintenance, **pause application submissions** and verify the
dedicated sidecar queue is empty before changing transports. The route manager
refuses to apply/restore over queued messages, preserves root-only snapshots
and checks the installed custom SMTP port; this does not remove the need for a
maintenance window or a proper disaster-recovery plan.

## 5. Microsoft 365 delivery verification

With explicit tenant administrator access on a TEST tenant, validate app-only OAuth2, Exchange scoped SMTP.SendAsApp grant, accepted domain and approved mailbox. For Connector verify the actual tenant inbound Connector, authorized unshared public IP or matching TLS identity, and outbound TCP 25. Connector-only sender policies allow accepted-domain envelope identity preservation or subdomain-to-accepted-domain rewrite. These operations are NOT Microsoft 365 sender permission grants. The scoped Dovecot login ownership file protects envelope MAIL FROM; RFC5322 From headers require a separate reviewed Milter or equivalent header policy. Validate negative ownership tests and final recipient delivery on a test tenant before production. For Direct Send enforce INTERNAL recipient scope. The Wizard has independent fresh Direct Send and fixed-sender Connector sidecar installers requiring no Entra/OAuth app, and a separate SHA-guarded route switch for an existing XOAUTH2 sidecar. Neither Linux sidecar installer creates an Exchange Connector or changes MX/SPF/DKIM/DMARC, nor do they alter the primary Postfix. A separate Windows Wizard provisioning action can create a new tenant Connector only with explicit administrative approval. Tenant domain ownership, actual Connector authorization and delivered messages must still be verified.

Send from a real internal app to an approved internal mailbox, then, if the chosen transport supports it, an external test mailbox. Confirm queue disposition, Exchange acceptance and final receipt, including authorized sender identity. Collect no private keys, passwords, tokens or recipient mail contents. Do not claim delivery solely from localhost SMTP success.

## 5a. Read-only Exchange Online accepted-domain / Connector evidence

On the administrator's final test workstation with **PowerShell 7 and the
ExchangeOnlineManagement module**, first open a delegated interactive Exchange
Online session for the exact approved test tenant. The following PowerShell
check works **inside that already authenticated session** (it will not
connect, create or edit any Exchange object):

    Connect-ExchangeOnline -Device
    ./windows/Test-LinuxMailRelay365OutboundMode.ps1 -Mode DirectSend -AcceptedDomain example.org
    ./windows/Test-LinuxMailRelay365OutboundMode.ps1 -Mode Connector -AcceptedDomain example.org -PublicIpv4 198.51.100.20

Replace example domain and the documentation-only public IP with the real
approved test values. The report never returns actual Connector names, tenant
IDs, recipient addresses or secrets; it only reports accepted-domain and
Connector **candidate** status. A Connector candidate is NOT proof of
authorization or delivery. Check the actual Connector restrictions, certificate
identity/IP, TLS policy, tenant context, scope and an approved end-to-end
recipient delivery separately.


The Windows Wizard can optionally create a NEW OnPremises Inbound Connector
in Exchange Online, separately from any Linux installation. Preview first
checks the exact Exchange session tenant ID, existing accepted domain,
duplicate names/IP/certificate and current inventory SHA. Create requires
a separate administrative Device Code sign-in, reviewed SHA and explicit
typed confirmation; it does not edit or delete existing Connectors.
The tenant's real sending IP, certificate identity, threat-protection
settings, mail flow and external recipient acceptance must be inspected
independently. If a new Connector must be revoked, disable it manually
under approved Exchange Admin Center change control. Production rollback
of tenant-side permissions has not been tested.

## 5b. Guarded public SMTP submission (expert opt-in; NOT production-approved)

Public exposure remains **off by default**. Only the independent XOAUTH2
sidecar on a selected private IPv4, with working Dovecot SMTP AUTH,
mandatory STARTTLS (TLS 1.2+), trusted CA and exact DNS/SNI, an active local
health timer and active, **operator-tested Fail2ban postfix and dovecot jails**
is eligible. The script checks jail existence, not whether real attacks
actually trigger a ban or whether the logs are collected from the sidecar.

The separate public manager configures per-IP authentication, connection,
message and recipient rate limits, removes rate-limit exceptions and
preserves `permit_sasl_authenticated, reject` relay rules. It opens an
all-source firewall rule **only to the chosen local private IPv4 and custom
TCP port**, requiring exactly one already-active UFW/firewalld backend. It
neither opens primary port 25 nor configures router/NAT forwarding. RHEL
SELinux Enforcing remains blocked pending actual live OS verification.

    sudo python3 linux/manage-public-smtp.py --check-only --smtp-port 46500 \
      --listen-ip 192.168.40.2 --server-name relay.example.org

A reviewed SHA-256, typed Wizard confirmation and declaration of actual
anti-abuse testing are mandatory for Apply. Local preflight or Apply is not
evidence of public reachability or Exchange Online mail delivery. Test with
external clients (TLS CA trust, bad password, unauthorized RCPT before AUTH),
a real Fail2ban ban drill, alerting, quota/queue limits and emergency
rollbacks on a disposable test VM.

The same manager provides guarded `--status` and `--restore`, including
an interrupted activation marked as incomplete in a durable recovery journal.
Restore closes its
firewall rule before restoring the original Postfix client restrictions. Each
activation retains an independent root-only archive. Verify interrupted
firewall changes and manual emergency rule removal. Only after a successful
restore may AUTH/TLS be downgraded or routing changed to Direct Send/Connector.

## 6. Windows release checks

From the last successful CI download the x64 and ARM64 preview EXE artifacts. Check 100/200% DPI, RU/EN/HE and RTL, window resizing, long paths, SSH key/agent, password-SSH host key verification, current-server identity, host-scoped preferences, all wizard steps, failure warnings and backup/restore controls. Verify an uninstalled or unsupported option never silently modifies an existing mail server. Check updater against a verified signed publication, not just a self-contained CI build.

## Signoff criteria

Do not release Stable until a real SELinux Enforcing target, real OS reboot, recipient delivery via Microsoft 365, client CA trust, full backup/restore and emergency recovery, GUI DPI/language checks, rollback fault injection and signed binary provenance are accepted on the target platforms. Keep PR in Draft until then.

Repository: https://github.com/sgennadi/LinuxMailRelay365
Draft PR: https://github.com/sgennadi/LinuxMailRelay365/pull/1
