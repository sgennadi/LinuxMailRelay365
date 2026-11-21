# Final acceptance plan — LinuxMailRelay365

**Development preview only. Do not merge, deploy to production or publish Stable without the evidence below.** The user will run the final acceptance checks after the development work is complete.

## Recipient-aware route advice (Preview)

The SSH wizard now asks whether delivery is tenant-internal only, includes external recipients,
or is undecided. A read-only MTA inventory plus this declared intent guides the operator:
Direct Send for internal-only recipients, a verified single-mailbox XOAUTH2 candidate for
external delivery on a supported Postfix host, and a separately guarded Connector candidate
for Exim/Sendmail preservation. Existing isolated relays, unknown or risky MTA state and
clean hosts without a tenant authorization path require manual review. The suggestion is
**never an automatic mode selection or tenant authorization**. An explicitly external
recipient requirement blocks Direct Send Apply before any Linux changes.

## Preview 20 offline mapped OAuth signer acceptance

The Windows Wizard offers a read-only PS256 signing check for mapped M365
mailbox identities. The root-owned 0600 sender map is reviewed before
each identity is checked as the dedicated m365mailer service user. Keys
and certificates must be inside the protected identity directory, and
each 0640 identity must be root:m365mailer owned. Sensitive material,
addresses, raw signatures or mail contents are not returned to Windows.

This is NOT evidence of Exchange Send As, authenticated SMTP submission,
queue-bound sender identity, tenant delivery, TPM nonexportability,
Entra token acceptance or RHEL SELinux Enforcing. Multi-mailbox Apply/Test
remain blocked pending each separately documented live acceptance gate.

## Preview 21 read-only Exim/Sendmail acceptance

Review Exim/Sendmail TLS and SMTP AUTH declarations without touching
primary mail. These checks inspect only declared settings and produce
fixed non-secret codes, not a verified SMTP AUTH/TLS client session.
Dynamic values are unverified. Configuration files must be complete,
stable and no-follow. systemd queries now distinguish loaded, not-found,
failed and transitioning service states. Unknown means manual review.

Live validation remains required for SMTP AUTH mechanisms, TLS certificate
trust and names, Exim ACL/routers/transports, Sendmail access maps, MTA
queue preservation, RHEL SELinux Enforcing and actual Microsoft 365 delivery.
Neither this inspection nor CI enables native Exim/Sendmail rewriting.

## Preview 23: Exim/Sendmail offline recovery preview and extraction

On a verified Exim or Sendmail host, the Wizard may compare each root-only
configuration archive against active /etc file SHA-256 hashes, reporting
only identical / different / unverified (and the reviewed archive digest).
It cannot prove a complete or restorable mail installation. The Wizard
also supports typed-confirmed export to a fresh 0700 root-only staging
directory inside /var/backups/linuxmailrelay365-foreign-mta, with only
0600 extracted regular files. Archive contents, SMTP credentials,
private keys and raw configuration are never copied to Windows.

**No live Exim/Sendmail Restore:** this operation does not overwrite
/etc/exim*, /etc/mail, queues, service files, systemd state or firewall.
A separate isolated VM acceptance plan is required for true recovery:
capture and test the actual primary service and queues, external TLS
keys/certificates, package versions, aliases, permissions, enabled service
state, DNS, relay ACLs, authenticated clients and real M365 recipient
receipt. No production cutover is authorized by these tests.

## Preview 22: primary Exim/Sendmail configuration archive, no restore

The Backup & Restore step now splits Postfix and non-Postfix primary MTA
operations. The primary Postfix backup/restore controls are visible only
after matching Postfix discovery. For an active, matching Exim or Sendmail
and inspected Linux hostname, the GUI offers **Create + verify archive**,
**List verified archives**, and **Verify SHA-256 and contents**. The matching
SSH identity is checked before every operation. No secondary transport
or cross-MTA Restore is allowed.

The protected archive is stored only under
`/var/backups/linuxmailrelay365-foreign-mta/{exim,sendmail}/ID` as root-only
0600 files in a 0700 directory. A manifest binds the archive SHA-256 and
every regular-file SHA-256. Backups use a fixed /etc allowlist, reject
symlinks, non-root-owned or group-writable files, and cap size and count.
A completely verified archive is atomically published. Listing does not
create directories. Snapshots can include SMTP credentials, so archive
contents are NEVER copied into Windows. This is a **configuration-only**
backup: no queue, external certificate files, unit state or package state.
No automatic Exim/Sendmail Restore is implemented or promised.

Archive verification DOES NOT prove correct mail delivery or recovery.
Production restoration still needs a separately tested and approved
administrator procedure and backups covering the actual live environment.

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
| RHEL-family TPM2 dependency preparation | Read-only RPM preview and SHA-approved DNF install, separate native-provider vs PKCS#11 profiles | Verified real RHEL/Rocky host package transactions and provider availability; RPM scriptlet/service review |
| Offline TPM/HSM OAuth signing diagnostics | Fixed root-owned active/staged identity audit and PS256 signature check as `m365mailer`; no SMTP | Physical hardware provenance/nonexportability still unverified |
| New TPM2 RSA OAuth key + public certificate provisioning | SHA-reviewed root-only TPM2 owner primary RSA2048 creation at free 0x8101xxxx handle, provider/certificate preflight, PS256 signing as m365mailer, no destructive evict, active OAuth unchanged; mocked Ubuntu/RHEL-family tests | Real TPM owner authorization/device permission, TPM 2.0 provider support, SELinux AVC, reboot/key provenance, Entra and SMTP acceptance are NOT yet demonstrated |
| TPM/HSM OAuth candidate staging (not key creation) | Reviewed SHA256 for active identity, already provisioned TPM2/PKCS#11 key reference, provider, public certificate and installed binaries; root-only exclusive hardware-staged.json with offline PS256 verification and failure cleanup | Physical TPM/HSM provisioning, public certificate verification, provider accessibility, Entra registration and RHEL Enforcing acceptance still blocked |
| Staged TPM/HSM Exchange SMTP AUTH (no message) | SHA-approved separate STARTTLS/XOAUTH2 test to smtp.office365.com:587 using staged hardware identity, sends no MAIL FROM/RCPT TO/DATA, no active app.json or Postfix changes; simulated tests | Real Exchange tenant/TPM SMTP AUTH to confirm, then separate authorized recipient delivery/queue/SELinux acceptance |
| Staged TPM2/PKCS11 Entra token verification (without cutover) | SHA-reviewed, explicit approval, PS256 signature and live Entra token check with candidate-config as m365mailer; stdout contains no token; active app.json, Postfix and mail unchanged | Real tenant and physical TPM/HSM test needed; successful token does NOT prove Exchange Online SMTP AUTH or recipient delivery |
| Entra Graph public hardware OAuth certificate addKey | SSH public DER export, matching active/staged identity, tenant/client/app Object ID read-only review, strict Graph credential SHA and current-key RS256 PoP; explicit typed POST addKey with no PATCH/removeKey; postcheck existing key retention | Real authorized Graph tenant, module install, active PEM signer, certificate chain policy, proof device-code timing, Entra acceptance and SMTP delivery remain unverified |
| Two-recipient active hardware OAuth SMTP acceptance | Exact internal/external addresses and sender-domain classification reviewed by SHA256, typed operator confirmation, one-use root-only ledger, fixed short messages accepted over Exchange SMTP via active hardware OAuth; no automatic resend and no PII in status | Independent inbox receipt/Message Trace, accepted-domain verification, full Postfix ingress+queue delivery, authorized tenant and real hardware still require live tests |
| TPM/HSM identity staged-to-active switch and rollback | SHA-reviewed activation, root-only previous identity backup, atomic swap; staged and active PS256 signature, Entra token and Exchange STARTTLS/XOAUTH2 AUTH checks with no MAIL/RCPT/DATA; rollback on any postcheck failure | Real physical TPM, authorized tenant/Exchange policy, recipient delivery, reboot and SELinux Enforcing acceptance still not verified |
| Microsoft 365 XOAUTH2 sender transport | Preview | Live Entra tenant + Exchange scoped mailbox + delivered test |
| Microsoft 365 Direct Send | Fresh isolated installation without Entra/OAuth, or guarded route switch of an existing XOAUTH2 sidecar; exact fixed MAIL FROM required | Approved accepted domain, root-owned map/postmap negative tests, real internal recipient receipt |
| Microsoft 365 Connector | New isolated fixed-sender sidecar with exact fixed MAIL FROM or guarded switch of existing XOAUTH2 route | Verified tenant Connector authorization, exact-sender negative tests, real host install, external recipient receipt |
| New Exchange Online tenant Inbound Connector | Guarded PowerShell 7 read-only Preview and separate Create with exact tenant, accepted domain and inventory SHA | Real authorized creation, exclusive IP/certificate, anti-abuse and message delivery on a test tenant |
| Public-domain DNS MX/SPF/DMARC/DKIM report | Read-only evidence | Verify records against actual Exchange/tenant configuration, DKIM enabled state and recipients |
| Connector sender preserve accepted domain / masquerade subdomains | Exact authenticated MAIL FROM owner map plus separately staged root-only, policy-pinned RFC5322 From Milter. Multi-sender route now **blocks** without the running, verified Milter; it attaches an SMTP-only fail-closed Milter and prohibits local postdrop bypass. New Ubuntu Postfix/Dovecot live Unix-socket and spoof-rejection smoke is **pending exact-HEAD CI**. | Actual Postfix message-header reject before queue, approved test-tenant delivery, real RHEL Enforcing and per-app negative mail tests |
| Internet-wide SMTP listener | Guarded opt-in manager, not production-approved | Real Fail2ban ban drill, external client TLS trust, firewall/NAT, abuse controls and rollback on disposable test host |
| Primary Postfix backup restore confirmation | Linux `--restore ID` requires explicit confirmation; installer rollback has distinct marker | Restore/rollback after fault injection on disposable VM, validate external dependencies and queue durability |
| Independent Relay config backup and offline restore | Root-only allowlisted application configuration, archive SHA+per-member hashes, pre-restore emergency snapshot, stopped isolated units + empty queue required, reviewed current SHA and explicit confirmation; no auto service start. Real Ubuntu/Postfix Direct Send and Connector backup/restore + invalid-master fault injection; new Dovecot AUTH/TLS recovery smoke after credential rotation **pending exact-HEAD CI**. | Live RHEL SELinux Enforcing, cross-host disaster recovery, external CA/cert dependencies, queue durability and M365 tenant delivery; do not claim Stable based only on CI |
| Signed Stable Windows EXE | Not released | Signing provenance, GUI / x64 / ARM64 production QA |

The new standalone From Guard is staged through the Wizard (advanced Connector
multi-sender policy) by a separate SHA-reviewed Preview and typed approval.
It runs as a dedicated non-privileged systemd user with a private Unix
socket; staging **does not** modify Postfix EOP routing. The separate
Connector route Preview/Apply will refuse multi-sender sender preservation
or masquerading unless the guard is live and its policy SHA matches the
root-only sender-login ownership file. With the guard attached, Postfix
must **tempfail**, never accept, on guard unavailability. Only strict
From = MAIL FROM matching is supported in Preview; Sender must also
match, ambiguous headers and Resent-* are refused. This may reject
legitimate but more complex mail workflows. Require real test SMTP DATA
rejection and authenticated positive recipient delivery before production.
The non-SMTP local postdrop route is disabled only for this mode.

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

The companion `tests/smoke_scoped_auth_recovery.sh` runs after Dovecot
AUTH/TLS and SMTP password rotation on both Ubuntu versions. It verifies
that root-only archives contain the locally stored Dovecot service/config,
private TLS key/cert and salted account hashes without putting their contents
in CI logs; stops all isolated services/timer, changes only independent test
settings, restores them, verifies exact file hashes and manually starts
Dovecot/Postfix to log in over validated TLS. This does **not** restore
external CA or system trust files, and is not yet verified on RHEL Enforcing.

The CI smoke script `tests/smoke_scoped_recovery.sh` is gated to disposable
GitHub Actions runners and is invoked after both fresh Direct Send and fresh
Connector installation on Ubuntu 24.04 and ubuntu-latest. It backs up the
**running** separate Postfix, rejects an online restore and a nonempty
`maildrop`, stops **only** the isolated Postfix, changes a non-secret
sidecar setting, takes a SHA-reviewed preview, performs offline restoration,
verifies its emergency snapshot and unchanged primary Postfix files/queue,
then explicitly restarts the independent service and verifies EHLO without
SMTP DATA. This is a real service/configuration smoke, not a Microsoft 365
recipient-delivery or RHEL SELinux Enforcing test. Only declare it accepted
after that exact revision's CI runs complete successfully.

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

## Offline TPM2/PKCS#11 signing acceptance

These tests do not provision TPM keys, install providers, alter an active identity or contact Microsoft 365. After configuring a disposable host, inspect fixed root-owned identities and perform a separate local PS256 signature check:

    sudo python3 linux/verify-hardware-oauth.py --inventory-only
    sudo python3 linux/verify-hardware-oauth.py

An unconfigured or PEM-only identity remains `not_configured` or `software_signer_or_unconfigured`. Signed results report `provider_ps256_certificate_match_verified` only for successful OpenSSL provider signing and certificate verification; hardware provenance is separately marked NOT verified. Inspect system SELinux AVCs, TPM provider, module path and service-user access separately, without leaking keys or device PINs. This is **not** an end-to-end acceptance test.


## Staged TPM/HSM OAuth activation acceptance — pending live host

Before any production trial, create and protect a matching TPM/HSM certificate already registered with the Entra app, and stage the candidate `hardware-staged.json` under the correct identity directory. The operator must approve a separate window and verify the original PEM key/cert remain usable.

Run plan-only and review all status fields: `HARDWARE_CUTOVER_ROUTING_IDENTITY_UNCHANGED=yes`, the 64-character `HARDWARE_CUTOVER_PLAN_SHA256`, plus explicit NOT YET statuses for signing/Entra. Approve the same plan SHA and typed `ACTIVATE_HARDWARE_OAUTH`. Confirm Entra token and local PS256 succeed before active JSON replacement and after it. Record the opaque recovery ID without copying identity contents.

Exercise negative cases on a disposable host: mismatching tenant/client/mailbox, malicious PKCS#11 URI, symlinked identity, changed cert/transport bytes, wrong typed approval, invalid Entra token, interrupted postcheck and preexisting administrator config change. Automatic rollback must restore original SHA or report critical/manual restoration; it must never silently overwrite an unexpected current identity.

Independently test the explicit rollback from the listed root-only backup. Verify there were **no changes** to Postfix configuration, service state, mail queues, DNS, firewall, active SMTP port, Entra app registration or private-key storage.

Blocked until actual physical key tests: TPM provenance/attestation, RHEL8 OpenSSL3 limitations, the RHEL9 PKCS#11 module requirements, SELinux Enforcing service-user authorization, real Microsoft 365 SMTP delivery with internal/external recipients, reboot continuity and signed Windows stable acceptance.


## TPM/HSM candidate stage acceptance — code complete, physical host pending

Test the Wizard Preview/Stage sequence with both TPM2 and PKCS#11 providers on disposable Linux hosts. The Wizard must refuse PIN-bearing URIs, untrusted provider configs, missing certificate, broken key references, a changed SHA plan, an already staged identity, PEM fallback and any changed tenant/client/mailbox.

Confirm that a successful stage creates only the root:m365mailer `hardware-staged.json` with mode 0640 and a matching offline PS256 signature, while active `app.json`, Postfix, Entra, firewall and SMTP queues remain unchanged. An error during file publication, directory flush or PS256 verification must remove the candidate only if it is still exactly the created candidate; other changes require manual review and may not be overwritten.

Do not interpret a successful software or provider-layer test as hardware attestation. Generate or provision an actual persistent hardware key, register the matching public certificate, test signing as `m365mailer` after reboot and separately validate live Microsoft 365 SMTP delivery before Stable.


## TPM2 key provisioning physical acceptance — pending

Use only a disposable TPM2 host with operator authorization and a verified backup/recovery plan. Record the empty owner handle and root-managed provider package origin. Review SHA256 preview first. On explicit provisioning, verify the chosen handle was absent before and present after and that previously occupied handles remain byte-for-byte unchanged; capture only nonsecret public key fingerprints. Confirm `hardware-app.crt` matches the TPM persistent key by PS256 signing as `m365mailer` and that `app.json` and Postfix configuration never changed.

Run the following negative/rollback cases: occupied and malformed handles, provider absent/OpenSSL 1.1, blocked device and user access, owner auth required, certificate mismatch, interrupted persistence, disk exhaustion and SELinux label failures. The tool intentionally **does not** delete a persisted TPM key after failed certificate publication. Explicit human recovery is necessary; no dangerous `tpm2_clear` or evict commands should be added.

Physical TPM attestation/nonexportability, certificate registration into Entra, live token issuance, SMTP internal/external delivery, reboot continuity and RHEL 8/9/10 Enforcing behavior remain Stable blockers.


## Entra Graph addKey acceptance — live tenant still required

On a disposable approved tenant/app, create a staged hardware OAuth identity, verify the real active certificate already exists in Entra and that the previous private key is still available. Use read-only Preview with exact tenant and existing Application Client ID; verify that the Graph app Object ID, all current key IDs/thumprints/validity windows and candidate public DER SHA256 are included in the review SHA. Preview must not mutate the app.

Test negative paths before permission to Apply: tenant mismatch, wrong client ID, no valid active Entra certificate, expired credential, candidate already present, changed Linux stage/cert SHA, changed Graph key inventory, invalid JWT audience/issuer/lifetime/RS256 signature, missing Graph module, missing delegated role. Never fall back to PATCH or replace the entire keyCredentials collection.

With explicit approval, inspect device-code delegated Graph Application.ReadWrite.All authorization and the short-lived RS256 proof signed by the existing key **on Linux**, never copied private PEM/TPM/HSM material. Graph application addKey is the sole cloud mutation. Verify new public thumbprint present and every existing key still unchanged; if the postcheck fails or the call times out, the state must be manually inspected without blindly reissuing addKey. Confirm active Linux app.json and Postfix were not modified.

Then and only then, separately review SHA-bound Linux staged-to-active switching, verify real Entra token acquisition before/after, reboot persistence, actual Exchange Online AUTH XOAUTH2 delivery and rollback under SELinux Enforcing. None of those production acceptance gates can be inferred from mocked CI.


## Actual mailbox-delivery acceptance — requires approved test recipients

Stage a disposable Microsoft 365 tenant and use a Linux test host with an active, validated hardware signer. Operator provides two consented test inboxes: one in the fixed sender domain and one outside that domain; accepted-domain authority must be separately confirmed by an Exchange admin. Review SHA256 evidence and a unique trace ID; ensure the preview has `MAIL_SENT=no`.

Explicit approval should produce at most one small fixed message per recipient, through the actual installed OAuth transport and Exchange STARTTLS/XOAUTH2. Preserve the root-only ledger as evidence even if only one SMTP operation succeeded or SSH timed out. Never automatically repeat the same run ID.

Successful SMTP submissions prove only Exchange **submission acceptance**. Locate both trace IDs in Microsoft 365 Message Trace, inspect each inbox or quarantine, record final acceptance/delivery/bounce/deferral (from recipient/Exchange evidence, not inferred from SMTP 250), check mail content, and verify there was no SMTP relay abuse, unexpected sender, Postfix config change, MTA restart, new firewall opening or secret leakage.

Complete a separate end-to-end test through the isolated custom-port Postfix listener, actual client SMTP AUTH/STARTTLS, local queue/retries, transport delivery, and recipient's inbox. This additional test is not provided by direct OAuth transport acceptance and blocks Stable.


## Automatic TPM2 RPM profile acceptance (Draft)

When the Linux security probe finds TPM 2.0, the Windows Wizard now defaults
to **Automatic TPM2 RPM profile** for RHEL, Oracle, Rocky and Alma 8-10. A
read-only SHA256 plan is mandatory before a separate typed, approved DNF
transaction. The app never enables third-party repositories, downloads RPMs
directly from arbitrary URLs, builds a provider unattended, clears a TPM,
evicts occupied handles or modifies Postfix.

* RHEL-family 10: prefer the native tpm2-openssl RPM profile.
* RHEL-family 9: only select the OpenSSL3 PKCS#11 path automatically if
  pkcs11-provider is **already installed**. Otherwise install only approved
  TPM2 utilities; selecting a provider requires independent repository/source
  review. Explicit administrator selection may fail on missing vendor RPMs.
* RHEL-family 8: only auto-select TPM2 utilities. Its default OpenSSL 1.1
  environment does not satisfy the hardware OAuth OpenSSL3 provider.
* /dev/tpm0 alone is not equivalent to /dev/tpmrm0. Report the kernel resource
  manager separately and block physical provisioning until it is verified.
* The reviewed SHA binds the requested and selected profile, package
  inventory, TPM node and the actual /usr/bin/tpm2_getcap executable check.
  After installation, missing tpm2_getcap must report an error even if RPM
  inventory indicates success.

Read-only command on an approved test host:

    sudo python3 linux/manage-tpm-dependencies.py --profile auto

A successful package installation does **not** prove the OpenSSL TPM provider
loads, that the service identity has hardware access, TPM provenance or
attestation, key usability after reboot, or Microsoft 365 SMTP delivery.
These remain independent acceptance gates.


## Post-install TPM provider readiness (explicit, read-only diagnostic)

The Windows Wizard has a separate **Inspect OpenSSL 3 and m365mailer TPM
access** action. After an administrator-approved DNF install it also attempts
this inspection automatically, but failure of the inspection is reported as
a distinct warning, not misrepresented as a package rollback.

    sudo python3 linux/manage-tpm-dependencies.py --profile auto --inspect-provider

This command does not install RPMs, create/clear/evict TPM objects, change
Entra/Postfix, sign an OAuth assertion or send email. It intentionally opens
the TPM only for non-mutating provider initialization and a
`tpm2_getcap properties-fixed` query as the **m365mailer** service account.
Both probes are bounded and run without the administrator's inherited
OpenSSL configuration, PKCS#11 PIN or environment. Standard output and error
from child processes are suppressed. Only fixed, non-secret status codes
are returned:

- `TPM_DEPS_DIAG_OPENSSL3` and `TPM_DEPS_DIAG_SERVICE_USER` describe
  executable and service-account preconditions.
- `TPM_DEPS_DIAG_TPM2_PROVIDER` and
  `TPM_DEPS_DIAG_PKCS11_PROVIDER` describe whether an OpenSSL3 provider
  can be loaded in a minimal environment by the service account.
- `TPM_DEPS_DIAG_TPM2_DEVICE_AS_SERVICE=read_verified` means that the
  service account can read TPM fixed capabilities. It is **not** proof
  of key provenance, persistent handle access, successful signing or
  device attestation.
- An unavailable provider can require an *already trusted* root-managed
  provider config; the minimal-environment probe does not establish
  that the application's own provider configuration is correct.

To test an existing hardware OAuth key, run the **separate**, explicitly
confirmed offline PS256 signing action (`verify-hardware-oauth.py`).
It still does not prove Entra authorization or Microsoft 365 SMTP delivery.


## Local Postfix envelope preflight (manual; does NOT send mail)

`linux/verify-sidecar-envelope.py` adds a separate Python3.6+ operator-only
session to test an installed independent Postfix listener over validated local
STARTTLS and an app-specific SMTP AUTH credential. It does not alter existing
`verify-sidecar-auth-client.py` (which still sends only EHLO/AUTH/QUIT).
Sender, recipient and password must be supplied via hidden interactive TTY
prompts; missing TTY, malformed addresses, invalid TLS trust, authentication
failure, unexpected RCPT response or port outside 1024–65535 fail closed.

    python3 linux/verify-sidecar-envelope.py --smtp-port 46500 \
      --server-name relay.example.org --login smtp-app01 \
      --ca-file /path/to/trusted-ca.pem

Require positive RCPT response for a permitted internal mailbox or add
`--expect-reject` to require a permanent 5xx response for a disallowed
recipient. The tool sends MAIL FROM/RCPT TO **only after** successful TLS and
AUTH, and always sends RSET before QUIT on successful checks. It **never
sends SMTP DATA**; therefore it cannot prove mail queue hand-off, XOAUTH2
delivery, Exchange Message Trace, actual tenant permissions or inbox arrival.

A separate future acceptance needs two explicitly consented recipients,
a short real message through the installed custom-port Postfix SMTP path,
queue and retry observation, Exchange Message Trace plus recipient evidence,
and signed deployment. Do not treat the envelope preflight as Stable evidence.


## Full local Postfix message path to loopback-only SMTP sink (CI acceptance)

The previous SMTP smoke tests exercised only EHLO/MAIL/RCPT, avoiding message
DATA and the independent Postfix queue. The Ubuntu fresh Connector and Direct Send CI matrices
now include bounded **real DATA** tests, using an explicitly disposable
GitHub Actions runner and synthetic `example.org` sender/recipient:

    bash tests/smoke_local_postfix_delivery.sh 46500

The script verifies that the primary Postfix service and configuration are
unchanged, the independent queue is empty and the private SMTP listener is
localhost-only. It stops the independent service, saves its original
`main.cf`, forces **all three** outbound relay routes to a fixed
`127.0.0.1:46601` sink, disables fallback relay and outbound TLS only
while this isolated fixture is running, binds outgoing SMTP to 127.0.0.1,
and restarts **only** the independent Postfix service.

The synthetic application client sends one message through the real Postfix
listener using MAIL/RCPT/DATA. A local Python SMTP server validates the exact
sender, recipient, Message-ID, From, To and body marker. The test requires
one sink delivery and a fully drained **independent** queue. On success, the
script stops the sidecar, restores the byte-identical original
`main.cf`, confirms the original `master.cf`, verifies the primary MTA's
SHA256 and queue location, and restarts the private service.

**Fail-closed recovery:** if any stage fails and the independent queue is
not provably empty, the service is stopped and the loopback-only route is
left intact, so restarting the service cannot send the test message to
Microsoft 365. In this failure case the CI VM is disposable and should be
destroyed; do not run this helper on production machines.

Evidence proves: application SMTP submission -> independent Postfix queue
and outbound SMTP client -> local sink on 127.0.0.1, including message DATA,
successful acceptance and queue drain. **It does not prove** Exchange Online
SMTP, actual tenant Connector, XOAUTH2, mailbox delivery, TLS enforcement to
Microsoft 365, hardware key provenance, real reboot persistence or SELinux
Enforcing. These remain independent acceptance requirements before Stable.

## Universal three-mode GUI and authenticated multi-sender acceptance

The Windows Wizard exposes three delivery modes (XOAUTH2, SMTP Connector,
Direct Send), while keeping the inbound custom TCP port independent from
outbound Microsoft 365 TCP 587 or TCP 25. The live diagram uses the entered
Linux host, listen IP, SMTP port, tenant MX and sender address. A separate
text explanation identifies sender rewriting/preservation, restrictions
on external recipients and service/tenant prerequisites. RU/EN/HE labels
for delivery and sender mode are present.

Initial private fixed-sender Connector and Direct Send preflight/install
actions are visible without Advanced. The selected mode controls outbound
preflight (XOAUTH2 uses 443/587; Connector/Direct Send use the tenant
MX/25 readiness audit). Entra app/SMTP mailbox configuration is not a
prerequisite in the Wizard for Connector or Direct Send. Existing EOP
sidecar rerouting, sender Milter management and restore remain guarded
Advanced operations.

Existing `mailTransport == oauth2` is a **single SMTP mailbox** identity
and the Python transport rewrites RFC5322 From and SMTP envelope sender.
The GUI can now save `OAuthSenderMode=authorized-multiple-mailboxes`
and an allowlisted, nonsecret Linux map **path only**, but does not read
the map, provision identities, enable mail submission or grant Exchange
Send As rights. Ordinary `ApplyAsync` and `SendTestAsync` explicitly
reject this planned mode. There is no unattended migration from the
single-mailbox transport.

A future multi-mailbox rollout is blocked until:
- each local SMTP login is authenticated and cryptographically bound to
  permitted SMTP envelope senders;
- RFC5322 From and Sender are checked against the authenticated login via
  fail-closed guard, including forged or nested headers;
- each selected mailbox and Microsoft 365 service principal has the
  intended Exchange Online Send As/app permission, verified in the exact
  tenant, and a safe denial test demonstrates least privilege;
- unique mailbox/account mapping and tenant/TPM certificate selection are
  reviewed; token and private-key contents never appear in GUI logs;
- a real Linux Postfix queue -> XOAUTH2 -> Microsoft 365 -> internal and
  external inbox acceptance is completed with recipient authorization;
- a reboot test, RHEL 8/9/10 SELinux Enforcing matrix and rollback
  are verified, with signed x64/ARM64 stable package acceptance.

CI screenshot capture exports ten real WinForms PNGs with synthetic
defaults and no live tenants: five base wizard steps, separate early
Connector/Direct Send selection screens, three transport variants in
step 4, and the blocked multi-mailbox XOAUTH2 plan with read-only audit
buttons. It is only a visual reference and not a DPI/RTL
accessibility certification.

## Multi-mailbox XOAUTH2 authorization map: read-only structural audit (Draft)

The universal Wizard now displays the three delivery methods **before** the
optional Entra step. Choosing Connector or Direct Send skips Entra app and
mailbox provisioning. Switching to XOAUTH2 reveals those identity settings.

The initial multi-mailbox XOAUTH2 engineering stage is deliberately a
**non-deploying audit**. An administrator creates a UTF-8 tab-separated
allowlist at an approved path under `/etc/linuxmailrelay365/` with exact
header (tabs between columns):

    smtp_login    envelope_from    m365_mailbox    identity_config_path

Each subsequent record maps ONE authenticated Linux SMTP login to ONE
permitted envelope sender and ONE Microsoft 365 mailbox and root-controlled
OAuth identity JSON path. E.g. a scanner can map to a permitted dedicated
service mailbox, but this audit does not grant the Exchange `Send As` right.
A sender cannot be assigned to multiple logins in the same map. Up to 256
unique envelope senders and 64 KiB map data are accepted.

Linux map file requirements: exact `root:root 0600`, regular file, no
symlink components and safe root-owned directories. The identity JSON
must be a root-controlled regular file with exact `0640` and the local
`m365mailer` group, with mailbox match, tenant/client GUIDs, certificate
reference, and exactly one configured signing backend (PEM or signer).
References to third-party paths or inline tokens, passwords, or secrets
are refused. Identity private keys/certificates and the service's access
to them are NOT inspected or validated at this stage.

The Wizard action **Audit SMTP login → sender → M365 mailbox map** runs a
temporary Python script over root SSH, returns only count summaries and a
map SHA256, and exposes no addresses, credentials, mailbox map, identity
JSON or private keys. It does not change files, Postfix, Entra, tokens or
SMTP messages. Invoke directly on an approved Linux host via:

    sudo python3 linux/audit-oauth-sender-map.py --map-path /etc/linuxmailrelay365/oauth-senders.tsv

An audit success reports `structural_review_only`. It explicitly reports
`LOCAL_SMTP_LOGIN_VERIFIED=no`, `ENVELOPE_AUTHORIZATION_ACTIVE=no`,
`HEADER_FROM_GUARD_ACTIVE=no`, `EXCHANGE_SENDAS_VERIFIED=no`,
`CERTIFICATE_AND_SIGNER_VERIFIED=no`, `POSTFIX_CHANGED=no` and
`MESSAGES_SENT=no`. It must **never** be interpreted as an active
multi-user XOAUTH2 implementation. Applying Postfix or sending a test
while this mode is selected remains blocked. Future implementation requires
authenticated login-to-envelope binding *before queue acceptance*,
RFC5322 From / Sender validation without spoofable identity headers,
per-mailbox OAuth token selection and verified Exchange app/Send As rights,
alongside fallback/rollback, end-to-end tests, physical TPM acceptance,
SELinux Enforcing checks and an explicit new approval gate.

## Offline XOAUTH2 sender policy spoofing simulation (not a live SMTP gate)

The read-only multi-mailbox authorization map audit now performs a deterministic
in-memory sender policy simulation for each map entry before reporting success:
it accepts a synthetic matching SMTP login, envelope sender, Microsoft 365
mailbox and RFC5322 From. It refuses mismatched logins, envelope senders,
mailboxes and From, forged Sender, duplicated From, ambiguous addresses,
Resent-From and Return-Path. At most 64 KiB of synthetic headers are parsed;
there are no network calls, no SMTP authentication, no mailbox token requests,
no queue submission, and no certificate signing.

The audit emits only `OAUTH_SENDER_MAP_POLICY_SIMULATION=passed_offline_only`
and an integer `OAUTH_SENDER_MAP_POLICY_SIMULATION_TEST_CASES`. Windows
Wizard displays these two allowlisted fields as well as the structural
counts and hash. All live-evidence fields remain `no`: authentication of
real SMTP logins, runtime authorization before accepting mail, installed
Milter/header guard, Exchange Send As permissions and actual delivery.

This **must not** be used to authorize an otherwise untrusted mail sender:
the simulated login is a trusted test parameter, not an authenticated SMTP
session identity. Normal multi-mailbox XOAUTH2 Apply/Test remain blocked.

## Existing From Guard mapping capacity boundary

The existing standalone From Guard parser and Dovecot user management accept
up to 64 explicitly authorized entries/accounts. The planning TSV format
can describe up to 256 sender entries. The read-only OAuth map audit now
reports `OAUTH_SENDER_MAP_EXISTING_FROM_GUARD_CAPACITY_COMPATIBLE=yes|no`
using this 64-entry limit. This is only a capacity comparison, **not**
proof that the Milter is installed, connected to Postfix or protecting SMTP
messages. An audit with more than 64 entries may be reviewed but cannot
be activated through the existing From Guard without a separately tested
scaling change. No automatic truncation or silent fallback is permitted.

## Read-only installed SMTP ingress comparison for planned multi-mailbox XOAUTH2

The operator can now run a **second** non-deploying Wizard diagnostic:
**Compare sender map with installed SMTP AUTH and From Guard (read-only)**.
It is not a setup action and does not enable multi-mailbox mail routing.

The Linux helper `linux/audit-oauth-ingress.py` imports the earlier
`audit-oauth-sender-map.py` only from the same bounded, private temporary
folder on the Linux server. It repeats the strict root-owned map and
identity structural review, checks the map SHA has not changed between
reads, and inspects local Dovecot/SMTP account names, From Guard owner
policy, `postconf` SASL/STARTTLS and sender restrictions, fail-closed
Milter settings, systemd status and private Unix socket metadata.
These checks expose **coded states only**. SMTP password hashes, account
names, sender addresses, mailbox names, key material and raw Postfix
stdout/stderr do not appear in Wizard logs. Fixed argv with bounded
timeouts are used for read-only `postconf` and systemd status.

    sudo python3 linux/audit-oauth-ingress.py --map-path /etc/linuxmailrelay365/oauth-senders.tsv

Possible outcomes are `OAUTH_INGRESS_OVERALL=not_ready` or
`ingress_config_consistent_not_live_verified`. The latter only confirms
static alignment with an existing **EOP Connector** style From Guard;
it is NOT a working multi-mailbox XOAUTH2 transport. The helper never
proves `master.cf` override safety, a real client SMTP AUTH session,
rejection of a spoofed live message, per-user queue identity provenance,
Entra Send As permission, or Exchange delivery. All these remain explicit
`no` flags. No service restart, package install, account creation,
SMTP submission, token request or Postfix edit occurs.

The default previous XOAUTH2 relay still rewrites From to one mailbox.
Do not apply the reviewed mapping to an active queue or claim that a
correctly formatted sender map is an authorization for real SMTP mail.
Future work must establish an authenticated identity and envelope owner
binding BEFORE queue acceptance, a trustworthy identity in the Postfix
transport, least-privileged per-mailbox OAuth and real tenant acceptance.

## Literal Postfix sender table and From Guard policy SHA diagnostics

The second read-only XOAUTH2 ingress diagnostic now compares the exact
installed Postfix `eop-sender-owners.regexp` contents against the planned
login/address associations. The allowed format is the fixed escaped
literal Postfix regexp form generated by the EOP deployer; any extra
entry, wildcard, wrong login, duplicated rule or missing entry reports
`OAUTH_INGRESS_POSTFIX_OWNER_RULES=different` and prevents even a
*static compatibility* claim. The file must be root-owned regular
with exact mode 0644, under safe directories.

It also requires the root:postfix 0640 `eop-from-owners.tsv` policy SHA
to be present in the configured `systemd ExecStart` of the independent
From Guard (`--expected-map-sha256`). If the hash is not pinned,
`OAUTH_INGRESS_FROM_GUARD_SHA_PIN=not_verified`, and the overall static
comparison remains `not_ready`. Neither finding proves that the
running Milter actually processed any SMTP message or that
`master.cf` does not contain overrides; those remain explicitly
unverified and require a separate live acceptance test.

## Real SMTP AUTH/STARTTLS and RFC5322 From Guard via independent Postfix (CI-only)

The disposable Ubuntu 24.04 and ubuntu-latest Postfix CI fixtures now run
`tests/smoke_authenticated_from_guard_loopback.sh` after installing and
activating the existing private SMTP AUTH/Dovecot and Connector From Guard.
The fixture checks actual Postfix SMTP behavior, **not merely a direct
Milter Unix-socket call or an offline parser simulation**.

Before submitting any SMTP DATA, the shell test requires GitHub Actions
disposable-runner context, a private 127.0.0.1 listener, active independent
Postfix/Dovecot/From Guard, active Milter and mandatory incoming TLS/Auth,
expected fixture-only EOP relay parameters, no alternate routing maps or
real fallback host, and a provably empty independent Postfix queue. It
stops **only** the isolated Postfix service; then it directs relayhost,
default_transport and relay_transport to fixed `127.0.0.1:46601`, explicitly
clears smtp_fallback_relay and binds the outbound SMTP client to loopback.
Postfix's documented `smtp_fallback_relay=$fallback_relay` default alias
is accepted only if the underlying `fallback_relay` is empty.

The Python client uses the disposable TLS CA and local SMTP AUTH account,
checks no AUTH before STARTTLS, refuses anonymous or wrong-password access,
checks refusal of another account's envelope sender, and submits synthetic
DATA containing mismatched or duplicate From/Sender and forged Return-Path
and Resent-From. Postfix drops Return-Path before Milter callbacks, so the
Connector now installs a separate root-owned header_checks REJECT regexp
for top-level client-supplied Return-Path before cleanup removes it. The CI
fixture verifies the map with postmap and requires real SMTP rejection.
It also verifies one
positive, correctly matched RFC5322 From and MAIL FROM is accepted into
the real Postfix queue and arrives at exactly one loopback-only SMTP sink.
An existing separate TLS identity test checks DNS/certificate hostname;
this fixture uses the pinned disposable CA on the loopback address.

After the test, the independent queue must be empty, and the isolated
main.cf/master.cf and the primary Postfix configuration and queue location
must match their pre-test fingerprints. A failed queue inspection or a
nonempty queue **leaves isolated Postfix stopped**, without restoring the
live EOP route. The disposable runner is then discarded.

**This does not establish multi-mailbox XOAUTH2 delivery.** Incoming
SMTP login/auth/From enforcement is a separate trust boundary from
mailbox-specific outbound OAuth credential choice, Exchange Online
application Send As permissions, or any live M365 recipient inbox. The
test never sends to a real tenant. Hardware TPM, SELinux Enforcing,
real-system reboot and signed Stable acceptance remain outstanding.
CI result must be checked for the exact commit; code presence is not a pass.


## Linux hostname and Postfix/Sendmail/Exim settings discovery

After SSH MTA discovery, a second **read-only** probe reports hostname -s,
hostname -f and hostname -d (when resolvable). It summarizes effective
Postfix myhostname/mydomain/myorigin/mydestination/inet_interfaces/inet_protocols,
Exim primary_hostname/qualify_domain/local_interfaces or safe Sendmail
sendmail.mc listener/masquerade presence. It does not dump full mail config
or assert that Sendmail/Exim ACLs are safe. The GUI offers explicit one-click
prefill of SMTP hostname and M365 domain, with confirmation; OS DNS information
does not verify Exchange accepted-domain ownership, DNS, CA, public reachability
or sender identity. Primary MTA configuration remains unchanged.


## Linux network interface and SMTP bind evidence

The read-only post-SSH report now separates (1) configured MTA inbound
interfaces, (2) administrative link state and kernel operstate from
`ip -j address show`, (3) assigned IPv4/IPv6 addresses, and (4) actual
TCP SMTP LISTEN sockets from `ss -H -lnt` on 25, 465, 587 and selected
custom port (2525 by default). Listener ownership is always **unverified**:
a socket can belong to another service. If Postfix's explicit
`inet_interfaces` address is not assigned, the report flags it. A
configured wildcard with only loopback sockets also requires review.
Missing `ip`/`ss`, truncated inventories or complex DNS/variable
listener settings cannot be treated as safe.
`inet_interfaces = all` does not open firewall/NAT or prove SMTP reachability;
changing `inet_interfaces` or `inet_protocols` may require Postfix stop/start.


## Primary Postfix minimal identity profile (guarded, optional)

The wizard exposes the actual current Postfix values, network-interface and
SMTP-listener audits, then optionally lets the operator enter `myhostname`
and `mydomain`. The fixed baseline uses `myorigin = $mydomain`,
`mydestination = $myhostname, localhost.$mydomain, localhost`,
`inet_interfaces = loopback-only`, and `inet_protocols = ipv4`.
This is **not** needed for Preserve Existing Mail. External/wildcard bind
(`inet_interfaces = all`) can be previewed but is deliberately not
deployable via this primary-MTA profile; use a separately authenticated
isolated relay for network clients. Preview does not mutate Linux.
Apply checks a reviewed SHA256 fingerprint, rejects pre-existing non-loopback
listeners or custom local delivery destinations, creates a root-only
verified configuration backup, uses `postconf -e`, verifies `postfix check`
and restarts an active primary Postfix. On failure the recovery manager attempts
rollback; delivery checks and independent backups are still mandatory.
Sendmail/Exim primary configurations are not edited by this action.


## Active Linux network interfaces in the Wizard

In the SMTP Listener section, after a successful read-only Linux inspection,
the Wizard now offers explicit selection of an IPv4 address assigned to a
currently administrator-UP, operationally-UP interface. It suggests **only
RFC1918** addresses; loopback, public IPs and DOWN links are not offered.
Selecting one merely fills the planned `ListenIpv4` field. There is no
change to Linux interface state, SMTP bind, access controls or firewall.
Existing per-host Trusted CIDRs and AUTH/TLS safeguards still apply.


## WinForms layout refresh (100–200% DPI)

The main Wizard now opens up to 1220×900 at standard DPI, bounded by the current
monitor's available working area. High-DPI sizing scales toward the usable
desktop instead of retaining an undersized 1050px window; the minimum is
also clamped to the actual monitor. Its title/header supports multiline
wrapping, center content is independently scrollable, and the bottom navigation,
status and expandable activity journal use a fixed docked footer.
Long RU/EN/HE action labels wrap within measured buttons instead of ellipsizing.
Responsive page labels and form fields reflow without replacing user values or
SSH secrets. SSH authentication mode labels now follow the selected UI language.
Windows CI self-tests cover sizes at 96/192 dpi, plus existing real Wizard
screenshots for the five steps.


## Fixed footer for SSH connection action

The SSH "Check connection and continue" action now lives in the always-visible
footer and is the default Enter action, with "Skip connection check" kept
separate and non-primary. The old in-card primary action was removed so that
users at 150–200% DPI no longer have to scroll down to connect. Failed actions
also reveal the expandable journal without its footer row remaining collapsed.
CI captures extra compact-size screens for all five Wizard steps and RU/EN/HE
SSH layouts in addition to its existing 16 snapshots (24 PNGs total).


## DPI-friendly modal dialogs and footer visual assertions

Destructive-operation confirmation dialogs now have a scrollable explanation
with a fixed confirmation/cancel footer; the typed approval is never inferred
and remains mandatory. They are resizable and stay within the desktop work
area at higher scaling. Optional Security Help likewise uses a resizable
viewport with a fixed Close footer instead of a 65px bar. The Wizard's
main footer now reports its true preferred height; CI screen capture checks
that the visible status and Activity toggle do not extend beyond the client
area, catching the clipping previously seen in compact screenshots.


## Preserve Existing Mail: readable compact diagram

The live route diagram now uses an independent vertical two-lane view under
790px viewport width instead of shrinking a wide 3-column drawing. It adjusts
its height to the new view, keeps text at readable point sizes, and exposes
its full routing and sender explanation through accessible text. Existing
MTA statuses, route hints and flow captions have RU/EN/HE variants; the
universal fourth Wizard step is named SMTP delivery rather than Postfix
because Exim/Sendmail and clean Linux sidecar routing are supported.


## Scroll viewport and footer isolation regression

The Wizard reserves a dedicated bottom row with a dynamically calculated
navigation/status/activity height instead of relying on AutoSize inference
from an unbounded scrollable page. The center percent-height scroll viewport
can now contain a tall 650px vertical mail-flow preview without displacing
the fixed footer. Width, DPI, wrapped buttons, multi-line status and expanded
activity are included in the reservation. CI screen capture validates footer
bounds both before and **after** actual WinForms DrawToBitmap rendering.
The wide mail-flow cards now wrap long MTA names and route hints.


## Pinned footer architecture (independent docking)

The top/logo/header and the AutoScroll wizard content now live in a dedicated
non-AutoSize content shell. The navigation/status/activity footer is a
separate DockStyle.Bottom panel on a non-scrolling frame, with a calculated
height to fit wrapped buttons and localized status. This removes the
TableLayoutPanel auto-size interaction which previously moved status to the
bottom edge when a long mail-flow diagram was present. No SMTP operation or
routing behavior is changed by this UI-only change.


## Advanced UI localization

The Wizard now translates Postfix listener scope, TPM2 package/dependency
profiles, TPM/OpenSSL vs PKCS#11 hardware providers, sidecar/primary hardware
cutover targets, and SMTP account Add/Rotate/Revoke choices for RU/EN/HE.
Selected indices remain stable during relabeling; translated options must not
invalidate approval fingerprints or clear staged hardware settings. Combo-box
popup width expands up to the available desktop for long captions.
The optional Security Help dialog is now localized and supports RTL Hebrew.


## Explicit window regions to prevent dock-order occlusion

The body shell (header plus AutoScroll page) and the fixed footer now use
non-overlapping rectangles calculated from the frame's real client size.
Their bounds are refreshed on window resize and footer-height changes, with
reentrancy protection. This avoids platform-dependent DockStyle z-order
behavior that hid the footer under a long page in visual QA. The screenshot
test also asserts the footer's rectangle stays within the client frame.
Nested forms and field layout remain automatic, scaled and responsive.


## Real screenshot capture bounds

The CI-only Windows screenshot helper now captures `Form.Size` instead of
`Form.ClientSize`: WinForms `DrawToBitmap` includes the non-client title bar.
Using the smaller bitmap clipped about one caption-height from the bottom of
every captured Wizard screen, falsely suggesting that status text was outside
the form. Runtime client-control bounds remain checked independently of
screenshots. Full-size PNGs now include the real footer, status and window
chrome, enabling trustworthy visual review.


## Updater safety gate

The standalone public Windows build's Update button is read-only release
**discovery** plus explicit release-page navigation. No executable gets
downloaded or replaced. The CI workflow deliberately compiles
`UseSharedUpdater=false`; the separate pinned UniversalUpdater dependency
is private. The shared core itself provides staged file verification and
transaction primitives but does not supply an Authenticode-pinned,
out-of-process elevation/locked-file swap GUI. Before declaring full
auto-update, require a verified signed publisher identity, an independent
same-publisher check of the new executable, exact GitHub release asset and
archive SHA verification, a trusted external helper with parent-process
shutdown, tested .bak restore and a failed-health-check hold. Never apply
an unsigned CI preview automatically.


## Portable signed update implementation acceptance

The normal Windows x64/ARM64 executable supports optional same-publisher
signed update staging and externally assisted replacement. The existing
EXE must be Windows-trusted via WinVerifyTrust. The candidate must match
its SHA-256 publisher certificate, exact release metadata and SHA256 asset,
PE machine, informational version, and embedded self-test. A separate
publisher-verified helper waits for original process exit, revalidates, and
replaces with a .bak checkpoint. A failed post-install health check attempts
rollback and writes a per-user hold. Current unsigned CI artifacts fail
the signing precondition by design. Positive physical testing still requires
signing credentials and a published release; keep Draft and do not call it
a proven production updater until the real install and recovery are exercised.


Updater rollback checkpoints: pre-existing .bak is never overwritten in
place; it is first moved to a unique prior checkpoint. A healthy update
keeps the most recent .bak, then drops the older prior checkpoint.
On a failed update the helper restores prior backup where possible and
sets a persistent manual-review hold.


## Signed update UI progress and cancellation

The signed ZIP download now runs in a resizable, DPI-aware progress dialog
with a byte-count/MiB percent display and a real Cancel action backed by a
cancellation token. Cancellation or network error disposes incomplete staging
files and leaves the original EXE unchanged. Only after full downloaded ZIP
hash, PE architecture, publisher signature and staged self-test verification
does the signed out-of-process replacement helper start and the app close.


## Release artifact ZIP contract (offline CI only)

Windows x64 and ARM64 builds now include verified single-EXE ZIP candidates
with exact release asset names, machine header validation and SHA256
content comparison. No Authenticode signing is fabricated by CI. A production
release must rebuild each archive around the actually publisher-signed EXE
and record both archive SHA256 values before trusted updater acceptance.
