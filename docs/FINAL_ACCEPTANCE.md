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
| Opt-in 15-min local journald systemd timer | Preview | Verify after OS reboot; external alerting not installed |
| Root-only real reboot baseline and verification | Implemented | Controlled actual Linux reboot |
| RHEL 8/9/10, Oracle, Rocky, Alma SELinux port/file/process context audit | Read-only | Real Enforcing process AVC allow/deny integration |
| RHEL SELinux custom smtp_port_t label preparation and rollback | Implemented with reviewed SHA and explicit confirmation | Verify `semanage port` change/rollback on a real disposable enforcing host; not a full service acceptance |
| Microsoft 365 XOAUTH2 sender transport | Preview | Live Entra tenant + Exchange scoped mailbox + delivered test |
| Microsoft 365 Direct Send | Fresh isolated installation without Entra/OAuth, or guarded route switch of an existing XOAUTH2 sidecar | Approved accepted domain and real internal recipient receipt |
| Microsoft 365 Connector | Existing isolated sidecar only; no tenant provisioning | Verified tenant Connector authorization and external recipient receipt |
| Connector sender preserve accepted domain / masquerade subdomains | Implemented in isolated EOP route, not primary Postfix | Real Postfix envelope/header acceptance, sender authorization and delivery |
| Internet-wide SMTP listener | Guarded opt-in manager, not production-approved | Real Fail2ban ban drill, external client TLS trust, firewall/NAT, abuse controls and rollback on disposable test host |
| Signed Stable Windows EXE | Not released | Signing provenance, GUI / x64 / ARM64 production QA |

The incoming Linux custom port is separate from Microsoft 365 outbound 587 (XOAUTH2) or 25 (Direct Send / Connector). Direct Send is restricted to recipients in the Microsoft 365 organization.

## 1. Prepare a disposable test server

Take a recoverable VM snapshot; baseline primary Postfix service, port 25, queue, configuration and existing programs. Choose an available custom private inbound port, for example 46500. Allow only loopback or explicit trusted RFC1918 client CIDRs by default. Do NOT disable SELinux or expose the listener to the public Internet without an explicitly approved, isolated public-submission acceptance test.

Prepare an approved test Tenant, authorized mailbox and an exact DNS SAN TLS certificate. Keep passwords, TLS private keys and OAuth credentials only in approved protected local storage. Never attach them to bug reports.

## 2. Read-only Linux diagnostics

On a test machine with a copy of the project branch, run the following commands (replace 46500 with the chosen installed private port).

    sudo python3 linux/platform-compat.py --smtp-port 46500
    sudo python3 linux/rhel-selinux-doctor.py --smtp-port 46500
    sudo python3 linux/manage-rhel-selinux-port.py --check-only --smtp-port 46500
    sudo python3 linux/installed-sidecar-audit.py --smtp-port 46500
    sudo python3 linux/relay-health.py --smtp-port 46500
    sudo python3 linux/audit-sidecar-auth-archives.py

Inspect all non-success codes. A SELinux smtp_port_t mapping and present socket labels do NOT mean a policy actually authorizes access. On Enforcing machines, collect a redacted AVC report and verify permissions on a disposable test host with approved policy changes. Automatic SMTP AUTH installation remains blocked on unverified RHEL Enforcing/Permissive/unknown modes.


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

The optional health monitor writes local anonymized status to journald every 15 minutes. It does NOT configure email/SMS/webhook alerts. Verify actual queue thresholds, disk headroom, service readiness and certificate alerts. Inspect:

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

With explicit tenant administrator access on a TEST tenant, validate app-only OAuth2, Exchange scoped SMTP.SendAsApp grant, accepted domain and approved mailbox. For Connector verify the actual tenant inbound Connector, authorized unshared public IP or matching TLS identity, and outbound TCP 25. Connector-only sender policies allow accepted-domain envelope identity preservation or subdomain-to-accepted-domain rewrite. These operations are NOT Microsoft 365 sender permission grants. Validate RFC5322 From/header rewriting and final recipient delivery on a test tenant before enabling them on production. For Direct Send enforce INTERNAL recipient scope. The Wizard has an independent fresh Direct Send sidecar installer requiring no Entra/OAuth configuration and a separate SHA-guarded route switch for an existing XOAUTH2 sidecar. Neither creates an Exchange Connector or changes MX/SPF/DKIM/DMARC, nor do they alter the primary Postfix. Tenant domain ownership, actual Connector authorization and delivered messages must still be verified.

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


## 5b. Guarded public SMTP submission (expert opt-in; NOT production-approved)

Public exposure remains **off by default**. Only the independent XOAUTH2
sidecar on a selected private IPv4, with working Dovecot SMTP AUTH,
mandatory STARTTLS (TLS 1.2+), trusted CA and exact DNS/SNI, an active local
health timer and active, **operator-tested Fail2ban postfix and dovecot jails**
is eligible. The script checks jail existence, not whether real attacks
actually trigger a ban or whether the logs are collected from the sidecar.

The separate public manager configures per-IP authentication, connection,
message and recipient rate limits, removes rate-limit exceptions and
preserves \`permit_sasl_authenticated, reject\` relay rules. It opens an
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

The same manager provides guarded \`--status\` and \`--restore\`, closing its
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
