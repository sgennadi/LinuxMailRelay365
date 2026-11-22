# Multi-mailbox XOAUTH2 runtime (experimental, NOT Stable)

The Windows Wizard offers experimental Stage -> Preview -> Apply Offline
and Restore Preview -> Restore Offline. It never starts the route or
sends a message. This branch contains a guarded isolated Postfix runtime. No Microsoft 365 tenant
or real recipient tests have been performed. No daemon is automatically started.

## Data flow

1. An application submits mail to isolated Postfix on a custom port (for
   example 2525) using STARTTLS and Dovecot SMTP AUTH.
2. Postfix rejects a MAIL FROM that is not owned by the authenticated login.
   The From-Guard Milter checks that the RFC5322 From (and optional Sender)
   matches MAIL FROM; forged Return-Path and Resent headers are rejected.
   Non-SMTP submission through local sendmail/postdrop is denied with an
   empty authorized_submit_users list.
3. Postfix pipe passes **one recipient**, **MAIL FROM**, **SASL username**
   and **SASL auth mechanism** from its authenticated queue metadata to the
   unprivileged m365mailer process.
4. The pipe verifies the root-owned runtime map's reviewed SHA-256, checks
   ingress configuration, matches the SASL username and MAIL FROM to one
   identity, requires From/Sender consistency and chooses only that mailbox's
   protected OAuth2 configuration.
5. Using the selected OAuth2 certificate/TPM signer, SMTP is submitted via
   smtp.office365.com:587 and STARTTLS/XOAUTH2. SMTP acceptance **does not
   prove inbox delivery**.

**Important restriction:** Envelope From must equal configured M365 mailbox.
Arbitrary Exchange Send As, aliases, shared sender delegation, and
cross-mailbox identity selection are not authorized by this runtime. Separate
Exchange permissions and real tenant acceptance are prerequisites to expanding
that support.

## Root-only identity map

Source: /etc/linuxmailrelay365/oauth-senders.tsv, mode 0600 root:root.
Expected UTF-8 TSV header and sample values:

    smtp_login	envelope_from	m365_mailbox	identity_config_path
    alice	alice@example.org	alice@example.org	/etc/linuxmailrelay365/oauth-identities/alice.json
    bob	bob@example.org	bob@example.org	/etc/linuxmailrelay365/oauth-identities/bob.json

Identity JSON: root:m365mailer 0640 and protected signing material. No
passwords, access tokens or refresh tokens in the TSV. The installer copies
the reviewed source map to a root:m365mailer 0640 runtime map and embeds the
exact SHA-256 in the pipe transport command. Initial capacity: up to 64
individually authorized sender mappings.

## Preparing the source bundle

Copy these reviewed Python files into the root-owned directory
/opt/linuxmailrelay365/multi-oauth (not a user-writable directory):

    m365-multi-mailbox-transport.py
    manage-multi-mailbox-postfix.py
    m365_xoauth2_transport.py
    m365_hardware_signer.py
    audit-oauth-sender-map.py
    audit-oauth-ingress.py

Verify the existing SMTP AUTH, guard-Milter, owner maps, port, certificate
and Dovecot service first. The installer refuses an existing
/var/lib/linuxmailrelay365-eop-route-recovery/active.json ownership marker:
reconcile the existing route and recovery state separately; never overwrite
a current delivery route just to proceed.

Read-only preview, before any maintenance:

    sudo python3 /opt/linuxmailrelay365/multi-oauth/manage-multi-mailbox-postfix.py --plan

Review MULTI_OAUTH_PLAN_SHA256. The preview does not stop services, alter
Postfix, send SMTP, create cloud objects or open firewall ports.

The administrator must separately stop the isolated sidecar and confirm that
the queue is **empty**, then use the **same reviewed hash** during a
maintenance window:

    sudo python3 /opt/linuxmailrelay365/multi-oauth/manage-multi-mailbox-postfix.py --apply-offline --approve-sha256 REVIEWED_SHA256 --confirm INSTALL_MULTI_MAILBOX_OFFLINE

The installer creates a fresh root-only safety backup, checks exact host and
configuration fingerprints again, deploys the protected runtime bundle and
identity map, changes only the isolated sidecar main.cf/master.cf, performs
Postfix configuration check, and **leaves the service stopped**. New Postfix
parameters are default_transport=m365multi:, relay_transport=m365multi:,
m365multi_destination_recipient_limit=1 and
m365multi_destination_concurrency_limit=2. The master.cf transport is a
non-shell pipe with the following four trusted Postfix queue macros:

    recipient, sender, sasl_username, sasl_method

The installer refuses missing/incompatible configuration, changed fingerprints,
a nonempty queue, active/unknown service state, unsupported ACL/xattr state,
untrusted script paths, or a previously installed route. No primary
/etc/postfix files are intentionally changed. Errors attempt rollback only if
the sidecar is still stopped. Never start the service after an unverified
rollback; recover manually using the printed safety backup and a full system
backup.

## Remaining acceptance

- Check offline Postfix settings and all script/map permissions and hashes.
- Check a real authenticated SMTP session, correct sender, wrong login,
  forged headers, Milter outage and queue isolation.
- Test separate OAuth tokens per mailbox and real SMTP AUTH against Microsoft
  365, then send to one internal and one external recipient and verify inbox
  plus message trace.
- Check physical TPM, RHEL-compatible SELinux Enforcing, distro-specific
  behavior and restoration after reboot.
- Connect this workflow to the Windows Wizard with resizable 200% DPI UI and
  a reviewed Restore operation.
- Sign artifacts and pass production acceptance before marking Stable.

For app-only Microsoft 365 OAuth, Microsoft's Exchange documentation covers
SMTP.SendAsApp, admin consent, Exchange Online service principal registration,
mailbox access and separate Send As grants when using another sender. See:
https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth

## Root-issued ingress proof (supervised test only)

The XOAUTH2 pipe runs under the unprivileged `m365mailer` user. It **must not**
be added to the `dovecot` or `postfix` groups just to read the SMTP
password hash database or root:postfix From-Guard policy. The original
per-message ingress audit would have been denied by Linux permissions; this
has been replaced by an **expiring privileged receipt**.

With independent Postfix, Dovecot and From-Guard already running, a root
administrator may request a fresh read-only audit and publish an
`/etc/linuxmailrelay365/oauth-ingress-proof.json` receipt (root:m365mailer,
0640). The only write is this privacy-safe receipt. It contains **no
usernames, addresses, password hashes, OAuth tokens, private keys or message
contents**. Root verifies the exact active sender map, identities, SMTP
security policy, pinned From-Guard and configured Postfix pipe. The receipt
expires after **120 seconds**; the unprivileged transport checks its expiry,
the runtime sender-map SHA-256 and root-owned Postfix file metadata before
requesting a token. An absent, stale or changed proof results in a temporary
SMTP delivery failure, never a fallback to a different mailbox.

For explicit manual acceptance, use the new Wizard diagnostics button
`Refresh 120-second SMTP AUTH/From Guard proof`, or after reviewing the
exact map SHA-256 run on Linux:

    sudo python3 /opt/linuxmailrelay365/multi-oauth/refresh-multi-mailbox-proof.py --map-sha256 REVIEWED_MAP_SHA256 --confirm REFRESH_PRIVILEGED_MULTI_INGRESS_PROOF

**By default no automatic proof timer is installed.** An optional,
SHA-reviewed systemd renewal manager is provided below, but it is not
activated during source staging or offline route installation. Actual
production use still requires root-owned renewal validation and independent
policy revocation/stop acceptance; manual 120-second receipts are appropriate
only for supervised tests. It does not prove any real SMTP AUTH
client's identity, Exchange mailbox permissions, external recipient delivery,
or successful login to Microsoft 365. The sidecar is never started by the
installer or Wizard.

## Offline Multi-mailbox Restore (experimental)

**Before Preview or Restore, disable the optional experimental ingress-proof
renewal timer and revoke its receipt.** The restore tool refuses operation if
the managed service unit, timer unit or timer state directory exists (including
a symlink). The timer manager and route Restore share the root-only
`/run/linuxmailrelay365-sidecar-auth.lock` so an operator cannot enable or
disable timer units concurrently with configuration recovery.


The installer now writes a root-only (0600) active marker under
/var/backups/linuxmailrelay365-multi-oauth/active.json **only after** a
successful Postfix configuration check. The marker contains the SHA-256
of original and installed Postfix config files, the runtime sender map,
installed Python source, the original approved plan, and an exact
pre-install backup ID (pre-multi-XXXXXXXX). No credentials are stored.

**Read-only Preview** requires the marker, original safety archive,
manifest, current installed SHA, unchanged primary Postfix and protected
runtime map/source hashes. It returns the reviewed SHA and exact backup ID:

    sudo python3 /opt/linuxmailrelay365/multi-oauth/restore-multi-mailbox-postfix.py --preview

The operator must separately stop the isolated sidecar, verify the queue
is **empty**, and verify the custom SMTP port is not listening. Only then
can the exact reviewed SHA and archive be used to apply the restore:

    sudo python3 /opt/linuxmailrelay365/multi-oauth/restore-multi-mailbox-postfix.py --restore-offline --backup-id pre-multi-XXXXXXXX --approve-sha256 REVIEWED_RESTORE_SHA256 --confirm RESTORE_MULTI_MAILBOX_OFFLINE

The operation acquires the same exclusive sidecar-auth lock as EOP and
SMTP AUTH route management. It verifies a fresh root-only pre-restore
snapshot under /var/backups/linuxmailrelay365-multi-oauth/pre-restore-XXXXXXXX
before replacing any files. The original main.cf/master.cf are restored
and Postfix configuration is validated while the sidecar remains stopped.
The old OAuth runtime, protected sender map, expiring ingress proof and
active marker are **quarantined inside that private emergency snapshot**,
not deleted. The separate pre-install archive is retained unchanged.

Any failure triggers an attempted offline rollback. If rollback cannot be
verified, do **not** restart mail services: inspect the emergency backup
and perform manual recovery. The successful result
MULTI_RESTORE_STATUS=restored_offline_not_started confirms configuration
restoration, **not** live delivery or an automatically started service.

The Wizard includes a pair of Restore Preview and Restore Offline actions.
It binds the approval to the reviewed SHA, archive, SSH host and selected
route, then invalidates the approval after one attempt.

The EOP route manager reciprocally refuses changes when an active
Multi-mailbox marker owns the sidecar. **Automatic migration between
EOP Connector and Multi-mailbox XOAUTH2 is intentionally blocked**.
Restore the original route and start a separately reviewed operation;
never overwrite a manager-owned active route.

Physical TPM, SELinux Enforcing, actual Microsoft 365/recipient delivery,
and full Windows GUI 200% DPI visual tests remain open. Do not release
this branch as Stable.

## Controlled Microsoft 365 acceptance for one selected multi-mailbox sender

The development Wizard also provides **6. Preview two M365 messages**
(read-only, no network send) and **7. Confirm TWO real test messages**,
visible only after a reviewed Preview. The operator chooses one sender from
the active root-owned runtime sender map plus two consenting test recipients:
one in the sender's domain and one in a different domain. These domain
checks do not verify Microsoft 365 accepted-domain membership.

The Preview returns a fresh 32-character run ID, SHA-256 of the sender
and recipient values, and one immutable reviewed plan SHA. A second
typed confirmation is required before **any** SMTP submission. Address
values are sent only over the verified SSH session inside bounded
Base64-encoded JSON, never as Linux command arguments or raw logs.
An actual one-mailbox permission is checked in the active map; other
mailbox identities and arbitrary From aliases cannot be selected.

On an approved test, a root-only Linux orchestrator
`manage-multi-mailbox-acceptance.py` obtains the shared route lock,
rechecks the active ownership marker, pinned source and identity hashes,
and reserves the run ID in an exclusive root-only ledger **before**
network activity. It generates a new privileged 120-second From-Guard
proof immediately before each of the two messages, then invokes the
unprivileged m365mailer transport with a bounded role/recipient request.
The transport uses its existing fixed text-only acceptance template,
mapped OAuth certificate/hardware signer and Microsoft 365 STARTTLS +
XOAUTH2 on TCP 587. No custom headers, Bcc, attachments, message body,
recipient CLI switches or automatic retries are accepted.

A successful SMTP result is reported as
`MULTI_ACCEPTANCE_TWO_SMTP_SUBMISSIONS_ACCEPTED=yes` with
`MULTI_ACCEPTANCE_RECIPIENT_INBOX_VERIFIED=no` and
`MULTI_ACCEPTANCE_EXCHANGE_TRACE_VERIFIED=no`. A timeout, SSH loss or
first-message partial result is **unknown**, not a failure safe to retry.
The same run ID is permanently reserved for that host; inspect both
test inboxes and Exchange Online Message Trace before planning a new run.

The direct acceptance test validates **Entra token acquisition, Exchange
XOAUTH2 SMTP authentication and submission for one explicitly selected
mailbox**. It deliberately bypasses the local application's inbound SMTP
session, so it does **not** prove local Postfix SMTP AUTH, queue-bound
SASL ownership, the Milter's runtime reject behavior, real end-to-end
relay delivery, Dovecot TLS client trust or a recipient's inbox.
These require separate supervised client-to-Postfix SMTP tests and
independent Exchange message-trace evidence. No production rollout or
Stable release is authorized by a green CI or a successful test submission.


## Two fixed M365 acceptance messages and read-only status after SSH loss

In the development Windows Wizard, choose an explicitly authorized sender
mailbox already present in the active protected runtime map, one internal test
recipient in that sender's domain, and an external test recipient in another
domain. **Preview** calculates a SHA-256 bound to those three addresses, the
active route identity and the generated unique run ID without sending mail.
**Apply** requires typed permission to send exactly two fixed text test messages.
This is a **direct OAuth2/XOAUTH2 acceptance test**, not an end-to-end test of
the application's inbound local Postfix SMTP AUTH, and neither SMTP acceptance
nor the tool proves recipient inbox arrival.

Before each send the root-only controller verifies the active route and
short-lived SMTP ingress proof and reserves a new private append-only ledger
under /var/lib/linuxmailrelay365-multi-acceptance/<run-id>.jsonl. A reservation
or attempted-send record is fsynced **before** the helper opens an outbound
connection. The unprivileged direct test helper additionally verifies it was
launched by a root-owned Linux runuser process; other unprivileged
invocations are denied. There is no automatic retry after SSH disconnect,
timeout or partial delivery, even if the second send has not started.

A read-only ledger query never opens the network, sends mail or reveals
addresses/tokens:

    sudo python3 /opt/linuxmailrelay365/multi-oauth/manage-multi-mailbox-acceptance.py --status --run-id 0123456789abcdef0123456789abcdef

The Wizard displays this through **Inspect last SMTP attempt ledger**. Ledger
states distinguish reserved, internal attempted (outcome uncertain), internal
SMTP accepted, external attempted (outcome uncertain), both SMTP accepted but
final journal write missing, and fully recorded dual SMTP submission. This
record still cannot show Exchange transport or inbox delivery. Check both
test inboxes and Microsoft 365 Exchange message trace independently before
treating an interrupted or partial attempt as finished; start a **new reviewed
test with a new run ID** only after deciding deliberately whether to retry.

## Optional root-reviewed renewal of 120-second ingress proof (experimental)

The source staging bundle also includes `manage-multi-mailbox-proof-timer.py`.
**Staging or applying the multi-mailbox route does not enable this timer.**
The timer is an opt-in systemd facility for a separately configured and
working isolated SMTP AUTH/From-Guard ingress. On each run the existing
root-only static audit may publish a new 120-second receipt, but this
does not prove a real SMTP client, Exchange Online permissions, or inbox
delivery. It never starts the MTA or sends mail.

After separately starting and testing SMTP AUTH + STARTTLS, as root inspect
the exact sender map and installed route:

    sudo python3 /usr/local/libexec/linuxmailrelay365-multi-oauth/manage-multi-mailbox-proof-timer.py --plan

The plan is read-only and returns `MULTI_PROOF_TIMER_PLAN_SHA256`. Only if
the values are correct and the SMTP system is actively supervised can
the operator explicitly enable renewal:

    sudo python3 /usr/local/libexec/linuxmailrelay365-multi-oauth/manage-multi-mailbox-proof-timer.py --enable-reviewed --approve-sha256 REVIEWED_SHA256 --confirm ENABLE_REVIEWED_MULTI_INGRESS_TIMER

The manager installs one root-only systemd oneshot unit and a 60-second
timer. The service uses a pinned sender-map SHA and a restricted filesystem
sandbox, and its entrypoint never uses a stored OAuth token, SMTP password,
or network SMTP connection. An audit failure does **not** make a stale
receipt valid: the transport refuses an expired proof after 120 seconds.
Service activation also refuses changed runtime map or changed source/config
SHA. Check status with `--status`.

To disable renewal and revoke the current local proof (messages then fail
closed until a separately approved fresh proof exists), run:

    sudo python3 /usr/local/libexec/linuxmailrelay365-multi-oauth/manage-multi-mailbox-proof-timer.py --disable-reviewed --confirm DISABLE_AND_REVOKE_MULTI_INGRESS_TIMER

Timer disable/rollback requires the unit to be both stopped and disabled;
an inactive but still enabled timer blocks deletion and receipt revocation,
because systemd may reactivate it after a reboot.

If initial activation fails after a refresh attempt, the manager also attempts
to revoke that newly issued local receipt before removing verified unit files.
If any unit, ownership or state has unexpected content, the manager stops
and requires manual review instead of replacing or deleting it. Do not
modify these systemd units by hand while enabled. This workflow is not
auto-activated by the Windows Wizard and has **not** yet passed a real
systemd/timer acceptance test on a host with the full multi-mailbox stack.

Any production release still requires real client-to-Postfix SMTP AUTH,
the per-mailbox token/SMTP submission acceptance, Exchange message trace,
DPI/GUI checks and managed credential/signing validation.
