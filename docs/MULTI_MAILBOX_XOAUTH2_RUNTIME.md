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
SHA. `--status` reports both timer state and `MULTI_PROOF_RECEIPT`: `fresh_ttl_only`,
`expired`, `missing`, `map_changed` or `not_applicable`. A receipt within its
120-second lifetime is **not** evidence of successful SMTP AUTH or inbox
delivery; it is only an age and sender-map consistency indicator.

To disable renewal and revoke the current local proof (messages then fail
closed until a separately approved fresh proof exists), run:

    sudo python3 /usr/local/libexec/linuxmailrelay365-multi-oauth/manage-multi-mailbox-proof-timer.py --disable-reviewed --confirm DISABLE_AND_REVOKE_MULTI_INGRESS_TIMER

Timer disable/rollback now verifies the inactive/disabled systemd unit
properties separately after a nonzero quiet status. It refuses missing,
failed, masked, unexpected or externally replaced units: LoadState must be
loaded, FragmentPath must match our exact unit file, and NeedDaemonReload
must be no. It never treats a generic systemctl error as safe shutdown.
Timer disable also requires the oneshot audit service itself to be inactive,
not only the timer, before removing units or revoking the local proof. An
inactive but still enabled timer blocks deletion and revocation, because it
may restart after a reboot. A failed proof timer shutdown leaves state for
manual review rather than claiming safe removal.

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

## Source/runtime identity inventory (post-RC19, pending CI)

The Multi-mailbox identities and certificates dialog lists the prepared
root-only oauth-senders.tsv and installed oauth-runtime-senders.tsv on
separate tabs. It checks each exact login/sender/mailbox, protected identity
JSON, canonical tenant and application IDs, configured signer type and
referenced public PEM digest. It never opens a private key, invokes a
signer, obtains a token, sends mail, or changes a service. Both samples
must agree, and source/runtime SHA-256 values are compared independently.
The installed recovery marker is compared to the runtime map and current
main.cf/master.cf digests; this is not evidence of a running sidecar.
If an exact Graph/Exchange inventory was previously read on this same
Linux connection, certificate digests are compared only for the same
Tenant ID and Client ID; cached mailbox RBAC requires an exact mailbox as
well. The UI explicitly marks these observations as previous samples.
No certificate validity or key possession is inferred from local PEM bytes.
An absent, unsupported, malformed or changed configuration never becomes
a successful audit. Full live cloud per-mailbox inspection and protected
source-map editing remain separate development steps.

## Selected mailbox live cloud inspection (post-RC19, pending CI)

Select a source or runtime row and choose Verify selected mailbox in
Microsoft 365. The exact Tenant ID, Client ID and mailbox are shown for
explicit read-only sign-in approval. The main Wizard fields are not changed.
Native C# Graph retrieves that application and public certificate digests;
Exchange Online uses the exact returned Enterprise Application ID and a
mailbox-only mode, without enumerating connectors, scopes or assignments.
If Graph cannot identify the service principal, only the Graph observation
is shown and Exchange remains unverified. Each observation is tied to the
source/runtime scope, map SHA, complete row and runtime recovery binding.
Fresh Linux inventory is checked before and after the cloud call; selection,
SSH key or configuration drift invalidates the result. Observations are
in-memory and cleared by Refresh. The timestamp and separate SMTP AUTH,
mailbox identity, service principal and RBAC findings are shown per row.
The administrator may need separate Graph and EXO device-code sign-ins;
no new write permissions, tokens on disk, changes or mail sending are added.
Local certificate validity, key possession and actual provider SMTP AUTH
or delivery are still not verified. Real tenant acceptance remains open.

## Prepared source-map editor backend (pending CI)

The editor modifies only oauth-senders.tsv, never the runtime map, identity
files, cloud objects, services or queues. Add/Edit bind an existing exact
identity, by filename or unique valid mailbox match; Remove deletes only
the selected source row. The last row and noncanonical source files require
separate manual review. All remaining identities/public certificates must
pass the inventory guard. A preview binds old/new map SHA-256 and identity
evidence; saving requires the same plan and typed approval. The existing
sidecar installation lock is shared, a root-private backup with manifest
is synced before atomic replacement, and committed bytes are read back.
An existing SELinux label is preserved; initial creation on an SELinux
system is refused until policy-aware creation is separately implemented.
Other root administrators must not edit the source concurrently. The
backup directory is /etc/linuxmailrelay365/oauth-source-backups; automatic
restore, identity creation and live activation are separate operations.

The GUI exposes Add mailbox, Edit mailbox and Remove row on Source only.
A typed confirmation is tied to an exact preview (including existing
identity metadata and certificate digest). The saved receipt must match
the preview and a newly read source inventory. Cached cloud observations
and reviewed install/restore plans are invalidated before saving. An
uncertain save locks source editing for the current window, even after
Refresh, and directs the operator to the root-private backup. Runtime
remains read-only in this dialog. Add/Edit reuse an existing identity;
new identity provisioning and backup restore are not implemented here.

## Planned source-map restore (pending CI)

Restore source map accepts an exact backup ID from the previous save
receipt or root-private backup directory. It reads the original manifest
and verifies both the stored source digest and the recorded successor
against the current source map; newer edits cannot be overwritten by an
older backup. The original bytes must still form a valid canonical map
with verified remaining public identity evidence. Restore has a separate
typed approval, reuses the shared installer lock and creates a new backup
of the current map before atomic replacement. The existing source file's
ownership and SELinux label are preserved, not historic metadata. Backups
representing an originally absent map are refused (decommission is a
separate operation). The GUI verifies the saved receipt and new source
inventory; installed runtime, cloud objects and keys are untouched. The
Linux CI additionally exercises real root-owned temporary files, manifest
checks, atomic save/restore, stale-map and tampered-backup refusal. Signer
and identity checks use synthetic fixtures. This is not yet live SELinux
or tenant acceptance. No automatic backup deletion is added.

## Read-only compatible backup catalog

Restore source map now discovers compatible root-private backups before
showing the picker, with an optional exact-ID manual entry. The bounded
catalog inspects at most 256 directory entries and returns at most 64
matching backups; it refuses overflow rather than returning a partial
list. Each listed backup has a valid private manifest, canonical source
bytes, verified digest and a recorded successor equal to the current
source SHA. The catalog contains only IDs, stored map digests and row
counts; it does not read OAuth identity JSON, keys or certificates.
Missing, stale, malformed and unsafe backup entries are not offered.
The catalog is not a restore approval: selecting an ID still requires
the existing fresh identity/certificate checks, exact plan, typed
approval, shared lock and readback. No production services, runtime
routes, cloud objects, queues or backups are changed by browsing.


## Prepare an unbound local OAuth identity (experimental)

Source / planned now offers New OAuth identity. Enter an existing Entra
Tenant ID, application Client ID, mailbox and validity (1–365 days).
The read-only preview binds the new unique filename, current source/runtime
map digests, directory metadata, service group and OpenSSL version. Apply
requires the same reviewed plan and typed confirmation. The local RSA 3072
private key, public certificate and identity JSON are root:m365mailer 0640;
the JSON is published last after a real service-account PS256 signature
and certificate verification. The private key is never transferred. Export
only the public DER certificate (.cer) from the GUI; register it and review
Exchange permissions separately, then bind via Add mailbox. No cloud
application or mailbox is created; no route, map, queue or service changes.
No overwrite or automatic deletion of partially published files is allowed.
An interrupted apply requires manual review of the printed unique basename.
Requires existing trusted /etc/linuxmailrelay365 and m365mailer account.
A missing oauth-identities directory is created root:m365mailer 0750;
existing directories must already match that policy. SELinux-active hosts
are refused pending policy-aware creation; TPM is not yet offered here.
The real disposable CI test uses RSA/OpenSSL and a local service account,
not a real Microsoft 365 tenant. Existing bound mailbox rotation remains
separate.


## Append a prepared public certificate with native Graph addKey (experimental)

Select a mapped mailbox with an existing software certificate, then choose
Register prepared certificate and enter the unbound mbx-<32 hex>.json
identity filename. The last prepared filename is suggested in the current
window. The two identities must belong to the exact same tenant and Entra
application; the candidate must not already be bound in either map. The
Linux preview returns only exact public DER and map/identity digests.
Native Graph checks the existing valid registered certificate and reviewed
key inventory. A typed confirmation and fresh Linux review are required
before generating an ephemeral RS256 Graph proof using the existing key.
The proof stays in memory, is never logged or written to a payload file.
Graph addKey appends one public certificate, never PATCHes the certificate
collection or removes an existing key. Exact existing-key metadata and
new key presence are checked by the native Graph client. If the result is
uncertain, inspect the app before retrying; editing is locked in that window.
The new credential inherits the application's existing authority; this
operation does not grant, restrict, or test Exchange mailbox permissions.
No first-certificate bootstrap, hardware donor proof, or new application
creation is attempted. In those cases use the public certificate export
and separately reviewed Entra registration. No route, service or mail
changes. CI uses synthetic maps, real local RSA proof verification and
receipt tests; real Entra/Exchange acceptance remains open.


## Configure selected mailbox SMTP RBAC (experimental)

Select a source-map mailbox with a valid registered public certificate and
choose Configure SMTP RBAC. Native Graph verifies the exact app, Enterprise
Object ID and certificate. Exchange-only PowerShell checks the session's
tenant and resolves the primary SMTP address to the recipient GUID. A new
scope uses exact GUID equality, and must match precisely one recipient.
It does not use or change CustomAttribute15. Deterministic names are unique
per app and recipient; existing name collisions require manual review.
The reviewed SHA-bound plan optionally creates the absent EXO principal,
scope and Application SMTP.SendAsApp assignment. Existing in-scope roles
are not duplicated. Mailbox-only SMTP AUTH enable is opt-in and defaults
to unchanged. The plan is reread before Apply; exact scope, assignee, role,
policy and authorization are verified afterward. No Entra API grant,
organization policy, existing role/scope edit, Linux config or mail sending.
If an Apply result is uncertain, inspect the actual objects before retrying;
no automatic removal or rollback. Existing app grants remain cumulative:
this is not proof of exclusive mailbox access or live SMTP authentication.
See https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/smtp-app-rbac-onboarding
and https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac.
Live tenant acceptance, including actual Exchange property serialization,
remains necessary. Offline tests do not mutate a tenant.


## Dedicated new Entra app and initial certificate (experimental)

New Entra app / recover first stages a unique Linux RSA-3072 certificate
without a fake Client ID or usable identity JSON. A root-only pending record
binds tenant, mailbox, lifetime, source/runtime hashes and local key/cert
fingerprints. A separate typed confirmation authorizes native Graph creation
of a new single-tenant App Registration with its initial public certificate
and corresponding Enterprise Application. A durable root-only no-clobber
claim is written BEFORE Graph POST; it prevents repeating uncertain cloud
creation. Graph verifies the exact app name, IDs and sole public certificate
before the local identity JSON is published. No existing app is reused or
PATCHed, and no Exchange/API mail permissions or routing are activated.
Recover a pending stage using the original mailbox, tenant, lifetime and
64-hex recovery code. If claimed, find the exact generated app name in Entra
and enter its Client ID. Recovery is read-only in Graph, verifies the exact
certificate and Enterprise Application, and requires local bind approval.
If the cloud app or Enterprise Application was only partially created, repair
or review it manually; never blindly recreate. Pending/claim files are retained
as root-only evidence; no automatic deletion. Map changes invalidate the pending
context. TPM and SELinux policy-aware staging remain open. CI exercises the
actual local stage/claim/finalize flow, not a live tenant.


## Live selected mailbox SMTP AUTH-only diagnostic

Select one exact source or runtime identity and choose Test SMTP AUTH only.
After explicit approval, root resolves the selected map row and checks its
identity and public certificate digests; a temporary root-owned code bundle
under /run executes the actual signer and SMTP probe as m365mailer. Local
PS256 signature verification, a bounded no-redirect HTTPS token request to
Entra, and certificate-validated STARTTLS/XOAUTH2 to smtp.office365.com:587
are attempted. No recipient or message is accepted by this helper. Existing
mapped CLI delivery restrictions are unchanged. No MAIL FROM, RCPT TO, DATA,
queue/service changes, Graph writes or token export. The GUI shows fixed
result categories (including HTTP/SMTP codes), not raw server responses,
assertions or access tokens. It checks the selected identity again before
accepting an in-memory timestamped sample; refresh or edits clear samples.
This is not Postfix ingress, SELinux service-domain or mail-delivery proof.
No real tenant is exercised by offline tests. Network/proxy-only hosts and
hardware/SELinux permission failures require manual review, not policy bypass.


## Optional TPM 2.0 protection for an existing-app mailbox identity (experimental)

New OAuth identity first checks the connected Linux host, trusted identity
directory, dedicated m365mailer user, TPM2 resource manager, trusted tools,
OpenSSL 3 native TPM2 provider, provider/device access as m365mailer and a
free persistent handle. The software RSA-3072 default stays available;
TPM RSA-2048 appears only after successful prerequisite discovery. No
packages, device permissions or SELinux settings are changed. The exact
handle, TPM inventory, provider configuration, current map and identity
context are bound into the reviewed plan. A separate typed confirmation
creates one fresh TPM primary key, persists it using only its transient
context, verifies the public key, produces a public certificate, and
verifies PS256 as m365mailer. The protected identity JSON references the
persistent handle and its own root-managed provider config; no PEM private
key or fallback is created. Failure requires inspecting the specified handle
and partial files; never automatically remove or recreate a TPM object.
The local proof is not hardware attestation. Import the public certificate
manually in the existing Entra application, bind the mailbox separately,
and run a live SMTP AUTH-only check. No existing role, map, service, or
cloud changes. New Entra app initial TPM staging, automated hardware
candidate registration, SELinux-aware creation, provider packaging and real
physical/vTPM acceptance remain open. The automated TPM command tests use
mocks, not real hardware.


## TPM protection for a dedicated new Entra app (experimental)

The new-app certificate dialog shares the read-only TPM prerequisite check
with existing-app certificate creation. A reviewed free handle is optional;
software RSA-3072 remains the default. TPM RSA-2048 stages the initial
public certificate with a root-only durable attempt marker before key
persistence and verifies PS256 as m365mailer. No PEM private key is created.
The pending evidence binds the exact handle, provider configuration, attempt
marker, certificate, tenant, mailbox, recovery code and maps. The existing
one-shot Graph creation claim is still required before POST. The final
identity references the verified TPM handle only after the native Graph
application and enterprise identity checks. A claimed app is never recreated.
For recovery, enter the original handle as well as the original recovery
parameters; a different backend or handle cannot resume the same stage.
Legacy software requests and pending records retain their exact format.
If a TPM stage was interrupted before its pending record was completed,
inspect the attempt marker, handle and files manually. No automatic eviction,
software fallback, or policy change. Tests use a real public X.509 certificate
with mocked TPM commands; physical TPM/vTPM, real tenant and SELinux-aware
creation remain unverified. No mail or Postfix route activation.


## SELinux-aware software identity creation (existing Entra app, experimental)

The existing-app New OAuth identity workflow now supports active SELinux
for software RSA creation when the installed file-context policy is
verifiable. Preview reads the kernel mode and exact raw matchpathcon labels
for the trusted base directory, identity directory and the three new files.
Existing directory contexts must already match; missing/untrusted tools,
unsafe/default labels, foreign xattrs or mismatched contexts refuse the
operation. A standard etc_t configuration label is allowed when it is the
exact installed policy result. The plan digest binds all labels and the
mode; the GUI displays the mode and policy digest. A new directory is
created privately, labeled before granting service-group access. Only new
scratch inodes receive their reviewed destination label before exclusive
publication. Each publication rechecks the complete policy, the resulting
inode/ownership/mode/label and unchanged SELinux mode. The existing local
m365mailer PS256 proof and identity readback still apply. No changes to
SELinux policy, mode, existing labels, Postfix, services or Entra are made.
This is file-label publication and local account access evidence, not a
confined systemd-domain or live Enforcing VM acceptance result. Synthetic
user-xattr CI tests exercise real filesystem labeling, stale policy refusal
and unchanged existing files; they do not emulate kernel enforcement.
New-app stage/claim/recovery, TPM provisioning and new source-map creation
retain active-SELinux refusal until their additional markers and runtime
policy are integrated and validated. No global relabel or protection bypass.


## SELinux-aware new application software staging and recovery (experimental)

New Entra app / recover uses the exact installed-policy label reader and
exclusive publisher for software RSA. Only the three generated identity
files and their exact hidden pending and claim markers are allowed. Preview
binds prospective contexts and kernel mode. The root:root 0600 pending
record persists the reviewed mode and policy digest; inspect, claim and
finalize compare these against current installed policy and actual contexts.
Existing files are not relabeled. The root-only claim is still published
before Graph POST and remains bound to the exact pending record hash.
Drift in prospective or existing labels, mode changes, foreign xattrs or
missing policy tools refuse recovery. The GUI compares policy receipts
across stage/claim/finalize and shows evidence during review. Inactive
software stages keep their original schema. Different-mode stages require
manual review rather than silent migration. TPM with active SELinux and
unrelated source-map/runtime writes remain gated. Synthetic user-xattr tests
cover staging, claim, recovery and finalization; no live Enforcing VM,
confined service-domain or real tenant acceptance is claimed.


## TPM with reviewed active SELinux file policy (experimental)

Both TPM identity preparation and new-app TPM staging now use the reviewed
SELinux context publisher. Discovery checks directory contexts and service
account TPM/provider access; exact generated file contexts are checked at
Preview. The namespace includes the provider configuration and a root-only
TPM attempt marker. Both TPM workflows publish a durable marker before key
persistence; an uncertain attempt must be inspected, never automatically
recreated or evicted. New-app pending records bind all seven prospective
file contexts through claim and finalization. Existing labels, policy, mode,
mail routes and cloud permissions are unchanged. No PEM fallback. Inactive
pending schemas remain compatible. Tests use mocked TPM commands and real
temporary files with synthetic user xattrs, not kernel enforcement. Physical
TPM, confined systemd-domain, live Enforcing VM and tenant acceptance remain
open. The Windows new-app self-test now mutates certificate JSON fields
structurally instead of replacing potentially escaped Base64 text; production
receipt checks are not weakened.


## Register managed TPM public certificates in existing Entra applications

Register prepared certificate now accepts software and LinuxMailRelay365-managed
TPM identities on either side of the same-app pair. Only the exact per-identity
provider configuration and managed persistent handle range are accepted;
PKCS#11, wrapped blobs and arbitrary provider configs remain manual. Preview
is public evidence only and binds both signer types, identity hashes and
certificate digests. After explicit approval, a TPM candidate must pass a
fresh local PS256 check and a TPM donor signs the fixed short-lived Graph
RS256 proof as m365mailer, using PKCS#1 v1.5 (not transport PS256). The local
signature is verified against reviewed DER and native C# independently
verifies proof, current Graph certificate and plan before addKey. The
software donor path remains intact. No private key export, fallback, credential
replacement, SMTP or route changes. Primary/sidecar hardware donor support
is not changed. Existing valid registered donor certificate is required;
real TPM/provider and live tenant acceptance remain open. Tests cover mixed
pair approval, config tampering, read-only preview and mocked RS256 TPM
commands; these are not a physical TPM signature test.


## Source-map editor with reviewed SELinux file policy (experimental)

First source-map creation, edits and restore now use the installed SELinux
file-context policy when active. Preview binds the mode and exact expected
base directory, source map and private backup-root contexts; restore also
binds the selected backup directory and files. Existing contexts must
already match the installed policy. Only exclusively created scratch map
and backup inodes are labeled, using policy lookup for the actual target
path. New map creation remains no-clobber; replacements preserve group
and private mode and check the committed bytes and context. Existing files
are not relabeled. A stale plan, mismatched label or uncertain outcome is
refused or requires review. Backup catalogs omit mismatched backup entries.
No policy edits, mode changes, runtime map, Postfix reload or cloud changes.
Tests use synthetic user xattrs and real temporary files. Actual Enforcing
VM acceptance, runtime route installer/restore label coverage and confined
service-domain checks remain open.


## Offline runtime installation and restore with active SELinux (experimental)

The offline isolated Postfix route installer now binds the active mode and
expected installed-policy labels for managed config, runtime map, runtime
code, recovery and marker paths into the approved plan. Existing labels
must already match. New runtime code is labeled for its final destination
before publishing; the runtime map and marker use exclusive atomic links.
Configuration replacement verifies metadata, exact policy and committed
bytes; private safety copies are labeled and fsynced before changing routes.
The restore preview independently binds current policy, selected backup and
optional proof-file labels. New emergency copies are labeled; quarantined
existing objects retain their original contexts in a private recovery tree
and are checked after moving. No mass relabel, policy/mode edits or changes
to the primary Postfix configuration. A cross-filesystem quarantine is now
refused before modifying configuration. The sidecar must remain stopped,
queue empty and listener closed. Policy drift refuses the operation; an
uncertain rollback requires manual review. Synthetic xattr tests are not
live kernel enforcement or confined service-domain acceptance. Existing
staged installer scripts do not auto-upgrade; use a fresh supported source
stage after reviewing existing staged/runtime files. Existing inactive
marker schema remains unchanged; new evidence is recorded in the backup
manifest, while restore checks the installed policy independently.


## Guided Multi-mailbox setup (experimental)

The identity window now opens a six-step guided setup: key/application,
source mailbox binding, Entra/Exchange, AUTH-only check, offline Postfix
route, acceptance. The suggested step is based on fresh Linux evidence
and exact in-window source-row cloud and AUTH samples (ten-minute window).
The guidance is not authorization or delivery readiness; no stale or
unbound sample is counted. Back/Next never runs an operation. All actions
mode preserves the previous editor and maintenance controls. A successfully
prepared identity prefills the editable Add mailbox fields; Linux still
validates them. Route actions reuse the existing protected stage, Preview
and typed offline Apply, with a fresh inventory and pinned SSH checks.
Apply requires a Preview from this guided window; the backend still
requires stopped sidecar, empty queue and closed listener. Installed route
changes or recovery conflicts lead to the separate route/restore tools.
Acceptance opens the existing explicit two-recipient test form without
sending or filling recipient addresses; it is not local ingress or inbox
proof. Existing advanced actions remain available, including proof timer,
restore and acceptance ledger. The guided dialog does not start any service.
GUI self-tests check evidence and navigation; physical 200% DPI review,
real tenant/TPM/Enforcing VM and end-to-end delivery remain outstanding.
