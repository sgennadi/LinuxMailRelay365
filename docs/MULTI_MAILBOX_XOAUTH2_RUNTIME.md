# Multi-mailbox XOAUTH2 runtime (experimental, NOT Stable)

The LinuxMailRelay365 Windows Wizard does **not** yet activate this route.
This branch adds separate Linux runtime and an explicitly approved
**offline-only** isolated Postfix installation tool. No Microsoft 365 tenant
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

**No automatic proof timer is installed.** A real production deployment
needs a root-owned, validated periodic renewal service and an independently
verified policy revocation/stop pathway; this 120-second manual receipt is
appropriate only for supervised tests. It does not prove any real SMTP AUTH
client's identity, Exchange mailbox permissions, external recipient delivery,
or successful login to Microsoft 365. The sidecar is never started by the
installer or Wizard.
