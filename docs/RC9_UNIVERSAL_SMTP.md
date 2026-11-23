# RC9 universal outbound SMTP (development and unsigned Preview)

RC9 keeps the discovery-first design from RC8 and provides guarded **single-upstream
outbound Postfix configuration** for a user-selected SMTP server, not just M365,
Gmail or Google Workspace.

## What this changes

- Linux read-only inventory must finish before any route is proposed.
- A user may choose any syntactically valid host/IPv4 and outbound TCP port
  1-65535; the Linux *incoming* SMTP listener is never reassigned to 2525.
- Outbound transport choices: STARTTLS with peer certificate verification,
  implicit TLS with peer certificate verification, or explicitly approved
  unencrypted transport **without SMTP AUTH**. No downgrade on TLS error.
- The GUI distinguishes SMTP connection proof, password AUTH acceptance and
  real delivery. A TCP 25 success is not proof of a permitted sender/recipient.
- Postfix sender-domain rewrites, transport maps, virtual mailbox declaration,
  relay_domains and local-domain indicators are inspected read-only. Raw maps,
  messages, user secrets and protected configuration are not copied to Windows.
- The primary Postfix Apply accepts only an exact SHA-256 fingerprint, an empty
  queue, root-owned /etc/postfix, one active primary instance, supported local
  SASL when requested and no unrecognized per-destination routing/TLS maps.
- The existing recovery script creates/verifies a root-only backup, checks the
  same fingerprint again, mutates outbound settings only, runs postfix check
  and reload, verifies the outbound state and unchanged inbound/local delivery.
  A failure attempts verified root-only rollback and surfaces critical failure
  without claiming success.
- Shared exclusive file lock at /run/linuxmailrelay365-postfix-route.lock
  prevents concurrent Apply from RC9 Google and custom SMTP route managers.
- An approved SMTP username/password is passed through SSH stdin only and is
  saved to a root-only Postfix hash database *on Linux*. This database is NOT
  encryption: root administrators can recover the original credential.
- Real SMTP AUTH is tested through TLS before applying the same credential.
  No test MAIL FROM/RCPT TO/DATA is issued without a separate approved delivery
  acceptance flow.

## Intentional limits

The route manager changes **one upstream for a primary running Postfix**, not
per-user/per-domain transport maps or routes already owned by another manager.
Pre-existing routing maps, individual TLS policies, unknown mail queues,
self-loop risks and multiple Postfix instances block automatic Apply. No
configuration writes to an existing Exim/Sendmail are implemented in RC9.

Virtual mailbox or local destination declarations do not establish that local
users actually receive messages: the GUI reports only the available indicators.
A localhost:25 socket is not proof that only local mailboxes exist.

## Acceptance before signed Stable

Review Windows 100%/200% DPI GUI on real displays, RHEL-family SELinux
Enforcing, actual DNS+CA trust, Postfix reload/rollback and service/queue
persistence, authorized server/client SMTP AUTH, a real internal and external
recipient, tenant/relay policy and full signing-publisher requirements.
Green CI and an unsigned Preview are NOT production authorization.
