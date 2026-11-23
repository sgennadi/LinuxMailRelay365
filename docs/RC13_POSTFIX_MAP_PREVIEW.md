# RC13 - Postfix candidate map preview (local, read-only)

Unsigned test candidate. No conditional Apply. No Linux configuration changes.

After discovery for the current SSH identity, the WinForms planner displays a
scrollable illustration of candidate Postfix routing map key/value shapes:

- Exact envelope sender user@example.org maps to [upstream.example.net]:587.
- Sender domain @example.org maps to [upstream.example.net]:587.
- Recipient domain remote.example.org maps to smtp:[upstream.example.net]:25.

These are illustrative candidate records only; not a deployable main.cf,
master.cf or Postfix map. Selected outbound ports never alter inbound Linux
SMTP listeners. An implicit TLS (typically 465) route is commented out and
requires a separately verified wrapper-mode transport. STARTTLS requires a
mandatory TLS client policy and identity check. SMTP AUTH requires separate
credentials, sender authorization and per-provider verification.

PlanSha256 binds only the local hypothetical rules and their order.
InventorySha256 binds only selected, sanitized read-only MTA discovery
fields, independently of the local plan. Neither is a lock or approval on
the Linux server.

PostfixRoutePolicyAudit warnings remain visible for local and virtual
delivery, existing transport/relay maps, overlapping rules, unknown domain
classes, sender-dependent SASL and TLS. No candidate keys are shown for
Exim, Sendmail, absent or inactive Postfix.

Postfix routing mechanisms and address classes differ:
https://www.postfix.org/ADDRESS_REWRITING_README.html
https://www.postfix.org/transport.5.html
https://www.postfix.org/postconf.5.html
https://www.postfix.org/TLS_README.html

Validation includes executable C# self-tests for normalized keys, TLS
warnings, domain conflicts, unsupported MTA and separate fingerprints;
Python safety contracts prevent SSH, map queries, process invocation
and file writes from this preview panel. All Linux/Windows matrix jobs
must succeed on the exact candidate SHA before immutable unsigned
release publication. No real delivery, tenant or physical DPI acceptance
is claimed.

Future production Apply requires separate read-only map ownership analysis,
real lookup precedence checks, TLS and AUTH preflight, SHA-bound managed-only
backup, atomic write, verified rollback and operator approval.
