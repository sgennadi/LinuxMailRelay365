# Primary Postfix: shared mailbox migration candidate

This is a read-only, exact-byte candidate for the primary Postfix only. The
existing GUI Preview now returns the original config SHA-256, candidate
SHA-256, a mailbox-bound plan SHA-256, and a fixed allowlist of changed entries.
It does not save the candidate, install packages, provision identities, contact
Microsoft, send mail, or start/stop/reload services.

The planned changes are default_transport, relay_transport, clearing a former
relayhost, the dedicated pipe's recipient/concurrency limits, and adding the
pipe if absent. Unrelated lines and continuations are preserved byte for byte.
Local/virtual delivery and SMTP listener settings are not intentionally changed.
Ambiguous syntax, duplicate/continued target definitions, dependent macros,
conflicting routing, or unexpected pipe definitions block the candidate.

The candidate is not proof of effective Postfix configuration, certificate
signing, SMTP AUTH, sender authorization, or successful mail delivery. Its
plan SHA is not an Apply authorization and the identity field records only
the observed mailbox-match state. Before enabling Apply, require native
candidate validation, identity fingerprint binding, verified backup, a
maintenance-window/queue guard, rollback, and real distro coverage.
Do not use the destructive Force Replace path as a substitute.
