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

## Native alternate-configuration comparison

Preview v3 adds a root-only, short-lived `/run/lmr365-primary-native-*` scratch directory. It copies the original and proposed exact bytes sequentially to the same alternate config root and uses only native `postconf -c` reads: explicit parameters, selected expanded address-class/listener/policy settings, master services and service overrides. It first requires a normalized baseline equal to the live native snapshot, then allows only the reviewed transport parameters and exact dedicated pipe to differ. The live configuration and native snapshot are checked again, and scratch copies are removed. The report contains only status and SHA-256, not native output or configuration values. A verified native digest is bound to the plan; native mismatch, unsupported syntax, diagnostics, or drift require review and cannot authorize Apply. This is parser evidence, not a live daemon, map evaluation, address-resolution, identity, SMTP AUTH or mail-delivery proof. No service control, live file write, package installation, `postfix check`, or queue operation is introduced. The proposed route is still single-mailbox only; multi-mailbox primary routing, backup/restore, SELinux writes and native distro acceptance remain separate gates.
