# Experimental multi-transport stopped-host CLI

The new manager connects the existing native compiler and multi-file
transaction to the stopped-host maintenance guard. It is not a Stable
feature. No automatic stop/start/reload, inbound listener change, mail
submission, package install, queue edit, or existing-route replacement.

The administrator must prevent service starts, submissions and concurrent
configuration edits. Review accepts the non-secret rules array on stdin:
--review [--backend hash|lmdb] --maintenance-confirmation
I_HAVE_PREVENTED_CONCURRENT_MAIL_AND_CONFIG_CHANGES. Review binds the
plan, snapshot, effective policy, exact selected backend, Postfix account,
and DNS/certificate-verified TLS evidence for each destination/mode.
Both STARTTLS and implicit TLS are checked, but no provider AUTH is attempted.

Apply accepts the rules/credentials object on protected stdin, the exact
--backend, --approve-plan-sha256, --approve-review-sha256, --confirm
APPLY_NEW_STOPPED_POSTFIX_TRANSPORTS, and the same maintenance phrase.
Credentials are supplied at Apply, not Review, and are not part of a public
hash. Use synthetic credentials until native maintenance/runtime acceptance.
Do not pass a password as an argument, environment variable or saved request.
A reviewed plan does not validate Send As, account rights or password validity.
The exact review is repeated before and after native compilation. Before
writes the existing snapshot and native policy are rechecked again. The
transaction performs native postconf comparison and unprivileged postmap
verification of all newly published maps, without printing credential data.
A successful result returns only a random recovery revision and safe statuses.

Restore accepts --restore REVISION --confirm RESTORE_STOPPED_POSTFIX_TRANSPORTS
and the maintenance phrase. It checks the recorded group and original native
policy; existing ownership and drift checks remain mandatory. Do not start
Postfix after an uncertain result. Recovery contains protected config
snapshots and private hashes, not duplicate password databases. Runtime
SASL databases are not encrypted. SELinux/ACL writes remain blocked.

The first path intentionally requires the existing conservative single
instance, non-chroot, secure TLS/no global AUTH policy and refuses conflicting
maps, inherited client cert/key/debug settings and proxy interfaces. It does
not force changes to a working configuration to satisfy that gate. Only
default-class sender-dependent delivery is covered. CLI unit tests use
mocked host/network interfaces; prior native isolated transaction tests
do not prove real stopped-host CLI or multi-provider mail delivery.

## Windows wizard

The separate experimental Multi-provider panel supports review, first-install apply, recovery scan and restore. It binds review to the discovered SSH/configuration context and exact ordered sender plan. Each password is entered in a separate masked dialog for its specific transport; no Windows settings or activity log contain the credentials. The stdin payload is not written to a request file. SSH/sudo auditing can record input; the operator must use an approved channel that does not record secrets. Working Linux SASL databases contain readable credentials. Apply invalidates all discovery evidence, including on an uncertain result; after reinspection the independent read-only recovery scan can find random recovery revisions even if the SSH reply was lost. Selecting an observed record never authorizes restore. No active-set editing or service control is added. Automated GUI compilation/self-tests and real delivery acceptance are separate.
