# Stopped-host transport edit CLI (experimental)

Use the matching RC14 modules on a disposable host with exclusive maintenance.
All modes require root, an empty queue, stopped Postfix, the existing route lock
and the typed maintenance phrase. Existing SELinux/ACL restrictions remain.
The CLI never starts Postfix, sends mail or tries provider authentication.

- --review OLD_REVISION: nonsecret rules array on stdin; returns old/new plan,
  backend, TLS destination count, review SHA and per-new-rule retain indices
  (0 means no existing password candidate). No password reads in review.
- --switch OLD_REVISION: exact approved review and new plan, typed
  SWITCH_STOPPED_POSTFIX_TRANSPORTS confirmation; protected stdin object with
  rules and credentials. A credential slot is null for no AUTH,
  {"mode":"retain"} for an exact unchanged password rule, or
  {"mode":"new","credential":{"username":"...","password":"..."}}.
  Never pass passwords in command arguments or save request files.
- --review-recovery: discovers pending old/new revisions without an ID; returns
  phase, config layout and candidate directions, plus a fresh review SHA.
  These are file-level candidates, not native verification or write permission.
- --commit NEW_REVISION or --rollback NEW_REVISION: exact recovery review SHA
  and COMMIT_STOPPED_POSTFIX_TRANSPORT_EDIT or
  ROLLBACK_STOPPED_POSTFIX_TRANSPORT_EDIT. No stdin credentials required.

Every mutation repeats the stopped-host guard and selected generation's native
policy checks. Switch repeats DNS/TLS review before publication, checks all
selected maps under the Postfix identity, and compares non-managed effective
configuration in memory. Resolve verifies native policy and retained map lookup
before cleanup. Public receipts never include passwords, config content, private
database hashes or journal digests. The new and old maps can coexist temporarily;
input auditing may record new passwords. A timeout or uncertain result requires
a recovery review. Do not manually delete pending markers or restart Postfix
until resolution. Mixed configurations may only roll back. Once cleanup begins,
only the selected direction can resume. This is not production acceptance;
native integration, GUI integration and real delivery tests remain required.
