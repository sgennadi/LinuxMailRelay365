# Conditional sender-map transaction core (RC14 development)

This is a file transaction library, not a runnable production activation command. The separate experimental offline CLI integrates guarded review and verification. See CONDITIONAL_POSTFIX_OFFLINE.md. Tests use private temporary directories and explicitly injected
maintenance/native verification callbacks. The future Linux integration must
prove stopped primary Postfix, empty queues (including maildrop), correct
address-class precedence, no foreign maps, mandatory verified TLS, no
competing AUTH, provider rights, SELinux/ACL compatibility and exclusive
maintenance before invoking this library.

The initial transaction supports a single application-owned sender map,
using hash or lmdb, and preserves all original main.cf bytes before appending
one parameter. Existing explicit sender_dependent_relayhost_maps assignments
are refused, even if empty. master.cf is never written. The private recovery
directory stores exact before/after bytes, candidate DB and a canonical
SHA-bound manifest. The backup is verified before mutation. Atomic writes,
no-clobber map publication, exact post-write checks, and guarded rollback
are exercised by unit tests. Restore refuses unrelated configuration drift
and unknown map bytes, retains the backup, and never touches a queue or
service. Native offline VM acceptance and real delivery tests are still required. No production approval, GUI Apply or automatic service restart is provided.
