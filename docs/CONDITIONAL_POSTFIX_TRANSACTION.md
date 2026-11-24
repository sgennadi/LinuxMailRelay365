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

Recovery now requires an exclusive, fsynced publication receipt written after the application's no-clobber map creation and before main.cf is changed. Restore verifies the retained device/inode/size/mtime/ctime identity and content; matching bytes alone do not establish ownership. If the process dies before the receipt is durable or the map is replaced, the tool refuses automatic removal and retains recovery data. Older experimental backups without a receipt cannot authorize deleting a retained map.

## SELinux-aware transaction metadata (development)

The transaction core supports a version-2 recovery manifest binding exact raw SELinux labels on main.cf, master.cf and the proposed indexed map. A descriptor-based metadata check allows only security.selinux; other extended attributes and ACLs remain rejected. The replacement inode is labeled and checked before atomic publication. Restore uses the original metadata; recovery observation compares the manifest's map label. Existing unlabelled version-1 snapshots stay compatible. A separate policy helper uses native matchpathcon -N -n -m file for the actual target filename and refuses mismatches on existing configs. RHEL-family offline CI queries installed policy for hash and LMDB names, while temporary-filesystem tests simulate labels using user xattrs. These do not demonstrate kernel Enforcing behavior. The production offline CLI's SELinux write prohibition remains intact pending VM acceptance; no policy changes, restorecon, or SELinux mode changes are made.
