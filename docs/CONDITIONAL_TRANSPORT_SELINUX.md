# Multi-provider SELinux label preflight

The read-only helper derives exact sender and per-account SASL database names
from a validated nonsecret plan and chosen Hash/LMDB backend. It queries
installed policy using trusted matchpathcon, including the configuration
directory, main.cf, master.cf and every prospective map. Existing metadata
must match the policy; generic/default types, unexpected ACLs/xattrs, links,
unexpected source files, wrong map owner/group/mode and changes during
inspection are refused. The installed-mode scan opens files to inspect
metadata but does not read their credential bytes.

The standalone CLI takes a nonsecret rule array via stdin and --backend
hash or lmdb; --installed checks an existing set rather than prospective
destinations. Requires root and active SELinux. It returns status codes only
and never enables a write, relabels files, alters policy or starts Postfix.
This is not ownership verification or evidence of SELinux domain access,
network/port policy, native delivery or Enforcing runtime acceptance.

The RHEL-family container smoke also queries real packaged policy for both
map namespaces, without mounting SELinux or modifying the shared kernel.
Containers are not a substitute for an Enforcing VM. Existing stopped-host
write guards remain in force; labeled snapshot/journal publication,
label-preserving rotation/edit and real Enforcing acceptance remain necessary.

## Internal labeled publication metadata (V2)

An optional library-only snapshot format records the exact observed directory and
configuration labels and the individual prospective database labels. It accepts
only a complete exact-path policy label set; V1 remains unchanged and refuses
labeled configurations. The corresponding V2 publication journal binds every map
label to the snapshot. Apply and Restore preserve each file's own metadata using
the existing atomic writer and verify it during native ownership checks. Directory
label drift, label changes on a map, unsafe/default types and unsupported extended
attributes refuse the operation. Synthetic user-xattr tests exercise the real
filesystem publication/rollback mechanics without claiming kernel SELinux access.

Production CLI guards remain unchanged: active SELinux is not yet allowed for
writes. V2 internal credential rotation now preserves the
selected map's exact label in normal replacement, rollback, native readback
and pending recovery. It deliberately requires an unlabeled protected
activation directory and unlabeled private journal files, and refuses a
labeled recovery store before creating a rotation marker. Real SELinux recovery
metadata needs a separate exact-path policy design; these synthetic xattr
fixtures do not establish support for a real enforcing host. The future trusted
caller must recheck actual installed policy in every guard; passing a V2 label
dictionary alone is not policy or runtime acceptance.

## Internal V2 replacement transaction

The edit library now requires a trusted fresh policy reader for labeled
snapshots. It rechecks the exact policy of both generations throughout
preparation, publication and resolution. Replacement labels are derived from
the new destination paths; retained credential bytes do not inherit the old
map label. The original directory and both config labels must remain the same.
Missing readers, changed policy, mislabeled files and labeled private stores
are refused. The internal V2 transaction still requires an unlabeled recovery
parent and activation/marker files, and does not change the production SELinux
maintenance gate. Synthetic user-xattr tests cover retained maps with distinct
new labels, commit, rollback, interrupted switch and policy drift. They do not
prove SELinux runtime permissions, and are not a release acceptance claim.

## Private recovery-store metadata primitives

A separate internal library derives the exact snapshot, activation, receipt,
rotation and edit marker paths from validated rules and a revision. It checks
root-owned private directories, exact file mode/group, link identity and the
individual path's policy context. The read-only policy adapter queries the
installed matchpathcon policy under /var/lib. A scoped writer supports exclusive
creation and exact reviewed replacement of mutable JSON markers and rotation
overlays only, retaining the old label on replacement and applying the target
policy label to new files. It refuses immutable journal rewrites, unknown paths,
foreign xattrs, symlinks, stale observations and policy drift. Real user-xattr
fixtures test these filesystem mechanics. The library does not create/relabel
private directories or replace the live workflow's unlabeled-store restriction;
trusted policy adapters, durable directory/snapshot creation and integration in
rotation/edit recovery remain necessary. Enforcing writes remain disabled.

The scoped store now also supports exclusive creation of its own private
policy-labeled directories and immutable V2 snapshots. The manifest is written
last, and the complete labeled snapshot is re-read with content hashes and
per-file metadata. Snapshot configuration files retain the existing 2 MiB
limit; small journals remain bounded separately. Partial revisions are retained
and refused rather than overwritten. The underlying atomic writer has an
optional pre-link check for exclusive publication, so policy or path changes
between scratch preparation and publication can block the link. The new
primitives remain isolated from the production CLI: activation-journal and
receipt creation, full recovery integration and Enforcing VM acceptance are
still required.

## Labeled activation journal and publication receipts

The scoped V2 store now creates a labeled immutable activation journal from
already verified database candidates and reuses the existing journal, receipt
and rotation-overlay validators (legacy readers keep the same schemas). It
checks exact activation-directory entries and per-file policy metadata. The
internal first-install map publisher performs exclusive publication under the
caller guard, verifies the actual inode/content/label and creates its own
immutable labeled receipt. It refuses stale records, foreign equal-byte maps,
unknown entries, pending edits or rotations, and changes to the original
configuration. A lost publication receipt remains unproven; the library never
adopts or removes such a file. No database is stored in the recovery directory.
These are isolated library APIs, not a production Apply/Restore replacement.
The stopped-host CLI/GUI remains unchanged and active SELinux writes remain
blocked until full transaction integration and real Enforcing acceptance.

## Post-RC14 integration: labeled first-install Apply/Restore

The scoped private store now coordinates a complete first-install transaction
and explicit offline restore, using its own labeled snapshot, activation
journal and exact map publication receipts. A trusted fresh live policy reader
and maintenance guard are mandatory. Every configuration replacement checks
both the reviewed private record and current live policy, including before
atomic rename. New maps are checked before exclusive publication and after
publication. Unknown live scratch files, unproven maps, changed policy or
pending edits/rotations block the operation. Native verification must return
explicit success; ordinary failure attempts a guarded restore, while an
interrupted or unproven state remains for explicit recovery. Synthetic user-xattr
fixtures cover successful apply/restore, native rejection, interruption between
config writes, policy drift and a lost publication receipt. This is a library
integration milestone on the post-RC14 development branch, not a change to
production CLI or the frozen RC14 release. Rotation/edit with labeled private
stores and real SELinux Enforcing acceptance are still outstanding.

## Post-RC14 scoped labeled credential rotation

A new internal ScopedRotation library reuses the existing pending-marker and
overlay validators with the policy-bound private store. It writes a durable
labeled marker before the selected SASL database is replaced, records the
prepared inode, verifies all other maps and native readback, and updates the
labeled overlay using exact private receipts. Ordinary failure can restore the
previous bytes from memory; an interrupted or uncertain transaction is resolved
only by explicit review of the retained inode, digest, marker and overlay.
Normal activation reads and Restore remain blocked while rotation is pending.
Private marker removal is bound to its exact reviewed metadata. Synthetic
user-xattr tests cover success, native rollback, both retained generations,
policy drift and foreign equal-byte maps. This remains internal code: the
production SELinux maintenance guard, full labeled edit integration and actual
Enforcing acceptance are unchanged. The RC14 release branch is not modified.

## Post-RC14 scoped labeled edit transaction

The internal ScopedEdit coordinator now connects both labeled private stores
with the two-generation edit protocol. It performs a native-reviewed draft
comparison, compiles new databases, and retains only exact explicitly approved
password rules. A shared labeled marker binds both revisions, the old effective
ownership record and the new immutable journal before exclusive publication.
Each normal read remains blocked while the marker exists; only an exact,
revision-bound private observation permits recovery inspection. New destination
labels are assigned independently of the retained database bytes. Switch
rechecks both stores and live policy before each atomic config replacement.
Commit or Rollback requires exact recovery review and native verification;
cleanup direction is durable, and interrupted cleanup can resume only in that
direction. A map without its original publication receipt is never adopted.
Synthetic user-xattr fixtures cover successful commit/restore, rollback,
interruption, policy drift, foreign inodes and lost receipts. These APIs are
not wired to the production CLI/GUI, do not change the active SELinux guard,
and do not establish real Enforcing-domain permissions. The published RC14
remains unchanged.
