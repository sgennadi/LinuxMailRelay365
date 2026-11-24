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
writes. V2 replacement is still refused until prospective replacement policy
rechecks are implemented. V2 internal credential rotation now preserves the
selected map's exact label in normal replacement, rollback, native readback
and pending recovery. It deliberately requires an unlabeled protected
activation directory and unlabeled private journal files, and refuses a
labeled recovery store before creating a rotation marker. Real SELinux recovery
metadata needs a separate exact-path policy design; these synthetic xattr
fixtures do not establish support for a real enforcing host. The future trusted
caller must recheck actual installed policy in every guard; passing a V2 label
dictionary alone is not policy or runtime acceptance.
