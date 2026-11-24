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
