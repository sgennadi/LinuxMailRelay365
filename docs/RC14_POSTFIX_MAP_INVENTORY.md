# RC14 — read-only Postfix map metadata inventory

Development branch; not a deployable configuration or release yet.

After Linux discovery the existing advanced-routing panel shows metadata
status for transport_maps, sender_dependent_relayhost_maps,
sender_dependent_default_transport_maps and smtp_tls_policy_maps.
Only existing postconf -h parameter results are used. No lookup is run.

The bounded probe accepts up to eight simple local map declarations under
/etc/postfix. For hash/btree, lmdb and cdb it checks source and expected
compiled artifact metadata; for texthash/regexp/pcre it checks source
metadata only. Unsupported, remote, proxy, macro and out-of-scope maps
are flagged for manual review without filesystem probes. SASL password
map metadata is deliberately excluded.

Directory-descriptor-relative O_NOFOLLOW traversal and non-following
stat reject symlinks, writable/non-root files/directories and hard links.
No map is opened, parsed or queried. Paths and values never appear in
the report. Missing metadata is not evidence of absence. Root ownership
is NOT LinuxMailRelay365 ownership, ACL/SELinux verification, or permission
to overwrite. The inventory is a point-in-time observation, not a lock.

The Windows parser accepts only enumerated status values with matching
Postfix role declarations. Old reports remain readable; missing metadata
is unverified. The separate RC13 inventory hash now covers these statuses
and additional existing relay/TLS/AUTH declarations.

No Apply, postmap, reload, backup/restore or actual delivery is introduced.
An application-managed manifest, exact file identity, safe backup/restore
and live rollback tests remain required before conditional Apply.
