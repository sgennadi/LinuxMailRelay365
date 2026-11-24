# Two-generation stopped Postfix edit transaction (development)

The private edit transaction begins from a freshly reviewed manager-owned
installation and compiles/retains exactly the selected account maps. It creates
a new ordinary recovery snapshot based on the same pre-manager configuration.
A durable root-only pending marker binds both recovery revisions and their
private journals before publication of any new map. Normal multi-transport
install, discovery, Restore and credential rotation are blocked until resolution.

New maps are published exclusively with ownership receipts. The two configs
are replaced individually under exclusive stopped maintenance. Native validation
is mandatory; success leaves both generations present until a separate reviewed
Commit or Rollback. A failure leaves the marker for explicit recovery; an unknown
map, missing publication receipt, orphan scratch or unrelated edit prevents
automatic cleanup. The new namespace is never published over an existing map.

Commit requires the complete new pair and native verification. Rollback restores
the old pair and verifies it. Before any obsolete map is unlinked the selected
cleanup direction is durably fixed, so interrupted cleanup can only resume in
the same direction. The final selected generation is checked again before
removing the marker. Normal Restore can then restore the original pre-manager
configuration. Neither service control nor queue changes are performed.

Old and new protected runtime SASL DBs temporarily coexist, including duplicated
retained credentials; this is deliberate for rollback and is not encryption or
secure erasure. No additional DB backups are written. Keep Postfix stopped until
resolution and reinspection. Do not remove pending markers manually. This is a
library with synthetic fault-injection tests, not an exposed CLI or GUI workflow.
Native two-generation acceptance, public recovery receipts and CLI/GUI integration
remain necessary. Existing SELinux/ACL write restrictions still apply.

## Native acceptance fixture

The existing Ubuntu Postfix smoke now exercises actual installed Hash/LMDB map
backends, after credential rotation. It changes a custom port/TLS/endpoint,
retains the rotated second account at a new index, adds a no-AUTH rule and
removes two rules. It verifies native effective services and exact positive /
negative lookups under the Postfix account, interrupts the config switch,
rolls back, repeats the switch, interrupts commit cleanup, resumes commit,
and restores the original configuration. Only disposable alternate directories
and synthetic credentials are used. Primary configuration hashes must remain
unchanged. This is not live SMTP delivery, SELinux or CLI/GUI acceptance.
