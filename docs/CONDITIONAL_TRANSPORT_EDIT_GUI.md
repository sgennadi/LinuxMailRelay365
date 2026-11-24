# RC14 transport edit GUI (experimental)

The stopped-host Multi-provider panel can import an owned installed set, compare
it to a local draft, and perform an exact Edit Review. The review must match
the current SSH inspection, owned revision, old and new plans, backend, TLS
destination count and local calculation of exact retained credential indices.
For each password rule, unchanged rules offer Keep or Replace; changed/new
rules require a new masked credential. Cancellation never requests a write.

Switch requires separate typed confirmation and exclusive stopped maintenance.
It does not commit the new configuration. Reinspect the Linux host after any
attempted write, then use Review pending edit, which discovers both revisions
without requiring a remembered ID. The panel displays the pending phase and
file layout, and offers only candidate Commit/Rollback directions. A fresh
review and separate typed approval are required; native checks run again on
the host. A known pending edit hides ordinary multi-provider write controls.
No service is started or restarted automatically.

No password is retrieved to Windows. New passwords travel on protected SSH
stdin; input auditing may still record them. Old and new readable SASL maps
coexist temporarily until resolution. Array clearing is not secure memory
erasure. No real delivery, SELinux/ACL acceptance, runtime WinForms/DPI testing
or stable release is claimed. Windows self-tests and static wiring tests are
registered; native edit integration remains a separate acceptance gate.
