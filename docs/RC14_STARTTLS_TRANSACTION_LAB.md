# RC14 stopped Postfix sender-map + STARTTLS acceptance

This independent fixture calls the RC14 branch's unmodified map stage,
native compile/verify, and offline transaction library. It runs Postfix in
a hosted disposable Ubuntu Docker container with `--network none`, and
asserts that only loopback is present before making any changes. The names
resolve to loopback via a container-only hosts file. Fresh lab certificates,
dummy `.invalid` addresses and local accounts never leave the container.

The fixture proves real local and synthetic routed delivery after one
exact-envelope sender hash/LMDB map is installed with stopped Postfix and
an empty queue, using mandatory STARTTLS with trusted CA and next-hop
hostname verification. Restoring the backup removes the managed DB,
restores the exact config, and puts the same envelope back on its prior
default port. A certificate with the wrong peer name, signed by the same
CA, must defer mail without DATA or cleartext fallback.

The service lifecycle, TLS setup and guards belong solely to this fixture.
This does not expose a production CLI or GUI Apply, and does not validate
all map backends, SELinux/ACLs, SMTP AUTH, another server, a live tenant or
delivery into a real inbox. The branch has no publishing workflow.
