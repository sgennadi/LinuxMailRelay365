# Managed transport replacement preparation (development)

The private Python library builds a prospective replacement from the original
pre-manager main.cf/master.cf snapshot, not the currently appended configuration.
It accepts only a fully verified installed owned set with no pending credential
rotation, requires repeated caller-supplied native-policy and maintenance checks,
and refuses same-plan edits, empty plans, conflicting destinations and namespace
collisions. A new map namespace is derived from the new plan; the current backend
and CA bundle are preserved. Empty plans require the separate Restore workflow.

Each unchanged full password rule is eligible for explicit retain, including
reordering. Any change to selector, pattern, server, port, TLS or authentication
requires a new credential if password AUTH remains enabled. A retained map is
read only inside the privileged Linux process and verified for exact ownership,
identity, content, endpoint, and native positive and negative lookup. New
credentials are compiled individually with the existing native rotation compiler.
The new routing map and all generated service overrides are native-checked in
private tmpfs. No existing credential is returned to Windows. No persistent map,
configuration, journal, queue, inbound port or service is modified by this code.

This is a library and unit-test milestone, not an Apply feature. Its private
review and candidate bytes must never be serialized or logged. Synthetic unit
fixtures exercise planning, credential isolation, drift, collisions and redaction;
native isolated replacement tests and the durable two-generation publication,
rollback, cleanup and recovery mechanism remain required. No SELinux/ACL write
support or successful provider authentication is claimed.
