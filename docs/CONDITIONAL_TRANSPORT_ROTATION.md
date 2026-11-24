# Credential rotation core (development)

A single existing password-authenticated sender transport can be selected by
its validated plan index. The library requires an exact owned installed
record, a fresh caller-supplied review, verified native candidate bytes and
exclusive stopped-host maintenance. It replaces only that SASL DB, preserving
both configuration files and all other map identities. Normal Restore can
remove the rotated DB after checking the current ownership overlay.

An atomic, root-only current overlay records new private map hashes and file
identities; it binds to the original immutable publication journal. A durable
pending marker is written before replacement and records the prepared inode
identity before rename. Ordinary discovery, restore and further rotation
refuse a pending marker. The old DB is held in process memory for immediate
rollback on verified failures before commit. No persistent duplicate password
DB is created. If the process is killed, or overlay publication has uncertain
outcome, explicit recovery may be required; keep Postfix stopped. Automatic
post-crash repair is not yet implemented. Do not delete a pending marker or
assume the old credentials are recoverable. Private hashes/identity records
must not be exported or logged. No authentication or mail delivery is
claimed. The library does not expose a production CLI or GUI. Native
candidate compilation, pending-recovery workflow and real host acceptance
remain gates.
