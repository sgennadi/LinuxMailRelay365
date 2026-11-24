# Independent SMTP transport profile compiler (RC14 development)

The new native compiler is separate from the existing offline sender relayhost
transaction. It creates one private UNIX smtp service per disjoint exact
sender or sender-domain rule (up to eight), even when two rules have the same
host and port. Each service has its own TLS mode, strict certificate verification,
connection-cache isolation and, when enabled, its own indexed SASL password map.
The sender_dependent_default_transport_maps entries explicitly select a service
and bracketed next-hop/port. No inbound listener is added. Only the default
recipient address class can be selected this way; transport_maps take precedence.
Local, virtual and relay-domain delivery are not claimed to be covered.

STARTTLS and implicit TLS are supported; plaintext and OAuth are refused by
this first compiler. A public rule-plan SHA uses the existing Windows format.
Password-mode rules accept independent credential slots on stdin, never as
arguments, environment variables or plaintext source-map files. Credentials
are compiled by postmap -i into fresh 0600 maps in a 0700 verified tmpfs scratch
directory. No credential checksum or map contents appear in the receipt.
The directory is removed on ordinary completion/failure. tmpfs may swap and an
abrupt termination may leave private scratch files: this is not a general
secret vault or a secure-erasure guarantee.

CLI: --plan accepts the existing JSON array of non-secret routing rules.
--compile requires a JSON object with rules and credentials arrays (one slot
per rule, null for no AUTH, otherwise username/password), exact reviewed
--approve-sha256 and --confirm COMPILE_PRIVATE_TRANSPORTS_ONLY.
Use a protected stdin channel; do not put credentials in shell history or
a persistent request file. Initial credential format is printable ASCII with
no whitespace and no colon in usernames. Do not use production secrets for
this experimental compiler.

Native postconf verifies the full master service list, overrides, known
parameter names and route-map declaration. Native postmap verifies enumeration,
all positive keys and a missing key for every routing/credential map. The
existing Ubuntu native smoke additionally exercises multiple independent
synthetic accounts at the same SMTP endpoint and an implicit-TLS profile.
No connection, SMTP AUTH, service launch, configuration installation or
delivery occurs in this stage. Real runtime isolation, secure persistent
credential lifecycle, multi-file Backup/Restore/Apply, GUI integration,
RHEL package and SELinux Enforcing acceptance remain required.
