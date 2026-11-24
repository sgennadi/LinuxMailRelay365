# Offline conditional sender activation preflight (RC14 development)

Run as root only on a deliberately stopped, isolated-maintenance Postfix host:

    sudo python3 linux/inspect-conditional-postfix-activation.py --plan-sha256 PLAN --compiled-sha256 COMPILED

The command verifies staged and compiled candidate manifests and raw map
lookups, effective single-instance primary Postfix scope, conservative native
SMTP service and master.cf override requirements, absence of competing routing
and rewriting maps, mandatory secure TLS with nexthop matching and one
supported CA bundle, no SMTP AUTH, service/process inactivity, empty message
queues (including maildrop), and exact transaction before/after fingerprint.
The current narrow scope requires non-chroot smtp/relay services. This may
refuse otherwise valid distributions/configurations; do not relax conditions
or change a working server merely to make this preliminary check pass.

Up to four unique outbound host/port pairs and eight resolved IP addresses
are independently checked from Linux. Every resolved address must avoid
local interfaces, loopback and invalid destinations; each TCP connection
is pinned to its checked address and STARTTLS validates the requested host
against the existing CA bundle. No AUTH, MAIL FROM, RCPT TO, DATA or actual
message submission. Outputs contain only statuses and hashes, not IPs,
config values, map contents, credentials or SMTP server text.

Existing local and virtual delivery settings are retained, and sender maps
do not override those address classes. Read-only policy screening is NOT
complete runtime address-class precedence, provider authorization, SPF/DKIM
or delivery proof. Queue/process scans cannot prevent future submissions,
service starts, administrator edits or DNS changes. The operator must ensure
exclusive maintenance. SELinux/ACL and physical RHEL acceptance remain open.

Successful preflight still reports APPLY_ALLOWED=no. No production activation
or restore CLI is exposed yet. The exact-file transaction core remains
test-only pending native stopped-instance integration and real rollback tests.
