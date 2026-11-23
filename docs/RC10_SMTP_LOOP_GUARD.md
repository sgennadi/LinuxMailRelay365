# RC10 — Outbound SMTP destination and loop safety

This change extends RC9's discovery-first **custom SMTP relayhost** workflow. It is
not a replacement for operator configuration review, SMTP acceptance tests or
production rollout authorization.

## What the Linux manager checks before it permits Apply

1. Resolve the chosen FQDN or IPv4 on the **connected Linux machine** using its
   current resolver; never assume the Windows client's DNS answer applies.
2. Normalize IPv4, IPv6 and IPv4-mapped addresses and compare **every**
   resolved address with **all local Linux interface addresses** obtained from
   `ip -j address show`.
3. Refuse Apply if any resolved address is loopback, unspecified, multicast,
   link-local or equal to a local Linux interface address. This avoids the
   obvious recursive `relayhost` loop, including one hidden by a DNS alias.
4. Mark the result `unverified` and deny Apply if DNS, the network interface
   inventory or the resolver output cannot be validated. A successful TCP/TLS
   probe alone does not override an unknown self-loop result.
5. Report only the risk status and **SHA-256 of the sorted resolved IP set**.
   Do not expose raw DNS resolution or interface IP inventory to the GUI.
6. Preview binds the approval to two independent fingerprints: the effective
   Postfix configuration SHA-256 **and the destination resolution SHA-256**.
   Apply requires both and validates both again after the root-only backup,
   while holding the shared Postfix Apply lock.
7. No changes to incoming SMTP ports, local mail, Exim/Sendmail, sender maps,
   mailbox aliases, queue or firewall are made by this check.

A destination in a container network or a NAT hairpin may still route to the
same service without appearing on the host's interfaces. The DNS/IP check is
therefore **necessary but not a complete proof against every SMTP routing loop**.
Operator review and an authorized delivery test remain mandatory.

## Test coverage

`tests/test_custom_postfix_route.py` includes offline cases for loopback and
DNS aliases of local interfaces, remote addresses, unknown DNS / missing `ip`
output, changes of resolution after Preview and during backup, and refusal
before any Postfix configuration writes. C# SelfTest rejects tampered and
unverified resolution reports.

## Rollout

RC9 release is immutable. RC10 changes stay on
`feature/rc10-smtp-loop-guard` until Ubuntu/RHEL-family tests and Windows
x64/ARM64 build/self-tests pass. This is not a signed Stable candidate.
