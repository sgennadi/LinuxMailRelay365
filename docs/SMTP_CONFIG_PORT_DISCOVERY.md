# Linux SMTP port discovery (read-only)

After a verified SSH connection, LinuxMailRelay365 discovers the installed or
active MTA and reads its **configured inbound TCP/SMTP ports**. The operator's
sidecar port is a different field and never overrides the discovered result.

## Configuration sources

| MTA | Effective source | Discovery |
| --- | --- | --- |
| Postfix | `master.cf` through `postconf -M` | Include active `inet` services only; distinguish `smtp/inet` (TCP/25) from `smtp/unix` (outbound transport). Honor numeric/custom service names and explicit IP:port bindings. |
| Exim | `exim[4] -bP daemon_smtp_ports` | Parse literal service names or numbers; macros/dynamic values are unverified. |
| Sendmail | `/etc/mail/sendmail.cf` `DaemonPortOptions` | Parse the compiled config, not just the potentially stale `.mc` source. Unspecified daemon `Port` means SMTP/25 when a daemon option is present. |

Discovery is conservative: incomplete, unsafe or dynamic values are reported as
**unverified**, not as a free/default port. The independent public-relay safety
inspection and original primary-MTA service/queue protections are unchanged.

## Runtime comparison

A separate read-only `ss -H -lnt` inventory looks for actual listening sockets
on configured ports, conventional TCP/25, TCP/465, TCP/587 and the operator's
selected custom port (when valid). A configured port may have no live listener;
a listener may belong to a different process. Neither proves firewall/NAT
reachability, Internet exposure, tenant authorization or mail delivery.

The wizard displays all of the following separately:

1. Configured primary MTA SMTP ports (including the source of evidence).
2. Observed listening TCP sockets (without claiming their process owner).
3. Desired inbound port for the independent LinuxMailRelay365 relay.

If the desired port also appears in the primary MTA configuration, the wizard
warns; the installer must still independently verify the running listener,
existing MTA service and restart/autostart ownership before changing anything.
An invalid or blank desired port does **not** cause an implicit TCP/2525 probe:
the primary MTA configuration and its listening ports can still be audited.
No discovered port is automatically assigned to a new relay.

If a general MTA security probe fails, a separate read-only fallback attempts
configuration discovery anyway, but the failed general probe **continues to
block any installer or force-replace action**.

## Manual Linux verification (no changes)

```bash
# Postfix
postconf -M
postconf -h inet_interfaces
# Exim (choose the installed binary)
exim -bP daemon_smtp_ports
exim -bP local_interfaces
# Sendmail
grep -E '^O[[:space:]]+DaemonPortOptions=' /etc/mail/sendmail.cf
# Live TCP listeners: ownership requires separate privileged inspection
ss -H -lnt
```

Microsoft 365 **outbound** Direct Send/Connector typically targets TCP/25 and
XOAUTH2 submission TCP/587; these are not Linux inbound listener ports.
The existing `relayhost`, routing and tenant checks are separate.

## Acceptance limits

The unit/contract tests exercise mock Postfix, Exim and Sendmail settings and
custom TCP ports. A passing GitHub Actions run does not prove that a real host
uses those ports, that a real VM is running with SELinux Enforcing or that
Microsoft 365 accepted a message. Do not treat this as signed Stable approval.
