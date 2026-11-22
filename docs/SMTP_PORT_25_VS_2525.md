# Incoming SMTP 25 vs 2525 — operator safety guide

LinuxMailRelay365 distinguishes the **Linux listener** used by local applications from the **Microsoft 365 outbound endpoint**.

| Mode | Linux incoming listener | M365 outgoing destination |
| --- | --- | --- |
| XOAUTH2 | 25 or 1024–65535, explicitly chosen | `smtp.office365.com:587` over STARTTLS/XOAUTH2 |
| Direct Send | 25 or 1024–65535, explicitly chosen | Tenant MX (EOP) on TCP 25; internal recipients only |
| Connector Relay | 25 or 1024–65535, explicitly chosen | Tenant MX (EOP) on TCP 25; tenant Connector and IP/cert authorization required |

TCP 2525 is a **conservative default**, not a Microsoft 365 requirement. A user may choose incoming 25 if and only if there is no primary MTA service that can claim TCP 25. Inbound 465 (implicit TLS) and 587 (submission) are not generalized listener presets: those protocols require separate validated SMTP AUTH/TLS configuration. Inbound 25 need not be public.

## Before selecting 25

On the Linux host, read-only checks include:

```sh
sudo ss -H -ltn '( sport = :25 )'
systemctl is-active postfix.service exim.service exim4.service sendmail.service
systemctl is-enabled postfix.service exim.service exim4.service sendmail.service
```

The installer re-runs these checks **as root** immediately before writing any sidecar configuration. An unreadable socket scan, occupied port, active primary MTA or enabled primary MTA is a **hard stop**. It does **not** disable, stop, mask or reconfigure primary Postfix/Exim/Sendmail automatically.

Safe scenarios:
- A clean, reviewed Postfix package bootstrap with the default primary service disabled/inactive and no TCP 25 listener: a separate Postfix with its own queue may use `127.0.0.1:25`.
- An existing Postfix/Exim/Sendmail owns TCP 25: keep it untouched and choose `2525` or another free high port for the isolated gateway.
- For applications on other private hosts, explicitly select an assigned RFC1918 listener IP and trusted client CIDRs. A separate, narrow firewall review is still required.

**Do not silently broaden the SMTP listener to `0.0.0.0` or Internet-wide access**. The standard private installation does not authorize a public relay. Public SMTP/25 acceptance requires separate external TLS/authentication, anti-abuse, rate-limit and firewall validation and is not part of the port-choice change.

## Recovery and platform restrictions

The isolated configuration backup/restore never includes a primary MTA queue. Before restoring a sidecar on TCP 25, the recovery tool also checks that the port is free and standard primary MTA services are disabled/inactive. After restore it **does not start** the mail service.

RHEL-family hosts with SELinux Enforcing remain blocked by the existing isolation acceptance gate until real systemd/Postfix/socket/SELinux policy validation succeeds. The port-choice change **does not disable SELinux** or imply production authorization.

The GitHub CI coverage includes: CLI port 25 / 2525 / custom input validation; rejection of 22, 465, and 587 as generic input ports; refusal to claim active primary SMTP/25; and a disposable Ubuntu clean-bootstrap TCP 25 test. Neither CI nor the input checks prove real Exchange Online delivery.
