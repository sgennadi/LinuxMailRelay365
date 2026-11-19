# CI warnings — review on 2026-11-19

This report separates application warnings from warnings in a disposable Linux CI runner. It does not certify live Microsoft 365 mail delivery, TPM or SELinux.

## Source warnings fixed

- **SYSLIB0057 (.NET x64/ARM64)**: public DER is loaded through `X509CertificateLoader.LoadCertificate`, replacing obsolete `X509Certificate2(byte[])`. Future SYSLIB0057 warnings fail builds.
- **Python `SyntaxWarning`**: invalid `\$` and `\.` escapes were replaced by literal/raw strings. Focused CI `py_compile` treats SyntaxWarning as error.
- **Python `DeprecationWarning`**: `datetime.utcnow()` replaced by timezone-aware `datetime.now(datetime.timezone.utc)`. Focused backup/restore tests treat DeprecationWarning as error.

## Postfix warnings observed in Ubuntu CI

- `WARNING: /etc/aliases exists, but does not have a root alias.` appeared during **primary Postfix package installation**, before the isolated sidecar.
- `warning: not owned by root: /var/spool/postfix/etc/resolv.conf` appeared for the primary Postfix.
- `warning: not owned by root: /var/spool/linuxmailrelay365-sidecar/etc/resolv.conf` appeared for isolated Postfix after chroot resolver synchronization.
- `Postfix is using backwards-compatible default settings` is a version/configuration notice; inspect effective compatibility before changing anything.

Treat the chroot warnings as security diagnostics, not cosmetic CI noise. Read-only operator inspection:

```sh
stat -c '%U:%G %a %n' /etc/resolv.conf /var/spool/postfix/etc/resolv.conf /var/spool/linuxmailrelay365-sidecar/etc/resolv.conf
namei -l /var/spool/linuxmailrelay365-sidecar/etc/resolv.conf
postconf -h queue_directory
postconf -c /etc/linuxmailrelay365/sidecar-postfix -h queue_directory
```

Files may not exist until the corresponding MTA is installed. Avoid blindly changing `/etc/resolv.conf`, which may be a systemd-resolved symlink; it can be recreated or managed by the OS. Correct ownership, if needed, only for the reviewed affected chroot with explicit operator approval. Never repair the primary Postfix or `/etc/aliases` as an incidental sidecar install step.
