# LinuxMailRelay365 — Security

**Preview software. Do not deploy to production without an isolated test of
Microsoft Entra permissions, Exchange Online RBAC, Postfix mail flow and Linux sudo.**

- The manager does not ask for or save any Microsoft 365 user/mailbox password.
- SSH passwords and optional `sudo` passwords remain in the interactive process
  memory during the session. They are not written to configuration files or
  passed in command-line arguments. Use a dedicated SSH service account.
- The application's Linux RSA private key is not uploaded to GitHub, Entra or
  the administrator's Windows computer. Its public certificate is uploaded to
  Entra. Ordinary software keys **are usable by root**.
- TPM/HSM, Conditional Access and Entra sign-in monitoring are detection-only
  or manual configuration in the current preview, all **off by default**.
- When reusing one Entra app with multiple Linux servers, each host can have
  its own certificate but all hosts inherit the application's permissions.
- The structured diagnostic report contains only allowlisted operation names,
  result categories, UTC timestamps and the app version. It does not contain
  server names, login names, mailbox addresses, raw logs, tokens or keys.
- GitHub releases are *not automatically installed* in this preview; the
  updater currently performs read-only checks and opens the release page.

## Credentials and incident response

If a Linux host is compromised, revoke its certificate credential in Entra,
rotate any shared credentials, review Entra service-principal sign-in logs,
Exchange mail activity and Postfix logs. A software key may have been copied,
and an already-issued access token may remain valid until expiry.

Do not paste private keys, tokens, MFA codes or password-containing logs into
GitHub issues. No diagnostic upload is automatic.

## Backups and Restore

The Linux recovery helper writes root-only archives under `/var/backups/linuxmailrelay365`.
They can contain mail server configuration, **private signing keys and other credentials**.
Never publish, upload, share, or attach these archives to issue reports. The Windows
wizard transfers only opaque backup identifiers and status, never backup contents.
Restoration covers `/etc/postfix`, the dedicated M365 transport and recorded
service state; it does not roll back packages, DNS, firewall or external files.
