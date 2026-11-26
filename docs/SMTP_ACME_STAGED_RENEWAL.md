# Staged ACME renewal

The supplied systemd units renew isolated Certbot lineages twice daily.
Install only after reviewing the root-owned renewal configuration and all
configured hooks. --no-directory-hooks does not disable per-lineage hooks.
ProtectSystem restricts filesystem writes but is not a complete hook sandbox.
Do not point Postfix at the ACME live symlinks: renewal is staging only.
A separate validated deployment transaction is required. The timer does not
prove CA compatibility or successful delivery. Inspect the service exit
status and private Certbot logs. Units are not enabled automatically.

After review, install the two units in /etc/systemd/system, run
systemctl daemon-reload and enable --now linuxmailrelay365-smtp-acme-renew.timer.
No existing Certbot timers need to be disabled.
