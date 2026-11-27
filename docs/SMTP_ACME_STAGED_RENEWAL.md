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

## Reviewed GUI systemd management

The SMTP certificate wizard ships the seven managed systemd units and their runtime dependencies. The new screen checks installed file hashes and effective unit paths, rejects conflicts/overrides, and installs missing files without overwriting existing ones or starting the timer. A partial installation may leave newly created runtime files for a reviewed retry. Enabling boot recovery, enabling/starting/stopping/disabling the timer and requesting live renewal are separate reviewed and confirmed actions. Live operations require the production Let's Encrypt renewal profile, local TLS preflight and enabled recovery units. They use the existing service, which can activate renewed material in Postfix. A persistent timer may trigger immediately. Stopping the timer does not cancel an in-progress service. Next/last trigger and service result are observed, not a proof of successful renewal or delivery. The schedule is the packaged twice-daily schedule; editing the schedule, updating conflicting units and uninstalling remain separate work. SELinux-active hosts are blocked for live operations in this screen. Existing ordinary Certbot timers are not changed. External administrators must not edit the units or configuration concurrently. Real systemd, CA and mail delivery tests remain required.

## GUI public DNS provider discovery

The ACME plan dialog now exposes provider discovery separately from local resolver readiness. The connected Linux host queries one explicitly identified public resolver (1.1.1.1) for the public DNS zone and challenge CNAME/NS evidence, with a bounded query count, per-query timeout and total DNS budget. It checks installed Certbot authenticator registration, not credentials, and offers a candidate only when exactly one registered provider matches a non-delegated DNS hint. The administrator explicitly selects the suggestion. CNAME or directly observed challenge NS delegation requires manual review; absence of a direct record is not proof that every possible delegation is absent. DNS/provider failures do not authorize issuance; the existing manual/readiness plan remains available. Public DNS names are sent to the resolver, and Certbot plugin inventory may use its ordinary local logs. No DNS write, certificate issuance, Postfix change or Microsoft 365 authorization is performed. Root or the existing sudo path is required to inspect Certbot plugins; missing dig or failed public DNS access is reported as unavailable.
