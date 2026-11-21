# Exim/Sendmail: guarded offline configuration restore (experimental)

The LinuxMailRelay365 application previously supported **read-only backup**, SHA-256 verification, comparisons against current files, and root-only offline extraction of Exim/Sendmail configuration. The new `linux/restore-foreign-mta-config.py` adds a deliberately separate **offline file-only restore** operation. It is **not available as a production GUI action** and is **not** a full service or mail-queue recovery. The original `foreign-mta-config-backup.py` remains without any `--restore` option.

## Preconditions

1. A complete VM/system backup already exists. Queue files, systemd unit state, external keys, DNS, alternate config paths and any other system-wide dependencies are outside this script.
2. The exact Exim or Sendmail systemd unit is **loaded and inactive** and no matching workers or standard SMTP listeners are observed. Exim's queue counter or BOTH Sendmail queue views (-bp and -Ac -bp) must report empty. A missing tool or ambiguous state blocks Restore. The administrator stops the MTA separately; this script never does.
3. The desired backup was previously created by the protected `foreign-mta-config-backup.py` tool, and its archive and manifest verify.
4. Current and archived allowlisted file sets are identical. New files, deleted files, symlinks, special files, changed identities or unsupported extended attributes are hard refusals.
5. The working Exim/Sendmail configuration was checked outside this tool. This script does not guarantee syntactic or semantic compatibility of a restored file, nor does it restart a service.

## Example (manual, Linux root only)

```sh
sudo python3 linux/foreign-mta-config-backup.py --mta exim --list
sudo python3 linux/restore-foreign-mta-config.py --mta exim --plan SNAPSHOT_ID
```

Record the displayed `FOREIGN_RESTORE_PLAN_SHA256`. With the primary Exim service explicitly **stopped**, review and run:

```sh
sudo python3 linux/restore-foreign-mta-config.py --mta exim \
  --apply SNAPSHOT_ID \
  --approve-sha256 REVIEWED_64_CHARACTER_HASH \
  --confirm RESTORE_STOPPED_FOREIGN_MTA_CONFIG
```

Substitute `--mta sendmail` only for a verified Sendmail host. The tool will create a **new, verified safety snapshot of the pre-restore configuration**, print its ID, check again that the reviewed input is unchanged, then replace the corresponding configuration files. Each file is replaced atomically, but a multi-file restore cannot be atomic as a whole. On an error it attempts rollback while the service is still confirmed stopped. If rollback cannot be verified, **do not restart the MTA**: use the printed safety snapshot and full system backup for manual recovery.

The operation does not open firewall rules, enable SMTP AUTH, change M365 objects or send mail. It inspects queue state read-only before and after backup and after replacement, plus periodically in larger restores; it never drains or restores queues. Unknown/nonempty queue or active listeners abort the operation and attempt file rollback. Plan output includes bounded non-secret preflight states, not approval to restore. Custom queues/spools and external dependencies still need manual assessment. Because no live heterogeneous-MTA test has occurred, this functionality is **experimental** and is not part of a signed Stable release. Validation on Ubuntu, RHEL/Oracle/Rocky/Alma, SELinux Enforcing and real Exim/Sendmail service lifecycles remains required.

## Follow-up engineering

- Define a shared transaction/approval API before wiring this operation into Windows Wizard.
- Include a dedicated Exim config-check / Sendmail config-check stage using distribution-specific tools, with no automatic daemon restart.
- Verify forced rollback, systemd aliases, package update interactions, SELinux file contexts and queue preservation on disposable real hosts.
- Provide explicit emergency instructions when rollback cannot safely write, and preserve the identity and content of the original safety snapshot.
