# Exim/Sendmail: guarded offline configuration restore (experimental)

The LinuxMailRelay365 application previously supported **read-only backup**, SHA-256 verification, comparisons against current files, and root-only offline extraction of Exim/Sendmail configuration. The new `linux/restore-foreign-mta-config.py` adds a deliberately separate **offline file-only restore** operation. It is **not available as a production GUI action** and is **not** a full service or mail-queue recovery. The original `foreign-mta-config-backup.py` remains without any `--restore` option.

## Preconditions

1. A complete VM/system backup already exists. Queue files, systemd unit state, external keys, DNS, alternate config paths and any other system-wide dependencies are outside this script.
2. The exact Exim or Sendmail systemd unit is **loaded and inactive** and no matching workers or standard SMTP listeners are observed. Exim's queue counter or BOTH Sendmail queue views (-bp and -Ac -bp) must report empty. A missing tool or ambiguous state blocks Restore. The administrator stops the MTA separately; this script never does.
3. The desired backup was previously created by the protected `foreign-mta-config-backup.py` tool, and its archive and manifest verify.
4. Current and archived allowlisted file sets are identical. New files, deleted files, symlinks, special files, changed identities or unsupported extended attributes are hard refusals.
5. After file replacement and fresh queue/listener checks, the tool attempts a bounded native static parser gate BEFORE declaring success: Exim -bV or Sendmail -bt -C for both sendmail.cf and any submit.cf. The tool uses only resolved root-managed native MTA executables, refuses Exim/Postfix sendmail alternatives, an empty standard input and no shell; diagnostics are not copied to Windows. Failure triggers attempted rollback. Exim -bV validates the runtime configuration in use (which may be generated from Debian source snippets), and sendmail test mode is only a partial config check. Neither proves actual delivery or full source-to-runtime synchronization. The tool does not restart any service.

## Read-only native syntax validation in the Wizard

After SSH discovery of an exact Exim or Sendmail primary MTA, the Windows Backup & Restore step now provides **Validate Exim/Sendmail native configuration (read-only)** without requiring a snapshot. The bundled Linux script runs `--static-check` as root, rejects all restore/write approvals, validates the native executable and Sendmail compiled .cf files independently of stricter archive directory rules, then runs the existing bounded Exim `-bV` or Sendmail `-bt -C` static parser and emits only fixed non-secret status codes. The Windows UI requires an exact SSH/MTA match before and after the operation and never prints the native MTA's output. A syntax pass is not evidence that source snippets, TLS, SMTP AUTH, queues, DNS or Microsoft 365 delivery work.

This action is separate from the experimental offline Restore CLI; the Wizard still has no Exim/Sendmail Restore button. On Ubuntu Sendmail may
install /etc/mail with the dedicated smmta:smmsp (or other exact registered Sendmail service account/group) and directory mode 2755;
the **read-only parser gate only** accepts the registered smmta UID with
its primary group or the registered smmsp group (or smmsp's own UID/GID),
with exactly mode 2755, as well as normal root-owned directories and
root-owned, non-writable compiled
.cf files. The separate backup/restore allowlist is NOT weakened.

GitHub CI also provisions **real Exim and Sendmail packages in separate disposable
Ubuntu 24.04 runners** with service startup explicitly disabled, executes the
root-only static check and rejects inappropriate MTA selection or restore
confirmation. The workflow asserts that common SMTP ports remain unbound and
does not transmit messages. This tests native package compatibility on Ubuntu;
it does **not** establish RHEL/Oracle/Rocky/Alma syntax compatibility, queue
restoration, real mail delivery or production safety.

## Native RPM checks on RHEL-compatible distributions

Existing read-only CI covers Rocky, Alma and Oracle Linux 8/9/10. Additional
package-level smoke jobs check real RPM-installed Exim/Sendmail:

- Rocky Linux 8 and 9: Exim from EPEL and Sendmail from distro repositories
- AlmaLinux 9 and Oracle Linux 9: Sendmail from distribution repositories

These are disposable containers (no real systemd, SELinux Enforcing or TPM).
The parser check is run with a closed stdin, with no message delivery.
Configuration and queue hashes must remain unchanged; no standard SMTP
listeners may appear. The probe rejects wrong-MTA binaries and Restore
confirmation. Real SSH/systemd/firewall and signed enterprise RHEL acceptance
remain outstanding.

Sendmail was deprecated in RHEL 9 and removed from the official RHEL 10
package set. Exim comes via EPEL, not the standard Red Hat repositories.
An installed legacy MTA remains discoverable; the Wizard must not promise
these packages on every RHEL release.

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
- Extend the new Exim/Sendmail static parse stage to validate generated Exim configuration provenance and all included files on each distribution, without automatic daemon restart. Regress non-native sendmail alternative targets and malformed generated config.
- Verify forced rollback, systemd aliases, package update interactions, SELinux file contexts and queue preservation on disposable real hosts.
- Provide explicit emergency instructions when rollback cannot safely write, and preserve the identity and content of the original safety snapshot.


## Experimental native Exim offline restore drill (Draft)

The disposable Ubuntu 24.04 CI job for Debian-packaged Exim now runs
`tests/smoke_native_exim_offline_restore.sh` after its independent
read-only native syntax check. The experiment runs only on a GitHub-hosted
fresh runner with Exim installed but its services held stopped by the
package-start suppression policy; it requires an empty queue and no SMTP
listeners. No Microsoft 365 tenant, client message or SMTP DATA is used.

The drill takes a root-only verified Exim /etc snapshot, appends one
harmless comment to an existing packaged Exim configuration file,
requires a fresh reviewed SHA-256 Restore plan, proves stale SHA refusal
without write, performs explicitly approved offline file-only restore,
validates the restored file digest and native parser and rechecks service
stop state, empty queue and absence of SMTP listeners.

**This is an experimental host-specific smoke test, not production
recoverability evidence.** It does not restore service state, queued mail,
external credentials/certificates or Debian generated Exim runtime
config provenance. Do not enable GUI native Exim/Sendmail Restore or
publish Stable until real VM service/rollback, cross-distro, SELinux
and disaster recovery tests are signed off.


## Sendmail package ownership and backup-only exception (Draft)

Ubuntu/Debian Sendmail may install `/etc/mail` as `smmta:smmsp` mode `2755` while retaining root-owned regular `.cf` and map files. Configuration-only BACKUP/VERIFY on Linux now recognizes that **exact package-managed directory** only after matching the registered `smmta`/`smmsp` account and group; `/etc`, nested configuration directories, each file, Exim and all other paths keep their original root-only checks. Symlinks, unsafe writable modes, unknown owners, unexpected file links, incomplete reads, and unbounded snapshots remain hard refusals. No mail queue, message, service or SMTP configuration is changed by Backup.

A separate **write gate** keeps Exim/Sendmail file Restore disabled for non-root-owned Sendmail `/etc/mail`: `restore-foreign-mta-config.py --apply` refuses before any file modification, even when the snapshot can be read and verified. This is intentional. The Windows Wizard still has no Exim/Sendmail Restore action. Disposable Ubuntu CI exercises packaged Sendmail backup, SHA-256 verify and unchanged configuration/services and the offline unit suite confirms unsafe paths and restore refusal. Do not treat package ownership alone as recoverability proof; a full VM backup and a service/queue/SELinux restoration drill are still required.
