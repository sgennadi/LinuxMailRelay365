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

Ubuntu/Debian Sendmail may install `/etc/mail` as `smmta:smmsp` mode `2755` while retaining root-owned regular `.cf` and map files. Configuration-only BACKUP/VERIFY on Linux now recognizes that **exact package-managed directory** only after matching the registered `smmta`/`smmsp` account and group; `/etc`, nested configuration directories, each file, Exim and all other paths keep their original root-only checks. Unknown symlinks, unsafe writable modes, unknown owners, unexpected file links, incomplete reads, and unbounded snapshots remain hard refusals. Exact native Sendmail links are recorded as inert metadata only. No mail queue, message, service or SMTP configuration is changed by Backup.

A separate **write gate** keeps Exim/Sendmail file Restore disabled for non-root-owned Sendmail `/etc/mail`: `restore-foreign-mta-config.py --apply` refuses before any file modification, even when the snapshot can be read and verified. This is intentional. The Windows Wizard still has no Exim/Sendmail Restore action. Disposable Ubuntu CI exercises packaged Sendmail backup, SHA-256 verify and unchanged configuration/services and the offline unit suite confirms unsafe paths and restore refusal. Do not treat package ownership alone as recoverability proof; a full VM backup and a service/queue/SELinux restoration drill are still required.


## Sendmail package snapshot v2 (native backup, not Restore)

The first real Ubuntu 24.04 package Backup test correctly refused to treat
all `/etc/mail` entries as root-owned regular files. The metadata-only
diagnostic showed native `smmta:smmsp` generated `.db` files, service-owned
`m4`, `smrsh` and `tls` directories, and package-created `aliases`,
`smrsh/procmail` and `smrsh/mail.local` symbolic links.

Sendmail root-only Backup now emits **snapshot manifest v2** (v1 Exim and
legacy backups remain supported), with SHA-256-verified TAR members for
only readable regular files, including narrowly identified package-owned
generated `*.db` files directly under `/etc/mail`. A separate JSON
object map records directory owner/mode and allowlisted symlink targets
**as metadata only**. The code never follows those symlinks, reads targets
outside the allowlist, recursively walks them or copies external binaries.
Unknown links, unknown owners, writable files/directories, unexpected
extra objects or inventory drift still cause refusal. Snapshot contents
remain root-owned mode 0600 on the Linux host and can contain credentials.

`--verify` validates TAR regular files, manifest metadata and the archive
digest; `--preview-recovery` compares file and object metadata without
replacing files. **V2 snapshots cannot be automatically applied to active
/etc/mail.** An explicitly approved `--export-offline` creates a NEW private
rehearsal directory under /var/backups. Regular data files are mode 0600,
directories mode 0700, while original permissions, owners, service-owned DBs
and known package symlinks are recorded in `PACKAGE_RECOVERY_METADATA.json`.
The symlinks remain **inert metadata** and are NOT created, followed or used
for any reads. The verified archive and manifest remain available alongside
`READ_ME_BEFORE_RECOVERY.txt`. The export cannot safely be copied over
active /etc/mail or used as a ready-to-run MTA installation: this is a
reviewable offline recovery rehearsal ONLY. Use a full VM/system backup and
separate approved service/queue/SELinux recovery validation before production. Existing v1 Exim functionality
is unchanged.

Native CI must show `SENDMAIL_BACKUP_LAB_SNAPSHOT=verified_root_only`,
`SENDMAIL_BACKUP_LAB_V2_RESTORE=blocked_as_designed` and unchanged file
hashes/daemon state before this block can be marked accepted. The dedicated
offline v2 unit suite includes tampered TAR, altered objects, symlink drift
and safe private v2 export plus blocked active Restore cases.

### Review export (never live Restore)

For a validated snapshot, run on a disposable or explicitly approved server:

```shell
sudo python3 linux/foreign-mta-config-backup.py --mta sendmail --verify SNAPSHOT_ID
sudo python3 linux/foreign-mta-config-backup.py --mta sendmail --export-offline SNAPSHOT_ID --confirm EXTRACT_VERIFIED_FOREIGN_MTA_SNAPSHOT
```

The Linux command reports `FOREIGN_BACKUP_FORMAT=v2_package_metadata`,
`FOREIGN_BACKUP_OFFLINE_LINKS_MATERIALIZED=no` and the new private directory.
The Windows Wizard uses a separate `EXPORT INERT SENDMAIL SNAPSHOT` typed
confirmation and warns that the directory is not a restored MTA. The original
/etc/mail, mail queues, services, external certificates, Entra tenant and
Microsoft 365 routing are untouched. Only copy data out of this private
directory using an independently reviewed recovery procedure; it may contain
secrets. The native Ubuntu and RPM smoke checks require verified file hashes,
private modes and no materialized symlinks; this is NOT disaster-recovery signoff.


### Sendmail v2 isolated metadata recovery rehearsal (CI only)

A separate `tests/rehearse_sendmail_v2_metadata.py` fixture now reconstructs
files, original UID/GID and mode bits, and **exact known package link text**
inside a disposable root-private directory under `/var/backups` (never under
`/etc` or the primary Sendmail spool). In contrast, normal `--export-offline`
continues to create *no symlinks*. Only the CI rehearsal temporarily
materializes allowlisted links behind a 0700 root-owned parent, checks
ownership, file digests, metadata, then removes the temporary tree. It
checks source files and SMTP service/queue state remain unchanged.

This does **not** validate a real Sendmail service startup, systemd units,
queue recovery, TLS certificates, SELinux label restoration, macro
regeneration, or Microsoft 365 delivery. The rehearsal explicitly requires
root and `GITHUB_ACTIONS=true`, and is **not exposed as a GUI action**.
Full production/VM backup restore and disaster recovery sign-off are still
mandatory before introducing any live `/etc/mail` Restore operation.

### Reboot continuity after stopped Sendmail configuration recovery (KVM only)

The **experimental, root-attested disposable Rocky Linux 9.9 KVM** workflow
first validates a controlled restore of the single root-owned `sendmail.cf`
from a verified v2 snapshot, including its SHA-256, UID/GID, mode and SELinux
label. It restarts Sendmail only to test loopback SMTP EHLO/QUIT, then stops
it and restores the original Postfix. A second real VM reboot checks the
snapshot again, without changing any configuration or submitting test mail.

The reboot comparison includes the **entire snapshot member/object
inventory** via `--preview-recovery`, the archived SHA-256, restored
`sendmail.cf` SHA-256, owner/mode, SELinux label SHA-256, private snapshot
identifier, empty Postfix/Sendmail queues, stopped Sendmail and active
Postfix under Enforcing SELinux. The normalized report must be identical
before and after the new boot ID. This probe is read-only and CI-only.

**Scope limit:** This tests single-file recovery and read-only full-snapshot
comparison, **not** a full package-tree Restore. It does not restore package
DBs to active `/etc/mail`, materialize links there, replay queues, validate
external certificates, or send Microsoft 365 mail. Production live Restore
remains disabled and the Windows release stays Draft until independent
acceptance and signing gates have passed.

## Post-RC16 development

Diagnostics now has a provider-independent Backup & Restore page even for an unchanged mail route. The existing archive, compare, static check, preflight and export operations remain. The exact native Restore Plan runs the existing CLI in read-only --plan mode, checks a strict host/MTA/snapshot-bound receipt, and shows changed/total file counts, stopped-service, process, queue and listener evidence and plan SHA. Stopped-MTA preflight no longer accidentally requires an active service during its final identity check. Sendmail v2 still requires manual metadata recovery. No GUI native Apply or service restart is enabled. RC16 remains immutable; full live recovery acceptance is outstanding.

### Exact metadata and post-parser validation (development)

Native v1 preview now binds each current SELinux label digest to the exact
SHA-256 plan, rejects unsupported extended attributes before any safety
backup or replacement, and associates each label read with the same
verified file metadata as its content. Replacement checks the staged and
published label and refuses inherited unexpected metadata. Rollback checks
labels and ownership and will not overwrite a file with unexpected metadata.
After the native parser succeeds, the complete file set, contents, labels,
service state, queue and listener evidence are checked again. Unexpected
new files or label drift prevent a verified-rollback claim; preserve the
pre-operation safety snapshot and inspect manually. Synthetic xattr/label
unit tests are not proof of real SELinux Enforcing acceptance. No native GUI
Apply is enabled by this change.

### Durable interruption marker (development)

Before the first configuration replacement, the native v1 Restore verifies
that the safety archive contains the reviewed original file bytes, fsyncs
the snapshot directory and its parents, and exclusively publishes a private
0600 marker under the protected backup base. The marker identifies the MTA,
requested and safety snapshot IDs, archive digest and approved plan digest.
It does not contain mail contents, raw configuration or passwords. A fresh
Restore refuses any existing marker, including one left by interruption or
incomplete rollback; malformed and changed markers also refuse. A verified
completed operation or verified in-process rollback removes the marker and
syncs the directory. For read-only inspection use:

`sudo python3 linux/restore-foreign-mta-config.py --mta exim --pending-status`

The marker is global to the backup base, not limited to the requested MTA.
The status verifies the safety archive; it never resumes, clears or rolls
back an interrupted operation. If manual_recovery_required or a refusal is
reported, keep the MTA stopped and retain the marker and safety archive for
review. There is deliberately no automatic recovery/clear command yet.
This is a durable warning and retry guard, not a crash-atomic multi-file
transaction or a system-wide service-start interlock. Tests simulate Python
interruption and verify successful completion, rollback and malformed marker
refusal; real sudden-power-loss validation remains outstanding. GUI Apply
and Sendmail v2 restore are still not enabled.

### Interrupted Restore inventory (development)

New pending markers use schema 2 and bind the exact target archive SHA-256
in addition to the safety archive and approved plan. Existing schema 1
markers remain blocked and inspectable; their target is explicitly unbound.
Use `sudo python3 linux/restore-foreign-mta-config.py --mta exim --pending-inspect`
(or sendmail) to compare the current tree with both verified archives.
The report is global to the backup base and identifies the MTA actually
recorded in the marker. It gives counts of files matching only the original,
only the target, both, neither, missing and extra. It exports neither file
names nor contents. Invalid archives or unsafe inventory refuse inspection.
A shared lock refuses comparison while the restore tool is active; no lock
file is created. The marker, manifests and tree are rechecked before the
sampled report is returned. Counts compare content only, not recoverability,
metadata restoration or proof of a stopped MTA. Old markers report no counts.
No operation clears the marker, resumes Restore, rolls back or authorizes a
service start. Full system backups and independent administrator review remain
mandatory. The new unit tests exercise mixed states, drift, active locks and
legacy markers; they do not simulate real power loss or a full Sendmail v2
restore.

### Windows interrupted Restore inspection (development)

Backup & Restore now offers a global **Inspect interrupted native Restore (read-only)**
action independent of the current MTA or selected provider. The bundled command
accepts no caller-provided action, confirmation or archive path. It reports the
MTA recorded in the marker, verified safety archive ID/SHA-256, target ID and
(where bound in schema 2) target SHA-256 and the six sampled file counts. The
Windows parser requires exact non-mutating status fields, rejects extra or duplicate
fields and impossible totals, and rechecks the current SSH identity before showing
a report. A legacy marker never receives fabricated counts or target SHA. A clear
marker is not proof of service readiness. The GUI cannot resume, roll back or clear
a pending native operation; it provides an explicit manual-recovery warning.
CLI and C# regression tests cover the read-only contract. RC16 remains unchanged.

### Explicit recovery of an interrupted Exim restore (development CLI)

New Exim operations use schema-3 pending markers. Before the first write, the
exact original approved review is stored durably as a separate root-only
0600 file in the safety snapshot directory. Its SHA-256 must equal the
original operator-approved plan. The two archive digests remain bound.
Schema 1/2 and Sendmail package v2 markers remain manual recovery only.

For a stopped Exim on a disposable test host, inspect and review:

```sh
sudo python3 linux/restore-foreign-mta-config.py --mta exim --pending-rollback-plan
```

Only after reviewing the current result, explicitly supply its
FOREIGN_PENDING_ROLLBACK_PLAN_SHA256 and a separate confirmation:

```sh
sudo python3 linux/restore-foreign-mta-config.py --mta exim \
  --pending-rollback-apply --approve-sha256 REVIEWED_SHA256 \
  --confirm ROLLBACK_INTERRUPTED_EXIM_CONFIG
```

The fresh plan requires matching file sets, only original/target content,
the original reviewed UID/GID/mode and SELinux label digest, and fresh
offline service/process/queue/listener evidence. It refuses unknown files,
missing files, third-party content, changed metadata, changed review or
archive digests and stale approvals. Apply takes the exclusive lock,
rechecks the plan and uses the existing verified atomic single-file writer.
The original archived bytes are restored without recreating paths or
relabeling drifted files. It rechecks the entire tree and native parser,
then removes the marker only after verified completion. If rollback itself
is interrupted or the parser fails, the marker remains and a new plan is
required. The safety snapshot and review are retained. No service action,
queue replay, automatic resume, GUI Apply or production acceptance is
introduced. Unit tests cover partial progress, stale approvals, metadata
and content drift, bad evidence, re-interruption and parser failure.
Power-loss, native package/SELinux lifecycle and complete disaster recovery
acceptance remain outstanding.

### Experimental Windows Exim interrupted rollback

Backup & Restore offers independent Preview and Rollback actions. Both
request a fresh schema-3 Exim-only plan. The write action shows the exact
host, both archive IDs/digests, file counts and plan SHA, then requires
operator-typed ROLLBACK_INTERRUPTED_EXIM_CONFIG in the existing confirmation
dialog. It checks the SSH connection and pinned password-mode host key,
accepts only the matching verified apply receipt, and independently checks
that the marker is clear. Discovery evidence is invalidated even if SSH
fails during the write. No approval is saved or automatically reused.
This is experimental offline recovery for disposable test hosts, not a
normal Exim Restore Apply, Sendmail v2 recovery or approval to start services.
The native Ubuntu Exim CI drill now additionally exits the real restore
process immediately after a verified configuration file replacement, reviews
and performs the interrupted rollback, and verifies original bytes, stopped
services and the unchanged empty queue. It is not a physical power-loss test.
No new public release or successful acceptance is claimed until CI completes.

### Experimental normal Exim Restore from Windows

Backup & Restore offers Restore selected Exim configuration only for an
installed-inactive Exim and selected verified archive. It checks the pending
marker, reviews a fresh plan with archive and plan SHA-256, requires stopped
service/no process/empty queue/no listener and typed confirmation, then checks
SSH settings and selected archive again. The fixed Exim-only write command
retains all Linux safety archive, schema-3 interruption and stale-plan checks.
The durable recovery evidence is revalidated before clearing the marker.
The GUI verifies a matching apply receipt and separately inspects the marker;
it invalidates discovery even after a failed or lost response. No automatic
retry, service start, queue modification or Sendmail v2 Apply is introduced.
Experimental disposable-test-host operation only; CI and live GUI acceptance
are required. RC16 is unchanged.

### Post-RC17: Sendmail v2 scoped compiled-config review

The separate read-only `--mta sendmail --sendmail-v2-plan SNAPSHOT_ID` checks the verified archive and the exact raw manifest digest (including inert directory/link metadata). It compares a sampled complete package inventory, file bytes/UID/GID/modes, the two compiled files' current labels, and fresh stopped/queue/process/listener evidence. It reports changed compiled files, differences outside that scope, missing/extra files and metadata/object drift. A candidate requires both compiled files, unchanged remaining data and objects, original matching file metadata and a root-managed /etc/mail; a nonroot package directory can still be inspected but cannot qualify for writes. It refuses a pending restore, changes during inspection and supplied write approvals. The SHA binds a sampled review only; no Apply, symlink recreation, database restore, service action or queue change exists. Older v1/v2 write gates remain unchanged. Unit tests and a native disposable Sendmail smoke check the new report. RC17 release branch is kept separate.


### Post-RC17: native Windows Sendmail v2 read-only report

The existing exact Restore Plan button verifies the selected Sendmail archive and dispatches by verified format (legacy v1 remains unchanged). A v2 report is accepted only with a matching archive SHA-256, manifest and plan digests, consistent bounded counts and offline gates, exact non-mutation fields, and unchanged SSH connection, pinned host key, MTA and selection. The resizable report shows the two compiled targets, other changes, missing/extra files, permissions/owner and directory/symlink drift. No raw configuration, new Apply command, confirmation token, service start or queue changes are introduced. C# self-tests and Python source-contract tests cover the fixed command and rejected receipts. Physical GUI and CI acceptance remain required; RC17 release branch is unchanged.


### Post-RC17: experimental Sendmail v2 compiled configuration transaction (CLI)

For disposable stopped test hosts only, the separate `--sendmail-v2-apply SNAPSHOT_ID` action accepts the exact SHA from `--sendmail-v2-plan SNAPSHOT_ID` and typed confirmation `RESTORE_STOPPED_SENDMAIL_V2_COMPILED_CONFIG`. It replaces existing root-owned sendmail.cf / submit.cf bytes only. No symlink, generated database, permissions, unrelated file, queue or service is modified. The existing read-only GUI and generic v1 Apply remain unchanged.

Before writing it verifies and syncs a complete v2 safety archive and saves the exact reviewed inventory, then publishes a global schema-4 marker binding the target/safety archive and raw manifest hashes. The marker survives failures, parser refusal or interruption. A fresh Restore refuses the marker. Inspect with the existing --pending-inspect command, then use `--sendmail-v2-rollback-plan` and explicitly approve its fresh SHA via `--sendmail-v2-rollback-apply --approve-sha256 REVIEWED_SHA256 --confirm ROLLBACK_INTERRUPTED_SENDMAIL_V2_CONFIG` (all commands require --mta sendmail). Rollback refuses unexpected bytes, metadata, labels, unrelated inventory or archive drift; it never recreates paths. Both directions require a fresh offline queue/service/listener check and a partial native parser pass before clearing the marker. A failed rollback retains the marker for manual recovery. There is no automatic retry, power-loss guarantee, service-start interlock or production approval. Real Enforcing and physical lab acceptance remain mandatory. RC17 release branch is unchanged.


### Post-RC17: experimental Windows Sendmail v2 recovery

Backup & Restore now offers a distinct compiled-file Restore when discovery identifies stopped Sendmail, and provider-independent interrupted rollback Preview / Apply actions. Each write rechecks a fresh exact plan, host/SSH identity and required typed confirmation. C# strictly validates schema-4 operation receipts, both archive/manifest digests, approval digest, count, native parser result and no queue/service changes, then independently checks the global pending marker. A failed or lost write response invalidates cached discovery and archive selection; no approval is persisted. Read-only Restore Plan and legacy v1 behavior remain separate. No automatic service start or production acceptance is implied. Windows CI, real native Sendmail / SELinux and physical DPI acceptance remain outstanding.
