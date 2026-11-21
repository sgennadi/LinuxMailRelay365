#!/usr/bin/env bash
# Verify native Debian Sendmail package config backup, without changing mail.
set -Eeuo pipefail
umask 077
export LC_ALL=C
test "${GITHUB_ACTIONS:-}" = true || { echo "SENDMAIL_BACKUP_LAB_ONLY"; exit 3; }
test -d "${GITHUB_WORKSPACE:-/missing}" || exit 3
test "$(id -u)" -ne 0 || exit 3
! sudo systemctl is-active --quiet sendmail.service || exit 3
! sudo pgrep -x sendmail >/dev/null || exit 3
! sudo ss -H -lnt | grep -Eq ":(25|465|587|2525)[[:space:]]" || exit 3

# Only hashes are logged. Contents, recipients and credentials stay on Linux.
before="$(sudo find /etc/mail -xdev -type f -exec sha256sum {} + | sha256sum | cut -d " " -f 1)"
test "$before" != "" || exit 3

if ! report="$(sudo python3 linux/foreign-mta-config-backup.py --mta sendmail --backup)"; then
  # Disposable CI only: disclose bounded metadata and refusal *category*;
  # never print mail content, passwords, private keys or SMTP messages.
  sudo python3 - <<'PY'
import importlib.util, os, stat
from pathlib import Path
spec = importlib.util.spec_from_file_location("lmr365snap", "linux/foreign-mta-config-backup.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    module.selected_files("sendmail")
except Exception as error:
    print("SENDMAIL_BACKUP_CI_REFUSAL=" + type(error).__name__ + ":" + str(error))
seen = 0
for base in (Path("/etc/mail"), Path("/etc/aliases"), Path("/etc/aliases.db")):
    candidates = [base]
    if base.is_dir() and not base.is_symlink():
        candidates += list(base.rglob("*"))[:128]
    for path in candidates:
        try:
            m = path.lstat()
            print("SENDMAIL_CONFIG_META={} kind={} uid={} gid={} mode={:o} symlink={}".format(
                path, stat.S_IFMT(m.st_mode), m.st_uid, m.st_gid,
                stat.S_IMODE(m.st_mode), path.is_symlink()))
            seen += 1
        except OSError:
            pass
        if seen >= 128:
            break
    if seen >= 128:
        break
PY
  exit 1
fi
printf "%s\n" "$report" | grep -Fxq "FOREIGN_BACKUP_STATUS=verified"
id="$(printf "%s\n" "$report" | sed -n 's/^FOREIGN_BACKUP_ID=//p')"
[[ "$id" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$ ]] || exit 3
sudo python3 linux/foreign-mta-config-backup.py --mta sendmail --verify "$id" |
  grep -Fxq "FOREIGN_BACKUP_STATUS=verified"
comparison="$(sudo python3 linux/foreign-mta-config-backup.py --mta sendmail --preview-recovery "$id")"
printf "%s\n" "$comparison" | grep -Fxq "FOREIGN_BACKUP_CURRENT_CONFIG_MATCH=identical"
# A valid v2 snapshot is verify-only; no silent flattened recovery.
if sudo python3 linux/restore-foreign-mta-config.py --mta sendmail \
    --plan "$id" >/dev/null 2>&1; then
  echo "SENDMAIL_BACKUP_LAB_V2_PLAN_UNEXPECTEDLY_ALLOWED"; exit 1
fi
export_report="$(sudo python3 linux/foreign-mta-config-backup.py --mta sendmail \
    --export-offline "$id" --confirm EXTRACT_VERIFIED_FOREIGN_MTA_SNAPSHOT)"
printf "%s\n" "$export_report" | grep -Fxq "FOREIGN_BACKUP_STATUS=exported_offline_only"
printf "%s\n" "$export_report" | grep -Fxq "FOREIGN_BACKUP_FORMAT=v2_package_metadata"
printf "%s\n" "$export_report" | grep -Fxq "FOREIGN_BACKUP_OFFLINE_LINKS_MATERIALIZED=no"
export_dir="$(printf "%s\n" "$export_report" | sed -n 's/^FOREIGN_BACKUP_OFFLINE_DIRECTORY=//p')"
[[ "$export_dir" =~ ^/var/backups/linuxmailrelay365-foreign-mta/sendmail/\.offline-recovery-[A-Za-z0-9_-]{8,20}$ ]] || exit 1
sudo -E env GITHUB_ACTIONS=true python3 tests/assert_sendmail_v2_export.py "$export_dir" "$id"
# Rebuild package metadata in a disposable root-private tree only; never /etc.
sudo -E env GITHUB_ACTIONS=true python3 tests/rehearse_sendmail_v2_metadata.py "$export_dir" "$id"
echo "SENDMAIL_BACKUP_LAB_V2_RESTORE=blocked_as_designed"
test "$(sudo find /etc/mail -xdev -type f -exec sha256sum {} + | sha256sum | cut -d " " -f 1)" = "$before" || {
  echo "SENDMAIL_BACKUP_LAB_SOURCE_MUTATED"; exit 1;
}
! sudo systemctl is-active --quiet sendmail.service || exit 1
! sudo pgrep -x sendmail >/dev/null || exit 1
! sudo ss -H -lnt | grep -Eq ":(25|465|587|2525)[[:space:]]" || exit 1
echo "SENDMAIL_BACKUP_LAB_PACKAGE_LAYOUT=accepted_if_trusted"
echo "SENDMAIL_BACKUP_LAB_SOURCE_CONFIG=unchanged"
echo "SENDMAIL_BACKUP_LAB_SNAPSHOT=verified_root_only"
echo "SENDMAIL_BACKUP_LAB_PRIMARY_SERVICE=stopped"
echo "SENDMAIL_BACKUP_LAB_EXTERNAL_DELIVERY_TESTED=no"
