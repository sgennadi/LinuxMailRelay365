#!/usr/bin/env bash
# Real native Exim file-only offline restore drill in a DISPOSABLE GitHub runner.
# No SMTP submission, cloud tenant, service start, queue drain or network mail.
set -Eeuo pipefail
umask 077
export LC_ALL=C

# This mutates one packaged Exim configuration file ONLY on ephemeral CI.
test "${GITHUB_ACTIONS:-}" = true || { echo "EXIM_RESTORE_LAB_ONLY_GITHUB_RUNNER"; exit 3; }
test "${RUNNER_TEMP:-}" != "" || { echo "EXIM_RESTORE_LAB_RUNNER_TEMP_REQUIRED"; exit 3; }
test "$(id -u)" -ne 0 || { echo "EXIM_RESTORE_LAB_NONROOT_CALLER_REQUIRED"; exit 3; }
test -d "${GITHUB_WORKSPACE:-/missing}" || exit 3
for service in exim.service exim4.service; do
  ! sudo systemctl is-active --quiet "$service" || { echo "EXIM_RESTORE_LAB_MTA_RUNNING"; exit 3; }
done
! sudo pgrep -x exim4 >/dev/null || exit 3
! sudo pgrep -x exim >/dev/null || exit 3
! sudo ss -H -lnt | grep -Eq ":(25|465|587|2525)[[:space:]]" || exit 3

config="/etc/exim4/update-exim4.conf.conf"
sudo test -f "$config" || { echo "EXIM_RESTORE_LAB_CONFIG_NOT_FOUND"; exit 3; }
# Do not weaken the backup tool trust policy to accommodate a package layout.
sudo python3 - "$config" <<'PY'
import os, stat, sys
st = os.lstat(sys.argv[1])
if not (stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
        and not st.st_mode & 0o022 and st.st_size < 16*1024*1024):
    raise SystemExit("EXIM_RESTORE_LAB_CONFIG_NOT_TRUSTED")
PY
original="$(sudo sha256sum "$config" | cut -d " " -f 1)"
queue_before="$(sudo exim4 -bpc)"
test "$queue_before" = 0 || { echo "EXIM_RESTORE_LAB_QUEUE_NOT_EMPTY"; exit 3; }

# The snapshot captures exactly the current root-managed /etc file inventory.
backup_report="$(sudo python3 linux/foreign-mta-config-backup.py --mta exim --backup)"
printf "%s\n" "$backup_report" | grep -Fxq "FOREIGN_BACKUP_STATUS=verified"
backup_id="$(printf "%s\n" "$backup_report" | sed -n 's/^FOREIGN_BACKUP_ID=//p')"
[[ "$backup_id" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$ ]] || exit 3
sudo python3 linux/foreign-mta-config-backup.py --mta exim --verify "$backup_id" |
  grep -Fxq "FOREIGN_BACKUP_STATUS=verified"
echo "EXIM_RESTORE_LAB_ARCHIVE=verified"

# Only append a harmless comment; deliberately avoid routing changes.
printf "\n# LMR365 temporary offline restore acceptance comment\n" | sudo tee -a "$config" >/dev/null
changed="$(sudo sha256sum "$config" | cut -d " " -f 1)"
test "$changed" != "$original" || exit 3

# Preview has NO write permission; digest binds the exact changed config.
plan="$(sudo python3 linux/restore-foreign-mta-config.py --mta exim --plan "$backup_id")"
printf "%s\n" "$plan" | grep -Fxq "FOREIGN_RESTORE_STATUS=preview_only"
printf "%s\n" "$plan" | grep -Fxq "FOREIGN_RESTORE_PREFLIGHT_GATE=offline_candidate_manual_recovery_only"
printf "%s\n" "$plan" | grep -Eq "^FOREIGN_RESTORE_CHANGED_FILES=[1-9][0-9]*$"
approval="$(printf "%s\n" "$plan" | sed -n 's/^FOREIGN_RESTORE_PLAN_SHA256=//p')"
[[ "$approval" =~ ^[a-f0-9]{64}$ ]] || exit 3
test "$(sudo sha256sum "$config" | cut -d " " -f 1)" = "$changed" || exit 3
echo "EXIM_RESTORE_LAB_REVIEW=stopped_empty_queue_sha256_bound"

# Wrong digest MUST refuse before replacing any file.
if sudo python3 linux/restore-foreign-mta-config.py --mta exim --apply "$backup_id" \
    --approve-sha256 "$(printf "%064d" 0)" \
    --confirm RESTORE_STOPPED_FOREIGN_MTA_CONFIG >/dev/null 2>&1; then
  echo "EXIM_RESTORE_LAB_STALE_REVIEW_UNEXPECTED_SUCCESS"; exit 1
fi
test "$(sudo sha256sum "$config" | cut -d " " -f 1)" = "$changed" || exit 1
echo "EXIM_RESTORE_LAB_STALE_REVIEW=refused_no_write"

# Explicit operator-shaped confirmation, only in disposable ephemeral CI.
apply="$(sudo python3 linux/restore-foreign-mta-config.py --mta exim \
  --apply "$backup_id" --approve-sha256 "$approval" \
  --confirm RESTORE_STOPPED_FOREIGN_MTA_CONFIG)"
printf "%s\n" "$apply" | grep -Fxq "FOREIGN_RESTORE_STATUS=config_replaced_service_not_started"
printf "%s\n" "$apply" | grep -Fxq "FOREIGN_RESTORE_NATIVE_STATIC_CHECK=passed_partial_parse_only"
printf "%s\n" "$apply" | grep -Eq "^FOREIGN_RESTORE_SAFETY_BACKUP_ID=[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$"
test "$(sudo sha256sum "$config" | cut -d " " -f 1)" = "$original" || {
  echo "EXIM_RESTORE_LAB_CONFIG_NOT_RECOVERED"; exit 1;
}
test "$(sudo exim4 -bpc)" = "$queue_before" || exit 1
for service in exim.service exim4.service; do
  ! sudo systemctl is-active --quiet "$service" || exit 1
done
! sudo pgrep -x exim4 >/dev/null || exit 1
! sudo pgrep -x exim >/dev/null || exit 1
! sudo ss -H -lnt | grep -Eq ":(25|465|587|2525)[[:space:]]" || exit 1
echo "EXIM_RESTORE_LAB_PRIMARY_CONFIG=restored_verified"
echo "EXIM_RESTORE_LAB_NATIVE_STATIC_PARSE=passed"
echo "EXIM_RESTORE_LAB_QUEUE=unchanged_empty"
echo "EXIM_RESTORE_LAB_SERVICES=stopped"
echo "EXIM_RESTORE_LAB_EXTERNAL_DELIVERY_TESTED=no"
