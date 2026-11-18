#!/usr/bin/env bash
# Disposable GitHub Actions VM ONLY. Real independent Postfix; no SMTP DATA.
set -Eeuo pipefail
export LC_ALL=C
[ "$GITHUB_ACTIONS" = true ] && [ -n "$RUNNER_TEMP" ] || {
  echo 'RECOVERY_SMOKE_ERROR=ephemeral_actions_runner_required' >&2
  exit 2
}
[ "$#" -eq 1 ] && [[ "$1" =~ ^[0-9]{4,5}$ ]] &&
[ "$1" -ge 1024 ] && [ "$1" -le 65535 ] || exit 2
PORT="$1"
CONF=/etc/linuxmailrelay365/sidecar-postfix
UNIT=linuxmailrelay365-sidecar.service
SCRIPT=linux/sidecar-config-recovery.py
sudo systemctl is-active --quiet postfix
sudo systemctl is-active --quiet "$UNIT"
test "$(sudo postconf -c "$CONF" -h queue_directory)" = /var/spool/linuxmailrelay365-sidecar
test "$(sudo postconf -h queue_directory)" = /var/spool/postfix
primary_before="$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)"
primary_queue="$(sudo postconf -h queue_directory)"
primary_active="$(sudo systemctl is-active postfix)"
main_before="$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')"
master_before="$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')"

echo '=== Real verified root-only independent Postfix configuration backup ==='
backup_out="$(sudo python3 "$SCRIPT" --backup)"
printf '%s\n' "$backup_out" | grep -Fx 'SIDECAR_BACKUP_STATUS=verified_config_only_no_queue'
backup_id="$(printf '%s\n' "$backup_out" | sed -n 's/^SIDECAR_BACKUP_ID=//p')"
[[ "$backup_id" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$ ]]
sudo python3 "$SCRIPT" --verify "$backup_id" |
  grep -Fx 'SIDECAR_BACKUP_STATUS=verified_config_only_no_queue'
sudo python3 "$SCRIPT" --list | grep -Fx "SIDECAR_BACKUP_ID=$backup_id"

echo '=== Live sidecar restore must be rejected ==='
online_review="$(sudo python3 "$SCRIPT" --preview-restore "$backup_id")"
online_sha="$(printf '%s\n' "$online_review" | sed -n 's/^SIDECAR_CURRENT_SHA256=//p')"
[[ "$online_sha" =~ ^[a-f0-9]{64}$ ]]
if sudo python3 "$SCRIPT" --restore "$backup_id" \
  --expect-current-sha256 "$online_sha" \
  --confirm RESTORE_ISOLATED_RELAY_CONFIGURATION; then
  echo 'RECOVERY_SMOKE_ERROR=live_sidecar_restore_allowed' >&2
  exit 1
fi
sudo systemctl is-active --quiet "$UNIT"
test "$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$main_before"

echo '=== Stop independent sidecar, not primary Postfix ==='
sudo systemctl stop "$UNIT"
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  [ -z "$(sudo ss -H -ltn "( sport = :$PORT )")" ] && break
  sleep .3
done
test -z "$(sudo ss -H -ltn "( sport = :$PORT )")"
sudo systemctl is-active --quiet postfix

echo '=== Nonempty isolated maildrop must block restore without deleting mail ==='
sudo touch /var/spool/linuxmailrelay365-sidecar/maildrop/LMR365-RECOVERY-QUEUE-TEST
if sudo python3 "$SCRIPT" --restore "$backup_id" \
  --expect-current-sha256 "$online_sha" \
  --confirm RESTORE_ISOLATED_RELAY_CONFIGURATION; then
  echo 'RECOVERY_SMOKE_ERROR=nonempty_maildrop_restore_allowed' >&2
  exit 1
fi
sudo test -f /var/spool/linuxmailrelay365-sidecar/maildrop/LMR365-RECOVERY-QUEUE-TEST
sudo rm /var/spool/linuxmailrelay365-sidecar/maildrop/LMR365-RECOVERY-QUEUE-TEST

echo '=== Change ONLY sidecar config, preview expected SHA and restore OFFLINE ==='
sudo postconf -c "$CONF" -e 'myhostname = changed-in-ci.example.test'
test "$(sudo postconf -c "$CONF" -h myhostname)" = changed-in-ci.example.test
review="$(sudo python3 "$SCRIPT" --preview-restore "$backup_id")"
printf '%s\n' "$review" | grep -Fx 'CHANGES_APPLIED=no'
expected="$(printf '%s\n' "$review" | sed -n 's/^SIDECAR_CURRENT_SHA256=//p')"
[[ "$expected" =~ ^[a-f0-9]{64}$ ]]
if sudo python3 "$SCRIPT" --restore "$backup_id" \
  --expect-current-sha256 "$(printf '%064d' 0)" \
  --confirm RESTORE_ISOLATED_RELAY_CONFIGURATION; then
  echo 'RECOVERY_SMOKE_ERROR=incorrect_config_sha_accepted' >&2
  exit 1
fi
test "$(sudo postconf -c "$CONF" -h myhostname)" = changed-in-ci.example.test
restored="$(sudo python3 "$SCRIPT" --restore "$backup_id" \
  --expect-current-sha256 "$expected" \
  --confirm RESTORE_ISOLATED_RELAY_CONFIGURATION)"
printf '%s\n' "$restored" | grep -Fx "SIDECAR_RESTORED_BACKUP_ID=$backup_id"
printf '%s\n' "$restored" | grep -Fx 'SIDECAR_SERVICES_STARTED=no'
printf '%s\n' "$restored" | grep -Fx 'PRIMARY_MTA_CHANGED=no'
emergency="$(printf '%s\n' "$restored" |
  sed -n 's/^SIDECAR_PRE_RESTORE_BACKUP_ID=//p')"
[[ "$emergency" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$ ]]
test "$emergency" != "$backup_id"
sudo python3 "$SCRIPT" --verify "$emergency" |
  grep -Fx 'SIDECAR_BACKUP_STATUS=verified_config_only_no_queue'
test "$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$main_before"
! sudo systemctl is-active --quiet "$UNIT"
test -z "$(sudo ss -H -ltn "( sport = :$PORT )")"
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
test "$(sudo postconf -h queue_directory)" = "$primary_queue"
test "$(sudo systemctl is-active postfix)" = "$primary_active"

echo '=== Real fault injection: reject invalid archived extra SMTP listener and ROLLBACK ==='
# This only changes the STOPPED independent master.cf on a DISPOSABLE VM.
# An invalid archived listener is applied then rejected by postconf -M
# verification. Original sidecar files MUST be restored automatically.
bad_port="$((PORT + 1))"
printf '%s inet n - n - - smtpd\n' "$bad_port" |
  sudo tee -a "$CONF/master.cf" >/dev/null
bad_backup="$(sudo python3 "$SCRIPT" --backup)"
bad_id="$(printf '%s\n' "$bad_backup" | sed -n 's/^SIDECAR_BACKUP_ID=//p')"
[[ "$bad_id" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$ ]]
sudo python3 "$SCRIPT" --verify "$bad_id" |
  grep -Fx 'SIDECAR_BACKUP_STATUS=verified_config_only_no_queue'
# Remove only the exact last line appended for the fault fixture.
test "$(sudo tail -n 1 "$CONF/master.cf")" = "$bad_port inet n - n - - smtpd"
sudo sed -i '$d' "$CONF/master.cf"
test "$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')" = "$master_before"
bad_review="$(sudo python3 "$SCRIPT" --preview-restore "$bad_id")"
bad_expected="$(printf '%s\n' "$bad_review" | sed -n 's/^SIDECAR_CURRENT_SHA256=//p')"
[[ "$bad_expected" =~ ^[a-f0-9]{64}$ ]]
if failed_restore="$(sudo python3 "$SCRIPT" --restore "$bad_id" \
  --expect-current-sha256 "$bad_expected" \
  --confirm RESTORE_ISOLATED_RELAY_CONFIGURATION)"; then
  echo 'RECOVERY_SMOKE_ERROR=invalid_master_was_restored' >&2; exit 1
fi
printf '%s\n' "$failed_restore" |
  grep -Fx 'SIDECAR_RESTORE_FAILED_STAGE=restored_master_cf_has_unexpected_smtp_listener'
printf '%s\n' "$failed_restore" |
  grep -Fx 'SIDECAR_RECOVERY_ERROR=offline_restore_failed_original_configuration_retained'
test "$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$main_before"
test "$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')" = "$master_before"
! sudo systemctl is-active --quiet "$UNIT"
test -z "$(sudo ss -H -ltn "( sport = :$PORT )")"
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
test "$(sudo postconf -h queue_directory)" = "$primary_queue"
test "$(sudo systemctl is-active postfix)" = "$primary_active"
echo 'REAL_POSTFIX_INVALID_RESTORE_ROLLBACK=PASS'

echo '=== Explicit restart AFTER restore; EHLO only, never MAIL DATA ==='
sudo systemctl start "$UNIT"
sudo systemctl is-active --quiet "$UNIT"
python3 - "$PORT" <<'PY'
import smtplib, sys, time
port = int(sys.argv[1])
for attempt in range(24):
    try:
        with smtplib.SMTP("127.0.0.1", port, timeout=5) as smtp:
            code, _ = smtp.ehlo("recovered-ci.invalid")
            if code == 250:
                break
    except (OSError, smtplib.SMTPException):
        pass
    time.sleep(.25)
else:
    raise AssertionError("Restored isolated Postfix did not accept EHLO")
print("MAIL_DATA_SENT=no")
PY
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
sudo systemctl is-active --quiet postfix
echo 'REAL_POSTFIX_ISOLATED_CONFIG_RESTORE_SMOKE=PASS'
echo 'PRIMARY_POSTFIX_UNCHANGED=yes'
echo 'QUEUE_RESTORE_VERIFIED=no'
echo 'EXTERNAL_TLS_DEPENDENCIES_VERIFIED=no'
echo 'MICROSOFT365_DELIVERY_VERIFIED=no'
