#!/usr/bin/env bash
# Disposable GitHub Actions VM only, after SMTP AUTH/TLS + client rotation.
# No message DATA or real tenant. Host-wide MTA and queued mail are untouched.
set -Eeuo pipefail
export LC_ALL=C
[ "$GITHUB_ACTIONS" = true ] && [ -n "$RUNNER_TEMP" ] || exit 2
[ "$#" -eq 2 ] || exit 2
PORT="$1"
CA="$2"
[[ "$PORT" =~ ^[0-9]{4,5}$ ]] && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || exit 2
[ "$CA" = /etc/linuxmailrelay365-ci-smtp/next-cert.pem ] || exit 2
CONF=/etc/linuxmailrelay365/sidecar-postfix
AUTH=/etc/linuxmailrelay365/smtp-auth
SCRIPT=linux/sidecar-config-recovery.py
PRIMARY=postfix.service
SIDE=linuxmailrelay365-sidecar.service
DOVE=linuxmailrelay365-smtp-auth.service
TIMER=linuxmailrelay365-health.timer
HEALTH=linuxmailrelay365-health.service
for unit in "$PRIMARY" "$SIDE" "$DOVE" "$TIMER"; do
  sudo systemctl is-active --quiet "$unit"
done
test "$(sudo postconf -c "$CONF" -h smtpd_sasl_auth_enable)" = yes
test "$(sudo postconf -c "$CONF" -h smtpd_tls_security_level)" = encrypt
test "$(sudo postconf -c "$CONF" -h queue_directory)" = /var/spool/linuxmailrelay365-sidecar
test "$(sudo postconf -h queue_directory)" = /var/spool/postfix
primary_before="$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)"
primary_queue="$(sudo postconf -h queue_directory)"
primary_active="$(sudo systemctl is-active "$PRIMARY")"
main_before="$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')"
dove_before="$(sudo sha256sum "$AUTH/dovecot.conf" | awk '{print $1}')"
passwd_before="$(sudo sha256sum "$AUTH/passwd" | awk '{print $1}')"
key_before="$(sudo sha256sum "$AUTH/privkey.pem" | awk '{print $1}')"
cert_before="$(sudo sha256sum "$AUTH/fullchain.pem" | awk '{print $1}')"

echo '=== Backup real running independent Postfix + Dovecot SMTP AUTH/TLS ==='
output="$(sudo python3 "$SCRIPT" --backup)"
printf '%s\n' "$output" | grep -Fx 'SIDECAR_BACKUP_STATUS=verified_config_only_no_queue'
archive_id="$(printf '%s\n' "$output" | sed -n 's/^SIDECAR_BACKUP_ID=//p')"
[[ "$archive_id" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$ ]]
sudo python3 "$SCRIPT" --verify "$archive_id" |
  grep -Fx 'SIDECAR_BACKUP_STATUS=verified_config_only_no_queue'
# Only path-presence flags, not hashes or secret content, may reach CI logs.
sudo python3 - "$archive_id" <<'PY'
import json, pathlib, sys
folder = pathlib.Path('/var/backups/linuxmailrelay365-sidecar') / sys.argv[1]
manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
names = {r['path'] for r in manifest['entries']}
required = (
    'etc/linuxmailrelay365/smtp-auth/passwd',
    'etc/linuxmailrelay365/smtp-auth/privkey.pem',
    'etc/linuxmailrelay365/smtp-auth/fullchain.pem',
    'etc/linuxmailrelay365/smtp-auth/dovecot.conf',
    'etc/systemd/system/linuxmailrelay365-smtp-auth.service',
)
assert all(x in names for x in required), 'AUTH_BACKUP_INCOMPLETE'
assert not any(x.startswith('etc/postfix/') for x in names)
assert not any(x.startswith('var/spool/') for x in names)
assert folder.stat().st_mode & 0o077 == 0
print('AUTH_TLS_SCOPED_ARCHIVE=PASS')
PY

echo '=== Stop only independent SMTP, AUTH and monitoring units ==='
sudo systemctl stop "$TIMER"
sudo systemctl stop "$HEALTH" || true
sudo systemctl stop "$DOVE"
sudo systemctl stop "$SIDE"
for n in 1 2 3 4 5 6 7 8 9 10; do
  [ -z "$(sudo ss -H -ltn "( sport = :$PORT )")" ] && break
  sleep .3
done
test -z "$(sudo ss -H -ltn "( sport = :$PORT )")"
sudo systemctl is-active --quiet "$PRIMARY"
! sudo systemctl is-active --quiet "$SIDE"
! sudo systemctl is-active --quiet "$DOVE"
! sudo systemctl is-active --quiet "$TIMER"

echo '=== Change only stopped isolated SMTP/AUTH, restore reviewed snapshot ==='
sudo postconf -c "$CONF" -e 'myhostname = changed-auth-fixture.example.test'
printf '\n# Disposable CI isolated AUTH restore marker\n' |
  sudo tee -a "$AUTH/dovecot.conf" >/dev/null
review="$(sudo python3 "$SCRIPT" --preview-restore "$archive_id")"
expected="$(printf '%s\n' "$review" | sed -n 's/^SIDECAR_CURRENT_SHA256=//p')"
[[ "$expected" =~ ^[a-f0-9]{64}$ ]]
if sudo python3 "$SCRIPT" --restore "$archive_id" --expect-current-sha256 "$expected"; then
  echo 'AUTH_RECOVERY_SMOKE_ERROR=missing_restore_confirmation_allowed' >&2
  exit 1
fi
result="$(sudo python3 "$SCRIPT" --restore "$archive_id" \
  --expect-current-sha256 "$expected" \
  --confirm RESTORE_ISOLATED_RELAY_CONFIGURATION)"
printf '%s\n' "$result" | grep -Fx "SIDECAR_RESTORED_BACKUP_ID=$archive_id"
printf '%s\n' "$result" | grep -Fx 'SIDECAR_SERVICES_STARTED=no'
emergency="$(printf '%s\n' "$result" | sed -n 's/^SIDECAR_PRE_RESTORE_BACKUP_ID=//p')"
[[ "$emergency" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$ ]]
[ "$emergency" != "$archive_id" ]
sudo python3 "$SCRIPT" --verify "$emergency" |
  grep -Fx 'SIDECAR_BACKUP_STATUS=verified_config_only_no_queue'
test "$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$main_before"
test "$(sudo sha256sum "$AUTH/dovecot.conf" | awk '{print $1}')" = "$dove_before"
test "$(sudo sha256sum "$AUTH/passwd" | awk '{print $1}')" = "$passwd_before"
test "$(sudo sha256sum "$AUTH/privkey.pem" | awk '{print $1}')" = "$key_before"
test "$(sudo sha256sum "$AUTH/fullchain.pem" | awk '{print $1}')" = "$cert_before"
! sudo systemctl is-active --quiet "$SIDE"
! sudo systemctl is-active --quiet "$DOVE"
! sudo systemctl is-active --quiet "$TIMER"
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
test "$(sudo postconf -h queue_directory)" = "$primary_queue"
test "$(sudo systemctl is-active "$PRIMARY")" = "$primary_active"

echo '=== Manually restart isolated services and verify rotated SMTP AUTH over TLS ==='
sudo systemctl start "$SIDE"
sudo systemctl start "$DOVE"
sudo systemctl start "$TIMER"
sudo systemctl is-active --quiet "$SIDE"
sudo systemctl is-active --quiet "$DOVE"
sudo systemctl is-active --quiet "$TIMER"
sudo python3 - "$PORT" "$CA" <<'PY'
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location(
    'lmr365_ci_auth_after_restore','linux/verify-sidecar-auth-client.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
port = int(sys.argv[1])
ca = sys.argv[2]
last = 'none'
for attempt in range(25):
    try:
        version = module.verify(
            port, 'lmr365-ci.example.test', 'lmr365-ci-b', ca,
            password_provider=lambda _: 'disposable-test-credential')
        assert version in ('TLSv1.2', 'TLSv1.3')
        break
    except (OSError, module.Refused) as error:
        last = type(error).__name__
        time.sleep(.2)
else:
    raise AssertionError('Recovered TLS/AUTH failed: ' + last)
print('RECOVERED_ROTATED_SMTP_AUTH_TLS=PASS')
print('MAIL_DATA_SENT=no')
PY
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
test "$(sudo systemctl is-active "$PRIMARY")" = "$primary_active"
echo 'REAL_DOVECOT_SMTP_AUTH_TLS_CONFIG_RECOVERY=PASS'
echo 'EXTERNAL_TLS_CA_DEPENDENCY_RESTORED=no'
echo 'RHEL_SELINUX_ENFORCING_VERIFIED=no'
