#!/usr/bin/env bash
# CI-ONLY: real SMTP AUTH+TLS + Milter reject/accept; exactly one synthetic
# message may reach 127.0.0.1:46601. Never submit DATA to Microsoft 365.
set -Eeuo pipefail
export LC_ALL=C
if [ "$(printenv GITHUB_ACTIONS)" != true ] || [ -z "$(printenv RUNNER_TEMP)" ] ||
   [ "$#" -ne 1 ] || ! [[ "$1" =~ ^[0-9]{4,5}$ ]] ||
   [ "$1" -lt 1024 ] || [ "$1" -gt 65535 ]; then
  echo "SMTP_AUTH_GUARD_SMOKE_ERROR=disposable_runner_and_port_required" >&2
  exit 2
fi
PORT="$1"
SINK=46601
[ "$PORT" -ne "$SINK" ] || exit 2
CONF=/etc/linuxmailrelay365/sidecar-postfix
UNIT=linuxmailrelay365-sidecar.service
GUARD_UNIT=linuxmailrelay365-from-guard.service
DOVECOT_UNIT=linuxmailrelay365-smtp-auth.service
PRIMARY=/etc/postfix
CA=/etc/linuxmailrelay365-ci-smtp/next-cert.pem
sudo test -f "$CA" || exit 2
sudo systemctl is-active --quiet postfix
sudo systemctl is-active --quiet "$UNIT"
sudo systemctl is-active --quiet "$DOVECOT_UNIT"
sudo systemctl is-active --quiet "$GUARD_UNIT"
test "$(sudo postconf -c "$CONF" -h inet_interfaces)" = 127.0.0.1
test "$(sudo postconf -c "$CONF" -h smtpd_relay_restrictions)" = "permit_sasl_authenticated, reject"
test "$(sudo postconf -c "$CONF" -h smtpd_sasl_auth_enable)" = yes
test "$(sudo postconf -c "$CONF" -h smtpd_tls_security_level)" = encrypt
test "$(sudo postconf -c "$CONF" -h smtpd_milters)" = \
  unix:/run/linuxmailrelay365-from-guard/from-guard.sock
test "$(sudo postconf -c "$CONF" -h milter_default_action)" = tempfail
test "$(sudo postconf -c "$CONF" -h default_transport)" = \
  "smtp:[example-org.mail.protection.outlook.com]:25"
test "$(sudo postconf -c "$CONF" -h relay_transport)" = \
  "smtp:[example-org.mail.protection.outlook.com]:25"
test "$(sudo postconf -c "$CONF" -h relayhost)" = \
  "[example-org.mail.protection.outlook.com]:25"
# No secondary route may bypass the loopback-only capture. Check BEFORE any
# modification and refuse unknown routing constructs. Never run on real hosts.
for setting in transport_maps sender_dependent_relayhost_maps \
  smtp_fallback_relay smtp_tls_policy_maps; do
  test -z "$(sudo postconf -c "$CONF" -h "$setting")"
done
initial_queue="$(sudo postqueue -c "$CONF" -j)"
test -z "$initial_queue"
primary_sha="$(sudo sha256sum "$PRIMARY/main.cf" "$PRIMARY/master.cf")"
primary_queue="$(sudo postconf -h queue_directory)"
main_sha="$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')"
master_sha="$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')"
backup="$(sudo mktemp /tmp/lmr365-auth-guard-main.XXXXXXXX)"
sudo cp -p -- "$CONF/main.cf" "$backup"

finish() {
  local rc=$?
  trap - EXIT
  set +e
  sudo systemctl stop "$UNIT" >/dev/null 2>&1 || rc=1
  local queued
  queued="$(sudo postqueue -c "$CONF" -j 2>/dev/null)"
  if [ "$?" -ne 0 ] || [ -n "$queued" ]; then
    # Never restore a non-loopback route while a synthetic DATA message
    # might be queued. Keep the isolated service stopped, leaving the
    # last-installed outbound route loopback-only, then dispose CI VM.
    echo "SMTP_AUTH_GUARD_FAIL_CLOSED_QUEUED_MAIL_LOOPBACK_ROUTE_SERVICE_STOPPED=yes" >&2
    exit 1
  fi
  sudo cp -p -- "$backup" "$CONF/main.cf" || rc=1
  sudo rm -f -- "$backup" || rc=1
  [ "$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$main_sha" ] || rc=1
  [ "$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')" = "$master_sha" ] || rc=1
  [ "$(sudo sha256sum "$PRIMARY/main.cf" "$PRIMARY/master.cf")" = "$primary_sha" ] || rc=1
  [ "$(sudo postconf -h queue_directory)" = "$primary_queue" ] || rc=1
  sudo systemctl is-active --quiet postfix || rc=1
  if [ "$rc" -eq 0 ]; then
    sudo postfix -c "$CONF" check || rc=1
    sudo systemctl start "$UNIT" || rc=1
    sudo systemctl is-active --quiet "$UNIT" || rc=1
    sudo systemctl is-active --quiet "$DOVECOT_UNIT" || rc=1
    sudo systemctl is-active --quiet "$GUARD_UNIT" || rc=1
  fi
  if [ "$rc" -eq 0 ]; then
    echo "SMTP_AUTH_GUARD_LOOPBACK_QUEUE_DRAINED=yes"
    echo "SMTP_AUTH_GUARD_PRIVATE_POSTFIX_RESTORED=yes"
    echo "PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes"
    echo "MICROSOFT365_DELIVERY_VERIFIED=no"
  else
    echo "SMTP_AUTH_GUARD_SMOKE_FAILED_ISOLATED_SERVICE_LEFT_STOPPED=yes" >&2
    sudo systemctl stop "$UNIT" >/dev/null 2>&1
  fi
  exit "$rc"
}
trap finish EXIT

# All possible outbound SMTP routes now go to the fixed loopback sink.
# Stop the independent MTA FIRST. Never alter /etc/postfix.
sudo systemctl stop "$UNIT"
sudo postconf -c "$CONF" -e \
  "relayhost = [127.0.0.1]:$SINK" \
  "default_transport = smtp:[127.0.0.1]:$SINK" \
  "relay_transport = smtp:[127.0.0.1]:$SINK" \
  "smtp_fallback_relay =" \
  "smtp_tls_security_level = none" \
  "smtp_bind_address = 127.0.0.1"
test "$(sudo postconf -c "$CONF" -h relayhost)" = "[127.0.0.1]:$SINK"
test "$(sudo postconf -c "$CONF" -h default_transport)" = "smtp:[127.0.0.1]:$SINK"
test "$(sudo postconf -c "$CONF" -h relay_transport)" = "smtp:[127.0.0.1]:$SINK"
test -z "$(sudo postconf -c "$CONF" -h smtp_fallback_relay)"
test "$(sudo postconf -c "$CONF" -h smtp_tls_security_level)" = none
test "$(sudo postconf -c "$CONF" -h smtp_bind_address)" = 127.0.0.1
test "$(sudo sha256sum "$PRIMARY/main.cf" "$PRIMARY/master.cf")" = "$primary_sha"
sudo postfix -c "$CONF" check
sudo systemctl start "$UNIT"

echo "=== Real SMTP AUTH STARTTLS + Postfix From Guard, loopback-only DATA ==="
sudo env GITHUB_ACTIONS=true RUNNER_TEMP="$RUNNER_TEMP" python3 tests/smoke_authenticated_from_guard_loopback.py "$PORT" "$CA"

for attempt in $(seq 1 60); do
  remaining="$(sudo postqueue -c "$CONF" -j)"
  if test -z "$remaining"; then
    break
  fi
  sleep 0.25
done
remaining="$(sudo postqueue -c "$CONF" -j)"
test -z "$remaining"
echo "SMTP_AUTH_FROM_GUARD_REAL_POSTFIX_LOOPBACK_SMOKE=PASS"
