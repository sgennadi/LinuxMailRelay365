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
require_unit() {
  if ! sudo systemctl is-active --quiet "$1"; then
    echo "SMTP_AUTH_GUARD_PRECHECK_ERROR=inactive_$1" >&2
    exit 2
  fi
}
require_setting() {
  local name="$1" expected="$2" actual
  actual="$(sudo postconf -c "$CONF" -h "$name")" || {
    echo "SMTP_AUTH_GUARD_PRECHECK_ERROR=unreadable_$name" >&2
    exit 2
  }
  if [ "$actual" != "$expected" ]; then
    echo "SMTP_AUTH_GUARD_PRECHECK_ERROR=unexpected_$name" >&2
    exit 2
  fi
}
sudo test -f "$CA" || { echo "SMTP_AUTH_GUARD_PRECHECK_ERROR=missing_CA" >&2; exit 2; }
require_unit postfix
require_unit "$UNIT"
require_unit "$DOVECOT_UNIT"
require_unit "$GUARD_UNIT"
echo "SMTP_AUTH_GUARD_PRECHECK_SERVICES=pass"
require_setting inet_interfaces 127.0.0.1
require_setting smtpd_relay_restrictions "permit_sasl_authenticated, reject"
require_setting smtpd_sasl_auth_enable yes
require_setting smtpd_tls_security_level encrypt
require_setting smtpd_milters \
  unix:/run/linuxmailrelay365-from-guard/from-guard.sock
require_setting milter_default_action tempfail
echo "SMTP_AUTH_GUARD_PRECHECK_INGRESS=pass"
require_setting default_transport \
  "smtp:[example-org.mail.protection.outlook.com]:25"
require_setting relay_transport \
  "smtp:[example-org.mail.protection.outlook.com]:25"
require_setting relayhost \
  "[example-org.mail.protection.outlook.com]:25"
for setting in transport_maps sender_dependent_relayhost_maps \
  smtp_tls_policy_maps; do
  require_setting "$setting" ""
done
# Postfix's documented default is smtp_fallback_relay=$fallback_relay,
# even when fallback_relay itself is empty. Treat ONLY that exact alias
# with an empty underlying value as safe; block any actual fallback host.
fallback="$(sudo postconf -c "$CONF" -h smtp_fallback_relay)" || {
  echo "SMTP_AUTH_GUARD_PRECHECK_ERROR=fallback_read_failed" >&2; exit 2;
}
if [ "$fallback" = '$fallback_relay' ]; then
  require_setting fallback_relay ""
elif [ -n "$fallback" ]; then
  echo "SMTP_AUTH_GUARD_PRECHECK_ERROR=unsafe_fallback_relay" >&2
  exit 2
fi
echo "SMTP_AUTH_GUARD_PRECHECK_OUTBOUND=pass"
initial_queue="$(sudo postqueue -c "$CONF" -j)" || {
  echo "SMTP_AUTH_GUARD_PRECHECK_ERROR=unreadable_queue" >&2; exit 2;
}
if [ -n "$initial_queue" ]; then
  echo "SMTP_AUTH_GUARD_PRECHECK_ERROR=queue_not_empty" >&2
  exit 2
fi
echo "SMTP_AUTH_GUARD_PRECHECK_QUEUE=empty"
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
    # The From Guard's Requires= sidecar relationship can stop the guard
    # when this independently managed Postfix service is stopped. Restore
    # both dependencies explicitly after the isolated MTA is back.
    sudo systemctl start "$DOVECOT_UNIT" || rc=1
    sudo systemctl start "$GUARD_UNIT" || rc=1
    sudo systemctl is-active --quiet "$UNIT" || rc=1
    sudo systemctl is-active --quiet "$DOVECOT_UNIT" || rc=1
    sudo systemctl is-active --quiet "$GUARD_UNIT" || rc=1
    sudo test -S /run/linuxmailrelay365-from-guard/from-guard.sock || rc=1
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
sudo systemctl start "$DOVECOT_UNIT"
sudo systemctl start "$GUARD_UNIT"
# Prevent false passes based only on a unit's transient "active" status.
# The Milter socket must be recreated after the sidecar stop/start.
socket_ready=no
for attempt in $(seq 1 40); do
  if sudo systemctl is-active --quiet "$GUARD_UNIT" &&
     sudo test -S /run/linuxmailrelay365-from-guard/from-guard.sock; then
    socket_ready=yes
    break
  fi
  sleep 0.25
done
test "$socket_ready" = yes
sudo systemctl is-active --quiet "$DOVECOT_UNIT"
echo "SMTP_AUTH_GUARD_SOCKET_RECREATED_AFTER_SIDECAR_STOP=yes"

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
