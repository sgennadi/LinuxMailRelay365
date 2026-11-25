#!/usr/bin/env bash
# Disposable GitHub Actions VM only. Real Postfix queue -> 127.0.0.1 SMTP sink.
# One synthetic DATA message is delivered locally, NEVER to Microsoft 365.
set -Eeuo pipefail
export LC_ALL=C
if [[ ! -v GITHUB_ACTIONS || ! -v RUNNER_TEMP ]]; then
  echo 'LOCAL_POSTFIX_SMOKE_ERROR=ephemeral_actions_runner_required' >&2
  exit 2
fi
[ "$GITHUB_ACTIONS" = true ] && [ -n "$RUNNER_TEMP" ] || {
  echo 'LOCAL_POSTFIX_SMOKE_ERROR=ephemeral_actions_runner_required' >&2; exit 2;
}
[ "$#" -eq 1 ] && [[ "$1" =~ ^[0-9]{4,5}$ ]] &&
  [ "$1" -ge 1024 ] && [ "$1" -le 65535 ] || exit 2
PORT="$1"
SINK=46601
[ "$PORT" -ne "$SINK" ] || exit 2
CONF=/etc/linuxmailrelay365/sidecar-postfix
UNIT=linuxmailrelay365-sidecar.service
PRIMARY=/etc/postfix
sudo systemctl is-active --quiet postfix
sudo systemctl is-active --quiet "$UNIT"
test "$(sudo postconf -c "$CONF" -h inet_interfaces)" = 127.0.0.1
test "$(sudo postconf -c "$CONF" -h queue_directory)" = /var/spool/linuxmailrelay365-sidecar
test "$(sudo postconf -c "$CONF" -h smtpd_relay_restrictions)" = 'permit_mynetworks, reject'
test -z "$(sudo postqueue -c "$CONF" -j)"
primary_before="$(sudo sha256sum "$PRIMARY/main.cf" "$PRIMARY/master.cf")"
primary_queue="$(sudo postconf -h queue_directory)"
sidecar_main_before="$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')"
sidecar_master_before="$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')"
backup="$(sudo mktemp /tmp/lmr365-local-postfix-main.XXXXXXXX)"
sudo cp -p -- "$CONF/main.cf" "$backup"
safe_cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  # On failure, NEVER restart a server with an outstanding synthetic mail.
  sudo systemctl stop "$UNIT" >/dev/null 2>&1
  [ "$?" -eq 0 ] || rc=1
  local pending
  pending="$(sudo postqueue -c "$CONF" -j 2>/dev/null)"
  if [ "$?" -ne 0 ] || [ -n "$pending" ]; then
    echo 'LOCAL_POSTFIX_FAILURE_WITH_PENDING_MAIL_LEAVING_LOOPBACK_ROUTE_AND_SERVICE_STOPPED=yes' >&2
    exit 1
  fi
  sudo cp -p -- "$backup" "$CONF/main.cf" || rc=1
  sudo rm -f -- "$backup" || rc=1
  [ "$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$sidecar_main_before" ] || rc=1
  [ "$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')" = "$sidecar_master_before" ] || rc=1
  [ "$(sudo sha256sum "$PRIMARY/main.cf" "$PRIMARY/master.cf")" = "$primary_before" ] || rc=1
  [ "$(sudo postconf -h queue_directory)" = "$primary_queue" ] || rc=1
  sudo systemctl is-active --quiet postfix || rc=1
  if [ "$rc" -eq 0 ]; then
    sudo systemctl start "$UNIT" || rc=1
    sudo systemctl is-active --quiet "$UNIT" || rc=1
  fi
  if [ "$rc" -eq 0 ]; then
    echo 'LOCAL_POSTFIX_CONFIG_RESTORED=yes'
    echo 'PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes'
    echo 'LOCAL_POSTFIX_QUEUE_EMPTY=yes'
    echo 'M365_MESSAGE_SUBMITTED=no'
  else
    echo 'LOCAL_POSTFIX_FAILURE_SIDECAR_LEFT_STOPPED=yes' >&2
  fi
  exit "$rc"
}
trap safe_cleanup EXIT

# Freeze the independent daemon before replacing every possible M365 route.
sudo systemctl stop "$UNIT"
sudo postconf -c "$CONF" -e \
  "relayhost = [127.0.0.1]:$SINK" \
  "default_transport = smtp:[127.0.0.1]:$SINK" \
  "relay_transport = smtp:[127.0.0.1]:$SINK" \
  "smtp_fallback_relay =" \
  "smtp_tls_security_level = none" \
  "smtp_bind_address = 127.0.0.1" \
  "enable_long_queue_ids = yes" \
  "minimum_backoff_time = 600s" \
  "maximal_backoff_time = 600s" \
  "queue_run_delay = 600s" \
  "smtp_connection_cache_on_demand = no" \
  "transport_maps =" \
  "sender_dependent_relayhost_maps =" \
  "sender_dependent_default_transport_maps =" \
  "content_filter ="
test "$(sudo postconf -c "$CONF" -h relayhost)" = "[127.0.0.1]:$SINK"
test "$(sudo postconf -c "$CONF" -h default_transport)" = "smtp:[127.0.0.1]:$SINK"
test "$(sudo postconf -c "$CONF" -h relay_transport)" = "smtp:[127.0.0.1]:$SINK"
test -z "$(sudo postconf -c "$CONF" -h smtp_fallback_relay)"
test "$(sudo postconf -c "$CONF" -h smtp_tls_security_level)" = none
test "$(sudo postconf -c "$CONF" -h smtp_bind_address)" = 127.0.0.1
sudo postfix -c "$CONF" check
sudo systemctl start "$UNIT"
sudo systemctl is-active --quiet "$UNIT"
test "$(sudo sha256sum "$PRIMARY/main.cf" "$PRIMARY/master.cf")" = "$primary_before"
echo '=== One synthetic DATA message through real isolated Postfix ==='
python3 tests/smoke_local_postfix_sink.py "$PORT" "$SINK"

# A 250 at the sink is not enough: outgoing queue must be fully drained.
for attempt in $(seq 1 30); do
  if test -z "$(sudo postqueue -c "$CONF" -j)"; then
    break
  fi
  sleep .25
done
test -z "$(sudo postqueue -c "$CONF" -j)"
echo 'LOCAL_POSTFIX_QUEUE_TO_SMTP_LOOPBACK_ACCEPTANCE=PASS'

# Same disposable isolated instance and temporary loopback route. The
# product CLI, not a direct postsuper shortcut, must exercise every action.
python3 tests/smoke_local_postfix_maintenance.py "$PORT" "$SINK"
test -z "$(sudo postqueue -c "$CONF" -j)"
echo 'LOCAL_POSTFIX_QUEUE_MAINTENANCE_ACCEPTANCE=PASS'
