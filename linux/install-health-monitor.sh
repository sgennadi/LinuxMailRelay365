#!/usr/bin/env bash
# Optional local journaled monitoring of independent Postfix, no outbound alerts.
# Installs ONLY dedicated systemd oneshot/timer + health probe (no mail changes).
set -Eeuo pipefail
umask 077
export LC_ALL=C
CONF=/etc/linuxmailrelay365/sidecar-postfix
SERVICE=/etc/systemd/system/linuxmailrelay365-health.service
TIMER=/etc/systemd/system/linuxmailrelay365-health.timer
PROBE=/usr/local/libexec/linuxmailrelay365-relay-health.py
PORT='' MODE=check CONFIRM=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check-only) MODE=check; shift ;;
    --install) MODE=install; shift ;;
    --smtp-port) PORT="$2"; shift 2 ;;
    --confirm) CONFIRM="$2"; shift 2 ;;
    --self-test) echo 'HEALTH_TIMER_PARSER=available'; exit 0 ;;
    --help|-h)
      echo 'Usage: install-health-monitor.sh --check-only|--install --smtp-port N [--confirm ENABLE_PRIVATE_SMTP_MONITOR]'
      exit 0 ;;
    *) echo 'HEALTH_TIMER_ERROR=invalid_argument' >&2; exit 2 ;;
  esac
done
python3 - "$PORT" <<'PY'
import re,sys
port=sys.argv[1]
if not re.fullmatch(r'[0-9]{4,5}',port) or not 1024<=int(port)<=65535:
    raise SystemExit('HEALTH_TIMER_ERROR=invalid_custom_port')
PY
if [ "$MODE" = install ] && [ "$CONFIRM" != ENABLE_PRIVATE_SMTP_MONITOR ]; then
  echo 'HEALTH_TIMER_ERROR=confirmation_required' >&2; exit 2
fi
[ "$(id -u)" -eq 0 ] || { echo 'HEALTH_TIMER_ERROR=root_required' >&2; exit 1; }
command -v systemctl >/dev/null && command -v python3 >/dev/null || {
  echo 'HEALTH_TIMER_ERROR=systemd_or_python_missing' >&2; exit 1;
}
[ -f "$CONF/main.cf" ] && [ -f "$CONF/smtp-port" ] &&
[ "$(cat "$CONF/smtp-port")" = "$PORT" ] || {
  echo 'HEALTH_TIMER_ERROR=isolated_postfix_port_not_installed_or_mismatch' >&2; exit 1;
}
systemctl is-active --quiet linuxmailrelay365-sidecar.service || {
  echo 'HEALTH_TIMER_ERROR=isolated_smtp_service_inactive' >&2; exit 1;
}
[ ! -e "$SERVICE" ] && [ ! -L "$SERVICE" ] &&
[ ! -e "$TIMER" ] && [ ! -L "$TIMER" ] &&
[ ! -e "$PROBE" ] && [ ! -L "$PROBE" ] || {
  echo 'HEALTH_TIMER_ERROR=already_installed_no_silent_overwrite' >&2; exit 1;
}
[ -f "$(dirname "$0")/relay-health.py" ] || {
  echo 'HEALTH_TIMER_ERROR=health_probe_source_missing' >&2; exit 1;
}
if [ "$MODE" = check ]; then
  echo 'HEALTH_TIMER_PREFLIGHT=ready'
  echo "HEALTH_TIMER_CUSTOM_PORT=$PORT"
  echo 'HEALTH_TIMER_INTERVAL=15min'
  echo 'HEALTH_TIMER_ALERT_CHANNEL=local_journald_only'
  echo 'HEALTH_TIMER_INSTALLED=no'
  echo 'CHANGES_APPLIED=no'
  exit 0
fi
exec 9>/run/linuxmailrelay365-sidecar-auth.lock
flock -n 9 || { echo 'HEALTH_TIMER_ERROR=concurrent_configuration_change' >&2; exit 1; }
STARTED=0
rollback() {
  rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ] && [ "$STARTED" -eq 1 ]; then
    systemctl disable --now linuxmailrelay365-health.timer >/dev/null 2>&1 || true
    rm -f "$SERVICE" "$TIMER" "$PROBE"
    systemctl daemon-reload >/dev/null 2>&1 || true
    echo 'HEALTH_TIMER_ROLLBACK=attempted' >&2
  fi
  exit "$rc"
}
trap rollback EXIT
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$(dirname "$0")/relay-health.py" "$PROBE"
STARTED=1
cat > "$SERVICE" <<EOF
[Unit]
Description=LinuxMailRelay365 isolated SMTP health (read-only, no mail sent)
Wants=linuxmailrelay365-sidecar.service
After=linuxmailrelay365-sidecar.service

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/bin/python3 $PROBE --smtp-port $PORT
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
EOF
cat > "$TIMER" <<'EOF'
[Unit]
Description=LinuxMailRelay365 isolated SMTP health every 15 min

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true
RandomizedDelaySec=30s
Unit=linuxmailrelay365-health.service

[Install]
WantedBy=timers.target
EOF
chmod 0644 "$SERVICE" "$TIMER"
systemctl daemon-reload
systemctl enable --now linuxmailrelay365-health.timer
systemctl is-active --quiet linuxmailrelay365-health.timer
systemctl start linuxmailrelay365-health.service
systemctl is-active --quiet linuxmailrelay365-sidecar.service
trap - EXIT
echo 'HEALTH_TIMER_INSTALLED=yes'
echo "HEALTH_TIMER_CUSTOM_PORT=$PORT"
echo 'HEALTH_TIMER_INTERVAL=15min'
echo 'HEALTH_TIMER_ALERT_CHANNEL=local_journald_only'
echo 'HEALTH_TIMER_M365_DELIVERY_TESTED=no'
echo 'PRIMARY_POSTFIX_UNCHANGED=yes'
