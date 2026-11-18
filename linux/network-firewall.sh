#!/usr/bin/env bash
# LinuxMailRelay365: read-only network preflight; opt-in local firewall changes.
# Never enables/disables ufw/firewalld or opens a public/wildcard SMTP port.
set -Eeuo pipefail
umask 077
export LC_ALL=C
MODE=check
SMTP_PORT=2525
LISTEN_IP=''
CONFIRM=''
PUBLIC_INTERNET=0
TRUSTED_NETWORKS=()
usage() {
  echo 'Usage: network-firewall.sh --check|--validate-only|--apply --smtp-port N [--listen-ip IPv4 --trusted-network CIDR]...'
  echo 'Firewall changes require --apply --confirm OPEN_TRUSTED_SMTP_PORT.'
  echo 'Option --public-internet is risk assessment ONLY. Public firewall opening is blocked until SMTP AUTH/TLS are implemented.'
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check) MODE=check; shift ;;
    --validate-only) MODE=validate; shift ;;
    --apply) MODE=apply; shift ;;
    --smtp-port) SMTP_PORT="${2:?}"; shift 2 ;;
    --listen-ip) LISTEN_IP="${2:?}"; shift 2 ;;
    --trusted-network) TRUSTED_NETWORKS+=("${2:?}"); shift 2 ;;
    --public-internet) PUBLIC_INTERNET=1; shift ;;
    --confirm) CONFIRM="${2:?}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo 'Unsupported network/firewall option.' >&2; exit 2 ;;
  esac
done
command -v python3 >/dev/null 2>&1 || {
  echo 'Python 3 is required to validate network/firewall policy.' >&2; exit 2;
}
python3 - "$SMTP_PORT" "$LISTEN_IP" "${TRUSTED_NETWORKS[@]}" <<'PY'
import ipaddress, re, sys
try:
    port, listener, *cidrs = sys.argv[1:]
    if not re.fullmatch(r'[1-9][0-9]{3,4}', port) or not (1024 <= int(port) <= 65535):
        raise ValueError('SMTP port must be from 1024 to 65535')
    private = [ipaddress.IPv4Network(s) for s in
               ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if listener:
        addr = ipaddress.IPv4Address(listener)
        if str(addr) != listener or not any(addr in s for s in private):
            raise ValueError('Listener must be explicit RFC1918 IPv4')
        if not 1 <= len(cidrs) <= 8:
            raise ValueError('Remote SMTP requires 1..8 trusted RFC1918 CIDRs')
    elif cidrs:
        raise ValueError('Trusted CIDRs require an explicit listener IP')
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=True)
        if not isinstance(net, ipaddress.IPv4Network) or not any(
                (net.network_address in p and net.broadcast_address in p) for p in private):
            raise ValueError('Non-RFC1918 CIDR is not allowed')
except ValueError as exc:
    sys.stderr.write('NETWORK_POLICY=invalid (' + str(exc) + ')\n')
    sys.exit(2)
PY
if [ "$PUBLIC_INTERNET" -eq 1 ] && [ "$MODE" = apply ]; then
  echo 'PUBLIC_SMTP_APPLY_BLOCKED=authentication_tls_rate_limits_not_implemented' >&2
  echo 'Opening a public unauthenticated relay would allow spam, abuse and blacklisting.' >&2
  exit 3
fi
if [ "$MODE" = validate ]; then
  if [ "$PUBLIC_INTERNET" -eq 1 ]; then
    echo 'PUBLIC_SMTP_PLAN=selected_not_active'
    echo 'PUBLIC_SMTP_APPLY_ALLOWED=no'
    echo 'PUBLIC_SMTP_REQUIREMENTS=SMTP_AUTH_TLS_rate_limits_monitoring'
  fi
  echo 'NETWORK_POLICY=valid'
  echo 'FIREWALL_CHANGES=no'
  exit 0
fi
fw_backend=none
fw_active=no
firewalld_running=no
ufw_running=no
if command -v firewall-cmd >/dev/null 2>&1 &&
   [ "$(firewall-cmd --state 2>/dev/null || true)" = running ]; then
  firewalld_running=yes
fi
if command -v ufw >/dev/null 2>&1 &&
   ufw status 2>/dev/null | grep -Eiq '^Status:[[:space:]]+active$'; then
  ufw_running=yes
fi
if [ "$firewalld_running" = yes ] && [ "$ufw_running" = yes ]; then
  fw_backend=ambiguous
  fw_active=yes
elif [ "$firewalld_running" = yes ]; then
  fw_backend=firewalld
  fw_active=yes
elif [ "$ufw_running" = yes ]; then
  fw_backend=ufw
  fw_active=yes
elif command -v nft >/dev/null 2>&1 && [ -n "$(nft list ruleset 2>/dev/null || true)" ]; then
  fw_backend=nftables_manual
elif command -v iptables >/dev/null 2>&1; then
  fw_backend=other_or_inactive
fi
echo "FIREWALL_BACKEND=$fw_backend"
echo "FIREWALL_ACTIVE=$fw_active"
echo "SMTP_PORT=$SMTP_PORT"
echo "SMTP_LISTENER_REQUESTED=${LISTEN_IP:-loopback}"
echo "TRUSTED_CIDR_COUNT=${#TRUSTED_NETWORKS[@]}"
if [ "$PUBLIC_INTERNET" -eq 1 ]; then
  echo 'PUBLIC_SMTP_PLAN=selected_not_active'
  echo 'PUBLIC_SMTP_APPLY_ALLOWED=no'
  echo 'PUBLIC_SMTP_ABUSE_RISK=spam_open_relay_blocklists_identity_reputation'
  echo 'PUBLIC_SMTP_REQUIREMENTS=SMTP_AUTH_TLS_rate_limits_monitoring'
fi
if command -v ss >/dev/null 2>&1; then
  if ss -H -ltn "( sport = :$SMTP_PORT )" 2>/dev/null | grep -q .; then
    echo 'SMTP_LISTENER_PORT=in_use'
  else
    echo 'SMTP_LISTENER_PORT=available'
  fi
else
  echo 'SMTP_LISTENER_PORT=unknown_no_ss'
fi
if [ "$MODE" = check ]; then
  # We only test DNS/TCP connect, NOT authentication or delivery.
  python3 - <<'PY'
import socket
for label, host, port in (
    ('ENTRA_HTTPS_443', 'login.microsoftonline.com', 443),
    ('EXCHANGE_SMTP_587', 'smtp.office365.com', 587)
):
    try:
        with socket.create_connection((host, port), timeout=4):
            status = 'tcp_reachable'
    except (OSError, TimeoutError):
        status = 'blocked_or_unavailable'
    print(label + '=' + status)
PY
  if [ "$PUBLIC_INTERNET" -eq 1 ]; then
    conf=/etc/linuxmailrelay365/sidecar-postfix
    if command -v postconf >/dev/null 2>&1 && [ -f "$conf/main.cf" ]; then
      auth="$(postconf -c "$conf" -h smtpd_sasl_auth_enable 2>/dev/null || true)"
      tls="$(postconf -c "$conf" -h smtpd_tls_security_level 2>/dev/null || true)"
      [ "$auth" = yes ] && echo 'PUBLIC_SMTP_SASL_AUTH=available' || echo 'PUBLIC_SMTP_SASL_AUTH=missing'
      [ "$tls" = encrypt ] && echo 'PUBLIC_SMTP_TLS_REQUIRED=yes' || echo 'PUBLIC_SMTP_TLS_REQUIRED=no'
    else
      echo 'PUBLIC_SMTP_SASL_AUTH=not_checked'
      echo 'PUBLIC_SMTP_TLS_REQUIRED=not_checked'
    fi
    echo 'PUBLIC_SMTP_READY=no_unverified_auth_tls_security_controls'
  fi
  echo 'FIREWALL_CHANGES=no'
  echo 'INBOUND_FROM_OTHER_HOST=not_verified_by_local_probe'
  exit 0
fi
# No firewall modifications without explicit wizard opt-in and confirmation.
if [ "$MODE" != apply ] || [ "$CONFIRM" != OPEN_TRUSTED_SMTP_PORT ]; then
  echo 'Explicit firewall confirmation missing. No firewall changes.' >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  echo 'Firewall modifications require root; no changes.' >&2
  exit 1
fi
if [ -z "$LISTEN_IP" ] || [ "${#TRUSTED_NETWORKS[@]}" -eq 0 ]; then
  echo 'Loopback-only SMTP does not require an inbound firewall rule.' >&2
  exit 1
fi
if [ "$fw_active" != yes ] || { [ "$fw_backend" != ufw ] && [ "$fw_backend" != firewalld ]; }; then
  echo 'No single active supported firewall found. Never enable or change another firewall.' >&2
  exit 1
fi
# Ensure the installed isolated Postfix service REALLY uses this port/IP/CIDR.
CONF=/etc/linuxmailrelay365/sidecar-postfix
if [ ! -f "$CONF/smtp-port" ] ||
   [ "$(cat "$CONF/smtp-port")" != "$SMTP_PORT" ] ||
   ! command -v postconf >/dev/null 2>&1 ||
   ! systemctl is-active --quiet linuxmailrelay365-sidecar.service; then
  echo 'Installed isolated SMTP service/port does not match request. Firewall unchanged.' >&2
  exit 1
fi
actual_listen="$(postconf -c "$CONF" -h inet_interfaces | tr ',' ' ')"
if ! printf '%s\n' "$actual_listen" | tr ' ' '\n' | grep -Fxq -- "$LISTEN_IP"; then
  echo 'Sidecar is not bound to the requested IP. Firewall unchanged.' >&2
  exit 1
fi
actual_networks="$(postconf -c "$CONF" -h mynetworks | tr ',' ' ')"
for cidr in "${TRUSTED_NETWORKS[@]}"; do
  if ! printf '%s\n' "$actual_networks" | tr ' ' '\n' | grep -Fxq -- "$cidr"; then
    echo "Requested CIDR $cidr is not trusted by sidecar. Firewall unchanged." >&2
    exit 1
  fi
done
if ! command -v ip >/dev/null 2>&1; then
  echo 'iproute2 is needed to select the correct firewall zone.' >&2; exit 1
fi
interface="$(ip -o -4 addr show | awk -v ip="$LISTEN_IP" '{split($4,a,"/"); if(a[1]==ip){print $2;exit}}')"
if [ -z "$interface" ]; then
  echo 'Listener IP is not assigned to any local interface.' >&2; exit 1
fi
changed=0
if [ "$fw_backend" = firewalld ]; then
  zone="$(firewall-cmd --get-zone-of-interface="$interface" 2>/dev/null || true)"
  if [ -z "$zone" ] || [ "$zone" = "no zone" ]; then
    zone="$(firewall-cmd --get-default-zone 2>/dev/null || true)"
  fi
  if ! [[ "$zone" =~ ^[A-Za-z0-9_+-]{1,32}$ ]]; then
    echo 'Unable to determine safe interface zone; no rules added.' >&2; exit 1
  fi
  echo "FIREWALL_ZONE=$zone"
  added_runtime=()
  added_permanent=()
  rollback() {
    local rc=$?
    if [ "$rc" -ne 0 ]; then
      echo 'Firewall modification failed; undoing rules created in this run.' >&2
      for rule in "${added_runtime[@]}"; do
        firewall-cmd --zone="$zone" --remove-rich-rule="$rule" >/dev/null 2>&1 || true
      done
      for rule in "${added_permanent[@]}"; do
        firewall-cmd --permanent --zone="$zone" --remove-rich-rule="$rule" >/dev/null 2>&1 || true
      done
    fi
  }
  trap rollback EXIT
  for cidr in "${TRUSTED_NETWORKS[@]}"; do
    rule="rule family=\"ipv4\" source address=\"$cidr\" destination address=\"$LISTEN_IP\" port port=\"$SMTP_PORT\" protocol=\"tcp\" accept"
    if ! firewall-cmd --zone="$zone" --query-rich-rule="$rule" >/dev/null 2>&1; then
      firewall-cmd --zone="$zone" --add-rich-rule="$rule" >/dev/null
      added_runtime+=("$rule")
      changed=$((changed+1))
    fi
    if ! firewall-cmd --permanent --zone="$zone" --query-rich-rule="$rule" >/dev/null 2>&1; then
      firewall-cmd --permanent --zone="$zone" --add-rich-rule="$rule" >/dev/null
      added_permanent+=("$rule")
      changed=$((changed+1))
    fi
  done
  trap - EXIT
else
  # UFW preserves its rules across reboots. Never run 'ufw enable', only add
  # host/destination/source scoped rules with the already-active firewall.
  for cidr in "${TRUSTED_NETWORKS[@]}"; do
    if ! ufw --dry-run allow in proto tcp from "$cidr" to "$LISTEN_IP" port "$SMTP_PORT" >/dev/null; then
      echo 'UFW did not accept the planned rule; stopped.' >&2
      exit 1
    fi
  done
  for cidr in "${TRUSTED_NETWORKS[@]}"; do
    if ! ufw allow in proto tcp from "$cidr" to "$LISTEN_IP" port "$SMTP_PORT" comment LinuxMailRelay365 >/dev/null; then
      echo 'UFW failed; inspect previously applied rules manually.' >&2
      exit 1
    fi
    changed=$((changed+1))
  done
fi
echo "FIREWALL_RULE_OPERATIONS=$changed"
echo 'FIREWALL_APPLY_COMPLETED=yes'
echo 'FIREWALL_EXTERNAL_REACHABILITY=not_verified'
echo 'FIREWALL_REMAINS_ENABLED_AS_BEFORE=yes'
