#!/usr/bin/env bash
# Standalone Direct Send on an independent Postfix, without Entra/OAuth setup.
# Primary Postfix config, service, port 25 and mail queue are never modified.
set -Eeuo pipefail
umask 077
export LC_ALL=C
CONF=/etc/linuxmailrelay365/sidecar-postfix
QUEUE=/var/spool/linuxmailrelay365-sidecar
DATA=/var/lib/linuxmailrelay365-sidecar
UNIT=/etc/systemd/system/linuxmailrelay365-sidecar.service
PORT=2525 LISTEN='' CIDRS='' MX='' DOMAIN='' SENDER='' ACTION=check CONFIRM='' FOREIGN_MTA='' SIDECAR_HOSTNAME='' PRESERVE_APPROVAL='' FOREIGN_BASELINE='' GUARD_PATH=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --smtp-port) PORT="$2"; shift 2 ;;
    --listen-ip) LISTEN="$2"; shift 2 ;;
    --trusted-network) CIDRS="$CIDRS,$2"; shift 2 ;;
    --mx-host) MX="$2"; shift 2 ;;
    --accepted-domain) DOMAIN="$2"; shift 2 ;;
    --fixed-sender) SENDER="$2"; shift 2 ;;
    --preserve-primary-mta) FOREIGN_MTA="$2"; shift 2 ;;
    --sidecar-hostname) SIDECAR_HOSTNAME="$2"; shift 2 ;;
    --confirm-preserve-primary-mta) PRESERVE_APPROVAL="$2"; shift 2 ;;
    --check-only) ACTION=check; shift ;;
    --apply) ACTION=apply; shift ;;
    --confirm-accepted-domain) CONFIRM="$2"; shift 2 ;;
    --self-test) echo 'DIRECT_SEND_SIDECAR_PARSER=ready'; exit 0 ;;
    --help|-h)
      echo 'Usage: --mx-host EOP_MX --accepted-domain DOMAIN --fixed-sender ADDRESS --smtp-port PORT [--listen-ip PRIVATE_IP --trusted-network RFC1918_CIDR] [--preserve-primary-mta exim|sendmail --sidecar-hostname FQDN --confirm-preserve-primary-mta PRESERVE_EXISTING_EXIM|PRESERVE_EXISTING_SENDMAIL] --check-only|--apply'
      exit 0 ;;
    *) echo 'DIRECT_SEND_ERROR=unknown_argument' >&2; exit 2 ;;
  esac
done
python3 - "$PORT" "$LISTEN" "$CIDRS" "$MX" "$DOMAIN" "$SENDER" "$FOREIGN_MTA" "$SIDECAR_HOSTNAME" <<'PY'
import ipaddress,re,sys
try:
    port,listen,networks,mx,domain,sender,foreign,hostname=sys.argv[1:]
    if foreign not in ('', 'exim', 'sendmail') or (foreign and not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+',hostname)) or (not foreign and hostname):
        raise ValueError('invalid_foreign_mta_or_explicit_sidecar_hostname')
    if not re.fullmatch(r'[0-9]{4,5}',port) or not 1024<=int(port)<=65535:
        raise ValueError('invalid_custom_port')
    dns=r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+'
    if not re.fullmatch(dns,mx) or not mx.lower().endswith('.mail.protection.outlook.com'):
        raise ValueError('invalid_eop_mx')
    if not re.fullmatch(dns,domain):
        raise ValueError('invalid_accepted_domain')
    if not re.fullmatch(r'[A-Za-z0-9.!#$%&*+/=?^_~-]+@'+dns,sender) or \
            sender.rsplit('@',1)[1].lower()!=domain.lower():
        raise ValueError('sender_must_match_declared_domain')
    allowed=[ipaddress.ip_network(x) for x in
             ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    cidrs=[x for x in networks.split(',') if x]
    if listen:
        address=ipaddress.IPv4Address(listen)
        if not any(address in p for p in allowed):
            raise ValueError('remote_listener_must_be_rfc1918')
        if not 1<=len(cidrs)<=8:
            raise ValueError('remote_listener_requires_1_to_8_private_cidrs')
    elif cidrs:
        raise ValueError('private_cidrs_require_listener')
    for raw in cidrs:
        net=ipaddress.ip_network(raw,strict=True)
        if not isinstance(net,ipaddress.IPv4Network) or not any(
            net.network_address in p and net.broadcast_address in p for p in allowed):
            raise ValueError('client_cidr_not_private')
except ValueError as e:
    raise SystemExit('DIRECT_SEND_ERROR='+str(e))
PY
if [ "$ACTION" = check ]; then
  echo 'DIRECT_SEND_PREFLIGHT=inputs_valid_only'
  echo "DIRECT_SEND_CUSTOM_PORT=$PORT"
  echo 'DIRECT_SEND_RECIPIENT_SCOPE=declared_internal_domain_only'
  echo 'DIRECT_SEND_TENANT_DOMAIN_VERIFIED=no'
  if [ -n "$FOREIGN_MTA" ]; then
    echo 'FOREIGN_PRIMARY_MTA_PRESERVATION=requires_live_root_guard_and_explicit_approval'
    echo 'FOREIGN_PRIMARY_MTA_PACKAGE_MUTATION=no'
  fi
  echo 'CHANGES_APPLIED=no'
  exit 0
fi
[ "$CONFIRM" = TENANT_DOMAIN_CHECKED ] || {
  echo 'DIRECT_SEND_ERROR=tenant_domain_confirmation_required' >&2; exit 2;
}
if [ -n "$FOREIGN_MTA" ]; then
  [ "$PRESERVE_APPROVAL" = "PRESERVE_EXISTING_${FOREIGN_MTA^^}" ] || {
    echo 'DIRECT_SEND_ERROR=foreign_mta_explicit_preservation_confirmation_required' >&2; exit 2;
  }
elif [ -n "$PRESERVE_APPROVAL" ]; then
  echo 'DIRECT_SEND_ERROR=unexpected_foreign_mta_confirmation' >&2; exit 2
fi
[ "$(id -u)" -eq 0 ] || { echo 'DIRECT_SEND_ERROR=root_required' >&2; exit 1; }
for cmd in postfix postconf postqueue python3 systemctl sha256sum ss flock; do
  command -v "$cmd" >/dev/null || {
    echo "DIRECT_SEND_ERROR=missing_$cmd" >&2; exit 1;
  }
done
if [ -z "$FOREIGN_MTA" ]; then
  [ -f /etc/postfix/main.cf ] && [ -f /etc/postfix/master.cf ] || {
    echo 'DIRECT_SEND_ERROR=primary_postfix_required_preserve_mode' >&2; exit 1;
  }
  # Never install a default Postfix-mode sidecar onto an unacknowledged
  # active Exim/Sendmail server. Select the explicit guarded path instead.
  for foreign_unit in exim.service exim4.service sendmail.service; do
    foreign_state="$(systemctl is-active "$foreign_unit" 2>/dev/null || true)"
    case "$foreign_state" in
      active)
        echo 'DIRECT_SEND_ERROR=active_foreign_mta_requires_preservation_mode' >&2; exit 1 ;;
      inactive|failed) ;;
      unknown)
        foreign_load="$(systemctl show --property=LoadState --value "$foreign_unit" 2>/dev/null || true)"
        [ "$foreign_load" = not-found ] || {
          echo 'DIRECT_SEND_ERROR=unknown_foreign_mta_state' >&2; exit 1;
        } ;;
      *)
        echo 'DIRECT_SEND_ERROR=unknown_foreign_mta_state' >&2; exit 1 ;;
    esac
  done
else
  GUARD_PATH="$(cd "$(dirname "$0")" && pwd)/guard-foreign-mta.py"
  [ -f "$GUARD_PATH" ] && [ ! -L "$GUARD_PATH" ] || {
    echo 'DIRECT_SEND_ERROR=foreign_primary_mta_guard_missing' >&2; exit 1;
  }
fi
if [ -e "$CONF" ] || [ -L "$CONF" ] || [ -e "$UNIT" ] || [ -L "$UNIT" ]; then
  echo 'DIRECT_SEND_ERROR=existing_sidecar_refuse_overwrite' >&2; exit 1
fi
osid="$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | head -n 1 | tr -d '"')" || true
selinux="$(getenforce 2>/dev/null || true)"
if [ -r /sys/fs/selinux/enforce ] && [ "$(cat /sys/fs/selinux/enforce)" = 1 ]; then
  selinux=Enforcing
fi
if [ "$selinux" = Enforcing ]; then
  echo 'DIRECT_SEND_ERROR=selinux_enforcing_not_integration_verified' >&2; exit 3
fi
case "$osid" in
  rhel|ol|rocky|almalinux|centos)
    [ "$selinux" = Disabled ] || {
      echo 'DIRECT_SEND_ERROR=rhel_selinux_state_not_verified' >&2; exit 3;
    } ;;
esac
if [ -n "$LISTEN" ]; then
  command -v ip >/dev/null || exit 1
  ip -o -4 addr show | awk '{split($4,a,"/");print a[1]}' |
    grep -Fxq "$LISTEN" || {
      echo 'DIRECT_SEND_ERROR=private_listener_not_assigned' >&2; exit 1;
    }
fi
if ss -H -ltn "( sport = :$PORT )" | grep -q .; then
  echo 'DIRECT_SEND_ERROR=port_already_bound' >&2; exit 1;
fi
postconf -m | grep -Fxq regexp || {
  echo 'DIRECT_SEND_ERROR=postfix_regexp_lookup_not_installed' >&2; exit 1;
}
bundle=''
for candidate in /etc/ssl/certs/ca-certificates.crt \
    /etc/pki/tls/certs/ca-bundle.crt \
    /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem; do
  if [ -s "$candidate" ]; then bundle="$candidate"; break; fi
done
[ -n "$bundle" ] || { echo 'DIRECT_SEND_ERROR=ca_bundle_missing' >&2; exit 1; }
if [ -n "$FOREIGN_MTA" ]; then
  HOSTNAME="$SIDECAR_HOSTNAME"
else
  HOSTNAME="$(postconf -h myhostname)"
fi
[[ "$HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || {
  echo 'DIRECT_SEND_ERROR=bad_primary_hostname' >&2; exit 1;
}
exec 9>/run/linuxmailrelay365-sidecar-auth.lock
flock -n 9 || { echo 'DIRECT_SEND_ERROR=concurrent_mail_operation' >&2; exit 1; }
if [ -n "$FOREIGN_MTA" ]; then
  if ! foreign_output="$(python3 "$GUARD_PATH" --mta "$FOREIGN_MTA" --hostname "$HOSTNAME")"; then
    echo "$foreign_output" >&2
    echo 'DIRECT_SEND_ERROR=foreign_primary_mta_preflight_refused' >&2; exit 1
  fi
  FOREIGN_BASELINE="$(printf '%s\n' "$foreign_output" | sed -n 's/^FOREIGN_MTA_BASELINE_SHA256=//p')"
  [[ "$FOREIGN_BASELINE" =~ ^[0-9a-f]{64}$ ]] || {
    echo 'DIRECT_SEND_ERROR=foreign_mta_snapshot_invalid' >&2; exit 1;
  }
else
  PRIMARY_BEFORE="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)"
fi
STARTED=0
rollback() {
  rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ] && [ "$STARTED" -eq 1 ]; then
    systemctl stop linuxmailrelay365-sidecar.service >/dev/null 2>&1 || true
    systemctl disable linuxmailrelay365-sidecar.service >/dev/null 2>&1 || true
    rm -f -- "$UNIT"
    rm -rf -- "$CONF"
    systemctl daemon-reload >/dev/null 2>&1 || true
    echo 'DIRECT_SEND_ROLLBACK=attempted_isolated_only' >&2
  fi
  exit "$rc"
}
trap rollback EXIT
install -d -o root -g root -m 0755 /etc/linuxmailrelay365
install -d -o root -g root -m 0755 "$QUEUE"
install -d -o postfix -g postfix -m 0700 "$DATA"
install -d -o root -g root -m 0755 "$CONF"
STARTED=1
inet='127.0.0.1'; networks='127.0.0.0/8'
if [ -n "$LISTEN" ]; then
  inet="127.0.0.1, $LISTEN"
  networks="$networks $(printf '%s' "$CIDRS" | tr ',' ' ')"
fi
python3 - "$CONF" "$DOMAIN" "$SENDER" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1]); domain=sys.argv[2].lower(); sender=sys.argv[3].lower()
escaped=domain.replace('.','[.]')
special=r'\.^$*+?{}[]()|'
literal=''.join('\\'+ch if ch in special else ch for ch in sender)
(root/'eop-fixed-sender.regexp').write_text(
    ':^{}$: OK\n'.format(literal),encoding='ascii')
(root/'eop-sender-canonical.regexp').write_text(
    '/^.+$/ {}\n'.format(sender.replace('$','$$')),encoding='ascii')
(root/'eop-recipients.regexp').write_text(
    '/^[^@[:space:]]+@{}$/ OK\n'.format(escaped),encoding='ascii')
PY
chmod 0644 "$CONF"/*.regexp
cat > "$CONF/main.cf" <<EOF
myhostname = $HOSTNAME
myorigin = \$myhostname
queue_directory = $QUEUE
data_directory = $DATA
inet_interfaces = $inet
inet_protocols = ipv4
mynetworks = $networks
mydestination =
relay_domains =
relayhost = [$MX]:25
default_transport = smtp:[$MX]:25
relay_transport = smtp:[$MX]:25
local_transport = error:LocalDeliveryDisabled
smtpd_client_restrictions = permit_mynetworks, reject
smtpd_relay_restrictions = permit_mynetworks, reject
smtpd_sender_restrictions = check_sender_access regexp:$CONF/eop-fixed-sender.regexp, reject
smtpd_recipient_restrictions = check_recipient_access regexp:$CONF/eop-recipients.regexp, reject
sender_canonical_maps = regexp:$CONF/eop-sender-canonical.regexp
sender_canonical_classes = envelope_sender, header_sender
# Apply sender canonical maps to remote SMTP headers too; default Postfix
# does not necessarily rewrite message headers from remote clients.
local_header_rewrite_clients = static:all
smtp_tls_security_level = secure
smtp_tls_secure_cert_match = nexthop
smtp_tls_CAfile = $bundle
smtp_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_sasl_auth_enable = no
disable_vrfy_command = yes
smtpd_helo_required = yes
message_size_limit = 26214400
syslog_name = postfix-lmr365
authorized_submit_users =
EOF
printf '%-10s inet  n       -       n       -       -       smtpd\n' "$PORT" > "$CONF/master.cf"
cat >> "$CONF/master.cf" <<'EOF'
pickup     unix  n       -       n       60      1       pickup
cleanup    unix  n       -       n       -       0       cleanup
qmgr       unix  n       -       n       300     1       qmgr
rewrite    unix  -       -       n       -       -       trivial-rewrite
bounce     unix  -       -       n       -       0       bounce
defer      unix  -       -       n       -       0       bounce
trace      unix  -       -       n       -       0       bounce
verify     unix  -       -       n       -       1       verify
flush      unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix  -       -       n       -       1       proxymap
anvil      unix  -       -       n       -       1       anvil
scache     unix  -       -       n       -       1       scache
tlsmgr     unix  -       -       n       1000?   1       tlsmgr
showq      unix  n       -       n       -       -       showq
error      unix  -       -       n       -       -       error
smtp       unix  -       -       n       -       5       smtp
EOF
chmod 0644 "$CONF/main.cf" "$CONF/master.cf"
printf '%s\n' "$PORT" > "$CONF/smtp-port"
chmod 0644 "$CONF/smtp-port"
cat > "$UNIT" <<'EOF'
[Unit]
Description=LinuxMailRelay365 independent Direct Send Postfix
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/postfix -c /etc/linuxmailrelay365/sidecar-postfix start
ExecStop=/usr/sbin/postfix -c /etc/linuxmailrelay365/sidecar-postfix stop
ExecReload=/usr/sbin/postfix -c /etc/linuxmailrelay365/sidecar-postfix reload
TimeoutStartSec=90

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"
postfix -c "$CONF" check
systemctl daemon-reload
systemctl enable --now linuxmailrelay365-sidecar.service
systemctl is-active --quiet linuxmailrelay365-sidecar.service
postfix -c "$CONF" status >/dev/null
if [ -n "$FOREIGN_MTA" ]; then
  if ! foreign_output="$(python3 "$GUARD_PATH" --mta "$FOREIGN_MTA" --hostname "$HOSTNAME" --expect-sha256 "$FOREIGN_BASELINE")"; then
    echo "$foreign_output" >&2
    echo 'DIRECT_SEND_ERROR=foreign_primary_mta_changed_or_unverified' >&2; exit 1
  fi
else
  [ "$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$PRIMARY_BEFORE" ] || {
    echo 'DIRECT_SEND_ERROR=primary_postfix_changed' >&2; exit 1;
  }
fi
trap - EXIT
echo 'DIRECT_SEND_SIDECAR_INSTALLED=yes'
echo "DIRECT_SEND_CUSTOM_PORT=$PORT"
echo 'DIRECT_SEND_RECIPIENT_SCOPE=declared_internal_domain_only'
echo 'DIRECT_SEND_TENANT_DOMAIN_VERIFIED=operator_attestation_only'
echo 'MICROSOFT365_DELIVERY_VERIFIED=no'
if [ -n "$FOREIGN_MTA" ]; then
  echo 'PRIMARY_FOREIGN_MTA_PRESERVED=guard_fingerprint_unchanged'
  echo 'PRIMARY_MTA_STOP_OR_RESTART=no'
  echo 'PRIMARY_MTA_QUEUE_MODIFIED=no'
else
  echo 'PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes'
fi
