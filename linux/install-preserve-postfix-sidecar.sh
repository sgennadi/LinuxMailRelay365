#!/usr/bin/env bash
# LinuxMailRelay365 Preserve Existing Mail: separate Postfix on TCP 2525.
# NEVER changes the primary Postfix service, main.cf, master.cf, or mail queue.
set -Eeuo pipefail
umask 077
export LC_ALL=C
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONF=/etc/linuxmailrelay365/sidecar-postfix
IDENTITY=/etc/linuxmailrelay365/sidecar-identity
QUEUE=/var/spool/linuxmailrelay365-sidecar
DATA=/var/lib/linuxmailrelay365-sidecar
UNIT=/etc/systemd/system/linuxmailrelay365-sidecar.service
TRANSPORT=/usr/local/libexec/linuxmailrelay365-sidecar-transport.py
SOURCE_CERT=/etc/postfix/m365-oauth
TENANT='' CLIENT='' MAILBOX='' LISTEN_IP='' CHECK_ONLY=0
TRUSTED_NETWORKS=()
usage() {
  echo 'Usage: sidecar.sh --tenant-id GUID --client-id GUID --mailbox address [--listen-ip IPv4 --trusted-network CIDR]'
  echo 'Options: --check-only (no modifications) | --self-test'
}
if [ "${1:-}" = --self-test ] && [ "$#" -eq 1 ]; then
  echo 'Sidecar arguments self-test OK'; exit 0
fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    --tenant-id) TENANT="${2:?}"; shift 2 ;;
    --client-id) CLIENT="${2:?}"; shift 2 ;;
    --mailbox) MAILBOX="${2:?}"; shift 2 ;;
    --listen-ip) LISTEN_IP="${2:?}"; shift 2 ;;
    --trusted-network) TRUSTED_NETWORKS+=("${2:?}"); shift 2 ;;
    --check-only) CHECK_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo 'Unsupported preserve-mode option.' >&2; exit 2 ;;
  esac
done
python3 - "$TENANT" "$CLIENT" "$MAILBOX" "$LISTEN_IP" "${TRUSTED_NETWORKS[@]}" <<'PY'
import ipaddress, re, sys, uuid
try:
    tenant, client, mailbox, listen, *cidrs = sys.argv[1:]
    for val in (tenant, client):
        if val and str(uuid.UUID(val)) != val.lower():
            raise ValueError('Invalid Tenant/Client ID')
    if mailbox and not re.fullmatch(r'[A-Za-z0-9.!#$%&*+/=?^_{}|~-]+@[A-Za-z0-9.-]+', mailbox):
        raise ValueError('Invalid sender mailbox')
    rfc1918 = [ipaddress.ip_network(n) for n in
               ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if listen:
        addr = ipaddress.IPv4Address(listen)
        if str(addr) != listen or not any(addr in n for n in rfc1918):
            raise ValueError('Listener must be an explicit RFC1918 IPv4')
        if not cidrs or len(cidrs) > 8:
            raise ValueError('Remote listener requires 1..8 trusted subnets')
    elif cidrs:
        raise ValueError('Trusted networks require an explicit IPv4 listener')
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=True)
        if not isinstance(net, ipaddress.IPv4Network) or not any(
                net.subnet_of(base) for base in rfc1918):
            raise ValueError('CIDR outside RFC1918')
except ValueError as exc:
    sys.stderr.write('Sidecar input rejected: ' + str(exc) + '\n')
    sys.exit(2)
PY
if [ "$CHECK_ONLY" -eq 1 ]; then
  echo 'SIDECAR_INPUTS_VALID=yes'
  echo 'SIDECAR_APPLIED=no'
  exit 0
fi
[ "$(id -u)" -eq 0 ] || { echo 'Root privileges required.' >&2; exit 1; }
[ -n "$TENANT" ] && [ -n "$CLIENT" ] && [ -n "$MAILBOX" ] || {
  echo 'Tenant, Client and Mailbox required for installation.' >&2; exit 2;
}
for command in postfix postconf postqueue python3 openssl systemctl sha256sum ss runuser; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Missing $command. Preserve mode does not install or replace MTA packages." >&2
    exit 1
  }
done
id postfix >/dev/null 2>&1 && id m365mailer >/dev/null 2>&1 || {
  echo 'Postfix and m365mailer service users required.' >&2; exit 1;
}
[ -f /etc/postfix/main.cf ] && [ -f /etc/postfix/master.cf ] || {
  echo 'Existing primary Postfix required. Sendmail/Exim are not modified.' >&2
  exit 1
}
[ -f "$SOURCE_CERT/app.key" ] && [ -f "$SOURCE_CERT/app.crt" ] || {
  echo 'Prepare and register the Linux certificate first.' >&2; exit 1;
}
[ -f "$SCRIPT_DIR/m365_xoauth2_transport.py" ] || {
  echo 'Bundled XOAUTH2 transport missing.' >&2; exit 1;
}
for target in "$CONF" "$IDENTITY" "$UNIT" "$TRANSPORT"; do
  if [ -e "$target" ] || [ -L "$target" ]; then
    echo 'Existing sidecar detected; refusing overwrite.' >&2
    exit 1
  fi
done
if [ -n "$LISTEN_IP" ]; then
  command -v ip >/dev/null 2>&1 || { echo 'iproute2 required.' >&2; exit 1; }
  ip -o -4 addr show | awk '{split($4,a,"/"); print a[1]}' | grep -Fxq -- "$LISTEN_IP" || {
    echo 'Listener IP is not assigned locally.' >&2; exit 1;
  }
fi
if ss -H -ltn '( sport = :2525 )' | grep -q .; then
  echo 'Port 2525 already in use. No service changed.' >&2
  exit 1
fi
BEFORE="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf | sha256sum | awk '{print $1}')"
created=0
rollback() {
  rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ] && [ "$created" -eq 1 ]; then
    systemctl stop linuxmailrelay365-sidecar.service >/dev/null 2>&1 || true
    systemctl disable linuxmailrelay365-sidecar.service >/dev/null 2>&1 || true
    rm -f -- "$UNIT" "$TRANSPORT"
    rm -rf -- "$CONF" "$IDENTITY"
    systemctl daemon-reload >/dev/null 2>&1 || true
    echo 'New sidecar configuration rolled back; independent queue retained.' >&2
  fi
  exit "$rc"
}
trap rollback EXIT
install -d -o root -g root -m 0755 /etc/linuxmailrelay365
install -d -o root -g root -m 0755 "$QUEUE"
install -d -o postfix -g postfix -m 0700 "$DATA"
install -d -o root -g root -m 0755 "$CONF"
install -d -o root -g m365mailer -m 0750 "$IDENTITY"
created=1
install -o root -g m365mailer -m 0640 "$SOURCE_CERT/app.key" "$IDENTITY/app.key"
install -o root -g m365mailer -m 0644 "$SOURCE_CERT/app.crt" "$IDENTITY/app.crt"
install -o root -g root -m 0755 "$SCRIPT_DIR/m365_xoauth2_transport.py" "$TRANSPORT"
python3 - "$TENANT" "$CLIENT" "$MAILBOX" "$IDENTITY/app.json" <<'PY'
import json, sys
with open(sys.argv[4], 'w', encoding='utf-8') as out:
    json.dump(dict(tenant_id=sys.argv[1], client_id=sys.argv[2], mailbox=sys.argv[3],
                   certificate='/etc/linuxmailrelay365/sidecar-identity/app.crt',
                   private_key='/etc/linuxmailrelay365/sidecar-identity/app.key'), out)
    out.write('\n')
PY
chown root:m365mailer "$IDENTITY/app.json"
chmod 0640 "$IDENTITY/app.json"
HOSTNAME="$(postconf -h myhostname)"
[[ "$HOSTNAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$ ]] || {
  echo 'Primary Postfix myhostname invalid.' >&2; exit 1;
}
INET='127.0.0.1'
NETWORKS='127.0.0.0/8'
if [ -n "$LISTEN_IP" ]; then
  INET="127.0.0.1, $LISTEN_IP"
  NETWORKS="$NETWORKS ${TRUSTED_NETWORKS[*]}"
fi
cat > "$CONF/main.cf" <<EOF
myhostname = $HOSTNAME
myorigin = \$myhostname
queue_directory = $QUEUE
data_directory = $DATA
inet_interfaces = $INET
inet_protocols = ipv4
mynetworks = $NETWORKS
mydestination =
relay_domains =
default_transport = m365xoauth2:
relay_transport = m365xoauth2:
local_transport = error:LocalDeliveryDisabled
smtpd_client_restrictions = permit_mynetworks, reject
smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination
smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination
disable_vrfy_command = yes
smtpd_helo_required = yes
message_size_limit = 26214400
m365xoauth2_destination_recipient_limit = 1
m365xoauth2_destination_concurrency_limit = 2
syslog_name = postfix-lmr365
authorized_submit_users =
EOF
cat > "$CONF/master.cf" <<'EOF'
2525       inet  n       -       n       -       -       smtpd
pickup     unix  n       -       n       60      1       pickup
cleanup    unix  n       -       n       -       0       cleanup
qmgr       unix  n       -       n       300     1       qmgr
rewrite    unix  -       -       n       -       -       trivial-rewrite
bounce     unix  -       -       n       -       0       bounce
defer      unix  -       -       n       -       0       bounce
trace      unix  -       -       n       -       0       bounce
verify     unix  -       -       n       -       1       verify
flush      unix  n       -       n       1000?   0       flush
showq      unix  n       -       n       -       -       showq
error      unix  -       -       n       -       -       error
m365xoauth2 unix - n n - 2 pipe
  flags=q user=m365mailer argv=/usr/bin/python3 /usr/local/libexec/linuxmailrelay365-sidecar-transport.py --config /etc/linuxmailrelay365/sidecar-identity/app.json --recipient ${recipient}
EOF
chmod 0644 "$CONF/main.cf" "$CONF/master.cf"
cat > "$UNIT" <<'EOF'
[Unit]
Description=LinuxMailRelay365 isolated SMTP relay (Postfix 2525)
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
postfix -c "$CONF" status >/dev/null
runuser -u m365mailer -- /usr/bin/python3 "$TRANSPORT" --config "$IDENTITY/app.json" --config-check
AFTER="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf | sha256sum | awk '{print $1}')"
[ "$AFTER" = "$BEFORE" ] || {
  echo 'Primary Postfix config changed externally during setup; inspect it.' >&2
  exit 1
}
trap - EXIT
echo 'SIDECAR_INSTALLED=yes'
echo 'SIDECAR_PORT=2525'
echo "SIDECAR_LISTEN=${LISTEN_IP:-127.0.0.1}"
echo "SIDECAR_CONFIG=$CONF"
echo "SIDECAR_QUEUE=$QUEUE"
echo 'PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes'
echo 'SIDECAR_DELIVERY_VERIFIED=no'
