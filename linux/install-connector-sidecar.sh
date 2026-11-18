#!/usr/bin/env bash
# Standalone Microsoft 365 Inbound Connector on independent Postfix, no OAuth.
# Fixed sender only, custom private inbound port. Tenant connector separately verified.
# Primary Postfix config, service, port 25 and mail queue are never modified.
set -Eeuo pipefail
umask 077
export LC_ALL=C
CONF=/etc/linuxmailrelay365/sidecar-postfix
QUEUE=/var/spool/linuxmailrelay365-sidecar
DATA=/var/lib/linuxmailrelay365-sidecar
UNIT=/etc/systemd/system/linuxmailrelay365-sidecar.service
PORT=2525 LISTEN='' CIDRS='' MX='' DOMAIN='' SENDER='' ACTION=check DOMAIN_APPROVED='' CONNECTOR_APPROVED='' PUBLIC_IP='' CERT='' KEY=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --smtp-port) PORT="$2"; shift 2 ;;
    --listen-ip) LISTEN="$2"; shift 2 ;;
    --trusted-network) CIDRS="$CIDRS,$2"; shift 2 ;;
    --mx-host) MX="$2"; shift 2 ;;
    --accepted-domain) DOMAIN="$2"; shift 2 ;;
    --fixed-sender) SENDER="$2"; shift 2 ;;
    --check-only) ACTION=check; shift ;;
    --apply) ACTION=apply; shift ;;
    --confirm-accepted-domain) DOMAIN_APPROVED="$2"; shift 2 ;;
    --confirm-connector) CONNECTOR_APPROVED="$2"; shift 2 ;;
    --public-ip) PUBLIC_IP="$2"; shift 2 ;;
    --tls-cert) CERT="$2"; shift 2 ;;
    --tls-key) KEY="$2"; shift 2 ;;
    --self-test) echo 'CONNECTOR_SIDECAR_PARSER=ready'; exit 0 ;;
    --help|-h)
      echo 'Usage: --mx-host EOP_MX --accepted-domain DOMAIN --fixed-sender ADDRESS --smtp-port PORT [--listen-ip PRIVATE_IP --trusted-network RFC1918_CIDR] --check-only|--apply'
      exit 0 ;;
    *) echo 'CONNECTOR_ERROR=unknown_argument' >&2; exit 2 ;;
  esac
done
python3 - "$PORT" "$LISTEN" "$CIDRS" "$MX" "$DOMAIN" "$SENDER" "$PUBLIC_IP" "$CERT" "$KEY" <<'PY'
import ipaddress,re,sys
try:
    port,listen,networks,mx,domain,sender,public,cert,key=sys.argv[1:]
    if not re.fullmatch(r'[0-9]{4,5}',port) or not 1024<=int(port)<=65535:
        raise ValueError('invalid_custom_port')
    dns=r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+'
    if not re.fullmatch(dns,mx) or not mx.lower().endswith('.mail.protection.outlook.com'):
        raise ValueError('invalid_eop_mx')
    if not re.fullmatch(dns,domain):
        raise ValueError('invalid_accepted_domain')
    if not public and not (cert and key):
        raise ValueError('connector_public_ipv4_or_certificate_required')
    if bool(cert)!=bool(key):
        raise ValueError('connector_certificate_and_key_required')
    if public:
        try:
            address=ipaddress.IPv4Address(public)
            if not address.is_global:
                raise ValueError()
        except ValueError:
            raise ValueError('invalid_public_egress_ipv4')
    for filename in (cert,key):
        if filename and (not re.fullmatch(r'/[A-Za-z0-9_./-]{1,255}',filename)
                         or '..' in filename.split('/')):
            raise ValueError('invalid_connector_certificate_path')
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
    raise SystemExit('CONNECTOR_ERROR='+str(e))
PY
if [ "$ACTION" = check ]; then
  echo 'CONNECTOR_PREFLIGHT=inputs_valid_only'
  echo "CONNECTOR_CUSTOM_PORT=$PORT"
  echo 'CONNECTOR_RECIPIENT_SCOPE=external_recipients_need_verified_tenant_connector'
  echo 'CONNECTOR_TENANT_DOMAIN_VERIFIED=no'
  echo 'CONNECTOR_TENANT_CONNECTOR_VERIFIED=no'
  echo 'CHANGES_APPLIED=no'
  exit 0
fi
[ "$DOMAIN_APPROVED" = TENANT_DOMAIN_CHECKED ] || {
  echo 'CONNECTOR_ERROR=tenant_domain_confirmation_required' >&2; exit 2;
}
[ "$CONNECTOR_APPROVED" = TENANT_CONNECTOR_CHECKED ] || {
  echo 'CONNECTOR_ERROR=tenant_connector_confirmation_required' >&2; exit 2;
}
[ "$(id -u)" -eq 0 ] || { echo 'CONNECTOR_ERROR=root_required' >&2; exit 1; }
for cmd in postfix postconf postqueue python3 systemctl sha256sum ss flock openssl; do
  command -v "$cmd" >/dev/null || {
    echo "CONNECTOR_ERROR=missing_$cmd" >&2; exit 1;
  }
done
[ -f /etc/postfix/main.cf ] && [ -f /etc/postfix/master.cf ] || {
  echo 'CONNECTOR_ERROR=primary_postfix_required_preserve_mode' >&2; exit 1;
}
if [ -e "$CONF" ] || [ -L "$CONF" ] || [ -e "$UNIT" ] || [ -L "$UNIT" ]; then
  echo 'CONNECTOR_ERROR=existing_sidecar_refuse_overwrite' >&2; exit 1
fi
osid="$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | head -n 1 | tr -d '"')" || true
selinux="$(getenforce 2>/dev/null || true)"
if [ -r /sys/fs/selinux/enforce ] && [ "$(cat /sys/fs/selinux/enforce)" = 1 ]; then
  selinux=Enforcing
fi
if [ "$selinux" = Enforcing ]; then
  echo 'CONNECTOR_ERROR=selinux_enforcing_not_integration_verified' >&2; exit 3
fi
case "$osid" in
  rhel|ol|rocky|almalinux|centos)
    [ "$selinux" = Disabled ] || {
      echo 'CONNECTOR_ERROR=rhel_selinux_state_not_verified' >&2; exit 3;
    } ;;
esac
if [ -n "$LISTEN" ]; then
  command -v ip >/dev/null || exit 1
  ip -o -4 addr show | awk '{split($4,a,"/");print a[1]}' |
    grep -Fxq "$LISTEN" || {
      echo 'CONNECTOR_ERROR=private_listener_not_assigned' >&2; exit 1;
    }
fi
if ss -H -ltn "( sport = :$PORT )" | grep -q .; then
  echo 'CONNECTOR_ERROR=port_already_bound' >&2; exit 1;
fi
postconf -m | grep -Fxq regexp || {
  echo 'CONNECTOR_ERROR=postfix_regexp_lookup_not_installed' >&2; exit 1;
}
if [ -n "$CERT" ]; then
  python3 - "$CERT" "$KEY" "$DOMAIN" <<'PY'
import os,re,stat,subprocess,sys,grp
cert,key,domain=sys.argv[1:]
for filename in (cert,key):
    meta=os.lstat(filename)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022 or not 0<meta.st_size<16*1024*1024:
        raise SystemExit('CONNECTOR_ERROR=untrusted_certificate_or_key_source')
keyinfo=os.stat(key)
if keyinfo.st_gid!=grp.getgrnam('postfix').gr_gid or not keyinfo.st_mode&0o040 or keyinfo.st_mode&0o007:
    raise SystemExit('CONNECTOR_ERROR=private_key_requires_postfix_group_read')
def command(argv):
    return subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          universal_newlines=True,timeout=12)
valid=command(['openssl','x509','-in',cert,'-noout','-checkend','604800'])
san=command(['openssl','x509','-in',cert,'-noout','-ext','subjectAltName'])
if valid.returncode or san.returncode or domain.lower() not in [
       x.lower() for x in re.findall(r'DNS:([A-Za-z0-9.-]+)',san.stdout)]:
    raise SystemExit('CONNECTOR_ERROR=certificate_dns_san_or_expiry_invalid')
pub=command(['openssl','x509','-in',cert,'-pubkey','-noout'])
priv=command(['openssl','pkey','-in',key,'-pubout'])
if pub.returncode or priv.returncode or not pub.stdout or pub.stdout!=priv.stdout:
    raise SystemExit('CONNECTOR_ERROR=certificate_private_key_mismatch')
PY
fi
bundle=''
for candidate in /etc/ssl/certs/ca-certificates.crt \
    /etc/pki/tls/certs/ca-bundle.crt \
    /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem; do
  if [ -s "$candidate" ]; then bundle="$candidate"; break; fi
done
[ -n "$bundle" ] || { echo 'CONNECTOR_ERROR=ca_bundle_missing' >&2; exit 1; }
HOSTNAME="$(postconf -h myhostname)"
[[ "$HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || {
  echo 'CONNECTOR_ERROR=bad_primary_hostname' >&2; exit 1;
}
exec 9>/run/linuxmailrelay365-sidecar-auth.lock
flock -n 9 || { echo 'CONNECTOR_ERROR=concurrent_mail_operation' >&2; exit 1; }
PRIMARY_BEFORE="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)"
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
    echo 'CONNECTOR_ROLLBACK=attempted_isolated_only' >&2
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
import re,sys
root=Path(sys.argv[1]); domain=sys.argv[2].lower(); sender=sys.argv[3].lower()
escaped=domain.replace('.','[.]')
(root/'eop-fixed-sender.regexp').write_text(
    ':^{}$: OK\n'.format(re.escape(sender)),encoding='ascii')
(root/'eop-sender-canonical.regexp').write_text(
    '/^.+$/ {}\n'.format(sender),encoding='ascii')
(root/'eop-recipients.regexp').write_text(
    '/^[^@[:space:]]+@[^@[:space:]]+$/ OK\n',encoding='ascii')
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
smtp_tls_security_level = secure
smtp_tls_secure_cert_match = nexthop
smtp_tls_CAfile = $bundle
smtp_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtp_tls_cert_file = $CERT
smtp_tls_key_file = $KEY
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
Description=LinuxMailRelay365 independent Connector Postfix
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
[ "$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$PRIMARY_BEFORE" ] || {
  echo 'CONNECTOR_ERROR=primary_postfix_changed' >&2; exit 1;
}
trap - EXIT
echo 'CONNECTOR_SIDECAR_INSTALLED=yes'
echo "CONNECTOR_CUSTOM_PORT=$PORT"
echo 'CONNECTOR_RECIPIENT_SCOPE=external_recipients_need_verified_tenant_connector'
echo 'CONNECTOR_TENANT_DOMAIN_VERIFIED=operator_attestation_only'
echo 'CONNECTOR_TENANT_CONNECTOR_VERIFIED=operator_attestation_only'
echo 'MICROSOFT365_DELIVERY_VERIFIED=no'
echo 'PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes'
