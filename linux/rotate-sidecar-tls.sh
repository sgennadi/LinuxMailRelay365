#!/usr/bin/env bash
# LinuxMailRelay365 private-sidecar TLS cert rotation; never changes primary MTA.
set -Eeuo pipefail
umask 077
export LC_ALL=C
CONF=/etc/linuxmailrelay365/sidecar-postfix
AUTH=/etc/linuxmailrelay365/smtp-auth
BACKUPS=/var/lib/linuxmailrelay365-smtp-tls-recovery
PORT='' DNS='' CERT='' KEY='' CAFILE='' MODE=check EXPECT='' CONFIRM=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check-only) MODE=check; shift ;;
    --apply) MODE=apply; shift ;;
    --smtp-port) PORT="$2"; shift 2 ;;
    --server-name) DNS="$2"; shift 2 ;;
    --tls-cert) CERT="$2"; shift 2 ;;
    --tls-key) KEY="$2"; shift 2 ;;
    --ca-file) CAFILE="$2"; shift 2 ;;
    --expect-cert-sha256) EXPECT="$2"; shift 2 ;;
    --confirm) CONFIRM="$2"; shift 2 ;;
    --self-test) echo 'TLS_ROTATE_PARSER=available'; exit 0 ;;
    -h|--help)
      echo 'Use --check-only or --apply, --smtp-port, --server-name, --tls-cert, --tls-key, optional --ca-file'
      exit 0 ;;
    *) echo 'TLS_ROTATE_ERROR=unknown_argument' >&2; exit 2 ;;
  esac
done
python3 - "$PORT" "$DNS" "$CERT" "$KEY" "$CAFILE" "$MODE" "$EXPECT" <<'PY'
import ipaddress,re,sys
port,dns,cert,key,ca,mode,sha=sys.argv[1:]
if not re.fullmatch(r'[0-9]{4,5}',port) or not 1024<=int(port)<=65535:
    raise SystemExit('TLS_ROTATE_ERROR=invalid_custom_port')
if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+',dns):
    raise SystemExit('TLS_ROTATE_ERROR=invalid_dns')
try:
    ipaddress.ip_address(dns)
    raise SystemExit('TLS_ROTATE_ERROR=dns_required')
except ValueError: pass
for filename in (cert,key)+((ca,) if ca else ()):
    if not re.fullmatch(r'/[A-Za-z0-9_./-]{1,255}',filename) or '..' in filename.split('/'):
        raise SystemExit('TLS_ROTATE_ERROR=invalid_absolute_path')
# Self-signed internal TLS cert may also be the explicit CA trust bundle.
# Private key must NEVER be reused as certificate or CA bundle.
if cert == key or (ca and ca == key):
    raise SystemExit('TLS_ROTATE_ERROR=source_paths_must_differ')
if mode=='apply' and not re.fullmatch(r'[a-f0-9]{64}',sha):
    raise SystemExit('TLS_ROTATE_ERROR=expected_sha256_required')
PY
if [ "$MODE" = apply ] && [ "$CONFIRM" != ROTATE_PRIVATE_SMTP_TLS ]; then
  echo 'TLS_ROTATE_ERROR=explicit_confirmation_required' >&2; exit 2
fi
[ "$(id -u)" -eq 0 ] || { echo 'TLS_ROTATE_ERROR=root_required' >&2; exit 1; }
for cmd in python3 postfix postconf openssl sha256sum systemctl flock; do
  command -v "$cmd" >/dev/null || { echo "TLS_ROTATE_ERROR=missing_$cmd" >&2; exit 1; }
done
if [ "$MODE" = apply ]; then
  exec 9>/run/linuxmailrelay365-sidecar-auth.lock
  flock -n 9 || { echo 'TLS_ROTATE_ERROR=concurrent_operation' >&2; exit 1; }
fi
for f in "$CONF/main.cf" "$CONF/master.cf" "$CONF/smtp-port" \
 "$AUTH/fullchain.pem" "$AUTH/privkey.pem" "$CERT" "$KEY" \
 /etc/postfix/main.cf /etc/postfix/master.cf; do
  [ -f "$f" ] && [ ! -L "$f" ] || { echo 'TLS_ROTATE_ERROR=missing_or_symlink' >&2; exit 1; }
done
if [ -n "$CAFILE" ]; then
  [ -f "$CAFILE" ] && [ ! -L "$CAFILE" ] || { echo 'TLS_ROTATE_ERROR=ca_file_invalid' >&2; exit 1; }
fi
[ "$(cat "$CONF/smtp-port")" = "$PORT" ] || { echo 'TLS_ROTATE_ERROR=installed_port_mismatch' >&2; exit 1; }
systemctl is-active --quiet linuxmailrelay365-sidecar.service &&
systemctl is-active --quiet linuxmailrelay365-smtp-auth.service || {
  echo 'TLS_ROTATE_ERROR=isolated_services_not_active' >&2; exit 1;
}
[ "$(postconf -c "$CONF" -h smtpd_tls_security_level)" = encrypt ] &&
[ "$(postconf -c "$CONF" -h smtpd_sasl_auth_enable)" = yes ] &&
[ "$(postconf -c "$CONF" -h smtpd_tls_cert_file)" = "$AUTH/fullchain.pem" ] &&
[ "$(postconf -c "$CONF" -h smtpd_tls_key_file)" = "$AUTH/privkey.pem" ] || {
  echo 'TLS_ROTATE_ERROR=unexpected_existing_postfix_tls' >&2; exit 1;
}
osid="$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | head -n 1 | tr -d '"')" || true
selinux="$(getenforce 2>/dev/null || true)"
if [ -r /sys/fs/selinux/enforce ] && [ "$(cat /sys/fs/selinux/enforce)" = 1 ]; then selinux=Enforcing; fi
if [ "$selinux" = Enforcing ]; then
  echo 'TLS_ROTATE_ERROR=selinux_enforcing_not_integration_verified' >&2; exit 3
fi
case "$osid" in
  rhel|ol|rocky|almalinux|centos)
    [ "$selinux" = Disabled ] || { echo 'TLS_ROTATE_ERROR=rhel_selinux_policy_unknown' >&2; exit 3; } ;;
esac
python3 - "$CERT" "$KEY" "$CAFILE" "$DNS" <<'PY'
import os,re,stat,subprocess,sys
cert,key,ca,dns=sys.argv[1:]
for filename in (cert,key)+((ca,) if ca else ()):
    s=os.stat(filename)
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or not 0<s.st_size<=16*1024*1024:
        raise SystemExit('TLS_ROTATE_ERROR=invalid_source_permissions_or_size')
if os.stat(key).st_mode&0o077:
    raise SystemExit('TLS_ROTATE_ERROR=private_key_requires_0600')
p=subprocess.run(['openssl','x509','-in',cert,'-noout','-ext','subjectAltName'],
                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                 universal_newlines=True,timeout=10)
names=[x.lower() for x in re.findall(r'DNS:([A-Za-z0-9*.-]+)',p.stdout)]
if p.returncode or dns.lower() not in names:
    raise SystemExit('TLS_ROTATE_ERROR=certificate_dns_SAN_mismatch')
PY
openssl x509 -in "$CERT" -noout -checkend 604800 >/dev/null || {
  echo 'TLS_ROTATE_ERROR=certificate_expires_within_7_days' >&2; exit 1;
}
pubcert="$(openssl x509 -in "$CERT" -pubkey -noout |
  openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)"
pubkey="$(openssl pkey -in "$KEY" -pubout -outform DER 2>/dev/null | openssl dgst -sha256)"
[ -n "$pubcert" ] && [ "$pubcert" = "$pubkey" ] || {
  echo 'TLS_ROTATE_ERROR=certificate_key_mismatch' >&2; exit 1;
}
oldsha="$(sha256sum "$AUTH/fullchain.pem" | awk '{print $1}')"
newsha="$(sha256sum "$CERT" | awk '{print $1}')"
[ "$oldsha" != "$newsha" ] || { echo 'TLS_ROTATE_ERROR=identical_certificate' >&2; exit 1; }
if [ "$MODE" = check ]; then
  echo 'TLS_ROTATE_PREFLIGHT=ready'
  echo "TLS_ROTATE_OLD_CERT_SHA256=$oldsha"
  echo "TLS_ROTATE_CUSTOM_PORT=$PORT"
  echo 'TLS_ROTATE_APPLIED=no'
  exit 0
fi
[ "$EXPECT" = "$oldsha" ] || {
  echo 'TLS_ROTATE_ERROR=certificate_changed_since_preflight' >&2; exit 1;
}
VERIFIER="$(dirname "$0")/verify-sidecar-tls-identity.py"
[ -f "$VERIFIER" ] || { echo 'TLS_ROTATE_ERROR=verifier_missing' >&2; exit 1; }
[ ! -L "$BACKUPS" ] || { echo 'TLS_ROTATE_ERROR=recovery_directory_symlink' >&2; exit 1; }
install -d -o root -g root -m 0700 "$BACKUPS"
[ "$(stat -c '%u:%a' "$BACKUPS")" = '0:700' ] || {
  echo 'TLS_ROTATE_ERROR=unsafe_backup_permissions' >&2; exit 1;
}
backup="$(mktemp -d "$BACKUPS/recovery.XXXXXXXX")"
chmod 0700 "$backup"
cp -p "$AUTH/fullchain.pem" "$backup/fullchain.old"
cp -p "$AUTH/privkey.pem" "$backup/privkey.old"
[ "$(sha256sum "$backup/fullchain.old" | awk '{print $1}')" = "$oldsha" ] &&
[ "$(sha256sum "$backup/privkey.old" | awk '{print $1}')" = \
  "$(sha256sum "$AUTH/privkey.pem" | awk '{print $1}')" ] || {
  echo 'TLS_ROTATE_ERROR=backup_verification_failed' >&2; exit 1;
}
primary_before="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf | sha256sum | awk '{print $1}')"
CHANGED=0
TEMP_CERT='' TEMP_KEY=''
rollback() {
  status=$?
  trap - EXIT
  [ -z "$TEMP_CERT" ] || rm -f "$TEMP_CERT"
  [ -z "$TEMP_KEY" ] || rm -f "$TEMP_KEY"
  if [ "$status" -ne 0 ] && [ "$CHANGED" -eq 1 ]; then
    if cp -p "$backup/fullchain.old" "$AUTH/fullchain.pem" &&
       cp -p "$backup/privkey.old" "$AUTH/privkey.pem" &&
       postfix -c "$CONF" check && postfix -c "$CONF" reload; then
      echo 'TLS_ROTATE_ROLLBACK=attempted_original_cert_restored' >&2
    else
      echo 'TLS_ROTATE_ROLLBACK=MANUAL_RECOVERY_REQUIRED' >&2
    fi
  fi
  exit "$status"
}
trap rollback EXIT
TEMP_CERT="$(mktemp "$AUTH/.newcert.XXXXXXXX")"
TEMP_KEY="$(mktemp "$AUTH/.newkey.XXXXXXXX")"
install -o root -g root -m 0644 "$CERT" "$TEMP_CERT"
install -o root -g postfix -m 0640 "$KEY" "$TEMP_KEY"
CHANGED=1
mv -f "$TEMP_CERT" "$AUTH/fullchain.pem"; TEMP_CERT=''
mv -f "$TEMP_KEY" "$AUTH/privkey.pem"; TEMP_KEY=''
postfix -c "$CONF" check
postfix -c "$CONF" reload
if [ -n "$CAFILE" ]; then
  python3 "$VERIFIER" --smtp-port "$PORT" --server-name "$DNS" --ca-file "$CAFILE" |
    grep -Fx 'SMTP_TLS_PROBE_RESULT=verified_local_chain_dns_and_starttls'
else
  python3 "$VERIFIER" --smtp-port "$PORT" --server-name "$DNS" |
    grep -Fx 'SMTP_TLS_PROBE_RESULT=verified_local_chain_dns_and_starttls'
fi
primary_after="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf | sha256sum | awk '{print $1}')"
[ "$primary_before" = "$primary_after" ] || {
  echo 'TLS_ROTATE_ERROR=primary_postfix_changed' >&2; exit 1;
}
trap - EXIT
echo 'TLS_ROTATE_APPLIED=yes'
echo "TLS_ROTATE_CUSTOM_PORT=$PORT"
echo 'TLS_ROTATE_RECOVERY_ARCHIVE=root_only_manual_retention'
echo 'PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes'
echo 'MICROSOFT365_DELIVERY_VERIFIED=no'
