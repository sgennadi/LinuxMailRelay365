#!/usr/bin/env bash
# LinuxMailRelay365: optional AUTH and mandatory STARTTLS for existing isolated Postfix.
# Never modifies the primary Postfix, host Dovecot, firewall or SELinux policy.
set -Eeuo pipefail
umask 077
export LC_ALL=C
CONF=/etc/linuxmailrelay365/sidecar-postfix
AUTH=/etc/linuxmailrelay365/smtp-auth
UNIT=/etc/systemd/system/linuxmailrelay365-smtp-auth.service
QUEUE=/var/spool/linuxmailrelay365-sidecar
MODE=check
PORT='' NAME='' CERT='' KEY='' HASHFILE='' CONFIRM=''
usage() {
  echo 'Usage: enable-sidecar-auth-tls.sh --check-only|--apply --smtp-port N --server-name smtp.example.org --tls-cert /path/fullchain.pem --tls-key /path/key.pem --password-file /path/hashed-user'
  echo 'Apply requires --confirm ENABLE_PRIVATE_AUTH_TLS. Source hash must be created with interactive doveadm pw -s SHA512-CRYPT (1..64 distinct accounts).'
  echo 'NOT for public Internet. SELinux Enforcing requires separately validated socket labeling.'
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check-only) MODE=check; shift ;;
    --apply) MODE=apply; shift ;;
    --smtp-port) PORT="$2"; shift 2 ;;
    --server-name) NAME="$2"; shift 2 ;;
    --tls-cert) CERT="$2"; shift 2 ;;
    --tls-key) KEY="$2"; shift 2 ;;
    --password-file) HASHFILE="$2"; shift 2 ;;
    --confirm) CONFIRM="$2"; shift 2 ;;
    --self-test) echo 'AUTH_TLS_ARGUMENT_PARSER=available'; exit 0 ;;
    --help|-h) usage; exit 0 ;;
    *) echo 'AUTH_TLS_ERROR=unsupported_argument' >&2; exit 2 ;;
  esac
done
command -v python3 >/dev/null || { echo 'AUTH_TLS_ERROR=python3_missing' >&2; exit 2; }
# Input validation is read-only and works under RHEL 8 Python 3.6.
python3 - "$PORT" "$NAME" "$CERT" "$KEY" "$HASHFILE" <<'PY'
import re, sys
port, name, *paths = sys.argv[1:]
if not re.fullmatch(r'[1-9][0-9]{3,4}', port) or not 1024 <= int(port) <= 65535:
    raise SystemExit('AUTH_TLS_ERROR=invalid_custom_smtp_port')
if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+', name):
    raise SystemExit('AUTH_TLS_ERROR=invalid_server_dns_name')
if len(set(paths)) != len(paths):
    raise SystemExit('AUTH_TLS_ERROR=source_paths_must_be_distinct')
for path in paths:
    if not re.fullmatch(r'/[A-Za-z0-9_./-]{1,255}', path) or '..' in path.split('/'):
        raise SystemExit('AUTH_TLS_ERROR=invalid_absolute_linux_path')
PY
if [ "$MODE" = apply ] && [ "$CONFIRM" != ENABLE_PRIVATE_AUTH_TLS ]; then
  echo 'AUTH_TLS_ERROR=confirmation_required' >&2; exit 2
fi
[ "$(id -u)" -eq 0 ] || { echo 'AUTH_TLS_ERROR=root_required' >&2; exit 1; }
# Both activation and restoration use the same exclusive lock. Read-only
# --check-only never creates a lock file or changes any mail service.
if [ "$MODE" = apply ]; then
  command -v flock >/dev/null || { echo 'AUTH_TLS_ERROR=flock_missing' >&2; exit 1; }
  exec 9>/run/linuxmailrelay365-sidecar-auth.lock
  flock -n 9 || { echo 'AUTH_TLS_ERROR=concurrent_change_blocked' >&2; exit 1; }
fi
for cmd in postfix postconf openssl doveconf dovecot systemctl stat sha256sum; do
  command -v "$cmd" >/dev/null || { echo "AUTH_TLS_ERROR=missing_$cmd" >&2; exit 1; }
done
case "$(dovecot --version)" in
  2.3.*) ;;
  *) echo 'AUTH_TLS_ERROR=dovecot_2_3_required_2_4_is_incompatible' >&2; exit 1 ;;
esac
postconf -a | grep -Fxq dovecot || {
  echo 'AUTH_TLS_ERROR=postfix_dovecot_sasl_unavailable' >&2; exit 1;
}
for path in "$CONF/main.cf" "$CONF/master.cf" "$CONF/smtp-port" /etc/postfix/main.cf /etc/postfix/master.cf; do
  [ -f "$path" ] || { echo 'AUTH_TLS_ERROR=required_postfix_configuration_missing' >&2; exit 1; }
done
[ -d "$QUEUE" ] && systemctl is-active --quiet linuxmailrelay365-sidecar.service || {
  echo 'AUTH_TLS_ERROR=isolated_sidecar_not_active' >&2; exit 1;
}
[ "$(cat "$CONF/smtp-port")" = "$PORT" ] || {
  echo 'AUTH_TLS_ERROR=requested_port_differs_from_installed_sidecar' >&2; exit 1;
}
[ ! -e "$AUTH" ] && [ ! -L "$AUTH" ] && [ ! -e "$UNIT" ] && [ ! -L "$UNIT" ] || {
  echo 'AUTH_TLS_ERROR=already_configured_refuse_overwrite' >&2; exit 1;
}
[ "$(postconf -c "$CONF" -h smtpd_sasl_auth_enable)" != yes ] &&
[ "$(postconf -c "$CONF" -h smtpd_tls_security_level)" != encrypt ] || {
  echo 'AUTH_TLS_ERROR=preexisting_smtp_auth_tls_requires_manual_review' >&2; exit 1;
}
python3 - "$(postconf -c "$CONF" -h inet_interfaces)" <<'PY'
import ipaddress, sys
ips = sys.argv[1].replace(',', ' ').split()
private = [ipaddress.ip_network(x) for x in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
try:
    assert '127.0.0.1' in ips
    for value in ips:
        addr = ipaddress.IPv4Address(value)
        if str(addr) != '127.0.0.1' and not any(addr in net for net in private):
            raise ValueError()
except (ValueError, AssertionError):
    raise SystemExit('AUTH_TLS_ERROR=private_listener_required')
PY
# RHEL Enforcing cannot safely reuse default queue/socket labels for custom
# instances without a separately reviewed SELinux labeling plan.
if [ "$(getenforce 2>/dev/null || true)" = Enforcing ]; then
  echo 'AUTH_TLS_SELINUX=enforcing_manual_queue_socket_review_required'
  echo 'AUTH_TLS_ERROR=selinux_enforcing_not_verified' >&2
  exit 3
fi
for source in "$CERT" "$KEY" "$HASHFILE"; do
  [ -f "$source" ] && [ -r "$source" ] || {
    echo 'AUTH_TLS_ERROR=missing_credential_file' >&2; exit 1;
  }
done
python3 - "$CERT" "$KEY" "$HASHFILE" "$NAME" <<'PY'
import os, re, stat, subprocess, sys
cert, key, hashes, name = sys.argv[1:]
for filename in (cert, key, hashes):
    s = os.stat(filename)
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022 or s.st_size > 512000:
        raise SystemExit('AUTH_TLS_ERROR=source_must_be_root_owned_regular_nonwritable')
for filename in (key, hashes):
    if os.stat(filename).st_mode & 0o077:
        raise SystemExit('AUTH_TLS_ERROR=key_and_hash_source_require_root_only_permissions')
with open(hashes, 'r', encoding='ascii') as f:
    data = f.read(32769)
if not data or len(data) > 32768 or '\r' in data or '\x00' in data:
    raise SystemExit('AUTH_TLS_ERROR=invalid_hash_file_size_or_newlines')
lines = data.splitlines()
if not 1 <= len(lines) <= 64:
    raise SystemExit('AUTH_TLS_ERROR=one_to_64_hashed_accounts_required')
seen = set()
for line in lines:
    if line.count(':') != 1:
        raise SystemExit('AUTH_TLS_ERROR=invalid_auth_account_record')
    username, hashed = line.split(':', 1)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._@-]{2,63}', username):
        raise SystemExit('AUTH_TLS_ERROR=invalid_auth_username')
    if username.casefold() in seen:
        raise SystemExit('AUTH_TLS_ERROR=duplicate_auth_username')
    seen.add(username.casefold())
    if not re.fullmatch(r'\{SHA512-CRYPT\}\$6\$(?:rounds=[0-9]{3,9}\$)?[A-Za-z0-9./]{8,32}\$[A-Za-z0-9./]{30,128}', hashed):
        raise SystemExit('AUTH_TLS_ERROR=only_doveadm_SHA512_CRYPT_hash_accepted')
check = subprocess.run(['openssl','x509','-in',cert,'-noout','-ext','subjectAltName'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, timeout=10)
if check.returncode or name.lower() not in [
        v.lower() for v in re.findall(r'DNS:([A-Za-z0-9*.-]+)', check.stdout)]:
    raise SystemExit('AUTH_TLS_ERROR=certificate_requires_matching_exact_dns_SAN')
PY
openssl x509 -in "$CERT" -noout -checkend 604800 >/dev/null || {
  echo 'AUTH_TLS_ERROR=server_certificate_expires_within_seven_days' >&2; exit 1;
}
cert_pub="$(openssl x509 -in "$CERT" -pubkey -noout |
  openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)"
key_pub="$(openssl pkey -in "$KEY" -pubout -outform DER 2>/dev/null |
  openssl dgst -sha256)"
[ -n "$cert_pub" ] && [ "$cert_pub" = "$key_pub" ] || {
  echo 'AUTH_TLS_ERROR=certificate_private_key_mismatch' >&2; exit 1;
}
if [ "$MODE" = check ]; then
  echo 'AUTH_TLS_PREFLIGHT=ready'
  echo "AUTH_TLS_CUSTOM_PORT=$PORT"
  echo 'AUTH_TLS_PUBLIC_INTERNET=blocked'
  echo 'AUTH_TLS_CA_TRUST=client_must_verify'
  echo 'AUTH_TLS_APPLIED=no'
  exit 0
fi
id dovecot >/dev/null && id postfix >/dev/null || {
  echo 'AUTH_TLS_ERROR=missing_postfix_or_dovecot_service_account' >&2; exit 1;
}
BEFORE="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf | sha256sum | awk '{print $1}')"
BACKUP="$(mktemp /tmp/lmr365-auth-main.XXXXXXXX)"
cp -p "$CONF/main.cf" "$BACKUP"
STARTED=0
rollback() {
  rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ] && [ "$STARTED" -eq 1 ]; then
    echo 'AUTH_TLS_ROLLBACK=attempted' >&2
    restored=0
    if cp -p "$BACKUP" "$CONF/main.cf"; then
      if postfix -c "$CONF" reload >/dev/null 2>&1; then restored=1; fi
    fi
    systemctl stop linuxmailrelay365-smtp-auth.service >/dev/null 2>&1 || true
    systemctl disable linuxmailrelay365-smtp-auth.service >/dev/null 2>&1 || true
    if [ "$restored" -eq 1 ]; then
      rm -f "$UNIT"
      rm -rf "$AUTH"
      systemctl daemon-reload >/dev/null 2>&1 || true
      rm -f "$BACKUP"
      echo 'AUTH_TLS_ROLLBACK=verified' >&2
    else
      # Preserve both the original configuration and credential directory for
      # manual recovery; do not discard the only known-good snapshot.
      echo "AUTH_TLS_ROLLBACK=manual_restore_required backup=$BACKUP" >&2
      exit "$rc"
    fi
  else
    rm -f "$BACKUP"
  fi
  exit "$rc"
}
trap rollback EXIT
install -d -m 0711 -o root -g root "$AUTH"
STARTED=1
install -d -m 0755 -o root -g root /var/lib/linuxmailrelay365-dovecot
install -o root -g root -m 0644 "$CERT" "$AUTH/fullchain.pem"
install -o root -g postfix -m 0640 "$KEY" "$AUTH/privkey.pem"
install -o root -g dovecot -m 0640 "$HASHFILE" "$AUTH/passwd"
cat > "$AUTH/dovecot.conf" <<'EOF'
# Separate Dovecot 2.3 auth-only instance: no IMAP, POP3 or LMTP listener.
base_dir = /run/linuxmailrelay365-dovecot
state_dir = /var/lib/linuxmailrelay365-dovecot
instance_name = linuxmailrelay365-smtp-auth
protocols =
listen = 127.0.0.1
ssl = no
auth_mechanisms = plain login
auth_failure_delay = 2 secs
auth_verbose = no
auth_debug = no
disable_plaintext_auth = no
passdb {
  driver = passwd-file
  args = /etc/linuxmailrelay365/smtp-auth/passwd
}
userdb {
  driver = static
  args = uid=postfix gid=postfix home=/nonexistent
}
service auth {
  unix_listener /var/spool/linuxmailrelay365-sidecar/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF
chmod 0644 "$AUTH/dovecot.conf"
cat > "$UNIT" <<'EOF'
[Unit]
Description=LinuxMailRelay365 isolated Dovecot SMTP AUTH service
Requires=linuxmailrelay365-sidecar.service
After=linuxmailrelay365-sidecar.service

[Service]
Type=simple
ExecStart=/usr/sbin/dovecot -F -c /etc/linuxmailrelay365/smtp-auth/dovecot.conf
Restart=on-failure
RestartSec=3
RuntimeDirectory=linuxmailrelay365-dovecot
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"
doveconf -c "$AUTH/dovecot.conf" -n >/dev/null
systemctl daemon-reload
systemctl enable --now linuxmailrelay365-smtp-auth.service
systemctl is-active --quiet linuxmailrelay365-smtp-auth.service
# Type=simple may report active before Dovecot finishes creating its socket.
# Bound the wait; never proceed to Postfix until the UNIX socket exists.
socket_ready=0
for attempt in $(seq 1 40); do
  if [ -S "$QUEUE/private/auth" ]; then
    socket_ready=1
    break
  fi
  systemctl is-active --quiet linuxmailrelay365-smtp-auth.service || break
  sleep 0.25
done
if [ "$socket_ready" -ne 1 ]; then
  echo 'AUTH_TLS_ERROR=auth_socket_missing_after_10_seconds' >&2
  exit 1
fi
# Keep the existing client-IP allowlist; require AUTH even for loopback.
# Compatible with Postfix <3.6: mandatory TLS1.2+ via protocol exclusions.
postconf -c "$CONF" -e \
  "smtpd_tls_cert_file = $AUTH/fullchain.pem" \
  "smtpd_tls_key_file = $AUTH/privkey.pem" \
  'smtpd_tls_security_level = encrypt' \
  'smtpd_tls_auth_only = yes' \
  'smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1' \
  'smtpd_tls_mandatory_ciphers = high' \
  'smtpd_sasl_auth_enable = yes' \
  'smtpd_sasl_type = dovecot' \
  'smtpd_sasl_path = private/auth' \
  'smtpd_sasl_security_options = noanonymous' \
  'smtpd_relay_restrictions = permit_sasl_authenticated, reject' \
  'smtpd_recipient_restrictions = permit_sasl_authenticated, reject' \
  'smtpd_client_connection_rate_limit = 20' \
  'smtpd_client_message_rate_limit = 60' \
  'smtpd_client_recipient_rate_limit = 100' \
  'smtpd_error_sleep_time = 2s'
postfix -c "$CONF" check
postfix -c "$CONF" reload
# Handshake only: no authentication credential, recipients, or data submitted.
python3 - "$PORT" <<'PY'
import smtplib, ssl, sys
with smtplib.SMTP('127.0.0.1', int(sys.argv[1]), timeout=12) as smtp:
    code, _ = smtp.ehlo('lmr365-local-check.invalid')
    if code != 250 or not smtp.has_extn('starttls') or smtp.has_extn('auth'):
        raise SystemExit('AUTH_TLS_ERROR=unsafe_pre_tls_ehlo')
    smtp.starttls(context=ssl._create_unverified_context())
    smtp.ehlo('lmr365-local-check.invalid')
    if not smtp.has_extn('auth'):
        raise SystemExit('AUTH_TLS_ERROR=no_auth_after_starttls')
PY
AFTER="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf | sha256sum | awk '{print $1}')"
[ "$BEFORE" = "$AFTER" ] || {
  echo 'AUTH_TLS_ERROR=primary_postfix_changed_during_install' >&2; exit 1;
}
cp -p "$BACKUP" "$AUTH/main.cf.before-auth"
# Installation fingerprint. A future Restore must refuse changes if the
# security configuration or master.cf was modified after this activation.
sha256sum "$CONF/main.cf" | awk '{print $1}' > "$AUTH/main.cf.auth.sha256"
sha256sum "$CONF/master.cf" | awk '{print $1}' > "$AUTH/master.cf.auth.sha256"
chmod 0600 "$AUTH/main.cf.auth.sha256" "$AUTH/master.cf.auth.sha256"
rm -f "$BACKUP"
trap - EXIT
echo 'AUTH_TLS_APPLIED=yes'
echo "AUTH_TLS_CUSTOM_PORT=$PORT"
echo 'AUTH_TLS_STARTTLS_REQUIRED=yes'
echo 'AUTH_TLS_SMTP_AUTH_REQUIRED=yes'
echo 'AUTH_TLS_PUBLIC_INTERNET=blocked'
echo 'AUTH_TLS_CA_TRUST=client_must_verify'
echo 'PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes'
echo 'MICROSOFT365_DELIVERY_VERIFIED=no'
