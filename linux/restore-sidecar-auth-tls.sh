#!/usr/bin/env bash
# Restore the ORIGINAL trusted-network-only isolated Postfix configuration.
# SECURITY DOWNGRADE: existing clients will no longer require STARTTLS/AUTH.
# Never modifies primary Postfix or mail queue, SELinux, NAT, firewall or DNS.
set -Eeuo pipefail
umask 077
export LC_ALL=C
CONF=/etc/linuxmailrelay365/sidecar-postfix
AUTH=/etc/linuxmailrelay365/smtp-auth
UNIT=/etc/systemd/system/linuxmailrelay365-smtp-auth.service
QUEUE=/var/spool/linuxmailrelay365-sidecar
ARCHIVE_BASE=/var/lib/linuxmailrelay365-sidecar-auth-recovery
LOCK=/run/linuxmailrelay365-sidecar-auth.lock
MODE=check PORT='' EXPECT='' CONFIRM=''
usage() {
  echo 'Usage: restore-sidecar-auth-tls.sh --check-only --smtp-port N'
  echo '       restore-sidecar-auth-tls.sh --restore --smtp-port N --expect-main-sha256 HEX --confirm RESTORE_TRUSTED_NETWORK_SMTP'
  echo 'WARNING: Restores the previous PRIVATE / trusted-CIDR SMTP mode WITHOUT SMTP AUTH or mandatory STARTTLS.'
  echo 'An immutable-by-convention root-only archive of the previous authenticated configuration will be kept for manual recovery.'
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check-only) MODE=check; shift ;;
    --restore) MODE=restore; shift ;;
    --smtp-port) PORT="$2"; shift 2 ;;
    --expect-main-sha256) EXPECT="$2"; shift 2 ;;
    --confirm) CONFIRM="$2"; shift 2 ;;
    --self-test) echo 'AUTH_TLS_RESTORE_ARGUMENT_PARSER=available'; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo 'AUTH_TLS_RESTORE_ERROR=unsupported_argument' >&2; exit 2 ;;
  esac
done
command -v python3 >/dev/null || {
  echo 'AUTH_TLS_RESTORE_ERROR=python3_missing' >&2; exit 2;
}
python3 - "$PORT" "$MODE" "$EXPECT" <<'PY'
import re, sys
port, mode, expect = sys.argv[1:]
if not re.fullmatch(r'[1-9][0-9]{3,4}', port) or not (1024 <= int(port) <= 65535):
    raise SystemExit('AUTH_TLS_RESTORE_ERROR=invalid_custom_smtp_port')
if mode == 'restore' and not re.fullmatch(r'[a-f0-9]{64}', expect):
    raise SystemExit('AUTH_TLS_RESTORE_ERROR=expected_main_sha256_required')
if mode != 'restore' and expect:
    raise SystemExit('AUTH_TLS_RESTORE_ERROR=unexpected_expected_sha')
PY
if [ "$MODE" = restore ] && [ "$CONFIRM" != RESTORE_TRUSTED_NETWORK_SMTP ]; then
  echo 'AUTH_TLS_RESTORE_ERROR=explicit_security_downgrade_confirmation_required' >&2
  exit 2
fi
[ "$(id -u)" -eq 0 ] || { echo 'AUTH_TLS_RESTORE_ERROR=root_required' >&2; exit 1; }
for cmd in postfix postconf systemctl sha256sum python3 flock cp mv mktemp; do
  command -v "$cmd" >/dev/null || {
    echo "AUTH_TLS_RESTORE_ERROR=missing_$cmd" >&2; exit 1;
  }
done
if [ "$MODE" = restore ]; then
  exec 9>"$LOCK"
  flock -n 9 || { echo 'AUTH_TLS_RESTORE_ERROR=concurrent_change_blocked' >&2; exit 1; }
fi
for item in /etc/postfix/main.cf /etc/postfix/master.cf "$CONF/main.cf" \
            "$CONF/master.cf" "$CONF/smtp-port" "$AUTH/main.cf.before-auth" \
            "$AUTH/main.cf.auth.sha256" "$AUTH/master.cf.auth.sha256" "$UNIT"; do
  [ -f "$item" ] && [ ! -L "$item" ] || {
    echo 'AUTH_TLS_RESTORE_ERROR=required_file_missing_or_symlink' >&2; exit 1;
  }
done
[ -d "$AUTH" ] && [ ! -L "$AUTH" ] && [ -d "$QUEUE" ] || {
  echo 'AUTH_TLS_RESTORE_ERROR=sidecar_auth_or_queue_missing' >&2; exit 1;
}
systemctl is-active --quiet linuxmailrelay365-sidecar.service &&
systemctl is-active --quiet linuxmailrelay365-smtp-auth.service || {
  echo 'AUTH_TLS_RESTORE_ERROR=isolated_postfix_or_auth_not_running' >&2; exit 1;
}
[ "$(cat "$CONF/smtp-port")" = "$PORT" ] || {
  echo 'AUTH_TLS_RESTORE_ERROR=installed_custom_port_mismatch' >&2; exit 1;
}
[ "$(postconf -c "$CONF" -h queue_directory)" = "$QUEUE" ] &&
[ "$(postconf -c "$CONF" -h smtpd_sasl_auth_enable)" = yes ] &&
[ "$(postconf -c "$CONF" -h smtpd_tls_security_level)" = encrypt ] &&
[ "$(postconf -c "$CONF" -h smtpd_tls_auth_only)" = yes ] || {
  echo 'AUTH_TLS_RESTORE_ERROR=unexpected_active_authentication_policy' >&2; exit 1;
}
# Root-owned snapshots and manifests only; fail closed on unrecognized baseline.
python3 - "$AUTH" "$CONF" "$UNIT" "$QUEUE" "$PORT" <<'PY'
import ipaddress, os, pathlib, re, stat, sys
auth, conf, unit, queue, port = [pathlib.Path(v) for v in sys.argv[1:]]
def secure(path):
    mode = path.lstat()
    return mode.st_uid == 0 and not (mode.st_mode & 0o022)
if not secure(auth) or not secure(conf) or not secure(unit):
    raise SystemExit('AUTH_TLS_RESTORE_ERROR=unsafe_directory_or_unit_permissions')
for name in ('main.cf.before-auth', 'main.cf.auth.sha256', 'master.cf.auth.sha256'):
    p = auth / name
    m = p.lstat()
    if not stat.S_ISREG(m.st_mode) or not secure(p) or m.st_size > 32768:
        raise SystemExit('AUTH_TLS_RESTORE_ERROR=invalid_root_owned_snapshot_or_manifest')
data = (auth / 'main.cf.before-auth').read_text(encoding='ascii')
raw = {}
for line in data.splitlines():
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    m = re.fullmatch(r'([a-z][a-z0-9_]*)\s*=\s*(.*)', line)
    if not m or m.group(1) in raw:
        raise SystemExit('AUTH_TLS_RESTORE_ERROR=backup_has_unrecognized_or_duplicate_settings')
    raw[m.group(1)] = m.group(2).strip()
required = {
    'queue_directory': str(queue),
    'inet_protocols': 'ipv4',
    'smtpd_client_restrictions': 'permit_mynetworks, reject',
    'smtpd_relay_restrictions': 'permit_mynetworks, reject_unauth_destination',
    'smtpd_recipient_restrictions': 'permit_mynetworks, reject_unauth_destination',
    'default_transport': 'm365xoauth2:',
    'relay_transport': 'm365xoauth2:',
    'local_transport': 'error:LocalDeliveryDisabled',
    'mydestination': '',
    'relay_domains': '',
}
for key, value in required.items():
    if raw.get(key) != value:
        raise SystemExit('AUTH_TLS_RESTORE_ERROR=original_backup_does_not_match_private_policy')
if raw.get('smtpd_sasl_auth_enable') == 'yes' or raw.get('smtpd_tls_security_level') == 'encrypt':
    raise SystemExit('AUTH_TLS_RESTORE_ERROR=backup_not_original_unauthenticated_mode')
allowed = [ipaddress.ip_network(v) for v in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
loop = ipaddress.IPv4Address('127.0.0.1')
try:
    listen = [ipaddress.IPv4Address(v) for v in raw['inet_interfaces'].replace(',',' ').split()]
    networks = [ipaddress.ip_network(v, strict=False) for v in raw['mynetworks'].replace(',',' ').split()]
    if loop not in listen or not networks or not any(loop in n for n in networks):
        raise ValueError()
    if any(x != loop and not any(x in a for a in allowed) for x in listen):
        raise ValueError()
    if any(not isinstance(n, ipaddress.IPv4Network) or not (
           (n.network_address in ipaddress.ip_network('127.0.0.0/8') and n.broadcast_address in ipaddress.ip_network('127.0.0.0/8'))
           or any(n.network_address in a and n.broadcast_address in a for a in allowed)
        ) for n in networks):
        raise ValueError()
except (KeyError, ValueError):
    raise SystemExit('AUTH_TLS_RESTORE_ERROR=backup_contains_untrusted_listener_or_network')
master = (conf / 'master.cf').read_text(encoding='utf-8', errors='replace')
services = [row.split() for row in master.splitlines() if row.strip() and not row.lstrip().startswith('#')]
if len([t for t in services if len(t) > 1 and t[0] == str(port) and t[1] == 'inet']) != 1:
    raise SystemExit('AUTH_TLS_RESTORE_ERROR=custom_port_master_service_mismatch')
PY
# Enforcing hosts are not supported for the matching activation either.
# Do not silently relabel queue/socket or disable enforcement on rollback.
selinux_status="$(getenforce 2>/dev/null || true)"
# If getenforce is missing, inspect the kernel SELinux enforcement flag.
if [ -r /sys/fs/selinux/enforce ] && [ "$(cat /sys/fs/selinux/enforce)" = 1 ]; then
  selinux_status=Enforcing
fi
rhel_like=0
if [ -f /etc/os-release ] &&
   grep -Eq '^ID="?(rhel|ol|rocky|almalinux|centos)"?$' /etc/os-release; then
  rhel_like=1
fi
if [ "$selinux_status" = Enforcing ]; then
  echo 'AUTH_TLS_RESTORE_ERROR=selinux_enforcing_requires_manual_review' >&2
  exit 3
fi
if [ "$selinux_status" = Permissive ] && [ "$rhel_like" -eq 1 ]; then
  echo 'AUTH_TLS_RESTORE_ERROR=rhel_selinux_permissive_policy_not_verified' >&2
  exit 3
fi
case "$selinux_status" in
  Disabled|Permissive) ;;
  *) if [ "$rhel_like" -eq 1 ] || [ -e /etc/selinux/config ] ||
          [ -e /sys/fs/selinux/enforce ]; then
       echo 'AUTH_TLS_RESTORE_ERROR=selinux_status_unknown_manual_review_required' >&2
       exit 3
     fi ;;
esac
read_hash() {
  local value
  value="$(cat "$1")" || return 1
  [[ "$value" =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s' "$value"
}
saved_main="$(read_hash "$AUTH/main.cf.auth.sha256")" &&
saved_master="$(read_hash "$AUTH/master.cf.auth.sha256")" || {
  echo 'AUTH_TLS_RESTORE_ERROR=invalid_auth_fingerprint_files' >&2; exit 1;
}
current_main="$(sha256sum "$CONF/main.cf" | awk '{print $1}')"
current_master="$(sha256sum "$CONF/master.cf" | awk '{print $1}')"
[ "$current_main" = "$saved_main" ] && [ "$current_master" = "$saved_master" ] || {
  echo 'AUTH_TLS_RESTORE_ERROR=isolated_configuration_changed_since_activation' >&2; exit 1;
}
if [ "$MODE" = check ]; then
  echo 'AUTH_TLS_RESTORE_PREFLIGHT=ready'
  echo "AUTH_TLS_RESTORE_CUSTOM_PORT=$PORT"
  echo "AUTH_TLS_RESTORE_CURRENT_MAIN_SHA256=$current_main"
  echo 'AUTH_TLS_RESTORE_TARGET=private_trusted_network_without_auth'
  echo 'AUTH_TLS_RESTORE_SECURITY_DOWNGRADE=yes'
  echo 'AUTH_TLS_RESTORE_PUBLIC_INTERNET=blocked'
  echo 'AUTH_TLS_RESTORED=no'
  echo 'CHANGES_APPLIED=no'
  exit 0
fi
[ "$current_main" = "$EXPECT" ] || {
  echo 'AUTH_TLS_RESTORE_ERROR=operator_reviewed_sha256_no_longer_matches' >&2; exit 1;
}
# Create a root-only off-service archive BEFORE any changes. The archived
# auth directory includes private keys and password HASHES, never expose it.
install -d -o root -g root -m 0700 "$ARCHIVE_BASE"
chmod 0700 "$ARCHIVE_BASE"
ARCHIVE="$(mktemp -d "$ARCHIVE_BASE/recovery.XXXXXXXX")"
chmod 0700 "$ARCHIVE"
cp -p "$CONF/main.cf" "$ARCHIVE/main.cf.auth" &&
cp -p "$CONF/master.cf" "$ARCHIVE/master.cf.auth" &&
cp -p "$UNIT" "$ARCHIVE/linuxmailrelay365-smtp-auth.service" &&
cp -a "$AUTH" "$ARCHIVE/smtp-auth" || {
  echo 'AUTH_TLS_RESTORE_ERROR=backup_not_complete' >&2; exit 1;
}
primary_before="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf | sha256sum | awk '{print $1}')"
CHANGED=0
TEMP=''
rollback() {
  rc=$?
  trap - EXIT
  [ -z "$TEMP" ] || rm -f -- "$TEMP"
  if [ "$rc" -ne 0 ] && [ "$CHANGED" -eq 1 ]; then
    echo 'AUTH_TLS_RESTORE_ROLLBACK=attempted' >&2
    restored=0
    # The backup was copied before any changes and remains root-only.
    if [ ! -d "$AUTH" ]; then
      cp -a "$ARCHIVE/smtp-auth" "$AUTH" || true
    fi
    if [ ! -f "$UNIT" ]; then
      cp -p "$ARCHIVE/linuxmailrelay365-smtp-auth.service" "$UNIT" || true
    fi
    if cp -p "$ARCHIVE/main.cf.auth" "$CONF/main.cf" &&
       systemctl daemon-reload &&
       systemctl enable --now linuxmailrelay365-smtp-auth.service &&
       postfix -c "$CONF" check &&
       postfix -c "$CONF" reload &&
       systemctl is-active --quiet linuxmailrelay365-smtp-auth.service &&
       [ "$(sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$saved_main" ]; then
      restored=1
    fi
    if [ "$restored" -eq 1 ]; then
      echo 'AUTH_TLS_RESTORE_ROLLBACK=verified_auth_restored' >&2
    else
      echo 'AUTH_TLS_RESTORE_ROLLBACK=MANUAL_RECOVERY_REQUIRED' >&2
    fi
  fi
  echo 'AUTH_TLS_RESTORE_RECOVERY_ARCHIVE_SAVED=yes' >&2
  exit "$rc"
}
trap rollback EXIT
# Temp file in same directory keeps replacement of main.cf atomic.
TEMP="$(mktemp "$CONF/main.cf.restore.XXXXXXXX")"
cp -p "$AUTH/main.cf.before-auth" "$TEMP"
CHANGED=1
mv -f -- "$TEMP" "$CONF/main.cf"
TEMP=''
postfix -c "$CONF" check
postfix -c "$CONF" reload
python3 - "$PORT" <<'PY'
import smtplib, sys
with smtplib.SMTP('127.0.0.1', int(sys.argv[1]), timeout=12) as smtp:
    code, _ = smtp.ehlo('lmr365-restore-check.invalid')
    if code != 250 or smtp.has_extn('auth'):
        raise SystemExit('AUTH_TLS_RESTORE_ERROR=postfix_still_advertises_auth')
PY
systemctl disable --now linuxmailrelay365-smtp-auth.service
systemctl is-active --quiet linuxmailrelay365-smtp-auth.service && {
  echo 'AUTH_TLS_RESTORE_ERROR=auth_service_still_running' >&2; exit 1;
}
rm -f -- "$UNIT"
rm -rf -- "$AUTH"
systemctl daemon-reload
[ "$(postconf -c "$CONF" -h smtpd_sasl_auth_enable)" != yes ] &&
[ "$(postconf -c "$CONF" -h smtpd_tls_security_level)" != encrypt ] &&
[ "$(sha256sum "$CONF/master.cf" | awk '{print $1}')" = "$saved_master" ] || {
  echo 'AUTH_TLS_RESTORE_ERROR=restored_postfix_policy_mismatch' >&2; exit 1;
}
primary_after="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf | sha256sum | awk '{print $1}')"
[ "$primary_before" = "$primary_after" ] || {
  echo 'AUTH_TLS_RESTORE_ERROR=primary_postfix_changed_during_restore' >&2; exit 1;
}
CHANGED=0
trap - EXIT
echo 'AUTH_TLS_RESTORED=yes'
echo "AUTH_TLS_RESTORE_CUSTOM_PORT=$PORT"
echo 'AUTH_TLS_RESTORE_TARGET=private_trusted_network_without_auth'
echo 'AUTH_TLS_RESTORE_PUBLIC_INTERNET=blocked'
echo 'PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes'
echo 'AUTH_TLS_RESTORE_RECOVERY_ARCHIVE_SAVED=yes'
echo 'AUTH_TLS_RESTORE_ARCHIVED_CREDENTIALS_REQUIRE_SECURE_RETENTION=yes'
echo 'MICROSOFT365_DELIVERY_VERIFIED=no'
 /etc/os-release; then
  rhel_like=1
fi
if [ "$selinux_status" = Enforcing ]; then
  echo 'AUTH_TLS_RESTORE_ERROR=selinux_enforcing_requires_manual_review' >&2; exit 3
fi
if [ "$selinux_status" = Permissive ] && [ "$rhel_like" -eq 1 ]; then
  echo 'AUTH_TLS_RESTORE_ERROR=rhel_selinux_permissive_policy_not_verified' >&2
  exit 3
fi
case "$selinux_status" in
  Disabled|Permissive) ;;
  *) if [ "$rhel_like" -eq 1 ] || [ -e /etc/selinux/config ] ||
          [ -e /sys/fs/selinux/enforce ]; then
       echo 'AUTH_TLS_RESTORE_ERROR=selinux_status_unknown_manual_review_required' >&2
       exit 3
     fi ;;
esac
read_hash() {
  local value
  value="$(cat "$1")" || return 1
  [[ "$value" =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s' "$value"
}
saved_main="$(read_hash "$AUTH/main.cf.auth.sha256")" &&
saved_master="$(read_hash "$AUTH/master.cf.auth.sha256")" || {
  echo 'AUTH_TLS_RESTORE_ERROR=invalid_auth_fingerprint_files' >&2; exit 1;
}
current_main="$(sha256sum "$CONF/main.cf" | awk '{print $1}')"
current_master="$(sha256sum "$CONF/master.cf" | awk '{print $1}')"
[ "$current_main" = "$saved_main" ] && [ "$current_master" = "$saved_master" ] || {
  echo 'AUTH_TLS_RESTORE_ERROR=isolated_configuration_changed_since_activation' >&2; exit 1;
}
if [ "$MODE" = check ]; then
  echo 'AUTH_TLS_RESTORE_PREFLIGHT=ready'
  echo "AUTH_TLS_RESTORE_CUSTOM_PORT=$PORT"
  echo "AUTH_TLS_RESTORE_CURRENT_MAIN_SHA256=$current_main"
  echo 'AUTH_TLS_RESTORE_TARGET=private_trusted_network_without_auth'
  echo 'AUTH_TLS_RESTORE_SECURITY_DOWNGRADE=yes'
  echo 'AUTH_TLS_RESTORE_PUBLIC_INTERNET=blocked'
  echo 'AUTH_TLS_RESTORED=no'
  echo 'CHANGES_APPLIED=no'
  exit 0
fi
[ "$current_main" = "$EXPECT" ] || {
  echo 'AUTH_TLS_RESTORE_ERROR=operator_reviewed_sha256_no_longer_matches' >&2; exit 1;
}
# Create a root-only off-service archive BEFORE any changes. The archived
# auth directory includes private keys and password HASHES, never expose it.
install -d -o root -g root -m 0700 "$ARCHIVE_BASE"
chmod 0700 "$ARCHIVE_BASE"
ARCHIVE="$(mktemp -d "$ARCHIVE_BASE/recovery.XXXXXXXX")"
chmod 0700 "$ARCHIVE"
cp -p "$CONF/main.cf" "$ARCHIVE/main.cf.auth" &&
cp -p "$CONF/master.cf" "$ARCHIVE/master.cf.auth" &&
cp -p "$UNIT" "$ARCHIVE/linuxmailrelay365-smtp-auth.service" &&
cp -a "$AUTH" "$ARCHIVE/smtp-auth" || {
  echo 'AUTH_TLS_RESTORE_ERROR=backup_not_complete' >&2; exit 1;
}
primary_before="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf | sha256sum | awk '{print $1}')"
CHANGED=0
TEMP=''
rollback() {
  rc=$?
  trap - EXIT
  [ -z "$TEMP" ] || rm -f -- "$TEMP"
  if [ "$rc" -ne 0 ] && [ "$CHANGED" -eq 1 ]; then
    echo 'AUTH_TLS_RESTORE_ROLLBACK=attempted' >&2
    restored=0
    # The backup was copied before any changes and remains root-only.
    if [ ! -d "$AUTH" ]; then
      cp -a "$ARCHIVE/smtp-auth" "$AUTH" || true
    fi
    if [ ! -f "$UNIT" ]; then
      cp -p "$ARCHIVE/linuxmailrelay365-smtp-auth.service" "$UNIT" || true
    fi
    if cp -p "$ARCHIVE/main.cf.auth" "$CONF/main.cf" &&
       systemctl daemon-reload &&
       systemctl enable --now linuxmailrelay365-smtp-auth.service &&
       postfix -c "$CONF" check &&
       postfix -c "$CONF" reload &&
       systemctl is-active --quiet linuxmailrelay365-smtp-auth.service &&
       [ "$(sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$saved_main" ]; then
      restored=1
    fi
    if [ "$restored" -eq 1 ]; then
      echo 'AUTH_TLS_RESTORE_ROLLBACK=verified_auth_restored' >&2
    else
      echo 'AUTH_TLS_RESTORE_ROLLBACK=MANUAL_RECOVERY_REQUIRED' >&2
    fi
  fi
  echo 'AUTH_TLS_RESTORE_RECOVERY_ARCHIVE_SAVED=yes' >&2
  exit "$rc"
}
trap rollback EXIT
# Temp file in same directory keeps replacement of main.cf atomic.
TEMP="$(mktemp "$CONF/main.cf.restore.XXXXXXXX")"
cp -p "$AUTH/main.cf.before-auth" "$TEMP"
CHANGED=1
mv -f -- "$TEMP" "$CONF/main.cf"
TEMP=''
postfix -c "$CONF" check
postfix -c "$CONF" reload
python3 - "$PORT" <<'PY'
import smtplib, sys
with smtplib.SMTP('127.0.0.1', int(sys.argv[1]), timeout=12) as smtp:
    code, _ = smtp.ehlo('lmr365-restore-check.invalid')
    if code != 250 or smtp.has_extn('auth'):
        raise SystemExit('AUTH_TLS_RESTORE_ERROR=postfix_still_advertises_auth')
PY
systemctl disable --now linuxmailrelay365-smtp-auth.service
systemctl is-active --quiet linuxmailrelay365-smtp-auth.service && {
  echo 'AUTH_TLS_RESTORE_ERROR=auth_service_still_running' >&2; exit 1;
}
rm -f -- "$UNIT"
rm -rf -- "$AUTH"
systemctl daemon-reload
[ "$(postconf -c "$CONF" -h smtpd_sasl_auth_enable)" != yes ] &&
[ "$(postconf -c "$CONF" -h smtpd_tls_security_level)" != encrypt ] &&
[ "$(sha256sum "$CONF/master.cf" | awk '{print $1}')" = "$saved_master" ] || {
  echo 'AUTH_TLS_RESTORE_ERROR=restored_postfix_policy_mismatch' >&2; exit 1;
}
primary_after="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf | sha256sum | awk '{print $1}')"
[ "$primary_before" = "$primary_after" ] || {
  echo 'AUTH_TLS_RESTORE_ERROR=primary_postfix_changed_during_restore' >&2; exit 1;
}
CHANGED=0
trap - EXIT
echo 'AUTH_TLS_RESTORED=yes'
echo "AUTH_TLS_RESTORE_CUSTOM_PORT=$PORT"
echo 'AUTH_TLS_RESTORE_TARGET=private_trusted_network_without_auth'
echo 'AUTH_TLS_RESTORE_PUBLIC_INTERNET=blocked'
echo 'PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes'
echo 'AUTH_TLS_RESTORE_RECOVERY_ARCHIVE_SAVED=yes'
echo 'AUTH_TLS_RESTORE_ARCHIVED_CREDENTIALS_REQUIRE_SECURE_RETENTION=yes'
echo 'MICROSOFT365_DELIVERY_VERIFIED=no'
