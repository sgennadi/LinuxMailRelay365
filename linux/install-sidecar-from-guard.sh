#!/usr/bin/env bash
# Independent Postfix SMTP header From owner guard (preview / explicit opt-in).
# Does NOT configure Postfix smtpd_milters: the separate EOP route deployer
# activates that setting only after verifying this guard is live and pinned.
# Never installs packages or changes primary MTA /etc/postfix, TCP25 or queues.
set -Eeuo pipefail
umask 077
export LC_ALL=C
CONF=/etc/linuxmailrelay365/sidecar-postfix
AUTH=/etc/linuxmailrelay365/smtp-auth
GUARD=/usr/local/libexec/linuxmailrelay365-from-owner-milter.py
POLICY="$CONF/eop-from-owners.tsv"
UNIT=/etc/systemd/system/linuxmailrelay365-from-guard.service
SERVICE=linuxmailrelay365-from-guard.service
SOCKET=/run/linuxmailrelay365-from-guard/from-guard.sock
USER_NAME=linuxmailrelay365-fromguard
ACTION=check PORT=0 OWNERS='' ENGINE='' EXPECT_OWNER='' EXPECT_ENGINE='' CONFIRM=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check-only) ACTION=check; shift ;;
    --apply) ACTION=apply; shift ;;
    --smtp-port) PORT="$2"; shift 2 ;;
    --owner-file) OWNERS="$2"; shift 2 ;;
    --engine-file) ENGINE="$2"; shift 2 ;;
    --expect-owner-sha256) EXPECT_OWNER="$2"; shift 2 ;;
    --expect-engine-sha256) EXPECT_ENGINE="$2"; shift 2 ;;
    --confirm) CONFIRM="$2"; shift 2 ;;
    *) echo 'FROM_GUARD_ERROR=unknown_argument' >&2; exit 2 ;;
  esac
done
if [ "$(id -u)" != 0 ]; then
  echo 'FROM_GUARD_ERROR=root_required' >&2; exit 2
fi
case "$PORT" in
  ''|*[!0-9]*) echo 'FROM_GUARD_ERROR=invalid_custom_port' >&2; exit 2 ;;
esac
if [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  echo 'FROM_GUARD_ERROR=invalid_custom_port' >&2; exit 2
fi
for path in "$OWNERS" "$ENGINE"; do
  case "$path" in
    /*) ;;
    *) echo 'FROM_GUARD_ERROR=absolute_paths_required' >&2; exit 2 ;;
  esac
  case "$path" in
    *'..'*|*'//'*) echo 'FROM_GUARD_ERROR=unsafe_path' >&2; exit 2 ;;
  esac
done
for tool in systemctl postconf python3 sha256sum stat install getent flock; do
  command -v "$tool" >/dev/null || {
    echo 'FROM_GUARD_ERROR=missing_required_utility' >&2; exit 2;
  }
done
[ -f "$CONF/main.cf" ] && [ -f "$CONF/smtp-port" ] &&
[ -f "$AUTH/passwd" ] || {
  echo 'FROM_GUARD_ERROR=isolated_postfix_auth_missing' >&2; exit 2;
}
[ "$(cat "$CONF/smtp-port")" = "$PORT" ] || {
  echo 'FROM_GUARD_ERROR=port_mismatch' >&2; exit 2;
}
[ "$(postconf -c "$CONF" -h smtpd_sasl_auth_enable)" = yes ] &&
[ "$(postconf -c "$CONF" -h smtpd_tls_security_level)" = encrypt ] &&
[ "$(postconf -c "$CONF" -h smtpd_tls_auth_only)" = yes ] || {
  echo 'FROM_GUARD_ERROR=isolated_auth_tls_required' >&2; exit 2;
}
systemctl is-active --quiet linuxmailrelay365-sidecar.service &&
systemctl is-active --quiet linuxmailrelay365-smtp-auth.service || {
  echo 'FROM_GUARD_ERROR=dedicated_smtp_auth_service_inactive' >&2; exit 2;
}
[ -z "$(postconf -c "$CONF" -h smtpd_milters)" ] &&
[ -z "$(postconf -c "$CONF" -h non_smtpd_milters)" ] &&
[ -z "$(postconf -c "$CONF" -h smtpd_milter_maps)" ] || {
  echo 'FROM_GUARD_ERROR=existing_milter_config_requires_review' >&2; exit 2;
}
[ ! -e /var/lib/linuxmailrelay365-public-smtp/active.json ] &&
[ ! -L /var/lib/linuxmailrelay365-public-smtp/active.json ] &&
[ ! -e /var/lib/linuxmailrelay365-eop-route-recovery/active.json ] &&
[ ! -L /var/lib/linuxmailrelay365-eop-route-recovery/active.json ] || {
  echo 'FROM_GUARD_ERROR=disable_active_public_eop_first' >&2; exit 2;
}
[ ! -e "$UNIT" ] && [ ! -L "$UNIT" ] &&
[ ! -e "$POLICY" ] && [ ! -L "$POLICY" ] &&
[ ! -e "$GUARD" ] && [ ! -L "$GUARD" ] || {
  echo 'FROM_GUARD_ERROR=guard_already_installed' >&2; exit 2;
}
[ -f "$OWNERS" ] && [ ! -L "$OWNERS" ] &&
[ -f "$ENGINE" ] && [ ! -L "$ENGINE" ] || {
  echo 'FROM_GUARD_ERROR=invalid_source_or_engine_file' >&2; exit 2;
}
OWNER_SHA="$(sha256sum "$OWNERS" | cut -d ' ' -f 1)"
ENGINE_SHA="$(sha256sum "$ENGINE" | cut -d ' ' -f 1)"
python3 - "$OWNERS" "$AUTH/passwd" "$ENGINE" <<'PY'
import importlib.util, os, pathlib, stat, sys
owners, auth, script = map(pathlib.Path, sys.argv[1:])
for source in (owners,auth,script):
    st=source.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or \
            st.st_mode & 0o022 or st.st_nlink != 1:
        raise SystemExit('FROM_GUARD_ERROR=untrusted_input_file')
if stat.S_IMODE(owners.stat().st_mode) != 0o600 or \
        owners.stat().st_size > 16384:
    raise SystemExit('FROM_GUARD_ERROR=owner_source_must_be_root_0600')
spec=importlib.util.spec_from_file_location("lmr365_header_guard",str(script))
engine=importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)
record=engine.parse_owners(owners.read_bytes())
logins=set()
for raw in auth.read_text(encoding='ascii').splitlines():
    if ':' not in raw:
        raise SystemExit('FROM_GUARD_ERROR=malformed_smtp_auth_account')
    logins.add(raw.split(':',1)[0].lower())
if not record or set(record.values()) - logins:
    raise SystemExit('FROM_GUARD_ERROR=unknown_smtp_auth_owner')
print('FROM_GUARD_ACCOUNT_MAPPING_COUNT='+str(len(record)))
print('FROM_GUARD_SOURCE_VALIDATED=yes')
PY
if [ "$ACTION" = check ]; then
  [ -z "$EXPECT_OWNER" ] && [ -z "$EXPECT_ENGINE" ] &&
  [ -z "$CONFIRM" ] || {
    echo 'FROM_GUARD_ERROR=unexpected_mutating_arguments' >&2; exit 2;
  }
  echo "FROM_GUARD_OWNER_SHA256=$OWNER_SHA"
  echo "FROM_GUARD_ENGINE_SHA256=$ENGINE_SHA"
  echo 'FROM_GUARD_PREFLIGHT=ready'
  echo 'CHANGES_APPLIED=no'
  echo 'FROM_GUARD_POSTFIX_ROUTING_CHANGED=no'
  exit 0
fi
[[ "$EXPECT_OWNER" =~ ^[a-f0-9]{64}$ ]] &&
[[ "$EXPECT_ENGINE" =~ ^[a-f0-9]{64}$ ]] &&
[ "$OWNER_SHA" = "$EXPECT_OWNER" ] &&
[ "$ENGINE_SHA" = "$EXPECT_ENGINE" ] &&
[ "$CONFIRM" = ACTIVATE_PRIVATE_FROM_OWNER_GUARD ] || {
  echo 'FROM_GUARD_ERROR=reviewed_hash_and_confirmation_required' >&2; exit 2;
}
# Do not silently make a production-ready claim on untested SELinux labels.
if command -v getenforce >/dev/null; then
  selinux="$(getenforce 2>/dev/null || echo Unknown)"
  if [ "$selinux" != Disabled ]; then
    echo 'FROM_GUARD_ERROR=selinux_policy_not_live_verified' >&2; exit 2
  fi
fi
exec 9>/run/linuxmailrelay365-sidecar-auth.lock
flock -n 9 || {
  echo 'FROM_GUARD_ERROR=concurrent_sidecar_operation_blocked' >&2; exit 2
}
[ ! -e "$UNIT" ] && [ ! -e "$POLICY" ] && [ ! -e "$GUARD" ] || {
  echo 'FROM_GUARD_ERROR=guard_installed_during_preflight' >&2; exit 2
}
[ "$OWNER_SHA" = "$(sha256sum "$OWNERS" | cut -d ' ' -f 1)" ] &&
[ "$ENGINE_SHA" = "$(sha256sum "$ENGINE" | cut -d ' ' -f 1)" ] || {
  echo 'FROM_GUARD_ERROR=source_changed_after_preview' >&2; exit 2
}
command -v useradd >/dev/null || {
  echo 'FROM_GUARD_ERROR=useradd_missing' >&2; exit 2
}
[ -n "$(getent group postfix)" ] || {
  echo 'FROM_GUARD_ERROR=postfix_group_missing' >&2; exit 2;
}
if getent passwd "$USER_NAME" >/dev/null; then
  [ "$(id -u "$USER_NAME")" -ne 0 ] || {
    echo 'FROM_GUARD_ERROR=unsafe_service_identity' >&2; exit 2;
  }
else
  NOLOGIN="$(command -v nologin)"
  useradd --system --no-create-home --home-dir /nonexistent \
    --shell "$NOLOGIN" "$USER_NAME"
fi

created=0
rollback() {
  rc=$?
  trap - ERR
  if [ "$created" = 1 ]; then
    systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
    rm -f -- "$UNIT" "$POLICY" "$GUARD"
    systemctl daemon-reload >/dev/null 2>&1 || true
    echo 'FROM_GUARD_ROLLBACK=staged_service_removed' >&2
  fi
  exit "$rc"
}
trap rollback ERR
created=1
install -o root -g root -m 0755 "$ENGINE" "$GUARD"
install -o root -g postfix -m 0640 "$OWNERS" "$POLICY"
[ "$(sha256sum "$GUARD" | cut -d ' ' -f 1)" = "$ENGINE_SHA" ]
[ "$(sha256sum "$POLICY" | cut -d ' ' -f 1)" = "$OWNER_SHA" ]
cat > "$UNIT" <<EOF
[Unit]
Description=LinuxMailRelay365 private RFC5322 From ownership guard
Requires=linuxmailrelay365-sidecar.service
After=linuxmailrelay365-sidecar.service
[Service]
Type=simple
User=$USER_NAME
Group=postfix
UMask=0007
RuntimeDirectory=linuxmailrelay365-from-guard
RuntimeDirectoryMode=0750
ExecStart=/usr/bin/python3 $GUARD --serve --expected-map-sha256 $OWNER_SHA
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX
[Install]
# When the independent Postfix unit is stopped/restarted, systemd can
# stop its dependent guard. Pull it back in every time the isolated
# Postfix service starts; keep the SMTP listener in its existing chroot
# configuration and retain fail-closed Milter handling.
WantedBy=multi-user.target linuxmailrelay365-sidecar.service
EOF
chmod 0644 "$UNIT"
chown root:root "$UNIT"
systemctl daemon-reload
systemctl enable --now "$SERVICE"
systemctl is-active --quiet "$SERVICE"
ready=0
for attempt in $(seq 1 40); do
  if [ -S "$SOCKET" ]; then ready=1; break; fi
  systemctl is-active --quiet "$SERVICE"
  sleep 0.25
done
[ "$ready" = 1 ] || {
  echo 'FROM_GUARD_ERROR=socket_not_ready' >&2; false;
}
python3 - "$SOCKET" <<'PY'
import socket,struct,sys
s=socket.socket(socket.AF_UNIX)
s.settimeout(3)
s.connect(sys.argv[1])
payload=b'O'+struct.pack('!III',6,0,0)
s.sendall(struct.pack('!I',len(payload))+payload)
size=struct.unpack('!I',s.recv(4))[0]
assert size == 13,'milter_handshake_wrong_size'
frame=b''
while len(frame)<size:
    chunk=s.recv(size-len(frame))
    if not chunk: raise RuntimeError('milter_handshake_short')
    frame+=chunk
assert frame[0:1] == b'O', 'milter_negotiation_failed'
s.close()
print('FROM_GUARD_PRIVATE_SOCKET_NEGOTIATED=yes')
PY
created=0
trap - ERR
echo 'FROM_GUARD_SERVICE=active'
echo 'FROM_GUARD_POLICY_PINNED_SHA256=yes'
echo 'FROM_GUARD_POSTFIX_ROUTING_CHANGED=no'
echo 'EOP_ROUTE_FROM_HEADER_PROTECTED=not_until_separate_approved_eop_route_apply'
