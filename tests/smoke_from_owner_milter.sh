#!/usr/bin/env bash
# Disposable GitHub Actions runner ONLY. No SMTP DATA / Microsoft 365 mail.
set -Eeuo pipefail
export LC_ALL=C
[ "$GITHUB_ACTIONS" = true ] && [ -n "$RUNNER_TEMP" ] || exit 2
[ "$#" -eq 1 ] || exit 2
PORT="$1"
[[ "$PORT" =~ ^[0-9]{4,5}$ ]] || exit 2
CONF=/etc/linuxmailrelay365/sidecar-postfix
ENGINE=/root/linuxmailrelay365-from-owner-ci.py
OWNER=/root/linuxmailrelay365-from-owner-ci.txt
INSTALL=linux/install-sidecar-from-guard.sh
ROUTE=linux/manage-sidecar-eop-route.py
SOCKET=/run/linuxmailrelay365-from-guard/from-guard.sock
PRIMARY="$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)"
MAIN="$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')"
MASTER="$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')"
sudo systemctl is-active --quiet linuxmailrelay365-sidecar.service
sudo systemctl is-active --quiet linuxmailrelay365-smtp-auth.service
sudo install -o root -g root -m 0755 linux/sidecar-from-owner-milter.py "$ENGINE"
echo 'alice@example.org lmr365-ci-b' | sudo tee "$OWNER" >/dev/null
sudo chown root:root "$OWNER"
sudo chmod 0600 "$OWNER"

echo '=== Root-only separate Milter service preview and guarded apply ==='
plan="$(sudo bash "$INSTALL" --check-only --smtp-port "$PORT" \
  --owner-file "$OWNER" --engine-file "$ENGINE")"
printf '%s\n' "$plan" | grep -Fx 'FROM_GUARD_PREFLIGHT=ready'
owner_sha="$(printf '%s\n' "$plan" | sed -n 's/^FROM_GUARD_OWNER_SHA256=//p')"
engine_sha="$(printf '%s\n' "$plan" | sed -n 's/^FROM_GUARD_ENGINE_SHA256=//p')"
[[ "$owner_sha" =~ ^[a-f0-9]{64}$ ]]
[[ "$engine_sha" =~ ^[a-f0-9]{64}$ ]]
if sudo bash "$INSTALL" --apply --smtp-port "$PORT" \
  --owner-file "$OWNER" --engine-file "$ENGINE" \
  --expect-owner-sha256 "$owner_sha" \
  --expect-engine-sha256 "$engine_sha"; then
  echo 'FROM_GUARD_ERROR=missing_confirmation_accepted' >&2; exit 1
fi
sudo bash "$INSTALL" --apply --smtp-port "$PORT" \
  --owner-file "$OWNER" --engine-file "$ENGINE" \
  --expect-owner-sha256 "$owner_sha" \
  --expect-engine-sha256 "$engine_sha" \
  --confirm ACTIVATE_PRIVATE_FROM_OWNER_GUARD |
  grep -Fx 'FROM_GUARD_SERVICE=active'
sudo test -S "$SOCKET"
sudo systemctl is-active --quiet linuxmailrelay365-from-guard.service
test -z "$(sudo postconf -c "$CONF" -h smtpd_milters)"
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$PRIMARY"

echo '=== Review, apply and verify private Connector header protection ==='
# Synthetic Connector attestation only. No real Microsoft 365 permission or DATA.
args=(--smtp-port "$PORT" --mode connector
  --mx-host example-org.mail.protection.outlook.com
  --sender alerts@example.org --recipient-domain example.org
  --sender-policy preserve-domain --sender-owner-file "$OWNER"
  --public-ip 8.8.8.8)
preview="$(sudo python3 "$ROUTE" --check-only "${args[@]}")"
printf '%s\n' "$preview" | grep -Fx 'EOP_ROUTE_PREFLIGHT=ready'
printf '%s\n' "$preview" | grep -Fx 'EOP_ROUTE_HEADER_FROM_MATCH_VERIFIED=guard_ready_not_live_delivery'
main_sha="$(printf '%s\n' "$preview" | sed -n 's/^EOP_ROUTE_MAIN_SHA256=//p')"
reviewed_owner="$(printf '%s\n' "$preview" | sed -n 's/^EOP_ROUTE_OWNER_FILE_SHA256=//p')"
test "$reviewed_owner" = "$owner_sha"
sudo python3 "$ROUTE" --apply "${args[@]}" \
  --expect-main-sha256 "$main_sha" --expect-owner-sha256 "$reviewed_owner" \
  --confirm DEPLOY_PRIVATE_EOP_ROUTE \
  --connector-attestation TENANT_CONNECTOR_CHECKED |
  grep -Fx 'EOP_ROUTE_APPLIED=yes'
test "$(sudo postconf -c "$CONF" -h smtpd_milters)" = "unix:$SOCKET"
test "$(sudo postconf -c "$CONF" -h milter_default_action)" = tempfail
test -z "$(sudo postconf -c "$CONF" -h authorized_submit_users)"
sudo systemctl is-active --quiet linuxmailrelay365-from-guard.service
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$PRIMARY"

echo '=== Verify independent root-only DR archive includes service, script, owner policy ==='
backup="$(sudo python3 linux/sidecar-config-recovery.py --backup)"
printf '%s\n' "$backup" | grep -Fx 'SIDECAR_BACKUP_STATUS=verified_config_only_no_queue'
backup_id="$(printf '%s\n' "$backup" | sed -n 's/^SIDECAR_BACKUP_ID=//p')"
[[ "$backup_id" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$ ]]
sudo python3 linux/sidecar-config-recovery.py --verify "$backup_id" |
  grep -Fx 'SIDECAR_BACKUP_STATUS=verified_config_only_no_queue'
sudo python3 - "$backup_id" <<'PY'
import json, pathlib, sys
folder=pathlib.Path("/var/backups/linuxmailrelay365-sidecar") / sys.argv[1]
doc=json.loads((folder/"manifest.json").read_text(encoding="utf-8"))
paths={row["path"] for row in doc["entries"]}
required={
    "etc/linuxmailrelay365/sidecar-postfix/eop-from-owners.tsv",
    "etc/systemd/system/linuxmailrelay365-from-guard.service",
    "usr/local/libexec/linuxmailrelay365-from-owner-milter.py",
}
assert required.issubset(paths)
assert not any(s.startswith("etc/postfix/") for s in paths)
assert not any(s.startswith("var/spool/") for s in paths)
print("FROM_GUARD_SCOPED_DR_ARCHIVE=PASS")
PY

echo '=== Real Unix Milter callbacks; reject cross-account RFC5322 From ==='
sudo python3 - "$SOCKET" <<'PY'
import socket,struct,sys
endpoint=sys.argv[1]
def try_header(env, header_from):
    conn=socket.socket(socket.AF_UNIX)
    conn.settimeout(5)
    conn.connect(endpoint)
    def exact(n):
        result=b''
        while len(result)<n:
            buf=conn.recv(n-len(result))
            if not buf: raise AssertionError('milter_socket_disconnected')
            result+=buf
        return result
    def call(code,payload=b'',reply=True):
        data=code+payload
        conn.sendall(struct.pack('!I',len(data))+data)
        if not reply: return None
        count=struct.unpack('!I',exact(4))[0]
        if not 1<=count<=512: raise AssertionError('unsafe_response')
        return exact(count)
    assert call(b'O',struct.pack('!III',6,0,0))[0:1]==b'O'
    assert call(b'C',b'client.example.org\x00')==b'c'
    call(b'D',b'Mauth_authen\x00lmr365-ci-b\x00auth_type\x00PLAIN\x00',False)
    assert call(b'M',('<'+env+'>\x00').encode('ascii'))==b'c'
    assert call(b'R',b'<recipient@example.org>\x00')==b'c'
    assert call(b'T')==b'c'
    assert call(b'L',b'From\x00'+header_from.encode('ascii')+b'\x00')==b'c'
    result=call(b'N')
    conn.close()
    return result
assert try_header('alice@example.org','alice@example.org')==b'c'
assert try_header('alice@example.org','billing@example.org')==b'r'
print('FROM_GUARD_LIVE_SOCKET_CROSS_SENDER_REJECT=PASS')
print('SMTP_MESSAGE_DATA_SENT=no')
PY

echo '=== Revert isolated EOP route; primary untouched ==='
status="$(sudo python3 "$ROUTE" --status --smtp-port "$PORT")"
active_sha="$(printf '%s\n' "$status" |
  sed -n 's/^EOP_ROUTE_CURRENT_MAIN_SHA256=//p')"
[[ "$active_sha" =~ ^[a-f0-9]{64}$ ]]
sudo python3 "$ROUTE" --restore --smtp-port "$PORT" \
  --expect-main-sha256 "$active_sha" \
  --confirm RESTORE_PRIVATE_EOP_ROUTE |
  grep -Fx 'EOP_ROUTE_RESTORED=yes'
test "$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$MAIN"
test "$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')" = "$MASTER"
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$PRIMARY"
test -z "$(sudo postconf -c "$CONF" -h smtpd_milters)"
echo 'FROM_GUARD_REAL_POSTFIX_EOP_ROUTE_SMOKE=PASS'
echo 'MICROSOFT365_DELIVERY_VERIFIED=no'
