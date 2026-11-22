#!/usr/bin/env bash
# Disposable Rocky KVM guest only. Synthetic source tests actual systemd
# lifecycle, not real SMTP AUTH, OAuth or Microsoft 365 delivery.
set -Eeuo pipefail
test "$GITHUB_ACTIONS" = true
test "$(id -u)" = 0
test "$(cat /proc/1/comm)" = systemd
test "$(getenforce)" = Enforcing
source /etc/os-release
test "$ID:$VERSION_ID" = rocky:9.9
root=/usr/local/libexec/linuxmailrelay365-multi-oauth
parent=/etc/linuxmailrelay365
conf="$parent/sidecar-postfix"
backup=/var/backups/linuxmailrelay365-multi-oauth
manager="$root/manage-multi-mailbox-proof-timer.py"
proof="$parent/oauth-ingress-proof.json"
service=/etc/systemd/system/linuxmailrelay365-multi-proof.service
timer=/etc/systemd/system/linuxmailrelay365-multi-proof.timer
state=/var/lib/linuxmailrelay365-multi-proof-timer
lock=/run/linuxmailrelay365-sidecar-auth.lock
for item in "$root" "$parent" "$backup" "$service" "$timer" "$state" "$lock"; do
    if test -e "$item" || test -L "$item"; then
        echo 'LMR365_VM_TIMER_REFUSED=existing_state' >&2
        exit 1
    fi
done
if getent group m365mailer >/dev/null; then
    echo 'LMR365_VM_TIMER_REFUSED=existing_group' >&2
    exit 1
fi
groupadd --system m365mailer
install -d -o root -g root -m 0755 "$root" "$conf"
install -d -o root -g root -m 0700 "$backup"
install -o root -g root -m 0644 /home/ci/lmr365-proof-timer-manager.py "$manager"
python3 - <<'PYFIXTURE'
import grp
import hashlib
import json
from pathlib import Path
root = Path("/usr/local/libexec/linuxmailrelay365-multi-oauth")
conf = Path("/etc/linuxmailrelay365/sidecar-postfix")
mappath = Path("/etc/linuxmailrelay365/oauth-runtime-senders.tsv")
fake = """import argparse,grp,hashlib,json,os,time
from pathlib import Path
MAP=Path('/etc/linuxmailrelay365/oauth-runtime-senders.tsv')
PROOF=Path('/etc/linuxmailrelay365/oauth-ingress-proof.json')
def inspect(h):
    if hashlib.sha256(MAP.read_bytes()).hexdigest()!=h: raise ValueError('synthetic_map_drift')
    now=int(time.time())
    return dict(version=1,map_sha256=h,issued_at=now,expires_at=now+120,mailboxes=1,main_meta=[],master_meta=[],ingress='root_static_audit_consistent_not_live_delivery')
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--map-sha256',required=True)
    p.add_argument('--confirm',required=True)
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!='REFRESH_PRIVILEGED_MULTI_INGRESS_PROOF': raise ValueError('synthetic_auth_refused')
    raw=(json.dumps(inspect(a.map_sha256),sort_keys=True)+'\\n').encode('ascii')
    fd=os.open(str(PROOF),os.O_CREAT|os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW,0o640)
    try:
        os.fchown(fd,0,grp.getgrnam('m365mailer').gr_gid)
        os.fchmod(fd,0o640)
        if os.write(fd,raw)!=len(raw): raise OSError('short_fixture_write')
        os.fsync(fd)
    finally: os.close(fd)
"""
# Parse the generated nested Python source without creating __pycache__.
import ast
ast.parse(fake, filename="synthetic_ingress_stub.py")
source = root / "refresh-multi-mailbox-proof.py"
source.write_text(fake, encoding="ascii")
source.chmod(0o644)
mappath.write_bytes(b"synthetic_no_real_mailbox\n")
mappath.chmod(0o640)
import os
os.chown(str(mappath),0,grp.getgrnam("m365mailer").gr_gid)
for name in ("main.cf","master.cf"):
    (conf/name).write_bytes(b"# synthetic test only, not used by Postfix\n")
    (conf/name).chmod(0o644)
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
marker = dict(runtime_map_sha256=sha(mappath),
              active={n:sha(conf/n) for n in ("main.cf","master.cf")},
              source={n:sha(root/n) for n in
                      ("manage-multi-mailbox-proof-timer.py","refresh-multi-mailbox-proof.py")})
path=Path("/var/backups/linuxmailrelay365-multi-oauth/active.json")
path.write_text(json.dumps(marker,sort_keys=True)+"\n",encoding="ascii")
path.chmod(0o600)
PYFIXTURE
output="$(python3 "$manager" --plan)"
sha="$(printf '%s\n' "$output" | sed -n 's/^MULTI_PROOF_TIMER_PLAN_SHA256=//p')"
[[ "$sha" =~ ^[a-f0-9]{64}$ ]]
test ! -e "$service" && test ! -e "$timer"
echo 'LMR365_VM_TIMER_PREVIEW=read_only'
python3 "$manager" --enable-reviewed --approve-sha256 "$sha" \
    --confirm ENABLE_REVIEWED_MULTI_INGRESS_TIMER |
    grep -Fxq 'MULTI_PROOF_TIMER=enabled_static_audit_only'
systemctl is-active --quiet linuxmailrelay365-multi-proof.timer
systemctl is-enabled --quiet linuxmailrelay365-multi-proof.timer
before="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["issued_at"])' "$proof")"
echo 'LMR365_VM_TIMER_SYSTEMD=active_under_enforcing'
python3 "$manager" --status | grep -Fxq 'MULTI_PROOF_RECEIPT=fresh_ttl_only'
echo 'LMR365_VM_TIMER_RECEIPT_INITIAL=fresh_ttl_only'
sleep 75
after="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["issued_at"])' "$proof")"
test "$after" -gt "$before"
echo 'LMR365_VM_TIMER_SCHEDULED=renewed'
python3 "$manager" --status | grep -Fxq 'MULTI_PROOF_RECEIPT=fresh_ttl_only'
echo 'LMR365_VM_TIMER_RECEIPT_RENEWED=fresh_ttl_only'

# Negative lifecycle: altered sender map must NOT refresh an existing proof.
# A failed oneshot must leave the previous receipt intact and the manager
# must refuse even a read-only approval plan while its SHA pin is violated.
map="$parent/oauth-runtime-senders.tsv"
original_map_sha="$(sha256sum "$map" | cut -d ' ' -f 1)"
proof_before_drift="$(sha256sum "$proof" | cut -d ' ' -f 1)"
printf 'unapproved_synthetic_sender_change\n' > "$map"
test "$(sha256sum "$map" | cut -d ' ' -f 1)" != "$original_map_sha"
if systemctl start linuxmailrelay365-multi-proof.service >/dev/null 2>&1; then
    echo 'LMR365_VM_TIMER_MAP_DRIFT=unsafe_refresh_succeeded' >&2
    exit 1
fi
test "$(sha256sum "$proof" | cut -d ' ' -f 1)" = "$proof_before_drift"
python3 "$manager" --status | grep -Fxq 'MULTI_PROOF_RECEIPT=map_changed'
echo 'LMR365_VM_TIMER_RECEIPT_MAP_DRIFT=detected'
if python3 "$manager" --plan >/dev/null 2>&1; then
    echo 'LMR365_VM_TIMER_MAP_DRIFT=unapproved_plan_accepted' >&2
    exit 1
fi
echo 'LMR365_VM_TIMER_MAP_DRIFT=fail_closed'

# Restore exactly the fixture map, clear only the test's failed unit state,
# and prove the original signed SHA can be refreshed again.
printf 'synthetic_no_real_mailbox\n' > "$map"
test "$(sha256sum "$map" | cut -d ' ' -f 1)" = "$original_map_sha"
systemctl reset-failed linuxmailrelay365-multi-proof.service
sleep 2
systemctl start linuxmailrelay365-multi-proof.service
systemctl is-active --quiet linuxmailrelay365-multi-proof.timer
proof_after_recovery="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["issued_at"])' "$proof")"
test "$proof_after_recovery" -gt "$after"
echo 'LMR365_VM_TIMER_MAP_RECOVERY=verified'
python3 "$manager" --status | grep -Fxq 'MULTI_PROOF_RECEIPT=fresh_ttl_only'
echo 'LMR365_VM_TIMER_RECEIPT_RECOVERY=fresh_ttl_only'

python3 "$manager" --disable-reviewed --confirm DISABLE_AND_REVOKE_MULTI_INGRESS_TIMER |
    grep -Fxq 'MULTI_PROOF_TIMER=disabled_and_receipt_revoked'
test ! -e "$proof" && test ! -e "$service" && test ! -e "$timer" && test ! -e "$state"
python3 "$manager" --status | grep -Fxq 'MULTI_PROOF_TIMER=not_installed'
python3 "$manager" --status | grep -Fxq 'MULTI_PROOF_RECEIPT=not_applicable'
echo 'LMR365_VM_TIMER_RECEIPT_REVOKED=not_applicable'
echo 'LMR365_VM_TIMER_REVOCATION=verified'
rm -- "$lock" "$backup/active.json" "$manager" \
    "$root/refresh-multi-mailbox-proof.py" \
    "$parent/oauth-runtime-senders.tsv" "$conf/main.cf" "$conf/master.cf"
rmdir -- "$root" "$conf" "$parent" "$backup"
groupdel m365mailer
echo 'LMR365_VM_TIMER_FIXTURE=removed'
echo 'LMR365_VM_TIMER_REAL_M365_ACCEPTANCE=no'
