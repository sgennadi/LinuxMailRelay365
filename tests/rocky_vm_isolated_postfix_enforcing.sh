#!/usr/bin/env bash
# POSITIVE isolated Postfix runtime test on a disposable Rocky Linux KVM guest.
# The production installers remain Enforcing-gated. This fixture has NO
# external delivery: independent queue and data, error: transports, 127.0.0.1.
set -Eeuo pipefail
umask 077
test "$(cat /proc/1/comm)" = systemd
test "$(getenforce)" = Enforcing
test "$(cat /sys/fs/selinux/enforce)" = 1
test "$(id -u)" != 0  # Admin operations must use visible sudo.
sudo systemctl start postfix.service
# The earlier STARTTLS fixture MUST restore master.cf, not merely stop 2525.
test -z "$(sudo postconf -M '2525/inet' 2>/dev/null || true)" || {
  echo "LMR365_POSITIVE_SIDECAR_INHERITED_TEST_SMTP_2525"; exit 1;
}
test -z "$(sudo ss -H -ltn '( sport = :2525 )')" || {
  echo "LMR365_POSITIVE_SIDECAR_UNEXPECTED_SMTP_2525"; exit 1;
}
sudo systemctl is-active --quiet postfix.service
test -z "$(sudo postqueue -j)"

CONF=/etc/linuxmailrelay365/sidecar-postfix
QUEUE=/var/spool/linuxmailrelay365-sidecar
DATA=/var/lib/linuxmailrelay365-sidecar
UNIT=/etc/systemd/system/linuxmailrelay365-sidecar.service
MANAGER=/usr/local/libexec/lmr365-selinux-port.py
CONTEXT_MANAGER=/usr/local/libexec/lmr365-selinux-sidecar-context.py
PORT=2526
for p in "$CONF" "$QUEUE" "$DATA" "$UNIT"; do
  if sudo test -e "$p" || sudo test -L "$p"; then
    echo "LMR365_POSITIVE_SIDECAR_PREEXISTING_STATE_REFUSED"
    exit 1
  fi
done
test -z "$(sudo ss -H -ltn '( sport = :2526 )')"
test -f "$MANAGER"
test -f "$CONTEXT_MANAGER"

work="$(mktemp -d)"
cleanup() {
  result=$?
  trap - EXIT
  if test "$result" -ne 0; then
    echo "LMR365_POSITIVE_SIDECAR_FAILED_DIAGNOSTICS_BEGIN"
    sudo journalctl --no-pager -u linuxmailrelay365-sidecar.service -n 50 || true
    sudo ls -Zd "$CONF" "$QUEUE" "$DATA" 2>/dev/null || true
    sudo ls -ldZ "$QUEUE/public" "$QUEUE/private" "$QUEUE/maildrop" 2>/dev/null || true
    if command -v ausearch >/dev/null 2>&1; then
      sudo ausearch -m AVC,USER_AVC -ts recent 2>/dev/null |
        grep -E 'denied|scontext|tcontext' | tail -n 25 || true
    fi
    sudo postfix -c "$CONF" check 2>&1 || true
    echo "LMR365_POSITIVE_SIDECAR_FAILED_DIAGNOSTICS_END"
  fi
  sudo systemctl stop linuxmailrelay365-sidecar.service >/dev/null 2>&1 || true
  sudo systemctl disable linuxmailrelay365-sidecar.service >/dev/null 2>&1 || true
  sudo rm -f -- "$UNIT"
  sudo systemctl daemon-reload >/dev/null 2>&1 || true
  for p in "$CONF" "$QUEUE" "$DATA"; do
    sudo rm -rf -- "$p"
  done
  if sudo test -f /var/lib/linuxmailrelay365-selinux-context/active.json; then
    current_ctx="$(sudo python3 "$CONTEXT_MANAGER" --status 2>/dev/null |
      sed -n 's/^RHEL_FCONTEXT_POLICY_SHA256=//p')" || true
    if [[ "$current_ctx" =~ ^[a-f0-9]{64}$ ]]; then
      sudo python3 "$CONTEXT_MANAGER" --restore \
        --expect-policy-sha256 "$current_ctx" \
        --confirm REMOVE_REVIEWED_RHEL_SIDECAR_CONTEXTS || true
    fi
  fi

  if sudo test -f /var/lib/linuxmailrelay365-selinux-port/active.json; then
    current="$(sudo python3 "$MANAGER" --status --smtp-port "$PORT" 2>/dev/null |
      sed -n 's/^RHEL_PORT_CURRENT_POLICY_SHA256=//p')" || true
    if [[ "$current" =~ ^[a-f0-9]{64}$ ]]; then
      sudo python3 "$MANAGER" --restore --smtp-port "$PORT" \
        --expect-policy-sha256 "$current" \
        --confirm REMOVE_MANAGED_RHEL_SMTP_PORT >/dev/null 2>&1 || true
    fi
  fi
  # A green result requires the guest to be restored, not merely that
  # the service managed to start. All checks execute after cleanup.
  if test "$result" -eq 0; then
    if ! sudo systemctl is-active --quiet postfix.service; then
      echo "LMR365_POSITIVE_SIDECAR_CLEANUP_PRIMARY_STOPPED"
      result=1
    fi
    if test -n "$(sudo ss -H -ltn '( sport = :2526 )')"; then
      echo "LMR365_POSITIVE_SIDECAR_CLEANUP_PORT_STILL_OPEN"
      result=1
    fi
    for p in "$CONF" "$QUEUE" "$DATA" "$UNIT"; do
      if sudo test -e "$p" || sudo test -L "$p"; then
        echo "LMR365_POSITIVE_SIDECAR_CLEANUP_FILE_LEFT_BEHIND"
        result=1
      fi
    done
    if sudo test -f /var/lib/linuxmailrelay365-selinux-port/active.json; then
      echo "LMR365_POSITIVE_SIDECAR_CLEANUP_PORT_POLICY_STILL_MANAGED"
      result=1
    fi
    if sudo test -f /var/lib/linuxmailrelay365-selinux-context/active.json; then
      echo "LMR365_POSITIVE_SIDECAR_CLEANUP_CONTEXT_POLICY_STILL_MANAGED"
      result=1
    fi
    if ! sudo semanage fcontext -l -C > "$work/remaining-fcontext"; then
      echo "LMR365_POSITIVE_SIDECAR_CLEANUP_CONTEXT_INVENTORY_FAILED"
      result=1
    else
      for p in "$CONF" "$QUEUE" "$DATA"; do
        if grep -Fq -- "$p" "$work/remaining-fcontext"; then
          echo "LMR365_POSITIVE_SIDECAR_CLEANUP_CUSTOM_FCONTEXT_LEFT_BEHIND"
          result=1
        fi
      done
    fi
    if test "$(getenforce)" != Enforcing; then
      echo "LMR365_POSITIVE_SIDECAR_CLEANUP_ENFORCING_CHANGED"
      result=1
    fi
    if test "$result" -eq 0; then
      echo "LMR365_POSITIVE_SIDECAR_TEARDOWN=all_artifacts_and_policy_removed"
    fi
  fi
  rm -rf -- "$work"
  exit "$result"
}
trap cleanup EXIT
sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf > "$work/primary-before"
before_boot="$(cat /proc/sys/kernel/random/boot_id)"
sudo postqueue -j > "$work/primary-queue-before"

# Use our production port policy manager (exact SHA approval), never disable
# SELinux or call setenforce. Do not adopt a conflicting explicit port type.
preflight="$(sudo python3 "$MANAGER" --check-only --smtp-port "$PORT")"
echo "$preflight" | grep -Fxq 'RHEL_PORT_PREFLIGHT=ready'
policy_sha="$(printf '%s\n' "$preflight" | sed -n 's/^RHEL_PORT_POLICY_SHA256=//p')"
[[ "$policy_sha" =~ ^[a-f0-9]{64}$ ]]
sudo python3 "$MANAGER" --apply --smtp-port "$PORT" \
  --expect-policy-sha256 "$policy_sha" \
  --confirm ADD_REVIEWED_RHEL_SMTP_PORT >/dev/null
echo "LMR365_POSITIVE_SIDECAR_SMTP_PORT_LABEL=managed_smtp_port_t"

# The guest-only fixture reuses the production sidecar directory layout,
# but disables all mail transport. This does not circumvent installer safety.
sudo install -d -o root -g root -m 0755 /etc/linuxmailrelay365
sudo install -d -o root -g root -m 0755 "$CONF" "$QUEUE"
sudo install -d -o postfix -g postfix -m 0700 "$DATA"

# Apply exactly three reviewed Postfix-specific equivalents using the
# experimental guarded manager; never overwrite unrelated local policy.
fcontext_preflight="$(sudo python3 "$CONTEXT_MANAGER" --check-only)"
echo "$fcontext_preflight" | grep -Fxq 'RHEL_FCONTEXT_PREFLIGHT=ready'
fcontext_sha="$(printf '%s\n' "$fcontext_preflight" |
  sed -n 's/^RHEL_FCONTEXT_POLICY_SHA256=//p')"
[[ "$fcontext_sha" =~ ^[a-f0-9]{64}$ ]]
sudo python3 "$CONTEXT_MANAGER" --apply \
  --expect-policy-sha256 "$fcontext_sha" \
  --confirm ADD_REVIEWED_RHEL_SIDECAR_CONTEXTS
sudo python3 "$CONTEXT_MANAGER" --relabel \
  --confirm RELABEL_REVIEWED_RHEL_SIDECAR_PATHS
echo "LMR365_POSITIVE_SIDECAR_FCONTEXT=managed_three_equivalences"

cat > "$work/main.cf" <<'CONFMAIN'
myhostname = smtp-ci.lab.invalid
myorigin = $myhostname
queue_directory = /var/spool/linuxmailrelay365-sidecar
data_directory = /var/lib/linuxmailrelay365-sidecar
inet_interfaces = 127.0.0.1
inet_protocols = ipv4
mynetworks = 127.0.0.0/8
mydestination =
relay_domains =
relayhost =
default_transport = error:ExternalMailDisabledInKVM
relay_transport = error:ExternalMailDisabledInKVM
local_transport = error:LocalMailDisabledInKVM
smtpd_client_restrictions = permit_mynetworks, reject
smtpd_relay_restrictions = reject
smtpd_sender_restrictions = reject
smtpd_recipient_restrictions = reject
disable_vrfy_command = yes
smtpd_helo_required = yes
syslog_name = postfix-lmr365-lab
authorized_submit_users =
CONFMAIN
sudo install -o root -g root -m 0644 "$work/main.cf" "$CONF/main.cf"
cat > "$work/master.cf" <<'CONFMASTER'
2526      inet  n       -       n       -       -       smtpd
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
CONFMASTER
sudo install -o root -g root -m 0644 "$work/master.cf" "$CONF/master.cf"
sudo python3 "$CONTEXT_MANAGER" --relabel \
  --confirm RELABEL_REVIEWED_RHEL_SIDECAR_PATHS
sudo postfix -c "$CONF" check
# 'postfix check' creates the queue subdirectories (including public and
# private). The earlier restorecon ran BEFORE these paths existed, so they
# inherited postfix_spool_t instead of specific public/private socket types.
# Relabel only this isolated instance after Postfix has created the layout.
sudo python3 "$CONTEXT_MANAGER" --relabel \
  --confirm RELABEL_REVIEWED_RHEL_SIDECAR_PATHS
sudo ls -ldZ "$QUEUE/public" "$QUEUE/private" "$QUEUE/maildrop"
sudo stat -c '%C' "$QUEUE/public" | grep -Fq ':postfix_public_t:'
sudo stat -c '%C' "$QUEUE/private" | grep -Fq ':postfix_private_t:'
echo "LMR365_POSITIVE_SIDECAR_QUEUE_LABELS=verified_public_and_private_types"

cat > "$work/sidecar.service" <<'SERVICE'
[Unit]
Description=LinuxMailRelay365 lab isolated Postfix under Enforcing
After=postfix.service
Requires=postfix.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/postfix -c /etc/linuxmailrelay365/sidecar-postfix start
ExecStop=/usr/sbin/postfix -c /etc/linuxmailrelay365/sidecar-postfix stop
TimeoutStartSec=90
[Install]
WantedBy=multi-user.target
SERVICE
sudo install -o root -g root -m 0644 "$work/sidecar.service" "$UNIT"
sudo restorecon -F "$UNIT"
sudo systemctl daemon-reload
sudo systemctl start linuxmailrelay365-sidecar.service
sudo systemctl is-active --quiet linuxmailrelay365-sidecar.service
sudo systemctl is-active --quiet postfix.service
sudo postfix -c "$CONF" status >/dev/null
echo "LMR365_POSITIVE_SIDECAR_SYSTEMD=active"

sudo python3 - <<'PY'
import socket
import subprocess
from pathlib import Path

r = subprocess.run(["ss", "-H", "-ltn"], stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, universal_newlines=True,
                   timeout=12, check=True)
present = {25: [], 2526: []}
for line in r.stdout.splitlines():
    parts = line.split()
    if len(parts) < 5:
        raise SystemExit("LMR365_POSITIVE_SIDECAR_UNPARSEABLE_PORT")
    address, _, port = parts[3].rpartition(":")
    if port.isdigit() and int(port) in present:
        present[int(port)].append(address)
if present != {25:["127.0.0.1"], 2526:["127.0.0.1"]}:
    raise SystemExit("LMR365_POSITIVE_SIDECAR_PRIMARY_OR_ISOLATION_BROKEN")
with socket.create_connection(("127.0.0.1",2526),timeout=8) as sock:
    sock.settimeout(8)
    f=sock.makefile("rb")
    line=f.readline(2049)
    if not line.startswith(b"220 "):
        raise SystemExit("LMR365_POSITIVE_SIDECAR_NO_SMTP_GREETING")
    sock.sendall(b"EHLO lmr365-ci.invalid\r\n")
    for i in range(30):
        line=f.readline(2049)
        if line.startswith(b"250 "):
            break
        if not line.startswith(b"250-"):
            raise SystemExit("LMR365_POSITIVE_SIDECAR_BAD_EHLO")
    else:
        raise SystemExit("LMR365_POSITIVE_SIDECAR_EHLO_UNBOUNDED")
    sock.sendall(b"QUIT\r\n")
    if not f.readline(2049).startswith(b"221 "):
        raise SystemExit("LMR365_POSITIVE_SIDECAR_QUIT_FAILED")
    f.close()
print("LMR365_POSITIVE_SIDECAR_LISTENERS=127.0.0.1_25_and_2526")
print("LMR365_POSITIVE_SIDECAR_SMTP=ehlo_quit_only")
PY

# Verify that even a loopback SMTP client cannot relay an external address.
# The lab has only error transports; never issue DATA or create a message.
python3 - <<'PY'
import smtplib

with smtplib.SMTP("127.0.0.1", 2526, timeout=8) as smtp:
    if smtp.ehlo("ci.lab.invalid")[0] != 250:
        raise SystemExit("LMR365_POSITIVE_SIDECAR_LOCAL_EHLO_FAILED")
    code, _ = smtp.mail("probe@ci.invalid")
    if code < 400:
        code, _ = smtp.rcpt("external@recipient.invalid")
    if code < 400:
        raise SystemExit("LMR365_POSITIVE_SIDECAR_UNAUTHORIZED_RELAY_ACCEPTED")
print("LMR365_POSITIVE_SIDECAR_RELAY=refused_without_data")
PY

test "$(getenforce)" = Enforcing
test "$(cat /sys/fs/selinux/enforce)" = 1
test "$(cat /proc/1/comm)" = systemd
test "$(cat /proc/sys/kernel/random/boot_id)" = "$before_boot"
test -z "$(sudo postqueue -j)"
test -z "$(sudo postqueue -c "$CONF" -j)"
sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf > "$work/primary-after"
cmp "$work/primary-before" "$work/primary-after"
sudo postqueue -j > "$work/primary-queue-after"
cmp "$work/primary-queue-before" "$work/primary-queue-after"
echo "LMR365_POSITIVE_SIDECAR_CONFIG=primary_unchanged"
echo "LMR365_POSITIVE_SIDECAR_QUEUES=separate_and_empty"
echo "LMR365_POSITIVE_SIDECAR_SELINUX=enforcing"

# Stop the lab instance while preserving the already-running main Postfix.
sudo systemctl stop linuxmailrelay365-sidecar.service
sudo postfix -c "$CONF" status >/dev/null 2>&1 &&
  { echo "LMR365_POSITIVE_SIDECAR_STOP_FAILED"; exit 1; } || true
sudo systemctl is-active --quiet postfix.service
echo "LMR365_POSITIVE_SIDECAR_RESTORE=primary_still_running"
echo "LMR365_POSITIVE_SIDECAR_EXTERNAL_DELIVERY_TESTED=no"
echo "LMR365_POSITIVE_SIDECAR_PRODUCT_INSTALLER_TESTED=no"
