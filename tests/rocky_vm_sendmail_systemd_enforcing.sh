#!/usr/bin/env bash
# EXPERIMENTAL: real Sendmail systemd lifecycle in a disposable Rocky 9.9 VM.
# Never production Restore. No SMTP DATA, queue runs or tenant connectivity.
set -Eeuo pipefail
umask 077
export LC_ALL=C

test "$(id -u)" != 0 || { echo "LMR365_SENDMAIL_VM_NONROOT_CALLER_REQUIRED"; exit 3; }
test "$(printenv GITHUB_ACTIONS || true)" = true || { echo "LMR365_SENDMAIL_VM_CI_ONLY"; exit 3; }
source /etc/os-release
test "$ID" = rocky && test "$VERSION_ID" = 9.9
test "$(uname -m)" = x86_64
test "$(cat /proc/1/comm)" = systemd
test "$(getenforce)" = Enforcing
test "$(cat /sys/fs/selinux/enforce)" = 1
# A disposable-guest marker is provisioned by our KVM boot harness only.
# It is bound to this kernel boot ID, root-owned, private and not a symlink.
sudo python3 - <<'PY'
from pathlib import Path
import socket
import stat
p = Path("/run/lmr365-disposable-sendmail-vm")
info = p.lstat()
if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
        stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or
        p.read_text(encoding="ascii").strip() !=
        Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() or
        socket.gethostname().split(".")[0] != "rocky-selinux-ci"):
    raise SystemExit("LMR365_SENDMAIL_VM_MISSING_DISPOSABLE_KVM_ATTESTATION")
PY
sudo systemctl is-active --quiet postfix.service
test -z "$(sudo postqueue -j)"
sudo test -f /etc/postfix/main.cf
sudo test -f /etc/postfix/master.cf
sudo test ! -e /var/lib/linuxmailrelay365-selinux-context/active.json
sudo test ! -e /var/lib/linuxmailrelay365-selinux-port/active.json

work="$(mktemp -d)"
cleanup() {
  result=$?
  trap - EXIT
  if test "$result" -ne 0; then
    echo "LMR365_SENDMAIL_VM_FAILURE_DIAGNOSTICS_BEGIN"
    sudo systemctl --no-pager -l status sendmail.service 2>&1 | tail -n 32 || true
    sudo journalctl --no-pager -u sendmail.service -n 35 || true
    sudo ss -H -ltn | grep -E ':(25|465|587|2525)[[:space:]]' || true
    echo "LMR365_SENDMAIL_VM_FAILURE_DIAGNOSTICS_END"
  fi
  sudo systemctl stop sendmail.service >/dev/null 2>&1 || true
  sudo systemctl stop sm-client.service >/dev/null 2>&1 || true
  sudo rm -f -- /run/lmr365-disposable-sendmail-vm || true
  if sudo rpm -q postfix >/dev/null 2>&1; then
    if ! sudo systemctl start postfix.service; then
      echo "LMR365_SENDMAIL_VM_POSTFIX_RESTART_FAILED"
      result=1
    fi
  else
    echo "LMR365_SENDMAIL_VM_POSTFIX_PACKAGE_CHANGED"
    result=1
  fi
  if test "$result" -eq 0; then
    sudo systemctl is-active --quiet postfix.service || result=1
    if sudo systemctl is-active --quiet sendmail.service; then
      echo "LMR365_SENDMAIL_VM_SENDMAIL_REMAINS_ACTIVE"
      result=1
    fi
    if ! sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf > "$work/postfix-after"; then
      result=1
    elif ! cmp "$work/postfix-before" "$work/postfix-after"; then
      echo "LMR365_SENDMAIL_VM_PRIMARY_CONFIG_CHANGED"
      result=1
    fi
    if ! sudo postqueue -j > "$work/postfix-queue-after"; then
      result=1
    elif ! cmp "$work/postfix-queue-before" "$work/postfix-queue-after"; then
      echo "LMR365_SENDMAIL_VM_PRIMARY_QUEUE_CHANGED"
      result=1
    fi
    if test "$(getenforce)" != Enforcing; then
      echo "LMR365_SENDMAIL_VM_SELINUX_MODE_CHANGED"
      result=1
    fi
    if test "$result" -eq 0; then
      echo "LMR365_SENDMAIL_VM_PRIMARY_POSTFIX_RESTORED=verified"
      echo "LMR365_SENDMAIL_VM_SELINUX=enforcing_unchanged"
    fi
  fi
  rm -rf -- "$work"
  exit "$result"
}
trap cleanup EXIT

sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf > "$work/postfix-before"
sudo postqueue -j > "$work/postfix-queue-before"
test ! -s "$work/postfix-queue-before"
test -z "$(sudo ss -H -ltn '( sport = :2526 )')"

# Installation occurs ONLY inside this disposable VM, after all Postfix
# acceptance tests. A package conflict must cause a hard refusal.
sudo dnf -y -q install sendmail
sudo rpm -q sendmail postfix >/dev/null
sudo test -f /etc/mail/sendmail.cf
sudo systemctl stop sendmail.service >/dev/null 2>&1 || true
sudo systemctl stop sm-client.service >/dev/null 2>&1 || true

# The installed sendmail.cf must explicitly bind all SMTP daemons to loopback,
# rather than relying on assumptions about a distro default.
sudo python3 - <<'PY'
from pathlib import Path
import re
content = Path("/etc/mail/sendmail.cf").read_text(encoding="latin-1")
entries = [
    row.strip() for row in content.splitlines()
    if re.match(r"^\s*O\s+DaemonPortOptions\s*=", row)
]
if not entries:
    raise SystemExit("LMR365_SENDMAIL_VM_NO_EXPLICIT_DAEMON_PORT")
ports = []
for row in entries:
    pairs = {}
    for field in row.split("=", 1)[1].split(","):
        if "=" in field:
            key, value = field.strip().split("=", 1)
            pairs[key.strip()] = value.strip()
    addr = pairs.get("Addr", "")
    port = pairs.get("Port", "smtp")
    if addr not in ("127.0.0.1", "::1") or port not in (
            "smtp", "25", "submission", "587"):
        raise SystemExit("LMR365_SENDMAIL_VM_UNSAFE_DAEMON_OPTIONS")
    ports.append(port)
if not any(p in ("smtp", "25") for p in ports):
    raise SystemExit("LMR365_SENDMAIL_VM_MISSING_LOOPBACK_SMTP_25")
print("LMR365_SENDMAIL_VM_CONFIG_LISTEN=loopback_only")
PY

# Require empty Sendmail queues before daemon startup: no message can be
# delivered from this fresh VM fixture.
sudo python3 - <<'PY'
from pathlib import Path
for base in ("/var/spool/mqueue", "/var/spool/clientmqueue"):
    path = Path(base)
    if path.is_dir() and any(
            p.is_file() and p.name.startswith(("qf", "df", "tf", "xf"))
            for p in path.iterdir()):
        raise SystemExit("LMR365_SENDMAIL_VM_QUEUE_NOT_EMPTY")
print("LMR365_SENDMAIL_VM_QUEUES=empty_before_start")
PY

sudo systemctl stop postfix.service
if sudo systemctl is-active --quiet postfix.service; then
  echo "LMR365_SENDMAIL_VM_POSTFIX_STILL_ACTIVE"
  exit 1
fi
test -z "$(sudo ss -H -ltn '( sport = :25 )')"

smoke() {
  sudo systemctl is-active --quiet sendmail.service
  test "$(getenforce)" = Enforcing
  python3 - <<'PY'
import smtplib
import subprocess

result = subprocess.run(
    ["ss", "-H", "-ltn"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    universal_newlines=True, timeout=12, check=True)
ports = {25: [], 587: []}
for row in result.stdout.splitlines():
    cols = row.split()
    if len(cols) < 5:
        raise SystemExit("LMR365_SENDMAIL_VM_BAD_LISTENER_INVENTORY")
    address, _, port = cols[3].rpartition(":")
    if port.isdigit() and int(port) in ports:
        ports[int(port)].append(address)
if ports[25] != ["127.0.0.1"] or any(
        x not in ("127.0.0.1", "[::1]", "::1") for x in ports[587]):
    raise SystemExit("LMR365_SENDMAIL_VM_NOT_LOOPBACK_ONLY")
with smtplib.SMTP("127.0.0.1", 25, timeout=12) as smtp:
    code, _ = smtp.ehlo("sendmail-ci.invalid")
    if code != 250:
        raise SystemExit("LMR365_SENDMAIL_VM_EHLO_FAILED")
    # The context manager sends QUIT. Never MAIL, RCPT, DATA or AUTH.
print("LMR365_SENDMAIL_VM_SMTP=ehlo_quit_only")
print("LMR365_SENDMAIL_VM_LISTENER=loopback_25")
PY
  sudo python3 - <<'PY'
from pathlib import Path
for base in ("/var/spool/mqueue", "/var/spool/clientmqueue"):
    p = Path(base)
    if p.is_dir() and any(
            f.is_file() and f.name.startswith(("qf", "df", "tf", "xf"))
            for f in p.iterdir()):
        raise SystemExit("LMR365_SENDMAIL_VM_MAIL_QUEUE_CHANGED")
print("LMR365_SENDMAIL_VM_QUEUES=empty_after_probe")
PY
}
sudo systemctl start sendmail.service
smoke
echo "LMR365_SENDMAIL_VM_SYSTEMD_FIRST_START=passed"
sudo systemctl stop sendmail.service
if sudo systemctl is-active --quiet sendmail.service; then
  echo "LMR365_SENDMAIL_VM_STOP_DID_NOT_COMPLETE"
  exit 1
fi
sudo systemctl start sendmail.service
smoke
echo "LMR365_SENDMAIL_VM_SYSTEMD_SECOND_START=passed"

# The CI-only restoration test runs with all daemons stopped and all queues
# empty. It performs ONE controlled comment edit to the root-owned .cf file,
# proves preview drift, then atomically restores the archived bytes and
# original SELinux label. It has no connection to production Restore code.
sudo systemctl stop sendmail.service
sudo systemctl stop sm-client.service >/dev/null 2>&1 || true
! sudo systemctl is-active --quiet sendmail.service
! sudo systemctl is-active --quiet postfix.service
! sudo systemctl is-active --quiet sm-client.service
backup_report="$(sudo python3 /usr/local/libexec/lmr365-kvm-sendmail-recovery/foreign-mta-config-backup.py \
  --mta sendmail --backup)"
printf '%s\n' "$backup_report" | grep -Fxq "FOREIGN_BACKUP_STATUS=verified"
printf '%s\n' "$backup_report" | grep -Fxq "FOREIGN_BACKUP_FORMAT=v2_package_metadata"
backup_id="$(printf '%s\n' "$backup_report" | sed -n 's/^FOREIGN_BACKUP_ID=//p')"
[[ "$backup_id" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$ ]] || {
  echo "LMR365_SENDMAIL_VM_BACKUP_ID_INVALID"; exit 1;
}
sudo env GITHUB_ACTIONS=true python3 \
  /usr/local/libexec/lmr365-kvm-sendmail-recovery/rocky_vm_sendmail_stopped_config_restore.py \
  "$backup_id"
sudo systemctl start sendmail.service
smoke
echo "LMR365_SENDMAIL_VM_RESTORED_SERVICE_START=passed"
sudo systemctl stop sendmail.service
sudo systemctl stop sm-client.service >/dev/null 2>&1 || true
! sudo systemctl is-active --quiet sendmail.service
echo "LMR365_SENDMAIL_VM_CONTROLLED_RESTORE=passed_offline_vm_only"
echo "LMR365_SENDMAIL_VM_EXTERNAL_DELIVERY_TESTED=no"
echo "LMR365_SENDMAIL_VM_PRODUCTION_RESTORE_TESTED=no"
