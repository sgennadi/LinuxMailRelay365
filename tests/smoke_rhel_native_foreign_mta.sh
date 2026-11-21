#!/usr/bin/env bash
# Native Exim/Sendmail package check on disposable RHEL-family CI containers.
# No tenant, SMTP DATA, MTA service, or customer mail queue is involved.
set -Eeuo pipefail

mta="$1"
case "$mta" in
  exim|sendmail) ;;
  *) echo "EL_NATIVE_MTA_INVALID_SELECTION" >&2; exit 2 ;;
esac

source /etc/os-release
major="$(printf '%s' "$VERSION_ID" | cut -d. -f1)"
case "$ID:$major:$mta" in
  rocky:8:exim|rocky:8:sendmail|rocky:9:exim|rocky:9:sendmail|almalinux:9:sendmail|ol:9:sendmail) ;;
  *) echo "EL_NATIVE_MTA_UNTESTED_OS" >&2; exit 2 ;;
esac

if test -e /run/systemd/system; then
  echo "EL_NATIVE_MTA_REFUSE_HOST_SYSTEMD" >&2
  exit 2
fi

# DNF operates only in this disposable container, never on a user MTA.
dnf -y install python3 coreutils
if test "$mta" = "exim"; then
  if test "$ID" != rocky; then
    echo "EL_NATIVE_EXIM_EPEL_TEST_REQUIRES_ROCKY" >&2; exit 2
  fi
  dnf -y install dnf-plugins-core epel-release
  if test "$major" = 8; then
    dnf config-manager --set-enabled powertools
  else
    dnf config-manager --set-enabled crb
  fi
  dnf -y install exim
else
  dnf -y install sendmail
fi

# An unrelated /usr/sbin/sendmail alternative must not count as Sendmail.
rpm -q "$mta" >/dev/null
test ! -e /run/systemd/system

state="$(mktemp -d)"
trap 'rm -rf -- "$state"' EXIT
snapshot_state() {
  python3 - <<'PY'
import hashlib
from pathlib import Path
for name in ("/etc/exim/exim.conf", "/etc/mail/sendmail.cf",
             "/etc/mail/submit.cf"):
    p = Path(name)
    if p.is_file():
        print("CONFIG", name, hashlib.sha256(p.read_bytes()).hexdigest())
for root in ("/var/spool/exim/input", "/var/spool/mqueue",
             "/var/spool/clientmqueue"):
    directory = Path(root)
    if directory.is_dir():
        for item in sorted(directory.rglob("*")):
            if item.is_file():
                print("QUEUE", str(item), hashlib.sha256(item.read_bytes()).hexdigest())
PY
}
no_smtp_listeners() {
  python3 - <<'PY'
from pathlib import Path
for name in ("/proc/net/tcp", "/proc/net/tcp6"):
    path = Path(name)
    if not path.is_file():
        raise SystemExit("EL_NATIVE_TCP_INVENTORY_MISSING")
    for line in path.read_text().splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            raise SystemExit("EL_NATIVE_TCP_INVENTORY_UNVERIFIED")
        if parts[3] == "0A" and int(parts[1].rsplit(":", 1)[-1], 16) in (
                25, 465, 587, 2525):
            raise SystemExit("EL_NATIVE_UNEXPECTED_SMTP_LISTENER")
PY
}
no_smtp_listeners
snapshot_state > "$state/before"

python3 linux/restore-foreign-mta-config.py \
  --mta "$mta" --static-check > "$state/check"
for expected in \
  'FOREIGN_STATIC_VERSION=1' \
  "FOREIGN_STATIC_MTA=$mta" \
  'FOREIGN_STATIC_CHECK=passed_partial_parse_only' \
  'FOREIGN_STATIC_CONFIG_CHANGED=no' \
  'FOREIGN_STATIC_QUEUE_CHANGED=no' \
  'FOREIGN_STATIC_SERVICE_CHANGED=no' \
  'FOREIGN_STATIC_DELIVERY_VERIFIED=no'; do
  grep -Fxq "$expected" "$state/check"
done

other=sendmail
if test "$mta" = sendmail; then other=exim; fi
if python3 linux/restore-foreign-mta-config.py --mta "$other" \
    --static-check > /dev/null 2>&1; then
  echo "EL_NATIVE_WRONG_MTA_ACCEPTED" >&2; exit 1
fi
if python3 linux/restore-foreign-mta-config.py --mta "$mta" \
    --static-check --confirm RESTORE_STOPPED_FOREIGN_MTA_CONFIG \
    > /dev/null 2>&1; then
  echo "EL_NATIVE_STATIC_ACCEPTED_RESTORE_APPROVAL" >&2; exit 1
fi

snapshot_state > "$state/after"
cmp "$state/before" "$state/after" ||
  { echo "EL_NATIVE_CONFIG_OR_QUEUE_CHANGED" >&2; exit 1; }
no_smtp_listeners
test ! -e /run/systemd/system
echo "EL_NATIVE_$mta=passed_real_package_without_delivery"
