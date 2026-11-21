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
# EL9 minimal containers include coreutils-single, incompatible with
# coreutils; never replace base packages just to run a syntax smoke test.
dnf -y install python3 hostname
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
if test "$mta" = sendmail; then
  # RPM Sendmail initialisation may perform canonical-host DNS lookups. In a
  # disposable Docker host ID the default hostname may lack an FQDN. Supply
  # exactly one local hosts-file entry; never write to a customer's /etc/hosts.
  python3 - <<'PY'
import re
import socket
from pathlib import Path

hostname = socket.gethostname()
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,90}", hostname):
    raise SystemExit("EL_SENDMAIL_UNSAFE_CI_HOSTNAME")
try:
    addr = socket.gethostbyname(hostname)
except OSError:
    addr = "127.0.0.1"
path = Path("/etc/hosts")
original = path.read_text(encoding="utf-8")
entry = "{} {}.ci.localdomain {}\n".format(addr, hostname, hostname)
with path.open("r+", encoding="utf-8") as stream:
    stream.write(entry + original)
    stream.truncate()
print("EL_SENDMAIL_CI_FQDN_HOSTS_ENTRY=added")
for name in ("sendmail.cf", "submit.cf"):
    p = Path("/etc/mail") / name
    print("EL_SENDMAIL_{}_EXISTS={}".format(
        name.replace(".", "_").upper(), "yes" if p.is_file() else "no"))
PY
fi

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
# EL minimal containers use coreutils-single: cmp is not necessarily present.
# Compare complete snapshot bytes using the already-required Python runtime.
python3 - "$state/before" "$state/after" <<'PY'
from pathlib import Path
import sys

before = Path(sys.argv[1]).read_bytes()
after = Path(sys.argv[2]).read_bytes()
if before != after:
    raise SystemExit("EL_NATIVE_CONFIG_OR_QUEUE_CHANGED")
print("EL_NATIVE_CONFIG_AND_QUEUE_HASHES=unchanged")
PY
no_smtp_listeners
test ! -e /run/systemd/system
echo "EL_NATIVE_$mta=passed_real_package_without_delivery"
