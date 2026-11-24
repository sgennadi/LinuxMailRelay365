#!/usr/bin/env bash
# SELinux policy-package integration on disposable RHEL-family CI containers.
# Tests compiled policy and fail-closed probes; NEVER claims Enforcing runtime.
set -Eeuo pipefail

test "$(id -u)" = 0
source /etc/os-release
major="$(printf '%s' "$VERSION_ID" | cut -d. -f1)"
case "$ID:$major" in
  rocky:8|rocky:9|rocky:10|almalinux:9|ol:9|ol:10) ;;
  *) echo "SELINUX_CONTAINER_UNSUPPORTED_PLATFORM" >&2; exit 2 ;;
esac
if test -e /run/systemd/system; then
  echo "SELINUX_CONTAINER_MUST_NOT_HAVE_REAL_SYSTEMD" >&2
  exit 2
fi

# Packages are installed only into the disposable CI job container, never
# on a connected customer Linux server.
dnf -y install python3 selinux-policy-targeted libselinux-utils \
  policycoreutils policycoreutils-python-utils setools-console
for pkg in selinux-policy-targeted libselinux-utils policycoreutils \
           policycoreutils-python-utils setools-console; do
  rpm -q "$pkg" >/dev/null
done
for exe in getenforce semanage seinfo; do
  command -v "$exe" >/dev/null || {
    echo "SELINUX_REQUIRED_REAL_TOOL_MISSING" >&2; exit 1;
  }
done

# This Docker job shares its GitHub host kernel; never use setenforce,
# load_policy or any privileged mount. Native enforcing requires a VM/host.
mode="$(getenforce)"
case "$mode" in
  Disabled|Permissive)
    echo "SELINUX_CONTAINER_RUNTIME=$mode"
    echo "SELINUX_ENFORCING_LIVE_TESTED=no"
    ;;
  *)
    echo "SELINUX_CONTAINER_UNEXPECTED_KERNEL_MODE=$mode" >&2; exit 2 ;;
esac

python3 - <<'PY'
import subprocess
from pathlib import Path

policies = sorted(Path("/etc/selinux/targeted/policy").glob("policy.*"))
if len(policies) != 1 or not policies[0].is_file():
    raise SystemExit("SELINUX_TARGETED_COMPILED_POLICY_MISSING")
policy = str(policies[0])
for required_type in ("smtp_port_t", "postfix_master_t", "postfix_spool_t"):
    result = subprocess.run(["seinfo", "-t", required_type, policy],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=45)
    if result.returncode != 0 or required_type not in result.stdout.split():
        raise SystemExit("SELINUX_NATIVE_POLICY_TYPE_MISSING:" + required_type)
    print("SELINUX_NATIVE_POLICY_TYPE_" + required_type + "=verified")
print("SELINUX_POLICY_BINARY_READABLE=yes")
PY

state="$(mktemp -d)"
trap 'rm -rf -- "$state"' EXIT
# Observe native policy mapping if the policy store can be queried offline.
# Failure to access the kernel/store in Docker is NOT evidence of Enforcing.
if semanage port -l > "$state/ports" 2>"$state/semanage-error"; then
  python3 - "$state/ports" <<'PY'
import importlib.util
import sys
from pathlib import Path

path = Path("linux/rhel-selinux-doctor.py")
spec = importlib.util.spec_from_file_location("selinux_doctor_ci", str(path))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
result = mod.port_label(25, Path(sys.argv[1]).read_text(encoding="utf-8"))
if result != "smtp_port_t":
    raise SystemExit("SELINUX_NATIVE_SMTP25_PORT_TYPE_UNEXPECTED:" + result)
print("SELINUX_REAL_PACKAGE_SMTP25_LABEL=smtp_port_t")
PY
else
  echo "SELINUX_NATIVE_SEMANAGE_OFFLINE_QUERY=unavailable_in_container"
fi

python3 linux/rhel-selinux-doctor.py --smtp-port 46500 > "$state/doctor"
grep -Fxq 'OS_FAMILY=rhel_family' "$state/doctor"
grep -Fxq 'SMTP_AUTH_ENFORCING_TESTED=no' "$state/doctor"
grep -Fxq 'CHANGES_APPLIED=no' "$state/doctor"
grep -Fxq 'SELINUX_ACCEPTANCE_STATUS=enforcing_mode_required_for_acceptance' "$state/doctor"

# The change-capable port tool must reject an inactive kernel SELinux policy.
# --check-only is read-only and does not change any service or port.
if python3 linux/manage-rhel-selinux-port.py --check-only \
  --smtp-port 46500 > "$state/port"; then
  echo "SELINUX_PORT_MANAGER_FALSE_ACCEPTANCE" >&2
  exit 1
fi
grep -Fxq 'RHEL_PORT_ERROR=selinux_must_be_active' "$state/port"
grep -Fxq 'CHANGES_APPLIED=no' "$state/port"

# Live SMTP TLS/Enforcing gate must refuse without a real enforcing host.
if python3 linux/rhel-enforcing-live-smoke.py --smtp-port 46500 \
  --server-name smtp.example.org > "$state/live"; then
  echo "SELINUX_LIVE_FALSE_ACCEPTANCE" >&2
  exit 1
fi
grep -Fxq 'RHEL_ENFORCING_LIVE_SMTP=refused' "$state/live"
grep -Fxq 'RHEL_ENFORCING_REASON=selinux_enforcing_mode_required' "$state/live"
grep -Fxq 'CHANGES_APPLIED=no' "$state/live"

# Actual installed policy path matching for a not-yet-created managed map.
# This is policy lookup only; no security.selinux writes in Docker.
python3 - <<'PY'
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "conditional_policy", str(Path("linux/inspect-conditional-postfix-activation.py")))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
for path in ("/etc/postfix/main.cf", "/etc/postfix/master.cf",
             "/etc/postfix/lmr365-conditional-" + "a"*64 + "-sender.db",
             "/etc/postfix/lmr365-conditional-" + "a"*64 + "-sender.lmdb"):
    raw = P.T.label_bytes(P.policy_file_label(path))
    assert raw.endswith(b"\0")
    print("CONDITIONAL_NATIVE_FILE_POLICY_QUERY=PASS")
PY
# Native policy for the exact multi-provider namespace (including separate
# credential databases); still no active kernel, file writes, or relabel.
python3 - <<'PY'
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "multi_label_policy", str(Path("linux/inspect-conditional-transport-selinux.py")))
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)
rules = [
    dict(selector="exact-envelope-sender", pattern="one@example.org",
         host="smtp.example.net", port=2526, tls="starttls", auth="password"),
    dict(selector="exact-envelope-sender", pattern="two@example.org",
         host="smtp.example.net", port=465, tls="implicit", auth="password"),
    dict(selector="envelope-sender-domain", pattern="other.example.org",
         host="smtp.example.net", port=25, tls="starttls", auth="none"),
]
for backend in ("hash", "lmdb"):
    plan, sources, labels = L.policy_labels(rules, backend)
    assert len(sources) == 3 and len(labels) == 6
    for value in labels.values():
        assert L.context(value)
    print("MULTI_TRANSPORT_NATIVE_SELINUX_POLICY=" + backend + ":PASS")
PY
python3 -m unittest discover -s tests -p test_conditional_transport_selinux.py
python3 -m unittest discover -s tests -p test_conditional_selinux_policy.py
python3 -m unittest discover -s tests -p test_rhel_selinux_doctor.py
python3 -m unittest discover -s tests -p test_rhel_selinux_port_manager.py
python3 -m unittest discover -s tests -p test_rhel_enforcing_live_smoke.py

test ! -e /run/systemd/system
test "$(getenforce)" = "$mode"
echo "SELINUX_OFFLINE_PACKAGE_POLICY_CHECK=passed"
echo "SELINUX_RUNTIME_ENFORCING_TESTED=no"
echo "SELINUX_SMTP_TLS_DELIVERY_TESTED=no"
