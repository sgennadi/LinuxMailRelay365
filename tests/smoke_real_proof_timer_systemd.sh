#!/usr/bin/env bash
# Disposable GitHub-hosted Ubuntu systemd acceptance. Never use on user hosts.
# Only fixture oneshot/timer units are created. No MTA, SMTP or tenant activity.
set -Eeuo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ||
      "${EUID}" -ne 0 || "$(< /proc/1/comm)" != systemd ]]; then
  echo 'MULTI_PROOF_REAL_SYSTEMD=refused_non_disposable_host' >&2
  exit 2
fi
[[ "${RUNNER_TEMP:-}" == /home/runner/work/_temp* ]] || {
  echo 'MULTI_PROOF_REAL_SYSTEMD=refused_unknown_runner_temp' >&2
  exit 2
}
command -v systemctl >/dev/null
command -v python3 >/dev/null

name='linuxmailrelay365-multi-proof'
svc="/etc/systemd/system/${name}.service"
timer="/etc/systemd/system/${name}.timer"
[[ ! -e "$svc" && ! -L "$svc" && ! -e "$timer" && ! -L "$timer" ]] || {
  echo 'MULTI_PROOF_REAL_SYSTEMD=refused_existing_units' >&2
  exit 2
}
# Refuse to co-opt units already registered from any other path.
if [[ "$(systemctl show --property=LoadState --value "${name}.timer" 2>/dev/null || true)" == loaded ||
      "$(systemctl show --property=LoadState --value "${name}.service" 2>/dev/null || true)" == loaded ]]; then
  echo 'MULTI_PROOF_REAL_SYSTEMD=refused_preloaded_unit' >&2
  exit 2
fi

created=0
cleanup() {
  set +e
  if (( created == 1 )); then
    systemctl disable --now "${name}.timer" >/dev/null 2>&1
    systemctl stop "${name}.service" >/dev/null 2>&1
    if grep -Fqx 'Description=LinuxMailRelay365 CI-only inert proof status service' "$svc" 2>/dev/null &&
       grep -Fqx 'Description=LinuxMailRelay365 CI-only inert proof status timer' "$timer" 2>/dev/null; then
      rm -f -- "$svc" "$timer"
      systemctl daemon-reload >/dev/null 2>&1
    else
      echo 'MULTI_PROOF_REAL_SYSTEMD_CLEANUP=manual_review_unexpected_file' >&2
    fi
  fi
}
trap cleanup EXIT
umask 077
( set -o noclobber; cat > "$svc" <<'EOF'
[Unit]
Description=LinuxMailRelay365 CI-only inert proof status service
[Service]
Type=oneshot
ExecStart=/usr/bin/true
EOF
)
created=1
( set -o noclobber; cat > "$timer" <<'EOF'
[Unit]
Description=LinuxMailRelay365 CI-only inert proof status timer
[Timer]
OnBootSec=12h
OnUnitActiveSec=12h
Persistent=false
Unit=linuxmailrelay365-multi-proof.service
[Install]
WantedBy=timers.target
EOF
)
chmod 0644 "$svc" "$timer"
systemctl daemon-reload

# Import the actual protected manager, with hard-coded production unit paths.
# This test does not call enable()/disable(), which require a real sender map.
python3 - <<'PY'
import importlib.util
from pathlib import Path
p = Path("linux/manage-multi-mailbox-proof-timer.py")
spec = importlib.util.spec_from_file_location("proof_manager_live_status", str(p))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert mod.systemctl("is-active", "--quiet", mod.TIMER.name,
                     allow_inactive=True) is False
assert mod.systemctl("is-active", "--quiet", mod.SERVICE.name,
                     allow_inactive=True) is False
assert mod.systemctl("is-enabled", "--quiet", mod.TIMER.name,
                     allow_inactive=True) is False
print("MULTI_PROOF_REAL_SYSTEMD_INACTIVE_DISABLED=verified")
PY

systemctl enable --now "${name}.timer" >/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location(
    "proof_manager_live_enabled", "linux/manage-multi-mailbox-proof-timer.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert mod.systemctl("is-active", "--quiet", mod.TIMER.name,
                     allow_inactive=True) is True
assert mod.systemctl("is-enabled", "--quiet", mod.TIMER.name,
                     allow_inactive=True) is True
print("MULTI_PROOF_REAL_SYSTEMD_ACTIVE_ENABLED=verified")
PY

systemctl disable --now "${name}.timer" >/dev/null
systemctl stop "${name}.service"
python3 - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location(
    "proof_manager_live_disabled", "linux/manage-multi-mailbox-proof-timer.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
for args in (("is-active", "--quiet", mod.TIMER.name),
             ("is-active", "--quiet", mod.SERVICE.name),
             ("is-enabled", "--quiet", mod.TIMER.name)):
    assert mod.systemctl(*args, allow_inactive=True) is False
print("MULTI_PROOF_REAL_SYSTEMD_STOPPED_DISABLED=verified")
PY

# Remove only the CI-owned fixture, then verify a missing unit cannot masquerade
# as a safe, inactive/disabled timer after reload.
if ! grep -Fqx 'Description=LinuxMailRelay365 CI-only inert proof status service' "$svc" ||
   ! grep -Fqx 'Description=LinuxMailRelay365 CI-only inert proof status timer' "$timer"; then
  echo 'MULTI_PROOF_REAL_SYSTEMD=changed_fixture_refused' >&2
  exit 2
fi
rm -f -- "$svc" "$timer"
systemctl daemon-reload
created=0
python3 - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location(
    "proof_manager_live_missing", "linux/manage-multi-mailbox-proof-timer.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
for args in (("is-active", "--quiet", mod.TIMER.name),
             ("is-active", "--quiet", mod.SERVICE.name),
             ("is-enabled", "--quiet", mod.TIMER.name)):
    try:
        mod.systemctl(*args, allow_inactive=True)
    except mod.Refused:
        continue
    raise AssertionError("Missing unit was accepted as safely disabled")
print("MULTI_PROOF_REAL_SYSTEMD_MISSING_UNIT=refused")
PY
echo 'MULTI_PROOF_REAL_SYSTEMD=passed_disposable_without_mail'
