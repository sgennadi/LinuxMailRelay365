#!/usr/bin/env bash
# Host KVM capability probe only: no VM image, package changes or secrets.
set -Eeuo pipefail

echo "LMR365_KVM_PROBE_VERSION=1"
echo "LMR365_RUNNER_KERNEL=$(uname -s)"
echo "LMR365_RUNNER_ARCH=$(uname -m)"
if test "$(uname -s)" != Linux || test "$(uname -m)" != x86_64; then
  echo "LMR365_KVM_STATUS=unsupported_runner_arch"
  exit 2
fi
if test ! -c /dev/kvm; then
  echo "LMR365_KVM_STATUS=device_absent"
  exit 2
fi
# Verify the actual kernel KVM API, not merely ls -l or CPU flags.
sudo python3 - <<'PY'
import fcntl
import os

KVM_GET_API_VERSION = 0xAE00
try:
    fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    try:
        version = fcntl.ioctl(fd, KVM_GET_API_VERSION, 0)
    finally:
        os.close(fd)
except OSError as exc:
    raise SystemExit("LMR365_KVM_STATUS=ioctl_failed:" + str(exc.errno))
if version != 12:
    raise SystemExit("LMR365_KVM_STATUS=unsupported_api:" + str(version))
print("LMR365_KVM_API_VERSION=12")
print("LMR365_KVM_STATUS=available")
PY

# A real Rocky Linux guest kernel with SELinux must be booted separately.
echo "LMR365_GUEST_BOOT_TESTED=no"
echo "LMR365_GUEST_ENFORCING_TESTED=no"
echo "LMR365_SMTP_AUTH_TESTED=no"
