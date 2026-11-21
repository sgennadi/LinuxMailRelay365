#!/usr/bin/env bash
# Boot genuine Rocky Linux 9.9 VM under KVM with isolated disk and SSH key.
# No Microsoft 365 login, SMTP DATA, persisted credentials or production host.
set -Eeuo pipefail
bash tests/rocky_vm_kvm_probe.sh
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq qemu-system-x86 qemu-utils cloud-image-utils openssh-client curl ca-certificates >/dev/null
work="$(mktemp -d)"
cleanup() {
  result=$?
  if test -f "$work/vm.pid"; then
    pid="$(cat "$work/vm.pid" || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      sudo kill "$pid" 2>/dev/null || true
    fi
  fi
  if test "$result" -ne 0 && test -f "$work/console.log"; then
    echo "LMR365_GUEST_SERIAL_TAIL_BEGIN"
    tail -n 55 "$work/console.log" || true
    echo "LMR365_GUEST_SERIAL_TAIL_END"
  fi
  sudo rm -rf -- "$work"
  exit "$result"
}
trap cleanup EXIT

image="Rocky-9-GenericCloud-Base-9.9-20261112.0.x86_64.qcow2"
url="https://download.rockylinux.org/pub/rocky/9/images/x86_64"
curl --fail --silent --show-error --location --retry 3 --connect-timeout 20 --max-time 90 \
    "$url/$image.CHECKSUM" --output "$work/checksum"
curl --fail --silent --show-error --location --retry 3 --connect-timeout 20 --max-time 480 \
    "$url/$image" --output "$work/$image"
python3 - "$work/checksum" "$work/$image" <<'PY'
from pathlib import Path
import hashlib
import re
import sys
lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
image = Path(sys.argv[2])
matches = []
for line in lines:
    if image.name in line:
        value = re.search(r'(?<![a-fA-F0-9])([a-fA-F0-9]{64})(?![a-fA-F0-9])', line)
        if value:
            matches.append(value.group(1).lower())
if len(matches) != 1:
    raise SystemExit("LMR365_GUEST_IMAGE_CHECKSUM_MISSING_OR_AMBIGUOUS")
digest = hashlib.sha256()
with image.open("rb") as f:
    while True:
        data = f.read(1024 * 1024)
        if not data:
            break
        digest.update(data)
if digest.hexdigest() != matches[0]:
    raise SystemExit("LMR365_GUEST_IMAGE_SHA256_MISMATCH")
print("LMR365_GUEST_IMAGE_CHECKSUM=verified_sha256")
PY

ssh-keygen -q -t ed25519 -N "" -f "$work/guest-key"
cat > "$work/user-data" <<EOF
#cloud-config
disable_root: true
ssh_pwauth: false
users:
  - name: ci
    groups: [wheel]
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$work/guest-key.pub")
EOF
cat > "$work/meta-data" <<EOF
instance-id: lmr365-$GITHUB_RUN_ID
local-hostname: rocky-selinux-ci
EOF
cloud-localds "$work/seed.iso" "$work/user-data" "$work/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$work/$image" "$work/overlay.qcow2" 16G
echo "LMR365_GUEST_VM_START=kvm"
sudo qemu-system-x86_64 -machine q35,accel=kvm -cpu host -smp 2 -m 4096 \
  -drive "if=virtio,format=qcow2,file=$work/overlay.qcow2" \
  -drive "if=virtio,format=raw,file=$work/seed.iso,media=cdrom" \
  -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:22222-:22" \
  -device virtio-rng-pci -display none -monitor none \
  -serial "file:$work/console.log" -no-reboot -daemonize -pidfile "$work/vm.pid"

ssh_opts=(-o BatchMode=yes -o ConnectionAttempts=1 -o ConnectTimeout=4 \
  -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$work/known_hosts" \
  -i "$work/guest-key" -p 22222)
ready=no
for i in $(seq 1 100); do
  if ssh "${ssh_opts[@]}" ci@127.0.0.1 'echo ready' >/dev/null 2>&1; then
    ready=yes
    break
  fi
  if ! sudo kill -0 "$(cat "$work/vm.pid")" 2>/dev/null; then
    echo "LMR365_GUEST_VM_EXITED_BEFORE_SSH"
    exit 1
  fi
  sleep 5
done
test "$ready" = yes || { echo "LMR365_GUEST_SSH_TIMEOUT"; exit 1; }
echo "LMR365_GUEST_SSH=ready"

ssh "${ssh_opts[@]}" ci@127.0.0.1 'bash -s' <<'GUEST'
set -Eeuo pipefail
source /etc/os-release
test "$ID" = rocky
test "$VERSION_ID" = 9.9
test "$(uname -m)" = x86_64
test "$(cat /proc/1/comm)" = systemd
test "$(getenforce)" = Enforcing
test "$(cat /sys/fs/selinux/enforce)" = 1
sudo systemctl is-active --quiet sshd
echo "LMR365_GUEST_DISTRO=rocky_9_9"
echo "LMR365_GUEST_PID1=systemd"
echo "LMR365_GUEST_SELINUX=enforcing"
echo "LMR365_GUEST_SELINUXFS=active"
echo "LMR365_GUEST_SSHD=active"
GUEST

scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
    linux/rhel-selinux-doctor.py ci@127.0.0.1:/tmp/lmr365-doctor.py
ssh "${ssh_opts[@]}" ci@127.0.0.1 \
    'sudo python3 /tmp/lmr365-doctor.py --smtp-port 2525' > "$work/doctor"
grep -Fxq 'OS_FAMILY=rhel_family' "$work/doctor"
grep -Fxq 'SELINUX_MODE=enforcing' "$work/doctor"
grep -Fxq 'SMTP_AUTH_ENFORCING_TESTED=no' "$work/doctor"
grep -Fxq 'CHANGES_APPLIED=no' "$work/doctor"
grep -Eq '^SELINUX_ACCEPTANCE_STATUS=(smtp_port_policy_review|file_context_review|manual_avc_and_runtime_test_required)$' "$work/doctor"
echo "LMR365_GUEST_DOCTOR_ENFORCING=verified_read_only"
echo "LMR365_GUEST_MAIL_DELIVERY_TESTED=no"
echo "LMR365_GUEST_SMTP_AUTH_TESTED=no"
