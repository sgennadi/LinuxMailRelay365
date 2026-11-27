#!/usr/bin/env bash
# Boot genuine Rocky Linux 9.9 (full suite) or 10.3 (native TPM provider)
# under KVM with isolated disk and SSH key.
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
    pid="$(sudo cat "$work/vm.pid" || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      sudo kill "$pid" 2>/dev/null || true
    fi
  fi
  if test -f "$work/tpm.pid"; then
    pid="$(cat "$work/tpm.pid" || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  fi
  if test "$result" -ne 0 && test -f "$work/console.log"; then
    echo "LMR365_GUEST_SERIAL_TAIL_BEGIN"
    sudo tail -n 55 "$work/console.log" || true
    echo "LMR365_GUEST_SERIAL_TAIL_END"
  fi
  sudo rm -rf -- "$work"
  exit "$result"
}
trap cleanup EXIT

# Rocky 9 remains the full existing acceptance suite. Rocky 10 is a
# separate, mandatory-provider experiment; it cannot substitute for Rocky 9.
case "${LMR365_KVM_ROCKY_MAJOR:-9}" in
  9)
    image="Rocky-9-GenericCloud-Base-9.9-20261112.0.x86_64.qcow2"
    url="https://download.rockylinux.org/pub/rocky/9/images/x86_64"
    expected_version=9.9
    ;;
  10)
    test "${LMR365_KVM_VTPM_ACCEPTANCE:-false}" = true
    test "${LMR365_KVM_VTPM_PROVIDER_REQUIRED:-false}" = true
    test "${LMR365_KVM_QUEUE_ACCEPTANCE:-false}" = false
    test "${LMR365_KVM_PRIMARY_MAILBOX_ACCEPTANCE:-false}" = false
    test "${LMR365_KVM_CLIENT_TLS_ACCEPTANCE:-false}" = false
    image="Rocky-10-GenericCloud-Base-10.3-20261112.0.x86_64.qcow2"
    url="https://download.rockylinux.org/pub/rocky/10/images/x86_64"
    expected_version=10.3
    ;;
  *) echo "LMR365_GUEST_UNSUPPORTED_ROCKY_MAJOR"; exit 1 ;;
esac
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
# Sendmail's default resolver can wait 60 seconds for an unqualified name.
# Give the disposable guest a local-only FQDN without depending on external DNS.
hostname: rocky-selinux-ci
fqdn: rocky-selinux-ci.example.invalid
prefer_fqdn_over_hostname: false
manage_etc_hosts: true
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
local-hostname: rocky-selinux-ci.example.invalid
EOF
cloud-localds "$work/seed.iso" "$work/user-data" "$work/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$work/$image" "$work/overlay.qcow2" 16G
tpm_args=()
if test "${LMR365_KVM_VTPM_ACCEPTANCE:-false}" = "true"; then
  # New, private simulator state; never attach the runner's physical TPM.
  sudo apt-get install -y -qq swtpm >/dev/null
  install -d -m 0700 "$work/tpm-state"
  swtpm socket --tpm2 --tpmstate dir="$work/tpm-state" \
    --ctrl type=unixio,path="$work/tpm.sock" --pid file="$work/tpm.pid" --daemon
  test -S "$work/tpm.sock" && test -s "$work/tpm.pid"
  tpm_args=(-chardev "socket,id=lmr-tpm,path=$work/tpm.sock"
            -tpmdev emulator,id=lmr-tpm-dev,chardev=lmr-tpm
            -device tpm-tis,tpmdev=lmr-tpm-dev)
  echo "LMR365_GUEST_TPM=isolated_swtpm2"
fi
echo "LMR365_GUEST_VM_START=kvm"
sudo qemu-system-x86_64 -machine q35,accel=kvm -cpu host -smp 2 -m 4096 "${tpm_args[@]}" \
  -drive "if=virtio,format=qcow2,file=$work/overlay.qcow2" \
  -drive "if=virtio,format=raw,file=$work/seed.iso,media=cdrom" \
  -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:22222-:22" \
  -device virtio-rng-pci -display none -monitor none \
  -serial "file:$work/console.log" -daemonize -pidfile "$work/vm.pid"

ssh_opts=(-o BatchMode=yes -o ConnectionAttempts=1 -o ConnectTimeout=4 \
  -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$work/known_hosts" \
  -i "$work/guest-key" -p 22222)
ready=no
for i in $(seq 1 100); do
  if ssh "${ssh_opts[@]}" ci@127.0.0.1 'echo ready' >/dev/null 2>&1; then
    ready=yes
    break
  fi
  if ! sudo kill -0 "$(sudo cat "$work/vm.pid")" 2>/dev/null; then
    echo "LMR365_GUEST_VM_EXITED_BEFORE_SSH"
    exit 1
  fi
  sleep 5
done
test "$ready" = yes || { echo "LMR365_GUEST_SSH_TIMEOUT"; exit 1; }
echo "LMR365_GUEST_SSH=ready"

ssh "${ssh_opts[@]}" ci@127.0.0.1 "bash -s -- '$expected_version'" <<'GUEST'
set -Eeuo pipefail
source /etc/os-release
test "$ID" = rocky
test "$VERSION_ID" = "$1"
case "$1" in 9.9|10.3) ;; *) exit 1 ;; esac
test "$(uname -m)" = x86_64
test "$(cat /proc/1/comm)" = systemd
test "$(getenforce)" = Enforcing
test "$(cat /sys/fs/selinux/enforce)" = 1
sudo systemctl is-active --quiet sshd
# Fail fast if cloud-init did not create the guest's local hostname mapping.
# No hostname or DNS setting on the runner or any real mail server is changed.
test "$(hostname -s)" = rocky-selinux-ci
test "$(timeout 5 hostname -f)" = rocky-selinux-ci.example.invalid
getent -s files hosts rocky-selinux-ci.example.invalid >/dev/null
getent -s files hosts rocky-selinux-ci >/dev/null
echo "LMR365_GUEST_LOCAL_FQDN=verified"
echo "LMR365_GUEST_DISTRO=rocky_${VERSION_ID//./_}"
echo "LMR365_GUEST_PID1=systemd"
echo "LMR365_GUEST_SELINUX=enforcing"
echo "LMR365_GUEST_SELINUXFS=active"
echo "LMR365_GUEST_SSHD=active"
GUEST

if test "$expected_version" = 9.9; then
# Real systemd + SELinux Enforcing; a synthetic auditor exercises only the
# optional proof-timer lifecycle, NOT mail authentication or cloud delivery.
scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
    linux/manage-multi-mailbox-proof-timer.py \
    ci@127.0.0.1:/home/ci/lmr365-proof-timer-manager.py
scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
    tests/rocky_vm_multi_proof_timer_enforcing.sh \
    ci@127.0.0.1:/home/ci/lmr365-proof-timer-smoke.sh
ssh "${ssh_opts[@]}" ci@127.0.0.1 \
    'sudo env GITHUB_ACTIONS=true bash /home/ci/lmr365-proof-timer-smoke.sh' \
    > "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_PREVIEW=read_only' "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_SYSTEMD=active_under_enforcing' "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_SCHEDULED=renewed' "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_RECEIPT_INITIAL=fresh_ttl_only' "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_RECEIPT_RENEWED=fresh_ttl_only' "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_RECEIPT_MAP_DRIFT=detected' "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_RECEIPT_RECOVERY=fresh_ttl_only' "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_RECEIPT_REVOKED=not_applicable' "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_MAP_DRIFT=fail_closed' "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_MAP_RECOVERY=verified' "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_REVOCATION=verified' "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_FIXTURE=removed' "$work/proof-timer"
grep -Fxq 'LMR365_VM_TIMER_REAL_M365_ACCEPTANCE=no' "$work/proof-timer"
echo 'LMR365_GUEST_PROOF_TIMER=synthetic_systemd_lifecycle_under_enforcing_verified'

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
fi

run_postfix_smoke() {
    # Test an actual guest Postfix daemon under SELinux Enforcing. Its SMTP
    # listener is loopback-only; do not create mail or contact any relay.
    scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
        tests/rocky_vm_postfix_enforcing.sh ci@127.0.0.1:/tmp/lmr365-postfix-smoke.sh
    ssh "${ssh_opts[@]}" ci@127.0.0.1 \
        'bash /tmp/lmr365-postfix-smoke.sh'
}
if test "$expected_version" = 9.9; then
    run_postfix_smoke
fi

# Independent virtual TPM acceptance. The native pipe tests remain separate.
if test "${LMR365_KVM_VTPM_ACCEPTANCE:-false}" = "true"; then
    scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
        linux/manage-tpm-oauth-key.py tests/rocky_vm_primary_tpm_device.py \
        linux/inspect-conditional-postfix-activation.py linux/conditional-postfix-transaction.py \
        linux/stage-conditional-postfix-maps.py \
        ci@127.0.0.1:/home/ci/
    ssh "${ssh_opts[@]}" ci@127.0.0.1 'bash -s' <<'VTPM_SETUP' | tee "$work/vtpm-receipt"
set -Eeuo pipefail
sudo dnf -y -q install tpm2-tools openssl policycoreutils
provider=unavailable
source /etc/os-release
if test "$VERSION_ID" = 10.3; then
    # TPM acceptance precedes the still-mandatory Postfix startup smoke.
    sudo dnf -y -q install postfix
    sudo systemctl stop postfix.service
    sudo postconf -e 'inet_interfaces = loopback-only'
    sudo postconf -e 'inet_protocols = ipv4'
    sudo postconf -e 'relayhost ='
    sudo postfix check
    # Mandatory distro-native provider; no third-party repo or source build.
    sudo dnf -y -q install tpm2-openssl
    rpm -q tpm2-openssl
    provider=present
elif rpm -q tpm2-openssl >/dev/null; then
    provider=present
else
    # Only already configured signed distribution repositories. Do not
    # silently introduce a third-party provider or compile unreviewed code.
    candidates="$(dnf -q repoquery --available --qf '%{name}' tpm2-openssl)"
    if grep -Fxq tpm2-openssl <<<"$candidates"; then
        sudo dnf -y -q install tpm2-openssl
        provider=present
    fi
fi
sudo install -d -o root -g root -m 0755 /usr/local/libexec/lmr365-kvm-vtpm
sudo install -o root -g root -m 0644 /home/ci/manage-tpm-oauth-key.py /home/ci/rocky_vm_primary_tpm_device.py /home/ci/inspect-conditional-postfix-activation.py /home/ci/conditional-postfix-transaction.py /home/ci/stage-conditional-postfix-maps.py /usr/local/libexec/lmr365-kvm-vtpm/
sudo restorecon -R /usr/local/libexec/lmr365-kvm-vtpm
sudo install -o root -g root -m 0600 /dev/null /run/lmr365-disposable-vtpm-vm
sudo sh -c "cat /proc/sys/kernel/random/boot_id > /run/lmr365-disposable-vtpm-vm"
sudo env GITHUB_ACTIONS=true LMR365_KVM_VTPM_GUEST=true LMR365_VTPM_PROVIDER_PACKAGE="$provider" \
    /usr/bin/python3 -B /usr/local/libexec/lmr365-kvm-vtpm/rocky_vm_primary_tpm_device.py
VTPM_SETUP
    for expected in \
        'LMR365_VM_VTPM_DENIAL=refused_before_key_creation' \
        'LMR365_VM_VTPM_OPEN=verified_exact_service_credentials' \
        'LMR365_VM_VTPM_DEVICE=original_metadata_restored' \
        'LMR365_VM_VTPM_PHYSICAL_HARDWARE=no' \
        'LMR365_VM_VTPM_PIPE_DOMAIN_TESTED=no' \
        'LMR365_VM_VTPM_CLOUD_OR_MAIL_TESTED=no'; do
        grep -Fxq "$expected" "$work/vtpm-receipt"
    done
    # BEGIN VTPM_PROVIDER_RECEIPT_CHECK
    if test "${LMR365_KVM_VTPM_PROVIDER_REQUIRED:-false}" = true; then
        grep -Fxq 'LMR365_VM_VTPM_PROVIDER=native_openssl3_provider' "$work/vtpm-receipt"
    fi
    if grep -Fxq 'LMR365_VM_VTPM_PROVIDER=native_openssl3_provider' "$work/vtpm-receipt"; then
        grep -Fxq 'LMR365_VM_VTPM_PS256=verified_emulated_tpm_certificate' "$work/vtpm-receipt"
        grep -Fxq 'TPM_PROVISION_SERVICE_ACCOUNT_PS256_VERIFIED=yes' "$work/vtpm-receipt"
        grep -Fxq 'TPM_PROVISION_PERSISTENT_KEY_CREATED=yes' "$work/vtpm-receipt"
        grep -Fxq 'TPM_PROVISION_CERTIFICATE_CREATED=yes' "$work/vtpm-receipt"
        if grep -Fxq 'LMR365_VM_VTPM_PS256=not_tested' "$work/vtpm-receipt" ||
           grep -Fxq 'LMR365_VM_VTPM_PROVIDER=unavailable_in_configured_repos' "$work/vtpm-receipt"; then
            exit 1
        fi
    else
        grep -Fxq 'LMR365_VM_VTPM_PROVIDER=unavailable_in_configured_repos' "$work/vtpm-receipt"
        grep -Fxq 'LMR365_VM_VTPM_PS256=not_tested' "$work/vtpm-receipt"
        if grep -Fxq 'LMR365_VM_VTPM_PS256=verified_emulated_tpm_certificate' "$work/vtpm-receipt"; then
            exit 1
        fi
    fi
    # END VTPM_PROVIDER_RECEIPT_CHECK
fi
if test "$expected_version" = 10.3; then
    grep -Fxq 'LMR365_VM_VTPM_POSTFIX_SCOPE=stopped_empty_native_queue' "$work/vtpm-receipt"
    grep -Fxq 'LMR365_VM_VTPM_NATIVE_SANDBOX=private_devices_without_bind' "$work/vtpm-receipt"
    echo "LMR365_GUEST_VTPM_NATIVE_PROVIDER_ONLY=passed"
    # Normalize only the mislabeled, empty package data directory in this
    # newly created Rocky 10.3 VM. This is NOT a production installer action.
    # Keep the actual Postfix startup and domain/listener assertions mandatory.
    ssh "${ssh_opts[@]}" ci@127.0.0.1 'bash -s' <<'ROCKY10_DATA_CONTEXT'
set -Eeuo pipefail
source /etc/os-release
test "$ID" = rocky && test "$VERSION_ID" = 10.3
test "$(hostname -s)" = rocky-selinux-ci
test "$(cat /proc/1/comm)" = systemd
test "$(getenforce)" = Enforcing
test "$(cat /sys/fs/selinux/enforce)" = 1
test "$(sudo systemctl show -p ActiveState --value postfix.service)" = inactive
test "$(sudo postconf -xh data_directory)" = /var/lib/postfix
test "$(sudo postconf -xh queue_directory)" = /var/spool/postfix
test "$(sudo postconf -xh mail_owner)" = postfix
test "$(sudo postconf -xh inet_interfaces)" = loopback-only
test -z "$(sudo postconf -xh relayhost)"
test -z "$(sudo postqueue -j)"
for path in /var /var/lib /var/lib/postfix; do
    sudo test -d "$path"
    sudo test ! -L "$path"
done
test "$(sudo stat -c %u /var/lib/postfix)" = "$(id -u postfix)"
test "$(sudo stat -c %a /var/lib/postfix)" = 700
test -z "$(sudo find /var/lib/postfix -mindepth 1 -maxdepth 1 -print -quit)"
before="$(sudo stat -c '%d:%i:%u:%g:%a' /var/lib/postfix)"
expected="$(sudo matchpathcon -N -n -m dir /var/lib/postfix)"
test "$expected" = system_u:object_r:postfix_data_t:s0
actual="$(sudo stat -c %C /var/lib/postfix)"
echo "LMR365_GUEST_POSTFIX_DATA_CONTEXT_BEFORE=$actual"
if test "$actual" = "$expected"; then
    echo "LMR365_GUEST_POSTFIX_DATA_CONTEXT_ACTION=already_correct"
else
    case "$actual" in
        *:object_r:var_lib_t:s0) ;;
        *) echo "LMR365_GUEST_POSTFIX_DATA_CONTEXT_UNEXPECTED"; exit 1 ;;
    esac
    # Use the installed policy, never chcon, chmod, chown or a policy override.
    sudo restorecon -F -v /var/lib/postfix
    echo "LMR365_GUEST_POSTFIX_DATA_CONTEXT_ACTION=restored_native_label"
fi
test "$(sudo stat -c %C /var/lib/postfix)" = "$expected"
sudo matchpathcon -V /var/lib/postfix
test "$(sudo stat -c '%d:%i:%u:%g:%a' /var/lib/postfix)" = "$before"
test -z "$(sudo find /var/lib/postfix -mindepth 1 -maxdepth 1 -print -quit)"
test "$(getenforce)" = Enforcing
echo "LMR365_GUEST_POSTFIX_DATA_CONTEXT=verified_unchanged_dac"
ROCKY10_DATA_CONTEXT
    run_postfix_smoke
    echo "LMR365_GUEST_VTPM_ROCKY10_POSTFIX_SMOKE=passed"
    exit 0
fi

# Native two-file XOAUTH2 transaction with real SELinux labels. This is
# separate from SMTP AUTH/pipe acceptance and uses a boot-bound lab marker.
if test "${LMR365_KVM_PRIMARY_MAILBOX_ACCEPTANCE:-false}" = "true"; then
    scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
        linux/manage-primary-mailbox-offline.py linux/primary-mailbox-transaction.py \
        linux/primary-mailbox-runtime.py linux/manage-tpm-oauth-key.py \
        linux/preview-primary-mailbox-route.py linux/export-hardware-oauth-cert.py \
        linux/manage-primary-oauth-rotation.py linux/manage-conditional-postfix-offline.py \
        linux/inspect-conditional-postfix-activation.py linux/conditional-postfix-transaction.py \
        linux/stage-conditional-postfix-maps.py tests/rocky_vm_primary_mailbox_enforcing.py \
        linux/m365_xoauth2_transport.py linux/m365_hardware_signer.py \
        linux/inspect-primary-mailbox-selinux.py \
        tests/rocky_vm_primary_pipe_worker.py tests/rocky_vm_primary_pipe_enforcing.py \
        ci@127.0.0.1:/home/ci/
    ssh "${ssh_opts[@]}" ci@127.0.0.1 \
        'sudo dnf -y -q install policycoreutils policycoreutils-python-utils && sudo install -d -o root -g root -m 0755 /usr/local/libexec/lmr365-kvm-primary-mailbox && sudo install -o root -g root -m 0644 /home/ci/manage-primary-mailbox-offline.py /home/ci/primary-mailbox-transaction.py /home/ci/primary-mailbox-runtime.py /home/ci/manage-tpm-oauth-key.py /home/ci/preview-primary-mailbox-route.py /home/ci/export-hardware-oauth-cert.py /home/ci/manage-primary-oauth-rotation.py /home/ci/manage-conditional-postfix-offline.py /home/ci/inspect-conditional-postfix-activation.py /home/ci/conditional-postfix-transaction.py /home/ci/stage-conditional-postfix-maps.py /home/ci/rocky_vm_primary_mailbox_enforcing.py /home/ci/m365_xoauth2_transport.py /home/ci/m365_hardware_signer.py /home/ci/rocky_vm_primary_pipe_worker.py /home/ci/rocky_vm_primary_pipe_enforcing.py /home/ci/inspect-primary-mailbox-selinux.py /usr/local/libexec/lmr365-kvm-primary-mailbox/ && sudo restorecon -R /usr/local/libexec/lmr365-kvm-primary-mailbox && sudo install -o root -g root -m 0600 /dev/null /run/lmr365-disposable-primary-mailbox-vm && sudo sh -c "cat /proc/sys/kernel/random/boot_id > /run/lmr365-disposable-primary-mailbox-vm"'
    ssh "${ssh_opts[@]}" ci@127.0.0.1 \
        'sudo env GITHUB_ACTIONS=true timeout 900 python3 -I -B /usr/local/libexec/lmr365-kvm-primary-mailbox/rocky_vm_primary_mailbox_enforcing.py' | tee "$work/primary-mailbox"
    # BEGIN PRIMARY_VM_RECEIPT_CHECK
    grep -Eq '^LMR365_PRIMARY_VM_LABEL_MISMATCH=(refused_without_write|not_present)$' "$work/primary-mailbox"
    for expected in \
        'LMR365_PRIMARY_VM_FIXTURE_POLICY=exact_context_baseline' \
        'LMR365_PRIMARY_VM_REVIEW=native_policy_and_postconf' \
        'LMR365_PRIMARY_VM_APPLY=verified_native_labels' \
        'LMR365_PRIMARY_VM_BACKUP=verified_native_private_labels' \
        'LMR365_PRIMARY_VM_RESTORE=exact_bytes_metadata_and_native' \
        'LMR365_PRIMARY_VM_ENFORCING_REVIEW=native_runtime_synthetic_auth' \
        'LMR365_PRIMARY_VM_PIPE_DOMAIN=postfix_pipe_t' \
        'LMR365_PRIMARY_VM_PIPE_PS256=verified_fixture_certificate' \
        'LMR365_PRIMARY_VM_PIPE_QUEUE=correlated_and_empty' \
        'LMR365_PRIMARY_VM_PIPE_TCP443=loopback_verified' \
        'LMR365_PRIMARY_VM_PIPE_TCP587=loopback_verified' \
        'LMR365_PRIMARY_VM_PIPE_BASELINE=restored_exact_bytes' \
        'LMR365_PRIMARY_VM_BASELINE=running_restored' \
        'LMR365_PRIMARY_VM_REAL_OAUTH_AUTH=no' \
        'LMR365_PRIMARY_VM_REAL_PIPE_DELIVERY=no'; do
        grep -Fxq "$expected" "$work/primary-mailbox"
    done
    # END PRIMARY_VM_RECEIPT_CHECK
fi

# Opt-in outbound TLS certificate acceptance, before foreign-MTA scenarios.
if test "${LMR365_KVM_CLIENT_TLS_ACCEPTANCE:-false}" = "true"; then
    scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
        linux/stage-smtp-relay-certificate.py linux/check-smtp-relay-certificate.py \
        linux/smtp-tls-generation.py linux/smtp-tls-transaction.py linux/smtp-tls-activate.py \
        linux/smtp-tls-postfix.py linux/smtp-tls-validate-generation.py linux/smtp-tls-selinux-prepare.py \
        linux/smtp-tls-initial-backup.py linux/smtp-tls-initial-candidate.py linux/smtp-tls-initial-journal.py \
        linux/smtp-tls-initial-deploy.py linux/plan-smtp-tls-initial.py linux/manage-smtp-tls-initial.py \
        linux/manage-smtp-tls-renewal.py linux/systemd/linuxmailrelay365-smtp-tls-initial-recovery.service \
        linux/systemd/linuxmailrelay365-smtp-tls-prestart.service \
        linux/systemd/linuxmailrelay365-smtp-tls-recovery.service \
        linux/systemd/linuxmailrelay365-smtp-acme-renew.service linux/systemd/linuxmailrelay365-smtp-acme-renew.timer \
        linux/manage-smtp-tls-process-renewal.py linux/smtp-tls-process-renewal.py linux/smtp-tls-renewal-profile.py \
        tests/rocky_vm_smtp_tls_renewal.py tests/rocky_vm_smtp_client_tls_enforcing.py ci@127.0.0.1:/home/ci/
    ssh "${ssh_opts[@]}" ci@127.0.0.1 \
        'sudo dnf -y -q install openssl policycoreutils && sudo install -d -o root -g root -m 0755 /usr/local/libexec/lmr365-kvm-client-tls && sudo install -o root -g root -m 0644 /home/ci/stage-smtp-relay-certificate.py /home/ci/check-smtp-relay-certificate.py /home/ci/smtp-tls-*.py /home/ci/plan-smtp-tls-initial.py /home/ci/manage-smtp-tls-initial.py /home/ci/manage-smtp-tls-renewal.py /home/ci/manage-smtp-tls-process-renewal.py /home/ci/rocky_vm_smtp_tls_renewal.py /home/ci/rocky_vm_smtp_client_tls_enforcing.py /usr/local/libexec/lmr365-kvm-client-tls/ && sudo restorecon -R /usr/local/libexec/lmr365-kvm-client-tls && sudo install -o root -g root -m 0600 /dev/null /run/lmr365-disposable-client-tls-vm && sudo sh -c "cat /proc/sys/kernel/random/boot_id > /run/lmr365-disposable-client-tls-vm"'
    ssh "${ssh_opts[@]}" ci@127.0.0.1 \
        'sudo install -d -o root -g root -m 0755 /usr/local/libexec/lmr365-kvm-client-tls/systemd && sudo install -o root -g root -m 0644 /home/ci/linuxmailrelay365-smtp-tls-initial-recovery.service /home/ci/linuxmailrelay365-smtp-tls-prestart.service /home/ci/linuxmailrelay365-smtp-tls-recovery.service /home/ci/linuxmailrelay365-smtp-acme-renew.service /home/ci/linuxmailrelay365-smtp-acme-renew.timer /usr/local/libexec/lmr365-kvm-client-tls/systemd/ && sudo restorecon -R /usr/local/libexec/lmr365-kvm-client-tls'
    ssh "${ssh_opts[@]}" ci@127.0.0.1 \
        'sudo env GITHUB_ACTIONS=true python3 -I -B /usr/local/libexec/lmr365-kvm-client-tls/rocky_vm_smtp_client_tls_enforcing.py --prepare-reboot' | tee "$work/client-tls"
    grep -Fxq 'LMR365_VM_CLIENT_TLS_REBOOT_PREPARED=switched' "$work/client-tls"
    client_tls_boot="$(ssh "${ssh_opts[@]}" ci@127.0.0.1 'cat /proc/sys/kernel/random/boot_id')"
    [[ "$client_tls_boot" =~ ^[0-9a-f-]{36}$ ]] || exit 1
    ssh "${ssh_opts[@]}" ci@127.0.0.1 'sudo systemctl reboot' >/dev/null 2>&1 || true
    client_tls_rebooted=no
    for i in $(seq 1 90); do
        client_tls_new_boot="$(ssh "${ssh_opts[@]}" ci@127.0.0.1 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)"
        if [[ "$client_tls_new_boot" =~ ^[0-9a-f-]{36}$ ]] && test "$client_tls_new_boot" != "$client_tls_boot"; then
            client_tls_rebooted=yes
            break
        fi
        sleep 5
    done
    test "$client_tls_rebooted" = yes || { echo "LMR365_VM_CLIENT_TLS_REBOOT_TIMEOUT"; exit 1; }
    ssh "${ssh_opts[@]}" ci@127.0.0.1 \
        'state=$(sudo timeout 90 systemctl is-system-running --wait || true); case "$state" in running|degraded) ;; *) echo LMR365_VM_CLIENT_TLS_BOOT_STATE_UNVERIFIED; exit 1;; esac; sudo env GITHUB_ACTIONS=true python3 -I -B /usr/local/libexec/lmr365-kvm-client-tls/rocky_vm_smtp_client_tls_enforcing.py --verify-reboot' | tee -a "$work/client-tls"
    for expected in \
        'LMR365_VM_CLIENT_TLS_INITIAL=presented_verified' \
        'LMR365_VM_CLIENT_TLS_ROTATION=presented_verified' \
        'LMR365_VM_CLIENT_TLS_ROLLBACK=presented_verified' \
        'LMR365_VM_CLIENT_TLS_RECOVERY=presented_verified' \
        'LMR365_VM_CLIENT_TLS_REBOOT_ORDER=verified_before_postfix' \
        'LMR365_VM_CLIENT_TLS_BOOT_RECOVERY=presented_verified' \
        'LMR365_VM_CLIENT_TLS_TIMER_TRIGGER=verified_exact_usec' \
        'LMR365_VM_CLIENT_TLS_TIMER=synthetic_material_processed' \
        'LMR365_VM_CLIENT_TLS_TIMER_RENEWAL=presented_verified' \
        'LMR365_VM_CLIENT_TLS_RENEWAL_UNCHANGED=verified' \
        'LMR365_VM_CLIENT_TLS_RENEWAL_MIXED=refused' \
        'LMR365_VM_CLIENT_TLS_RENEWAL_REFUSAL=presented_verified' \
        'LMR365_VM_CLIENT_TLS_RENEWAL_REAL_CA=no' \
        'LMR365_VM_CLIENT_TLS_BASELINE=restored_exact_bytes' \
        'LMR365_VM_CLIENT_TLS_EXTERNAL_DELIVERY=no'; do
        grep -Fxq "$expected" "$work/client-tls"
    done
fi

# Run actual sidecar installers under guest SELinux Enforcing and verify
# that they refuse safely without changing primary Postfix or mail queues.
scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
    linux/install-preserve-postfix-sidecar.sh \
    linux/install-direct-send-sidecar.sh \
    linux/install-connector-sidecar.sh \
    linux/enable-sidecar-auth-tls.sh \
    tests/rocky_vm_sidecar_installer_guard.sh \
    ci@127.0.0.1:/home/ci/
ssh "${ssh_opts[@]}" ci@127.0.0.1 \
    'bash /home/ci/rocky_vm_sidecar_installer_guard.sh'
echo "LMR365_GUEST_REAL_SIDECAR_INSTALLER_GUARDS=verified"

# Tenant-free loopback-only STARTTLS and SMTP AUTH acceptance inside the VM.
scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
    tests/rocky_vm_tls_auth_enforcing.sh ci@127.0.0.1:/home/ci/lmr365-tls-auth-ci.sh
scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
    linux/manage-rhel-selinux-port.py ci@127.0.0.1:/home/ci/lmr365-selinux-port.py
ssh "${ssh_opts[@]}" ci@127.0.0.1 \
    'sudo install -d -o root -g root -m 0755 /usr/local/libexec && sudo install -o root -g root -m 0755 /home/ci/lmr365-selinux-port.py /usr/local/libexec/lmr365-selinux-port.py'
ssh "${ssh_opts[@]}" ci@127.0.0.1 \
    'bash /home/ci/lmr365-tls-auth-ci.sh --setup'
echo "LMR365_GUEST_AUTH_TLS_SETUP=verified"

old_boot_id="$(ssh "${ssh_opts[@]}" ci@127.0.0.1 'cat /proc/sys/kernel/random/boot_id')"
if ! [[ "$old_boot_id" =~ ^[0-9a-f-]{36}$ ]]; then
    echo "LMR365_GUEST_OLD_BOOT_ID_UNVERIFIED"
    exit 1
fi
ssh "${ssh_opts[@]}" ci@127.0.0.1 'sudo systemctl reboot' >/dev/null 2>&1 || true
rebooted=no
for attempt in $(seq 1 90); do
    new_boot_id="$(ssh "${ssh_opts[@]}" ci@127.0.0.1 \
        'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)"
    if [[ "$new_boot_id" =~ ^[0-9a-f-]{36}$ ]] &&
       test "$new_boot_id" != "$old_boot_id"; then
        rebooted=yes
        break
    fi
    if ! sudo kill -0 "$(sudo cat "$work/vm.pid")" 2>/dev/null; then
        echo "LMR365_GUEST_REBOOT_QEMU_EXITED"
        exit 1
    fi
    sleep 5
done
test "$rebooted" = yes || {
    echo "LMR365_GUEST_REBOOT_BOOT_ID_UNCHANGED"
    exit 1
}
echo "LMR365_GUEST_REBOOT=verified_new_boot_id"
ssh "${ssh_opts[@]}" ci@127.0.0.1 'bash /home/ci/lmr365-tls-auth-ci.sh --verify'
echo "LMR365_GUEST_AUTH_TLS_POST_REBOOT=verified"
ssh "${ssh_opts[@]}" ci@127.0.0.1 'bash /home/ci/lmr365-tls-auth-ci.sh --cleanup' > "$work/tls-cleanup"
grep -Fxq "LMR365_LAB_POSTFIX_BASELINE=restored_exact_bytes" "$work/tls-cleanup"
grep -Fxq "LMR365_LAB_2525_MASTER_CF_ENTRY_REMOVED=yes" "$work/tls-cleanup"
echo "LMR365_GUEST_PORT_POLICY_RESTORE=verified_if_managed"
echo "LMR365_GUEST_POSTFIX_CONFIG_RESTORED=exact_pre_tls_baseline"

# Experimental fcontext manager is tested only in this disposable KVM
# guest; it is NOT wired into production installers.
scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
    linux/manage-rhel-selinux-sidecar-context.py \
    ci@127.0.0.1:/home/ci/lmr365-selinux-sidecar-context.py
ssh "${ssh_opts[@]}" ci@127.0.0.1 \
    'sudo install -o root -g root -m 0755 /home/ci/lmr365-selinux-sidecar-context.py /usr/local/libexec/lmr365-selinux-sidecar-context.py'

# Positive independent Postfix service under Enforcing, with error-only
# transport and no tenant/network delivery, separate from primary service.
scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
    tests/rocky_vm_isolated_postfix_enforcing.sh \
    ci@127.0.0.1:/home/ci/lmr365-positive-sidecar.sh
ssh "${ssh_opts[@]}" ci@127.0.0.1 \
    'bash /home/ci/lmr365-positive-sidecar.sh'
echo "LMR365_GUEST_POSITIVE_ISOLATED_POSTFIX=verified_under_enforcing"

# FINAL disposable guest acceptance: real native Sendmail service lifecycle.
# Run only AFTER the primary Postfix + sidecar tests and their cleanup;
# Sendmail may replace the default MTA provider, so never run this on a host.
# Provision a short-lived root-only marker bound to this guest's boot ID;
# the Sendmail test refuses to run without it and deletes it on exit.
ssh "${ssh_opts[@]}" ci@127.0.0.1 \
    "sudo install -o root -g root -m 0600 /dev/null /run/lmr365-disposable-sendmail-vm && sudo sh -c 'cat /proc/sys/kernel/random/boot_id > /run/lmr365-disposable-sendmail-vm'"
scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
    tests/rocky_vm_sendmail_systemd_enforcing.sh \
    ci@127.0.0.1:/home/ci/lmr365-sendmail-systemd-enforcing.sh
# Recovery fixtures are CI-only; root-owned, isolated under /usr/local/libexec.
# The v2 full-tree exercise writes ONLY into a private /var/backups scratch tree.
scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
    linux/foreign-mta-config-backup.py \
    linux/restore-foreign-mta-config.py \
    tests/rocky_vm_sendmail_stopped_config_restore.py \
    tests/rocky_vm_sendmail_stopped_dual_config_restore.py \
    tests/rocky_vm_sendmail_product_restore.py \
    tests/rocky_vm_sendmail_post_reboot_check.py \
    tests/assert_sendmail_v2_export.py \
    tests/rehearse_sendmail_v2_metadata.py \
    ci@127.0.0.1:/home/ci/
ssh "${ssh_opts[@]}" ci@127.0.0.1 \
    'sudo install -d -o root -g root -m 0755 /usr/local/libexec/lmr365-kvm-sendmail-recovery /usr/local/libexec/lmr365-kvm-sendmail-recovery/rehearsal/linux /usr/local/libexec/lmr365-kvm-sendmail-recovery/rehearsal/tests && sudo install -o root -g root -m 0755 /home/ci/foreign-mta-config-backup.py /home/ci/restore-foreign-mta-config.py /home/ci/rocky_vm_sendmail_stopped_config_restore.py /home/ci/rocky_vm_sendmail_stopped_dual_config_restore.py /home/ci/rocky_vm_sendmail_product_restore.py /home/ci/rocky_vm_sendmail_post_reboot_check.py /usr/local/libexec/lmr365-kvm-sendmail-recovery/ && sudo install -o root -g root -m 0755 /home/ci/foreign-mta-config-backup.py /usr/local/libexec/lmr365-kvm-sendmail-recovery/rehearsal/linux/foreign-mta-config-backup.py && sudo install -o root -g root -m 0755 /home/ci/assert_sendmail_v2_export.py /home/ci/rehearse_sendmail_v2_metadata.py /usr/local/libexec/lmr365-kvm-sendmail-recovery/rehearsal/tests/'
ssh "${ssh_opts[@]}" ci@127.0.0.1 \
    'env GITHUB_ACTIONS=true bash /home/ci/lmr365-sendmail-systemd-enforcing.sh'
echo "LMR365_GUEST_SENDMAIL_SYSTEMD_ENFORCING=verified"

# Confirm the validated full-tree Sendmail v2 snapshot, restored sendmail.cf,
# SELinux label, idle queues, and original Postfix service before and after
# a SECOND real guest reboot. This is READ-ONLY; no SMTP DATA or test mails.
reboot_check='sudo env GITHUB_ACTIONS=true python3 /usr/local/libexec/lmr365-kvm-sendmail-recovery/rocky_vm_sendmail_post_reboot_check.py'
ssh "${ssh_opts[@]}" ci@127.0.0.1 "$reboot_check" > "$work/sendmail-before-reboot"
grep -Fxq "LMR365_VM_REBOOT_SNAPSHOT_MATCH=identical" "$work/sendmail-before-reboot"
grep -Fxq "LMR365_VM_REBOOT_POSTFIX=active" "$work/sendmail-before-reboot"
grep -Fxq "LMR365_VM_REBOOT_SENDMAIL=stopped" "$work/sendmail-before-reboot"
grep -Fxq "LMR365_VM_REBOOT_SELINUX=enforcing" "$work/sendmail-before-reboot"
grep -Eq '^LMR365_VM_REBOOT_PACKAGE_SELINUX_OBJECTS=[1-9][0-9]*$' "$work/sendmail-before-reboot"
grep -Eq '^LMR365_VM_REBOOT_PACKAGE_SELINUX_SHA256=[a-f0-9]{64}$' "$work/sendmail-before-reboot"
grep -Fxq "LMR365_VM_REBOOT_SMTP_LISTENER=loopback_ipv4_25_only" "$work/sendmail-before-reboot"
grep -Fxq "LMR365_VM_REBOOT_SENDMAIL_PROCESS=absent" "$work/sendmail-before-reboot"
recovery_boot_id="$(ssh "${ssh_opts[@]}" ci@127.0.0.1 'cat /proc/sys/kernel/random/boot_id')"
[[ "$recovery_boot_id" =~ ^[0-9a-f-]{36}$ ]] || { echo "LMR365_GUEST_RECOVERY_BOOT_ID_INVALID"; exit 1; }
ssh "${ssh_opts[@]}" ci@127.0.0.1 'sudo systemctl reboot' >/dev/null 2>&1 || true
recovered_reboot=no
for attempt in $(seq 1 90); do
    reboot_id="$(ssh "${ssh_opts[@]}" ci@127.0.0.1 \
        'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)"
    if [[ "$reboot_id" =~ ^[0-9a-f-]{36}$ ]] && test "$reboot_id" != "$recovery_boot_id"; then
        recovered_reboot=yes
        break
    fi
    if ! sudo kill -0 "$(sudo cat "$work/vm.pid")" 2>/dev/null; then
        echo "LMR365_GUEST_SENDMAIL_RECOVERY_VM_EXITED"
        exit 1
    fi
    sleep 5
done
test "$recovered_reboot" = yes || { echo "LMR365_GUEST_SENDMAIL_RECOVERY_REBOOT_TIMEOUT"; exit 1; }
ssh "${ssh_opts[@]}" ci@127.0.0.1 "$reboot_check" > "$work/sendmail-after-reboot"
if ! diff -u "$work/sendmail-before-reboot" "$work/sendmail-after-reboot"; then
    echo "LMR365_GUEST_SENDMAIL_RECOVERY_POST_REBOOT_DRIFT"
    exit 1
fi
echo "LMR365_GUEST_SENDMAIL_RECOVERY_POST_REBOOT=verified_unchanged"
echo "LMR365_GUEST_SENDMAIL_RESTORED_SELINUX_POST_REBOOT=verified"
echo "LMR365_GUEST_SENDMAIL_PACKAGE_SELINUX_POST_REBOOT=verified_full_v2_inventory"
echo "LMR365_GUEST_SENDMAIL_LISTENER_POST_REBOOT=verified_private_ipv4_25"
echo "LMR365_GUEST_POSTFIX_AFTER_RECOVERY_REBOOT=active"

# Post-RC18 queue acceptance is opt-in for the exact new workflow invocation.
# Preserve the prior RC18 reboot/restore evidence, then exercise only private
# labeled spools in this disposable guest. The namespace hides them from the
# real Postfix and Sendmail queue paths outside the test process.
if test "${LMR365_KVM_QUEUE_ACCEPTANCE:-false}" = "true"; then
    scp -q -P 22222 -i "$work/guest-key" -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts" \
        linux/inspect-mail-queue.py tests/smoke_native_sendmail_queue_preview.py \
        ci@127.0.0.1:/home/ci/
    ssh "${ssh_opts[@]}" ci@127.0.0.1 \
        'sudo install -d -o root -g root -m 0755 /usr/local/libexec/lmr365-kvm-queue-test/linux /usr/local/libexec/lmr365-kvm-queue-test/tests && sudo install -o root -g root -m 0755 /home/ci/inspect-mail-queue.py /usr/local/libexec/lmr365-kvm-queue-test/linux/inspect-mail-queue.py && sudo install -o root -g root -m 0755 /home/ci/smoke_native_sendmail_queue_preview.py /usr/local/libexec/lmr365-kvm-queue-test/tests/smoke_native_sendmail_queue_preview.py && sudo install -o root -g root -m 0600 /dev/null /run/lmr365-disposable-sendmail-queue-vm && sudo sh -c "cat /proc/sys/kernel/random/boot_id > /run/lmr365-disposable-sendmail-queue-vm"'
    if ! ssh "${ssh_opts[@]}" ci@127.0.0.1 \
        'sudo env GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted RUNNER_TEMP=/tmp LMR365_CI_KVM_QUEUE_FIXTURE=1 unshare --mount --net --propagation private python3 /usr/local/libexec/lmr365-kvm-queue-test/tests/smoke_native_sendmail_queue_preview.py' \
        > "$work/sendmail-queue-enforcing"; then
        cat "$work/sendmail-queue-enforcing"
        echo "LMR365_GUEST_SENDMAIL_QUEUE_ENFORCING=failed"
        exit 1
    fi
    cat "$work/sendmail-queue-enforcing"
    test "$(grep -Fxc 'NATIVE_SENDMAIL_VM_BIND_IDENTITY=verified' "$work/sendmail-queue-enforcing")" = 2
    for expected in \
        'NATIVE_SENDMAIL_VM_SELINUX=enforcing_verified' \
        'NATIVE_SENDMAIL_FIXTURE_PRIVATE_MOUNTS=labeled_vm_bind' \
        'NATIVE_SENDMAIL_MTA_QUARANTINE_INVENTORY=verified_separate_classes' \
        'NATIVE_SENDMAIL_MSP_QUARANTINE_INVENTORY=verified_separate_classes' \
        'NATIVE_SENDMAIL_VM_QUEUE_LABELS=verified_policy_match' \
        'NATIVE_SENDMAIL_VM_QUEUE_TRANSITIONS=verified_under_enforcing'; do
        grep -Fxq "$expected" "$work/sendmail-queue-enforcing"
    done
    # Outside the namespaces the original spools and primary service must
    # still match the independently verified post-reboot RC18 evidence.
    ssh "${ssh_opts[@]}" ci@127.0.0.1 "$reboot_check" > "$work/sendmail-after-queue-test"
    diff -u "$work/sendmail-after-reboot" "$work/sendmail-after-queue-test"
    echo "LMR365_GUEST_SENDMAIL_QUEUE_ENFORCING=verified_native_transitions_original_spools_unchanged"
fi

echo "LMR365_GUEST_MICROSOFT365_DELIVERY_TESTED=no"
echo "LMR365_GUEST_EXTERNAL_MAIL_DELIVERY_TESTED=no"
