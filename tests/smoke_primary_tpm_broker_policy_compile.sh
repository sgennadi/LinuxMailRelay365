#!/usr/bin/env bash
# Only compile an SELinux module in a disposable Rocky 10 CI container.
# Never load policy, change labels, modify the TPM or start any service.
set -Eeuo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "$(id -u)" = 0
source /etc/os-release
test "$ID" = rocky
test "${VERSION_ID%%.*}" = 10
test ! -e /run/systemd/system
mode="$(getenforce)"
case "$mode" in Disabled|Permissive) ;; *) exit 2 ;; esac
dnf -y install selinux-policy-devel make
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
cp linux/selinux/lmr365_tpm_signer.te linux/selinux/lmr365_tpm_signer.fc "$work/"
make -C "$work" -f /usr/share/selinux/devel/Makefile lmr365_tpm_signer.pp
test -s "$work/lmr365_tpm_signer.pp"
test "$(getenforce)" = "$mode"
test ! -e /run/systemd/system
echo 'PRIMARY_TPM_BROKER_POLICY_COMPILE=passed'
echo 'PRIMARY_TPM_BROKER_POLICY_LOADED=no'
echo 'PRIMARY_TPM_BROKER_LIVE_ENFORCING_TESTED=no'
