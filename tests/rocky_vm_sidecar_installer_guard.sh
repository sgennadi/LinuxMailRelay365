#!/usr/bin/env bash
# Actual installer negative acceptance in disposable Rocky Enforcing KVM guest.
# Synthetic domain/identity, no tenant, SMTP DATA, public listener, or mail send.
set -Eeuo pipefail
test "$(cat /proc/1/comm)" = systemd
test "$(getenforce)" = Enforcing
test "$(cat /sys/fs/selinux/enforce)" = 1
sudo systemctl is-active --quiet postfix.service
test -z "$(sudo postqueue -j)"
test -z "$(sudo ss -H -ltn '( sport = :2525 )')"
no_sidecar() {
  for target in /etc/linuxmailrelay365/sidecar-postfix \
    /etc/linuxmailrelay365/sidecar-identity \
    /etc/linuxmailrelay365/smtp-auth \
    /var/spool/linuxmailrelay365-sidecar \
    /var/lib/linuxmailrelay365-sidecar \
    /etc/systemd/system/linuxmailrelay365-sidecar.service \
    /etc/systemd/system/linuxmailrelay365-smtp-auth.service \
    /run/linuxmailrelay365-sidecar-auth.lock; do
    if sudo test -e "$target" || sudo test -L "$target"; then
      echo "LMR365_INSTALLER_SIDE_EFFECT_PRESENT"
      return 1
    fi
  done
}
no_sidecar
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
snapshot() {
  sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf
  sudo systemctl is-active postfix.service
  sudo postqueue -j
  sudo ss -H -ltn | awk '$4 ~ /:(25|2525|465|587)$/ {print $4}' | sort
  getenforce
}
snapshot > "$work/before"

check_refusal() {
  tag="$1"; expected="$2"; shift 2
  set +e
  output="$("$@" 2>&1)"
  code="$?"
  set -e
  if test "$code" -ne 3; then
    echo "LMR365_INSTALLER_UNEXPECTED_EXIT_$tag=$code"; exit 1
  fi
  if ! printf '%s\n' "$output" | grep -Fxq "$expected"; then
    echo "LMR365_INSTALLER_UNEXPECTED_REASON_$tag"; exit 1
  fi
  echo "LMR365_INSTALLER_GUARD_$tag=refused_enforcing"
}
for name in install-preserve-postfix-sidecar.sh \
  install-direct-send-sidecar.sh install-connector-sidecar.sh \
  enable-sidecar-auth-tls.sh; do
  bash -n "/home/ci/$name"
done

mx='lab-check.mail.protection.outlook.com'
domain='lab.invalid'
sender='sender@lab.invalid'
cert='/tmp/lmr365-test-absent-cert.pem'
key='/tmp/lmr365-test-absent-key.pem'
hash='/tmp/lmr365-test-absent-hashes.txt'
bash /home/ci/install-preserve-postfix-sidecar.sh \
  --check-only --smtp-port 2525 > "$work/preserve"
grep -Fxq 'SIDECAR_APPLIED=no' "$work/preserve"
bash /home/ci/install-direct-send-sidecar.sh --check-only \
  --smtp-port 2525 --mx-host "$mx" --accepted-domain "$domain" \
  --fixed-sender "$sender" > "$work/direct"
grep -Fxq 'CHANGES_APPLIED=no' "$work/direct"
bash /home/ci/install-connector-sidecar.sh --check-only \
  --smtp-port 2525 --mx-host "$mx" --accepted-domain "$domain" \
  --fixed-sender "$sender" --tls-cert "$cert" --tls-key "$key" \
  > "$work/connector"
grep -Fxq 'CHANGES_APPLIED=no' "$work/connector"

check_refusal PRESERVE \
  SIDECAR_ERROR=selinux_enforcing_sidecar_not_integration_verified \
  sudo bash /home/ci/install-preserve-postfix-sidecar.sh \
    --smtp-port 2525 \
    --tenant-id 00000000-0000-4000-8000-000000000001 \
    --client-id 00000000-0000-4000-8000-000000000002 \
    --mailbox "$sender"
check_refusal DIRECT_SEND \
  DIRECT_SEND_ERROR=selinux_enforcing_not_integration_verified \
  sudo bash /home/ci/install-direct-send-sidecar.sh --apply \
    --smtp-port 2525 --mx-host "$mx" --accepted-domain "$domain" \
    --fixed-sender "$sender" --confirm-accepted-domain TENANT_DOMAIN_CHECKED
check_refusal CONNECTOR \
  CONNECTOR_ERROR=selinux_enforcing_not_integration_verified \
  sudo bash /home/ci/install-connector-sidecar.sh --apply \
    --smtp-port 2525 --mx-host "$mx" --accepted-domain "$domain" \
    --fixed-sender "$sender" --tls-cert "$cert" --tls-key "$key" \
    --confirm-accepted-domain TENANT_DOMAIN_CHECKED \
    --confirm-connector TENANT_CONNECTOR_CHECKED
check_refusal AUTH \
  AUTH_TLS_ERROR=selinux_enforcing_not_verified \
  sudo bash /home/ci/enable-sidecar-auth-tls.sh --apply \
    --smtp-port 2525 --server-name smtp.lab.invalid \
    --tls-cert "$cert" --tls-key "$key" --password-file "$hash" \
    --confirm ENABLE_PRIVATE_AUTH_TLS

snapshot > "$work/after"
python3 - "$work/before" "$work/after" <<'PY'
from pathlib import Path
import sys
if Path(sys.argv[1]).read_bytes() != Path(sys.argv[2]).read_bytes():
    raise SystemExit("LMR365_INSTALLER_PRIMARY_CONFIG_QUEUE_OR_LISTENER_CHANGED")
PY
no_sidecar
test -z "$(sudo postqueue -j)"
test "$(getenforce)" = Enforcing
echo "LMR365_INSTALLERS_ALL_FOUR=fail_closed_no_mutation"
echo "LMR365_INSTALLERS_PRIMARY=unchanged"
echo "LMR365_INSTALLERS_QUEUE=empty"
echo "LMR365_INSTALLERS_POSITIVE_ENFORCING_DEPLOYMENT=not_tested"
