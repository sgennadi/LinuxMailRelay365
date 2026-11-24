#!/usr/bin/env bash
# Disposable GitHub-hosted systemd VM; use only synthetic test namespaces.
set -Eeuo pipefail
export LC_ALL=C
[[ "$EUID" == 0 && "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && -d "${RUNNER_TEMP:-/nonexistent}" ]] || exit 2
[[ "$(cat /proc/1/comm)" == systemd ]] || exit 2
systemd-detect-virt --vm --quiet || exit 2
source_ns=lmr-rc14-source
sink_ns=lmr-rc14-sink
scratch="$(mktemp -d "$RUNNER_TEMP/lmr-rc14-vm.XXXXXXXX")"
ca=/usr/local/share/ca-certificates/lmr365-rc14-synthetic-ci.crt
queue_marker=/var/spool/postfix/hold/LMR_TEST_SYNTHETIC_HOLD
manager=linux/manage-conditional-postfix-offline.py
preflight=linux/inspect-conditional-postfix-activation.py
stager=linux/stage-conditional-postfix-maps.py
maintenance=I_HAVE_PREVENTED_CONCURRENT_MAIL_AND_CONFIG_CHANGES
run() { ip netns exec "$source_ns" "$@"; }
sink_pid=
cleanup() {
  local status=$?
  trap - EXIT
  set +e
  rm -f "$queue_marker"
  if [[ -n "$sink_pid" ]]; then kill "$sink_pid" 2>/dev/null; wait "$sink_pid" 2>/dev/null; fi
  run postfix stop >/dev/null 2>&1
  ip netns del "$source_ns" >/dev/null 2>&1
  ip netns del "$sink_ns" >/dev/null 2>&1
  rm -rf "/etc/netns/$source_ns"
  rm -f "$ca"
  if [[ "$status" != 0 ]]; then
    tail -n 60 /var/log/lmr365-rc14-vm.log "$scratch"/sink.log 2>/dev/null
  fi
  rm -rf "$scratch"
  exit "$status"
}
trap cleanup EXIT

# Namespaces have only one IPv4 point-to-point lab subnet and no route to
# the runner's ordinary interface or to the Internet. Postfix and CLI are
# both run within the source namespace; the product code is not patched.
ip netns add "$source_ns"
ip netns add "$sink_ns"
ip link add lmr-source netns "$source_ns" type veth peer name lmr-sink netns "$sink_ns"
run ip link set lo up
run ip link set lmr-source up
run ip addr add 192.0.2.1/30 dev lmr-source
ip -n "$sink_ns" link set lo up
ip -n "$sink_ns" link set lmr-sink up
ip -n "$sink_ns" addr add 192.0.2.2/30 dev lmr-sink
test -z "$(run ip route show default)"
test -z "$(ip -n "$sink_ns" route show default)"
test -z "$(run ip -6 route show default)"
test -z "$(ip -n "$sink_ns" -6 route show default)"
test "$(run ip -o link show | wc -l)" -eq 2
test "$(ip -n "$sink_ns" -o link show | wc -l)" -eq 2
install -d -m 0755 "/etc/netns/$source_ns"
printf '127.0.0.1 localhost mail.local.invalid\n192.0.2.2 target.lab.invalid default.lab.invalid\n' >"/etc/netns/$source_ns/hosts"
printf 'hosts: files\npasswd: files\ngroup: files\n' >"/etc/netns/$source_ns/nsswitch.conf"
test "$(run getent ahostsv4 target.lab.invalid | head -n1 | cut -d' ' -f1)" = 192.0.2.2

wait_for() {
  local i
  for i in $(seq 1 100); do if "$@"; then return 0; fi; sleep .2; done
  echo "Timeout waiting for $*" >&2
  return 1
}
start_sink() {
  ip netns exec "$sink_ns" python3 -B tests/rc14_namespace_starttls_sink.py "$1" "$scratch/cert" >"$scratch/sink.log" 2>&1 &
  sink_pid=$!
  wait_for grep -qx "SINK_READY=$1" "$scratch/sink.log"
}
mkdir -m 0700 "$scratch/cert"
start_sink wrong
install -m 0644 "$scratch/cert/ca.pem" "$ca"
update-ca-certificates >/dev/null
id lmrfixture >/dev/null 2>&1 || useradd --no-create-home lmrfixture
systemctl stop postfix.service postfix@-.service
systemctl show postfix.service -p ActiveState | grep -qx ActiveState=inactive

run postconf -F smtp/inet/chroot=n smtp/unix/chroot=n relay/unix/chroot=n rewrite/unix/chroot=n
run postconf -e \
  'myhostname = mail.local.invalid' 'mydomain = local.invalid' 'myorigin = local.invalid' \
  'mydestination = local.invalid, localhost' 'inet_interfaces = loopback-only' 'inet_protocols = ipv4' \
  'mynetworks = 127.0.0.1/32' 'smtpd_relay_restrictions = permit_mynetworks, reject' \
  'relayhost = [default.lab.invalid]:46510' 'smtp_host_lookup = native' \
  'smtp_fallback_relay =' 'smtp_sasl_auth_enable = no' 'smtp_sasl_password_maps =' \
  'smtp_sender_dependent_authentication = no' 'sender_dependent_default_transport_maps =' \
  'transport_maps =' 'smtp_generic_maps =' 'sender_canonical_maps =' 'canonical_maps =' \
  'masquerade_domains =' 'content_filter =' 'multi_instance_enable = no' 'multi_instance_directories =' \
  'smtp_tls_wrappermode = no' 'smtp_tls_security_level = secure' 'smtp_tls_CApath =' 'smtp_tls_per_site =' \
  'smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt' 'smtp_tls_policy_maps =' 'smtp_tls_secure_cert_match = nexthop' \
  'smtp_tls_loglevel = 1' 'smtp_connection_cache_on_demand = no' 'smtp_connection_cache_destinations =' \
  'default_transport = smtp' 'relay_transport = relay' 'mail_owner = postfix' \
  'home_mailbox =' 'mail_spool_directory = /var/mail' 'maillog_file = /var/log/lmr365-rc14-vm.log'
run postfix check
baseline="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)"
assert_baseline() {
  test "$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$baseline"
  test -z "$(find /etc/postfix -maxdepth 1 -name 'lmr365-conditional-*-sender*' -print -quit)"
}

request='[{"selector":"exact-envelope-sender","pattern":"mapped@sender.invalid","host":"target.lab.invalid","port":46517,"tls":"starttls","auth":"none"}]'
field() { sed -n "s/^$1=//p" | head -n1; }
digest() { [[ "$1" =~ ^[a-f0-9]{64}$ ]]; }
plan="$(printf '%s' "$request" | run python3 -B "$stager" --plan | field CONDITIONAL_STAGE_PLAN_SHA256)"
digest "$plan"
stage="$(printf '%s' "$request" | run python3 -B "$stager" --stage --approve-sha256 "$plan" --confirm STAGE_CONDITIONAL_MAPS_ONLY | field CONDITIONAL_STAGE_MANIFEST_SHA256)"
digest "$stage"
receipt="$(run python3 -B "$stager" --compile "$plan" --approve-manifest-sha256 "$stage" --confirm COMPILE_CONDITIONAL_MAPS_ONLY)"
compiled="$(printf '%s\n' "$receipt" | field CONDITIONAL_STAGE_COMPILED_SHA256)"
digest "$compiled"
backend="$(printf '%s\n' "$receipt" | field CONDITIONAL_STAGE_MAP_BACKEND)"
case "$backend" in hash) suffix=.db;; lmdb) suffix=.lmdb;; *) exit 1;; esac
candidate_args=(--plan-sha256 "$plan" --compiled-sha256 "$compiled")
preflight_run() { run python3 -B "$preflight" "${candidate_args[@]}"; }
offline() { run python3 -B "$manager" --maintenance-confirmation "$maintenance" "$@"; }

# Wrong name but signed by the same CA. The refusal must be specifically TLS,
# not a DNS, Linux permission or queue failure that masks a bad certificate.
if bad="$(preflight_run)"; then echo "Wrong SMTP certificate accepted" >&2; exit 1; fi
echo "$bad"
grep -qx CONDITIONAL_PREFLIGHT_REASON=destination_tls_verification_failed <<<"$bad"
assert_baseline
kill "$sink_pid"
wait "$sink_pid" || true
sink_pid=
start_sink right
touch "$queue_marker"
if bad="$(preflight_run)"; then echo "Held fixture queue was not refused" >&2; exit 1; fi
echo "$bad"
grep -qx CONDITIONAL_PREFLIGHT_REASON=queue_not_empty_or_unverified <<<"$bad"
rm -f "$queue_marker"
assert_baseline
preflight_run | tee "$scratch/preflight.txt"
grep -qx CONDITIONAL_PREFLIGHT_STATUS=offline_reviewed "$scratch/preflight.txt"
out="$(offline --review "${candidate_args[@]}")"
echo "$out"
grep -qx CONDITIONAL_OFFLINE_STATUS=reviewed_offline_experimental <<<"$out"
txn="$(field CONDITIONAL_OFFLINE_TRANSACTION_SHA256 <<<"$out")"
evidence="$(field CONDITIONAL_OFFLINE_EVIDENCE_SHA256 <<<"$out")"
digest "$txn"
digest "$evidence"
test "$(field CONDITIONAL_PREFLIGHT_TRANSACTION_SHA256 <"$scratch/preflight.txt")" = "$txn"
different="$(printf 'stale fixture evidence' | sha256sum | cut -d' ' -f1)"
test "$different" != "$evidence"
apply() {
  offline --apply "${candidate_args[@]}" --approve-transaction-sha256 "$txn" \
    --approve-evidence-sha256 "$1" --confirm APPLY_STOPPED_POSTFIX_SENDER_MAP
}
# The supported policy is unchrooted outbound delivery; confirm that
# each explicit Debian-style chroot blocks preflight AND a previously approved
# offline Apply before it can install a map or create a recovery snapshot.
baseline_master="$scratch/master.cf.before-chroot"
cp -p -- /etc/postfix/master.cf "$baseline_master"
protected_state() {
  sha256sum /etc/postfix/main.cf /etc/postfix/master.cf
  stat -c '%d:%i:%a:%u:%g' /etc/postfix/main.cf /etc/postfix/master.cf
}
for service in smtp/unix relay/unix rewrite/unix; do
  run postconf -F "$service/chroot=y"
  test "$(run postconf -M "$service" | awk '{print $5}')" = y
  chroot_state="$(protected_state)"
  if bad="$(preflight_run)"; then
    echo "Chrooted $service unexpectedly passed offline preflight" >&2; exit 1
  else
    test "$?" -eq 2
  fi
  grep -qx CONDITIONAL_PREFLIGHT_STATUS=blocked <<<"$bad"
  grep -qx CONDITIONAL_PREFLIGHT_REASON=outbound_chroot_needs_separate_acceptance <<<"$bad"
  if bad="$(apply "$evidence")"; then
    echo "Chrooted $service unexpectedly accepted old offline approval" >&2; exit 1
  else
    test "$?" -eq 2
  fi
  grep -qx CONDITIONAL_OFFLINE_STATUS=refused_or_failed <<<"$bad"
  grep -qx CONDITIONAL_OFFLINE_SERVICE_STARTED=no <<<"$bad"
  test "$(protected_state)" = "$chroot_state"
  test ! -e "/var/lib/linuxmailrelay365-conditional-recovery/$txn"
  test -z "$(find /etc/postfix -maxdepth 1 -name 'lmr365-conditional-*-sender*' -print -quit)"
  cp -p -- "$baseline_master" /etc/postfix/master.cf
  assert_baseline
  echo "CHROOTED_OUTBOUND_REFUSED=$service:outbound_chroot_needs_separate_acceptance"
done

if bad="$(apply "$different")"; then echo "Changed approval accepted" >&2; exit 1; fi
echo "$bad"
assert_baseline
apply "$evidence" | tee "$scratch/apply.txt"
grep -qx CONDITIONAL_OFFLINE_STATUS=applied_offline_not_started "$scratch/apply.txt"
grep -qx CONDITIONAL_OFFLINE_SERVICE_STARTED=no "$scratch/apply.txt"
backup="$(field CONDITIONAL_OFFLINE_BACKUP_SHA256 <"$scratch/apply.txt")"
test "$backup" = "$txn"
map_file="/etc/postfix/lmr365-conditional-$plan-sender$suffix"
test "$(stat -c '%U:%G %a' "$map_file")" = 'root:postfix 640'
active="$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf "$map_file")"
run postfix start
wait_for run bash -c 'exec 3<>/dev/tcp/127.0.0.1/25'
if bad="$(offline --restore "$backup" --confirm RESTORE_STOPPED_POSTFIX_SENDER_MAP)"; then
  echo "Restore unexpectedly accepted with live native Postfix" >&2; exit 1
fi
echo "$bad"
test "$(sha256sum /etc/postfix/main.cf /etc/postfix/master.cf "$map_file")" = "$active"

submit() {
  run python3 -B - "$1" "$2" <<'PY'
import smtplib
import sys
from email.message import EmailMessage
m = EmailMessage()
m["From"], m["To"], m["Subject"] = "mapped@sender.invalid", sys.argv[1], sys.argv[2]
m.set_content(sys.argv[2])
with smtplib.SMTP("127.0.0.1", 25, timeout=5) as client:
    if client.send_message(m):
        raise RuntimeError("synthetic message was refused")
PY
}
queue_empty() { [[ -z "$(run postqueue -j)" ]]; }
submit recipient@remote.invalid MAPPED_SMTP_FIXTURE
wait_for grep -Eq '^DELIVERED port=46517 .* TLS=TLSv1\.[23] DATA=MAPPED_SMTP_FIXTURE$' "$scratch/sink.log"
submit lmrfixture@local.invalid LOCAL_MAIL_UNCHANGED
wait_for grep -qs LOCAL_MAIL_UNCHANGED /var/mail/lmrfixture
wait_for queue_empty
run postfix stop
offline --restore "$backup" --confirm RESTORE_STOPPED_POSTFIX_SENDER_MAP | tee "$scratch/restore.txt"
grep -qx CONDITIONAL_OFFLINE_STATUS=restored_offline_not_started "$scratch/restore.txt"
grep -qx CONDITIONAL_OFFLINE_SERVICE_STARTED=no "$scratch/restore.txt"
assert_baseline
test -f "/var/lib/linuxmailrelay365-conditional-recovery/$backup/transaction.json"
run postfix start
wait_for run bash -c 'exec 3<>/dev/tcp/127.0.0.1/25'
submit recipient@remote.invalid RESTORED_SMTP_FIXTURE
wait_for grep -Eq '^DELIVERED port=46510 .* TLS=TLSv1\.[23] DATA=RESTORED_SMTP_FIXTURE$' "$scratch/sink.log"
wait_for queue_empty
run postfix stop
test "$(grep -c '^DELIVERED ' "$scratch/sink.log")" -eq 2
grep '^DELIVERED ' "$scratch/sink.log"
echo RC14_SYSTEMD_VM_UNMODIFIED_CLI_APPLY_RESTORE=PASS
