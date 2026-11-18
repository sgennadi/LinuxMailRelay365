#!/usr/bin/env bash
# Ephemeral GitHub Actions VM only: real Postfix smoke test, no M365 mail sent.
set -Eeuo pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
PORT=2529
UNIT=linuxmailrelay365-sidecar.service
CONF=/etc/linuxmailrelay365/sidecar-postfix
on_exit() {
  result=$?
  if [ "$result" -ne 0 ]; then
    echo '=== FAILURE: isolated Postfix smoke log ==='
    sudo journalctl -u "$UNIT" --no-pager -n 100 || true
    sudo journalctl -u linuxmailrelay365-smtp-auth.service --no-pager -n 100 || true
    sudo postfix -c "$CONF" check || true
    sudo systemctl status "$UNIT" --no-pager || true
    echo '=== PRIMARY POSTFIX ==='
    sudo systemctl status postfix --no-pager || true
  fi
  sudo systemctl stop "$UNIT" >/dev/null 2>&1 || true
  exit "$result"
}
trap on_exit EXIT

echo '=== Prepare temporary Linux Postfix fixture ==='
if command -v debconf-set-selections >/dev/null; then
  printf '%s\n' \
    'postfix postfix/main_mailer_type select Local only' \
    'postfix postfix/mailname string ci.example.test' | sudo debconf-set-selections
fi
sudo apt-get update -qq
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postfix iproute2 openssl dovecot-core
sudo postconf -e 'myhostname = relay-ci.example.test'
sudo postfix check
sudo systemctl start postfix
sudo systemctl is-active --quiet postfix
sudo useradd --system --no-create-home --shell /usr/sbin/nologin m365mailer
sudo install -d -o root -g root -m 0755 /etc/postfix/m365-oauth
sudo openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
    -keyout /etc/postfix/m365-oauth/app.key \
    -out /etc/postfix/m365-oauth/app.crt \
    -subj /CN=linuxmailrelay365-ci.example.test -days 1 >/dev/null 2>&1
sudo chmod 0600 /etc/postfix/m365-oauth/app.key
sudo chmod 0644 /etc/postfix/m365-oauth/app.crt

primary_before="$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)"
primary_status="$(sudo systemctl is-active postfix)"
primary_queue="$(sudo postconf -h queue_directory)"
primary_master_before="$(sudo postfix status 2>&1 || true)"
echo "Primary queue: $primary_queue; primary service: $primary_status"
echo '=== Install real isolated instance ==='
sudo bash linux/install-preserve-postfix-sidecar.sh \
    --tenant-id 11111111-1111-1111-1111-111111111111 \
    --client-id 22222222-2222-2222-2222-222222222222 \
    --mailbox mailer@example.test --smtp-port "$PORT"

sudo systemctl is-active --quiet "$UNIT"
sudo postfix -c "$CONF" check
test "$(sudo cat "$CONF/smtp-port")" = "$PORT"
test "$(sudo postconf -c "$CONF" -h queue_directory)" = /var/spool/linuxmailrelay365-sidecar
test "$(sudo postconf -c "$CONF" -h data_directory)" = /var/lib/linuxmailrelay365-sidecar
test "$(sudo postconf -c "$CONF" -h inet_interfaces)" = 127.0.0.1
test "$(sudo postconf -c "$CONF" -h syslog_name)" = postfix-lmr365
baseline_sidecar_main="$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')"
baseline_sidecar_master="$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')"
test "$(sudo systemctl is-active postfix)" = "$primary_status"
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
test "$(sudo postconf -h queue_directory)" = "$primary_queue"

echo '=== Read-only operational queue and certificate health ==='
sudo python3 linux/relay-health.py --smtp-port "$PORT" |
  tee /tmp/lmr365-health-before.txt
grep -Fx 'CUSTOM_SMTP_PORT=2529' /tmp/lmr365-health-before.txt
grep -Fx 'CHANGES_APPLIED=no' /tmp/lmr365-health-before.txt
echo '=== Install journal-only 15-minute monitoring on the installed custom port ==='
sudo bash linux/install-health-monitor.sh --check-only --smtp-port "$PORT" |
  grep -Fx 'HEALTH_TIMER_PREFLIGHT=ready'
sudo bash linux/install-health-monitor.sh --install --smtp-port "$PORT" \
  --confirm ENABLE_PRIVATE_SMTP_MONITOR |
  grep -Fx 'HEALTH_TIMER_INSTALLED=yes'
sudo systemctl is-active --quiet linuxmailrelay365-health.timer
sudo systemctl start linuxmailrelay365-health.service
sudo systemctl is-active --quiet "$UNIT"
echo 'HEALTH_TIMER_REAL_SYSTEMD_SMOKE=PASS'
echo '=== Record reboot acceptance baseline without triggering an OS reboot ==='
sudo python3 linux/verify-reboot-continuity.py --record-baseline --smtp-port "$PORT" |
  tee /tmp/lmr365-reboot-baseline.txt
grep -Fx 'REBOOT_CONTINUITY_RESULT=baseline_recorded_requires_real_reboot' /tmp/lmr365-reboot-baseline.txt
if sudo python3 linux/verify-reboot-continuity.py --verify-after-reboot --smtp-port "$PORT"; then
  echo 'SECURITY ERROR: systemctl start/stop incorrectly counted as real Linux reboot' >&2
  exit 1
fi
echo 'REBOOT_VERIFIER_REFUSED_NO_REBOOT=PASS'
echo '=== Check installed isolated sidecar read-only audit before AUTH/TLS ==='
sudo python3 linux/installed-sidecar-audit.py --smtp-port "$PORT" |
  tee /tmp/lmr365-audit-before.txt
grep -Fx 'SMTP_SECURITY_RESULT=private_unauthenticated_not_public_safe' /tmp/lmr365-audit-before.txt
grep -Fx 'CHANGES_APPLIED=no' /tmp/lmr365-audit-before.txt

echo '=== Verify local SMTP greeting; DO NOT submit or send test mail ==='
python3 - "$PORT" <<'PY'
import smtplib, sys
with smtplib.SMTP('127.0.0.1', int(sys.argv[1]), timeout=8) as smtp:
    code, payload = smtp.ehlo('lmr365-ci.example.test')
    assert code == 250, (code, payload)
    assert not smtp.has_extn('AUTH'), 'Plain internal sidecar must not falsely advertise SMTP AUTH'
print('SIDECAR_SMTP_GREETING_OK=yes')
PY
echo '=== Reinstall must fail closed and leave both instances intact ==='
if sudo bash linux/install-preserve-postfix-sidecar.sh \
    --tenant-id 11111111-1111-1111-1111-111111111111 \
    --client-id 22222222-2222-2222-2222-222222222222 \
    --mailbox mailer@example.test --smtp-port "$PORT"; then
  echo 'SECURITY FAILURE: sidecar reinstall unexpectedly succeeded' >&2
  exit 1
fi
sudo systemctl is-active --quiet "$UNIT"
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
echo '=== Configure private TLS and hashed SMTP AUTH fixture (no M365 mail sent) ==='
FIXTURE=/etc/linuxmailrelay365-ci-smtp
sudo install -d -m 0700 "$FIXTURE"
sudo openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
  -keyout "$FIXTURE/privkey.pem" -out "$FIXTURE/fullchain.pem" \
  -subj /CN=lmr365-ci.example.test \
  -addext 'subjectAltName=DNS:lmr365-ci.example.test' -days 30 >/dev/null 2>&1
sudo chmod 0600 "$FIXTURE/privkey.pem"
sudo chmod 0644 "$FIXTURE/fullchain.pem"
# Disposable CI-only fixture. Only the salted HASH is stored on disk.
hash="$(openssl passwd -6 -salt ciRandomSalt ci-fixture-password)"
hash2="$(openssl passwd -6 -salt ciRandom2 ci-fixture-password-2)"
printf 'lmr365-ci:{SHA512-CRYPT}%s\nlmr365-ci-b:{SHA512-CRYPT}%s\n' "$hash" "$hash2" |
  sudo tee "$FIXTURE/smtp-users" >/dev/null
sudo chmod 0600 "$FIXTURE/smtp-users"

AUTH_SCRIPT=linux/enable-sidecar-auth-tls.sh
AUTH_ARGS=(
  --smtp-port "$PORT" --server-name lmr365-ci.example.test
  --tls-cert "$FIXTURE/fullchain.pem"
  --tls-key "$FIXTURE/privkey.pem"
  --password-file "$FIXTURE/smtp-users"
)
echo '=== Reject incorrect custom SMTP port before any change ==='
if sudo bash "$AUTH_SCRIPT" --check-only --smtp-port 2530 \
   --server-name lmr365-ci.example.test \
   --tls-cert "$FIXTURE/fullchain.pem" \
   --tls-key "$FIXTURE/privkey.pem" --password-file "$FIXTURE/smtp-users"; then
   echo 'AUTH TLS incorrectly accepted mismatching custom port' >&2; exit 1
fi
echo '=== Verify read-only TLS/AUTH preflight ==='
sudo bash "$AUTH_SCRIPT" --check-only "${AUTH_ARGS[@]}"
test "$(sudo postconf -c "$CONF" -h smtpd_sasl_auth_enable)" != yes
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"

echo '=== Enable AUTH/TLS on isolated Postfix only ==='
sudo bash "$AUTH_SCRIPT" --apply "${AUTH_ARGS[@]}" --confirm ENABLE_PRIVATE_AUTH_TLS
sudo systemctl is-active --quiet linuxmailrelay365-smtp-auth.service
test "$(sudo postconf -c "$CONF" -h smtpd_tls_security_level)" = encrypt
test "$(sudo postconf -c "$CONF" -h smtpd_sasl_auth_enable)" = yes
test "$(sudo postconf -c "$CONF" -h smtpd_relay_restrictions)" = 'permit_sasl_authenticated, reject'
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
test "$(sudo systemctl is-active postfix)" = "$primary_status"
test "$(sudo postconf -h queue_directory)" = "$primary_queue"
echo '=== Read-only installed AUTH/TLS audit on exact custom port ==='
sudo python3 linux/installed-sidecar-audit.py --smtp-port "$PORT" |
  tee /tmp/lmr365-audit-after.txt
grep -Fx 'SMTP_POLICY=mandatory_tls_and_auth' /tmp/lmr365-audit-after.txt
grep -Fx 'SMTP_SECURITY_RESULT=local_auth_tls_verified_external_unverified' /tmp/lmr365-audit-after.txt
grep -Fx 'CHANGES_APPLIED=no' /tmp/lmr365-audit-after.txt
grep -Fx 'MICROSOFT365_DELIVERY_VERIFIED=no' /tmp/lmr365-audit-after.txt

echo '=== Verify local STARTTLS DNS identity and CA trust (NO SMTP mail) ==='
IDENTITY_SCRIPT=linux/verify-sidecar-tls-identity.py
sudo python3 "$IDENTITY_SCRIPT" \
  --smtp-port "$PORT" --server-name lmr365-ci.example.test \
  --ca-file "$FIXTURE/fullchain.pem" |
  tee /tmp/lmr365-verified-tls.txt
grep -Fx 'SMTP_TLS_PROBE_RESULT=verified_local_chain_dns_and_starttls' /tmp/lmr365-verified-tls.txt
grep -Fx 'SMTP_TLS_CERT_CHAIN_AND_DNS=verified' /tmp/lmr365-verified-tls.txt
grep -Fx 'SMTP_TLS_NETWORK=loopback_only' /tmp/lmr365-verified-tls.txt
grep -Fx 'SMTP_TLS_EXTERNAL_CLIENT_TRUST=not_verified' /tmp/lmr365-verified-tls.txt
grep -Fx 'MICROSOFT365_DELIVERY_VERIFIED=no' /tmp/lmr365-verified-tls.txt
echo '=== A valid CA with the wrong DNS name must FAIL ==='
if sudo python3 "$IDENTITY_SCRIPT" \
  --smtp-port "$PORT" --server-name wrong-host.example.test \
  --ca-file "$FIXTURE/fullchain.pem"; then
  echo 'SECURITY ERROR: TLS verifier incorrectly accepted a mismatched DNS identity' >&2
  exit 1
fi
echo '=== The same server is NOT verified by default OS CA trust ==='
if sudo python3 "$IDENTITY_SCRIPT" \
  --smtp-port "$PORT" --server-name lmr365-ci.example.test; then
  echo 'SECURITY ERROR: Self-signed test cert was incorrectly trusted without explicit CA' >&2
  exit 1
fi
echo '=== Wrong custom port must not fall back to another listener ==='
if sudo python3 "$IDENTITY_SCRIPT" \
  --smtp-port 2530 --server-name lmr365-ci.example.test \
  --ca-file "$FIXTURE/fullchain.pem"; then
  echo 'SECURITY ERROR: TLS verifier incorrectly connected to another port' >&2
  exit 1
fi
echo 'TLS_VERIFIED_CA_DNS_CUSTOM_PORT_SMOKE=PASS'

echo '=== Rotate private SMTP TLS certificate on custom port ==='
TLS_ROTATE_SCRIPT=linux/rotate-sidecar-tls.sh
sudo openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout "$FIXTURE/next-key.pem" -out "$FIXTURE/next-cert.pem" \
  -subj /CN=lmr365-ci.example.test \
  -addext 'subjectAltName=DNS:lmr365-ci.example.test' -days 30 >/dev/null 2>&1
sudo chmod 0600 "$FIXTURE/next-key.pem"
sudo chmod 0644 "$FIXTURE/next-cert.pem"
tls_preview="$(sudo bash "$TLS_ROTATE_SCRIPT" --check-only \
  --smtp-port "$PORT" --server-name lmr365-ci.example.test \
  --tls-cert "$FIXTURE/next-cert.pem" --tls-key "$FIXTURE/next-key.pem" \
  --ca-file "$FIXTURE/next-cert.pem")"
printf '%s\n' "$tls_preview" | grep -Fx 'TLS_ROTATE_PREFLIGHT=ready'
tls_sha="$(printf '%s\n' "$tls_preview" | sed -n 's/^TLS_ROTATE_OLD_CERT_SHA256=//p')"
[[ "$tls_sha" =~ ^[a-f0-9]{64}$ ]]
sudo bash "$TLS_ROTATE_SCRIPT" --apply \
  --smtp-port "$PORT" --server-name lmr365-ci.example.test \
  --tls-cert "$FIXTURE/next-cert.pem" --tls-key "$FIXTURE/next-key.pem" \
  --ca-file "$FIXTURE/next-cert.pem" \
  --expect-cert-sha256 "$tls_sha" --confirm ROTATE_PRIVATE_SMTP_TLS |
  tee /tmp/lmr365-tls-rotated.txt
grep -Fx 'TLS_ROTATE_APPLIED=yes' /tmp/lmr365-tls-rotated.txt
sudo test -d /var/lib/linuxmailrelay365-smtp-tls-recovery
sudo python3 "$IDENTITY_SCRIPT" --smtp-port "$PORT" \
  --server-name lmr365-ci.example.test --ca-file "$FIXTURE/next-cert.pem" |
  grep -Fx 'SMTP_TLS_PROBE_RESULT=verified_local_chain_dns_and_starttls'
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
echo 'SMTP_TLS_CERT_ROTATION_REAL_SMOKE=PASS'

echo '=== Verify approved SMTP client credentials over trusted TLS; no mail DATA ==='
# Fixture directory is root-only (0700); run this local check under sudo.
sudo python3 - "$PORT" "$FIXTURE/next-cert.pem" <<'PY'
import importlib.util,sys
spec=importlib.util.spec_from_file_location(
    "lmr365_ci_auth_verify","linux/verify-sidecar-auth-client.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
port=int(sys.argv[1]); ca=sys.argv[2]
hostname="lmr365-ci.example.test"
result=mod.verify(port, hostname,"lmr365-ci",ca,
                  password_provider=lambda _: "ci-fixture-password")
assert result in ("TLSv1.2","TLSv1.3"), "Unexpected TLS version"
try:
    mod.verify(port,hostname,"lmr365-ci",ca,
               password_provider=lambda _: "wrong-ci-test-password")
except mod.Refused:
    pass
else:
    raise AssertionError("Wrong SMTP AUTH password accepted")
called=[]
try:
    mod.verify(port,"wrong-host.example.test","lmr365-ci",ca,
               password_provider=lambda _: called.append("called") or
               "ci-fixture-password")
except mod.Refused:
    pass
else:
    raise AssertionError("Certificate identity mismatch accepted")
assert not called, "Password was requested before trusted TLS identity"
print("SMTP_AUTH_CLIENT_REAL_TLS_LOGIN=PASS")
print("SMTP_MAIL_FROM_RCPT_DATA_SENT=no")
PY
echo '=== Exercise SMTP AUTH after STARTTLS, without MAIL FROM/RCPT/DATA ==='
python3 - "$PORT" <<'PY'
import smtplib, ssl, sys
port=int(sys.argv[1])
with smtplib.SMTP('127.0.0.1', port, timeout=10) as smtp:
    code,_=smtp.ehlo('fixture.local')
    assert code==250 and smtp.has_extn('STARTTLS'), 'STARTTLS missing'
    assert not smtp.has_extn('AUTH'), 'AUTH exposed before encryption'
    code,_=smtp.docmd('MAIL FROM:<nobody@example.test>')
    assert code != 250, 'Unsafe plaintext mail submission accepted'
    smtp.starttls(context=ssl._create_unverified_context())
    smtp.ehlo('fixture.local')
    assert smtp.has_extn('AUTH'), 'AUTH missing after STARTTLS'
    # Authenticated submission is mandatory even for trusted localhost.
    code, _ = smtp.mail('mailer@example.test')
    assert code == 250, 'Encrypted MAIL FROM not accepted before policy check'
    code, _ = smtp.rcpt('receiver@example.test')
    assert code != 250, 'Unauthenticated RCPT TO unexpectedly accepted'
    smtp.rset()
    try:
        smtp.login('lmr365-ci','not-the-ci-fixture-password')
    except smtplib.SMTPAuthenticationError:
        pass
    else:
        raise AssertionError('Wrong SMTP password was accepted')
    smtp.login('lmr365-ci','ci-fixture-password')
    code, _ = smtp.mail('mailer@example.test')
    assert code == 250, 'Authenticated sender not accepted'
    code, _ = smtp.rcpt('receiver@example.test')
    assert code == 250, 'Authenticated relay recipient was rejected'
    smtp.rset() # No DATA: nothing is queued or sent.
with smtplib.SMTP('127.0.0.1', port, timeout=10) as smtp:
    smtp.ehlo('fixture.local')
    smtp.starttls(context=ssl._create_unverified_context())
    smtp.ehlo('fixture.local')
    smtp.login('lmr365-ci-b','ci-fixture-password-2')
print('AUTH_TLS_REAL_SMTP_SMOKE=PASS')
PY
echo '=== Simulated systemd cold-start (NOT an actual host reboot) ==='
# Stop only the isolated Postfix and its independent Dovecot service. The
# Requires=/After= relationship must bring both back with the same custom port.
sudo systemctl stop linuxmailrelay365-smtp-auth.service
sudo systemctl stop "$UNIT"
sudo systemctl start linuxmailrelay365-smtp-auth.service
sudo systemctl is-active --quiet "$UNIT"
sudo systemctl is-active --quiet linuxmailrelay365-smtp-auth.service
python3 - "$PORT" <<'PY'
import smtplib, ssl, sys, time
port = int(sys.argv[1])
last = None
for attempt in range(24):
    try:
        with smtplib.SMTP('127.0.0.1', port, timeout=4) as smtp:
            code, _ = smtp.ehlo('lmr365-cold-start.invalid')
            assert code == 250 and smtp.has_extn('STARTTLS')
            assert not smtp.has_extn('AUTH')
            smtp.starttls(context=ssl._create_unverified_context())
            smtp.ehlo('lmr365-cold-start.invalid')
            assert smtp.has_extn('AUTH')
            smtp.login('lmr365-ci-b', 'ci-fixture-password-2')
        break
    except (OSError, smtplib.SMTPException, AssertionError) as error:
        last = str(type(error).__name__)
        time.sleep(0.25)
else:
    raise AssertionError('Cold-start SMTP AUTH/TLS not ready: ' + str(last))
print('AUTH_TLS_ISOLATED_SYSTEMD_COLD_START=PASS')
PY
test "$(sudo postconf -c "$CONF" -h smtpd_sasl_auth_enable)" = yes
test "$(sudo cat "$CONF/smtp-port")" = "$PORT"
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
if sudo bash "$AUTH_SCRIPT" --apply "${AUTH_ARGS[@]}" --confirm ENABLE_PRIVATE_AUTH_TLS; then
  echo 'AUTH TLS unexpectedly allowed silent overwrite' >&2; exit 1
fi
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
echo '=== Rotate one isolated SMTP account using only a salted hash file ==='
sudo openssl passwd -6 -salt CIsalt2026 disposable-test-credential > /tmp/lmr365-hash-sha512.tmp
sudo sh -c 'printf "{SHA512-CRYPT}%s\n" "$(cat /tmp/lmr365-hash-sha512.tmp)" > /etc/linuxmailrelay365-ci-smtp/rotated.hash'
sudo chmod 0600 /etc/linuxmailrelay365-ci-smtp/rotated.hash
ACCOUNT=linux/manage-sidecar-smtp-accounts.py
account_preview="$(sudo python3 "$ACCOUNT" --smtp-port "$PORT" --operation rotate --username lmr365-ci-b --hash-file /etc/linuxmailrelay365-ci-smtp/rotated.hash)"
printf '%s\n' "$account_preview" | grep -Fx 'SMTP_ACCOUNT_RESULT=preview_ready'
account_sha="$(printf '%s\n' "$account_preview" | sed -n 's/^SMTP_ACCOUNT_CURRENT_STATE_SHA256=//p')"
[[ "$account_sha" =~ ^[a-f0-9]{64}$ ]]
sudo python3 "$ACCOUNT" --smtp-port "$PORT" --operation rotate --username lmr365-ci-b \
  --hash-file /etc/linuxmailrelay365-ci-smtp/rotated.hash --apply \
  --expected-state-sha256 "$account_sha" --confirm CHANGE_PRIVATE_SMTP_ACCOUNT |
  grep -Fx 'SMTP_ACCOUNT_RESULT=applied'
sudo test -d /var/lib/linuxmailrelay365-smtp-account-recovery
sudo rm -f /tmp/lmr365-hash-sha512.tmp
echo 'SMTP_ACCOUNT_REAL_ROTATION=PASS'
python3 - "$PORT" <<'PY'
import smtplib, ssl, sys
with smtplib.SMTP('127.0.0.1', int(sys.argv[1]), timeout=10) as c:
    c.ehlo('password-rotation-check.invalid')
    c.starttls(context=ssl._create_unverified_context())
    c.ehlo('password-rotation-check.invalid')
    try:
        c.login('lmr365-ci-b','ci-fixture-password-2')
    except smtplib.SMTPAuthenticationError:
        pass
    else:
        raise AssertionError('Former credential still accepted after rotation')
    c.login('lmr365-ci-b','disposable-test-credential')
print('SMTP_ACCOUNT_NEW_PASSWORD_ONLY=PASS')
PY
revoke_preview="$(sudo python3 "$ACCOUNT" --smtp-port "$PORT" --operation revoke --username lmr365-ci)"
revoke_sha="$(printf '%s\n' "$revoke_preview" | sed -n 's/^SMTP_ACCOUNT_CURRENT_STATE_SHA256=//p')"
[[ "$revoke_sha" =~ ^[a-f0-9]{64}$ ]]
sudo python3 "$ACCOUNT" --smtp-port "$PORT" --operation revoke --username lmr365-ci \
  --apply --expected-state-sha256 "$revoke_sha" \
  --confirm CHANGE_PRIVATE_SMTP_ACCOUNT |
  grep -Fx 'SMTP_ACCOUNT_COUNT_AFTER=1'
if sudo python3 "$ACCOUNT" --smtp-port "$PORT" --operation revoke --username lmr365-ci-b; then
  echo 'SECURITY ERROR: account manager allowed revocation of final SMTP account' >&2
  exit 1
fi
python3 - "$PORT" <<'PY'
import smtplib, ssl, sys
with smtplib.SMTP('127.0.0.1', int(sys.argv[1]), timeout=10) as c:
    c.ehlo('revoke-check.invalid')
    c.starttls(context=ssl._create_unverified_context())
    c.ehlo('revoke-check.invalid')
    try:
        c.login('lmr365-ci','ci-fixture-password')
    except smtplib.SMTPAuthenticationError:
        pass
    else:
        raise AssertionError('Revoked SMTP account still authenticated')
    c.login('lmr365-ci-b','disposable-test-credential')
print('SMTP_ACCOUNT_REVOKE_REAL_SMOKE=PASS')
PY


echo '=== Real independent Postfix + Dovecot AUTH/TLS scoped recovery ==='
bash tests/smoke_scoped_auth_recovery.sh "$PORT" "$FIXTURE/next-cert.pem"

echo '=== Verify tamper-guarded private AUTH/TLS restore preflight ==='
RESTORE_SCRIPT=linux/restore-sidecar-auth-tls.sh
restore_preview="$(sudo bash "$RESTORE_SCRIPT" --check-only --smtp-port "$PORT")"
printf '%s\n' "$restore_preview"
printf '%s\n' "$restore_preview" | grep -Fx 'AUTH_TLS_RESTORE_PREFLIGHT=ready'
printf '%s\n' "$restore_preview" | grep -Fx 'AUTH_TLS_RESTORE_SECURITY_DOWNGRADE=yes'
printf '%s\n' "$restore_preview" | grep -Fx 'CHANGES_APPLIED=no'
active_auth_sha="$(printf '%s\n' "$restore_preview" |
  sed -n 's/^AUTH_TLS_RESTORE_CURRENT_MAIN_SHA256=//p')"
[[ "$active_auth_sha" =~ ^[a-f0-9]{64}$ ]]

echo '=== Wrong port, hash, or missing confirmation MUST NOT change SMTP ==='
if sudo bash "$RESTORE_SCRIPT" --check-only --smtp-port 2530; then
  echo 'SECURITY ERROR: wrong installed custom port accepted' >&2; exit 1
fi
if sudo bash "$RESTORE_SCRIPT" --restore --smtp-port "$PORT" \
  --expect-main-sha256 "$(printf '%064d' 0)" \
  --confirm RESTORE_TRUSTED_NETWORK_SMTP; then
  echo 'SECURITY ERROR: mismatching SHA accepted' >&2; exit 1
fi
if sudo bash "$RESTORE_SCRIPT" --restore --smtp-port "$PORT" \
  --expect-main-sha256 "$active_auth_sha"; then
  echo 'SECURITY ERROR: missing downgrade confirmation accepted' >&2; exit 1
fi
test "$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$active_auth_sha"
sudo systemctl is-active --quiet linuxmailrelay365-smtp-auth.service

echo '=== Simulate restore failure AFTER Postfix reload: AUTH must be rolled back ==='
sudo install -d -o root -g root -m 0700 /tmp/lmr365-restore-fixture
# Write the fixture as runner, then place it inside the root-only directory.
cat > /tmp/lmr365-systemctl-fixture.sh <<'SH'
#!/usr/bin/env bash
if [ "$1" = disable ] && [ "${2:-}" = --now ] &&
   [ "${3:-}" = linuxmailrelay365-smtp-auth.service ]; then
  echo 'CI simulated systemctl failure before service disable' >&2
  exit 77
fi
exec /usr/bin/systemctl "$@"
SH
sudo install -o root -g root -m 0755 /tmp/lmr365-systemctl-fixture.sh /tmp/lmr365-restore-fixture/systemctl
rm -f /tmp/lmr365-systemctl-fixture.sh
if sudo env PATH="/tmp/lmr365-restore-fixture:/usr/sbin:/usr/bin:/sbin:/bin" \
  bash "$RESTORE_SCRIPT" --restore --smtp-port "$PORT" \
  --expect-main-sha256 "$active_auth_sha" \
  --confirm RESTORE_TRUSTED_NETWORK_SMTP; then
  echo 'SECURITY ERROR: CI induced restore failure was ignored' >&2; exit 1
fi
test "$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$active_auth_sha"
test "$(sudo postconf -c "$CONF" -h smtpd_sasl_auth_enable)" = yes
test "$(sudo postconf -c "$CONF" -h smtpd_tls_security_level)" = encrypt
sudo systemctl is-active --quiet linuxmailrelay365-smtp-auth.service
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
echo 'AUTH_TLS_RESTORE_FAULT_INJECTION_ROLLBACK=PASS'

echo '=== Restore original private/unauthenticated isolated SMTP ==='
sudo bash "$RESTORE_SCRIPT" --restore --smtp-port "$PORT" \
  --expect-main-sha256 "$active_auth_sha" \
  --confirm RESTORE_TRUSTED_NETWORK_SMTP
test "$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$baseline_sidecar_main"
test "$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')" = "$baseline_sidecar_master"
test "$(sudo postconf -c "$CONF" -h smtpd_sasl_auth_enable)" != yes
test "$(sudo postconf -c "$CONF" -h smtpd_tls_security_level)" != encrypt
if sudo systemctl is-active --quiet linuxmailrelay365-smtp-auth.service; then
  echo 'SECURITY ERROR: auth service still active after verified restore' >&2
  exit 1
fi
sudo test ! -e /etc/linuxmailrelay365/smtp-auth
sudo test ! -e /etc/systemd/system/linuxmailrelay365-smtp-auth.service
sudo test -d /var/lib/linuxmailrelay365-sidecar-auth-recovery
echo '=== Verify root-only recovery archives are protected after restore ==='
sudo test "$(sudo stat -c '%u:%g:%a' /var/lib/linuxmailrelay365-sidecar-auth-recovery)" = '0:0:700'
sudo python3 - <<'PY'
import os
from pathlib import Path
base = Path('/var/lib/linuxmailrelay365-sidecar-auth-recovery')
archives = [p for p in base.iterdir() if p.is_dir() and p.name.startswith('recovery.')]
assert len(archives) >= 1, 'Missing root-only recovery archive'
for archive in archives:
    stat = archive.lstat()
    assert stat.st_uid == 0 and (stat.st_mode & 0o077) == 0, 'Archive must be root-only'
    for name in ('main.cf.auth', 'master.cf.auth',
                 'linuxmailrelay365-smtp-auth.service', 'smtp-auth'):
        assert (archive / name).exists(), 'Incomplete recovery archive'
    for name in ('smtp-auth/passwd', 'smtp-auth/privkey.pem',
                 'smtp-auth/main.cf.before-auth'):
        p = archive / name
        assert p.is_file() and p.stat().st_uid == 0, 'Missing or untrusted secret snapshot'
print('AUTH_TLS_RESTORE_ROOT_ONLY_ARCHIVE=PASS')
PY
sudo python3 linux/audit-sidecar-auth-archives.py |
  tee /tmp/lmr365-auth-archive-audit.txt
grep -Fx 'AUTH_TLS_ARCHIVE_STATUS=verified_root_only' /tmp/lmr365-auth-archive-audit.txt
grep -Fx 'AUTH_TLS_ARCHIVE_POLICY=manual_retention_required' /tmp/lmr365-auth-archive-audit.txt
grep -Fx 'CHANGES_APPLIED=no' /tmp/lmr365-auth-archive-audit.txt
sudo python3 linux/installed-sidecar-audit.py --smtp-port "$PORT" |
  tee /tmp/lmr365-restored-audit.txt
grep -Fx 'SMTP_SECURITY_RESULT=private_unauthenticated_not_public_safe' /tmp/lmr365-restored-audit.txt
python3 - "$PORT" <<'PY'
import smtplib, sys
with smtplib.SMTP('127.0.0.1', int(sys.argv[1]), timeout=10) as smtp:
    code, _ = smtp.ehlo('lmr365-restored.invalid')
    assert code == 250 and not smtp.has_extn('AUTH')
print('AUTH_TLS_RESTORE_LOCAL_SMTP_SMOKE=PASS')
PY
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
test "$(sudo systemctl is-active postfix)" = "$primary_status"
test "$(sudo postconf -h queue_directory)" = "$primary_queue"
sudo systemctl is-active --quiet "$UNIT"
echo 'AUTH_TLS_RESTORE_REAL_SMOKE=PASS'
echo '=== Local EOP Direct Send recipient and sender restrictions, reversible route ==='
bash tests/smoke_eop_route.sh "$PORT"
echo 'SIDECAR_REAL_LINUX_SMOKE=PASS'

