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
test "$(sudo systemctl is-active postfix)" = "$primary_status"
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
test "$(sudo postconf -h queue_directory)" = "$primary_queue"

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
printf 'lmr365-ci:{SHA512-CRYPT}%s\n' "$hash" |
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
    try:
        smtp.login('lmr365-ci','not-the-ci-fixture-password')
    except smtplib.SMTPAuthenticationError:
        pass
    else:
        raise AssertionError('Wrong SMTP password was accepted')
    smtp.login('lmr365-ci','ci-fixture-password')
print('AUTH_TLS_REAL_SMTP_SMOKE=PASS')
PY
if sudo bash "$AUTH_SCRIPT" --apply "${AUTH_ARGS[@]}" --confirm ENABLE_PRIVATE_AUTH_TLS; then
  echo 'AUTH TLS unexpectedly allowed silent overwrite' >&2; exit 1
fi
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
echo 'SIDECAR_REAL_LINUX_SMOKE=PASS'

