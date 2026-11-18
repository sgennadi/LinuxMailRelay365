#!/usr/bin/env bash
# Independent ephemeral GitHub Actions VM, NO Entra app, NO mail DATA.
set -Eeuo pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
PORT=46500
UNIT=linuxmailrelay365-sidecar.service
CONF=/etc/linuxmailrelay365/sidecar-postfix
on_exit() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    sudo journalctl -u "$UNIT" -n 70 --no-pager || true
    sudo postfix -c "$CONF" check || true
  fi
  sudo systemctl stop "$UNIT" >/dev/null 2>&1 || true
  exit "$rc"
}
trap on_exit EXIT
if command -v debconf-set-selections >/dev/null; then
  printf '%s\n' 'postfix postfix/main_mailer_type select Local only' \
     'postfix postfix/mailname string ci.example.test' |
     sudo debconf-set-selections
fi
sudo apt-get update -qq
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postfix iproute2 openssl
sudo postconf -e 'myhostname = connector-ci.example.test'
sudo postfix check
sudo systemctl start postfix
sudo systemctl is-active --quiet postfix
primary_before="$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)"
primary_queue="$(sudo postconf -h queue_directory)"
installer=linux/install-connector-sidecar.sh
echo '=== Fresh Connector preflight without Entra app or OAuth identity ==='
sudo bash "$installer" --check-only \
  --smtp-port "$PORT" --mx-host example-org.mail.protection.outlook.com \
  --accepted-domain example.org --fixed-sender alerts@example.org --public-ip 8.8.8.8 |
  tee /tmp/lmr365-connector-preflight.txt
grep -Fx 'CONNECTOR_PREFLIGHT=inputs_valid_only' /tmp/lmr365-connector-preflight.txt
grep -Fx 'CHANGES_APPLIED=no' /tmp/lmr365-connector-preflight.txt
if sudo bash "$installer" --apply \
  --smtp-port "$PORT" --mx-host example-org.mail.protection.outlook.com \
  --accepted-domain example.org --fixed-sender alerts@example.org --public-ip 8.8.8.8; then
  echo 'SECURITY ERROR: unacknowledged tenant domain was installed' >&2; exit 1
fi
if sudo bash "$installer" --check-only \
  --smtp-port 25 --mx-host example-org.mail.protection.outlook.com \
  --accepted-domain example.org --fixed-sender alerts@example.org --public-ip 8.8.8.8; then
  echo 'SECURITY ERROR: privileged port accepted as custom listener' >&2; exit 1
fi
if sudo bash "$installer" --apply --confirm-accepted-domain TENANT_DOMAIN_CHECKED \
  --smtp-port "$PORT" --mx-host example-org.mail.protection.outlook.com \
  --accepted-domain example.org --fixed-sender alerts@example.org --public-ip 8.8.8.8; then
  echo 'SECURITY ERROR: unacknowledged tenant Connector was installed' >&2; exit 1
fi
echo '=== Install fresh private Connector on TCP 46500 ==='
sudo bash "$installer" --apply --confirm-accepted-domain TENANT_DOMAIN_CHECKED \
  --confirm-connector TENANT_CONNECTOR_CHECKED \
  --smtp-port "$PORT" --mx-host example-org.mail.protection.outlook.com \
  --accepted-domain example.org --fixed-sender alerts@example.org --public-ip 8.8.8.8 |
  tee /tmp/lmr365-connector-installed.txt
grep -Fx 'CONNECTOR_SIDECAR_INSTALLED=yes' /tmp/lmr365-connector-installed.txt
grep -Fx 'PRIMARY_POSTFIX_CONFIG_UNCHANGED=yes' /tmp/lmr365-connector-installed.txt
grep -Fx 'MICROSOFT365_DELIVERY_VERIFIED=no' /tmp/lmr365-connector-installed.txt
grep -Fx 'CONNECTOR_TENANT_CONNECTOR_VERIFIED=operator_attestation_only' /tmp/lmr365-connector-installed.txt
sudo systemctl is-active --quiet "$UNIT"
test "$(sudo postconf -c "$CONF" -h queue_directory)" = /var/spool/linuxmailrelay365-sidecar
test "$(sudo postconf -c "$CONF" -h inet_interfaces)" = 127.0.0.1
test "$(sudo postconf -c "$CONF" -h default_transport)" = \
  'smtp:[example-org.mail.protection.outlook.com]:25'
test "$(sudo postconf -c "$CONF" -h smtp_tls_security_level)" = secure
test "$(sudo postconf -c "$CONF" -h smtp_tls_secure_cert_match)" = nexthop
# Exercise Postfix's POSIX regexp parser rather than only a Python approximation.
sender_map="regexp:$CONF/eop-fixed-sender.regexp"
test "$(sudo postmap -q alerts@example.org "$sender_map")" = OK
for forbidden in different@example.org 'alerts+ci@example.org'     alerts@example.org.attacker.invalid; do
  answer="$(sudo postmap -q "$forbidden" "$sender_map" || true)"
  test -z "$answer" || {
    echo 'SECURITY ERROR: unexpected fixed sender map match' >&2; exit 1;
  }
done
echo 'FRESH_FIXED_SENDER_POSTMAP_EXACT_MATCH=PASS'
test "$(sudo postconf -c "$CONF" -h smtpd_relay_restrictions)" = \
  'permit_mynetworks, reject'
sudo test ! -e /etc/linuxmailrelay365/sidecar-identity/app.json
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
test "$(sudo postconf -h queue_directory)" = "$primary_queue"
python3 - "$PORT" <<'PY'
import smtplib,sys,time
port=int(sys.argv[1])
last=None
for attempt in range(20):
    try:
        with smtplib.SMTP('127.0.0.1',port,timeout=6) as smtp:
            code,_=smtp.ehlo('new-connector-ci.invalid')
            assert code==250
            code,_=smtp.mail('alerts@example.org')
            assert code==250
            code,_=smtp.rcpt('valid@example.org')
            assert code==250, 'Internal recipient rejected '+str(code)
            smtp.rset()
            code,_=smtp.mail('alerts@example.org')
            assert code==250
            code,_=smtp.rcpt('external@gmail.com')
            assert code==250, 'Connector refused external RCPT '+str(code)
            smtp.rset()
            code,_=smtp.mail('spoof@invalid.example')
            if code<500:
                code,_=smtp.rcpt('valid@example.org')
            assert code>=500, 'Spoof sender accepted '+str(code)
            smtp.rset()
            code,_=smtp.mail('different@example.org')
            if code<500:
                code,_=smtp.rcpt('valid@example.org')
            assert code>=500, 'Same-domain non-approved MAIL FROM accepted '+str(code)
            smtp.rset()
            code,_=smtp.mail('alerts+tag@example.org')
            if code<500:
                code,_=smtp.rcpt('valid@example.org')
            assert code>=500, 'Plus-address variation of approved sender accepted '+str(code)
        break
    except (OSError,smtplib.SMTPException,AssertionError) as err:
        last=str(err)[:120]
        time.sleep(.25)
else:
    raise AssertionError('Connector SMTP policy failed: '+str(last))
print('FRESH_CONNECTOR_LOCAL_RCPT_POLICY=PASS')
print('MAIL_DATA_SENT=no')
PY
echo '=== Isolated systemd service cold start, no OS reboot ==='
sudo systemctl stop "$UNIT"
sudo systemctl start "$UNIT"
sudo systemctl is-active --quiet "$UNIT"
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$primary_before"
sudo postfix -c "$CONF" check
echo 'FRESH_CONNECTOR_NO_OAUTH_UBUNTU_SMOKE=PASS'
