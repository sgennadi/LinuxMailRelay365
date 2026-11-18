#!/usr/bin/env bash
# Real Postfix MAIL/RCPT-only Direct Send test: NEVER sends DATA or a message.
set -Eeuo pipefail
export LC_ALL=C
PORT=2529
if [ "$#" -gt 0 ]; then PORT="$1"; fi
CONF=/etc/linuxmailrelay365/sidecar-postfix
MANAGER=linux/manage-sidecar-eop-route.py
MX=example-org.mail.protection.outlook.com
SENDER=alerts@example.org
DOMAIN=example.org
PRIMARY_BEFORE="$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)"
BASE_MAIN="$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')"
BASE_MASTER="$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')"
echo '=== Read-only EOP preflight and wrong SHA refusal ==='
preview="$(sudo python3 "$MANAGER" --check-only --smtp-port "$PORT" \
  --mode direct-send --mx-host "$MX" --sender "$SENDER" \
  --recipient-domain "$DOMAIN")"
printf '%s\n' "$preview" | grep -Fx 'EOP_ROUTE_PREFLIGHT=ready'
printf '%s\n' "$preview" | grep -Fx 'EOP_ROUTE_OUTBOUND_PORT=25'
printf '%s\n' "$preview" | grep -Fx 'CHANGES_APPLIED=no'
expected="$(printf '%s\n' "$preview" | sed -n 's/^EOP_ROUTE_MAIN_SHA256=//p')"
[[ "$expected" =~ ^[a-f0-9]{64}$ ]]
if sudo python3 "$MANAGER" --apply --smtp-port "$PORT" \
  --mode direct-send --mx-host "$MX" --sender "$SENDER" \
  --recipient-domain "$DOMAIN" --expect-main-sha256 "$(printf '%064d' 0)" \
  --confirm DEPLOY_PRIVATE_EOP_ROUTE; then
  echo 'SECURITY ERROR: stale baseline accepted' >&2; exit 1
fi
test "$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$BASE_MAIN"
echo '=== Activate isolated EOP route; no outbound mail DATA ==='
sudo python3 "$MANAGER" --apply --smtp-port "$PORT" \
  --mode direct-send --mx-host "$MX" --sender "$SENDER" \
  --recipient-domain "$DOMAIN" --expect-main-sha256 "$expected" \
  --confirm DEPLOY_PRIVATE_EOP_ROUTE |
  tee /tmp/lmr365-eop-route-apply.txt
grep -Fx 'EOP_ROUTE_APPLIED=yes' /tmp/lmr365-eop-route-apply.txt
grep -Fx 'MICROSOFT365_DELIVERY_VERIFIED=no' /tmp/lmr365-eop-route-apply.txt
test "$(sudo postconf -c "$CONF" -h smtpd_relay_restrictions)" = 'permit_mynetworks, reject'
test "$(sudo postconf -c "$CONF" -h smtp_tls_security_level)" = secure
test "$(sudo postconf -c "$CONF" -h smtp_tls_secure_cert_match)" = nexthop
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$PRIMARY_BEFORE"
echo '=== Verify internal RCPT accepted, external RCPT/sender rejected locally ==='
python3 - "$PORT" <<'PY'
import smtplib,sys,time
port=int(sys.argv[1])
last=None
for attempt in range(20):
    try:
        with smtplib.SMTP('127.0.0.1',port,timeout=6) as s:
            code,_=s.ehlo('lmr365-eop-acceptance.invalid')
            assert code==250
            code,_=s.mail('alerts@example.org')
            assert code==250, 'declared sender rejected: '+str(code)
            code,_=s.rcpt('internal@example.org')
            assert code==250, 'internal RCPT rejected: '+str(code)
            s.rset()
            code,_=s.mail('alerts@example.org')
            assert code==250
            code,_=s.rcpt('external@gmail.com')
            assert code>=500, 'EXTERNAL RCPT ACCEPTED: '+str(code)
            s.rset()
            code,_=s.mail('spoof@evil.example')
            assert code>=500, 'FOREIGN SENDER ACCEPTED: '+str(code)
        break
    except (OSError,smtplib.SMTPException,AssertionError) as e:
        last=str(e)[:90];time.sleep(.25)
else:
    raise AssertionError('EOP policy not ready: '+str(last))
print('EOP_DIRECT_SEND_REJECTS_EXTERNAL_RCPT=PASS')
print('EOP_DIRECT_SEND_FIXED_SENDER_POLICY=PASS')
print('MAIL_DATA_SENT=no')
PY
echo '=== Guarded return to original isolated XOAUTH2 ==='
status="$(sudo python3 "$MANAGER" --status --smtp-port "$PORT")"
printf '%s\n' "$status" | grep -Fx 'EOP_ROUTE_STATUS=active'
printf '%s\n' "$status" | grep -Fx 'CHANGES_APPLIED=no'
fingerprint="$(printf '%s\n' "$status" |
  sed -n 's/^EOP_ROUTE_CURRENT_MAIN_SHA256=//p')"
[[ "$fingerprint" =~ ^[a-f0-9]{64}$ ]]
if sudo python3 "$MANAGER" --restore --smtp-port "$PORT" \
  --expect-main-sha256 "$(printf '%064d' 0)" \
  --confirm RESTORE_PRIVATE_EOP_ROUTE; then
  echo 'SECURITY ERROR: changed active-route SHA accepted' >&2; exit 1
fi
sudo python3 "$MANAGER" --restore --smtp-port "$PORT" \
  --expect-main-sha256 "$fingerprint" \
  --confirm RESTORE_PRIVATE_EOP_ROUTE |
  tee /tmp/lmr365-eop-route-restore.txt
grep -Fx 'EOP_ROUTE_RESTORED=yes' /tmp/lmr365-eop-route-restore.txt
test "$(sudo sha256sum "$CONF/main.cf" | awk '{print $1}')" = "$BASE_MAIN"
test "$(sudo sha256sum "$CONF/master.cf" | awk '{print $1}')" = "$BASE_MASTER"
test "$(sudo sha256sum /etc/postfix/main.cf /etc/postfix/master.cf)" = "$PRIMARY_BEFORE"
sudo test ! -e /var/lib/linuxmailrelay365-eop-route-recovery/active.json
sudo test -d /var/lib/linuxmailrelay365-eop-route-recovery
sudo systemctl is-active --quiet linuxmailrelay365-sidecar.service
echo 'EOP_DIRECT_SEND_APPLY_RESTORE_REAL_SMOKE=PASS'
