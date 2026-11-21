#!/usr/bin/env bash
# Isolated Rocky 9 guest-only test of STARTTLS, Dovecot SMTP AUTH and 2525.
# No tenant, outbound mail, SMTP DATA or public listener. Never run on a user MTA.
set -Eeuo pipefail
umask 077
mode="$1"
case "$mode" in --setup|--verify) ;; *) echo "LMR365_LAB_UNSUPPORTED_MODE" >&2; exit 2;; esac
test "$(cat /proc/1/comm)" = systemd
test "$(getenforce)" = Enforcing
test "$(cat /sys/fs/selinux/enforce)" = 1
sudo systemctl is-active --quiet postfix.service
cert=/etc/pki/tls/certs/lmr365-ci.pem
key=/etc/pki/tls/private/lmr365-ci.key
secret=/home/ci/.lmr365-ci-password

if test "$mode" = --setup; then
  sudo dnf -y -q install dovecot openssl policycoreutils-python-utils
  sudo postconf -a | grep -Fxq dovecot
  sudo openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
      -subj "/CN=smtp.lab.invalid" \
      -addext "subjectAltName=DNS:smtp.lab.invalid,IP:127.0.0.1" \
      -keyout "$key" -out "$cert" >/dev/null 2>&1
  sudo chmod 0600 "$key"
  sudo chmod 0644 "$cert"
  sudo restorecon -F "$key" "$cert"
  openssl rand -hex 24 > "$secret"
  chmod 0600 "$secret"
  hash="$(openssl passwd -6 -stdin < "$secret")"
  printf '%s:{SHA512-CRYPT}%s\n' "lmr365-ci" "$hash" |
      sudo tee /etc/dovecot/lmr365-ci-passwd >/dev/null
  # Match the actual LinuxMailRelay365 installer: Dovecot's auth worker
  # reads this file as the 'dovecot' group, not root. World access is denied.
  sudo chown root:dovecot /etc/dovecot/lmr365-ci-passwd
  sudo chmod 0640 /etc/dovecot/lmr365-ci-passwd
  sudo restorecon -F /etc/dovecot/lmr365-ci-passwd
  sudo install -d -m 0755 /var/lib/lmr365-ci-dovecot
  cat <<'CONF' | sudo tee /etc/dovecot/lmr365-ci-auth.conf >/dev/null
base_dir = /run/lmr365-ci-dovecot
state_dir = /var/lib/lmr365-ci-dovecot
instance_name = lmr365-ci-auth
protocols =
listen = 127.0.0.1
ssl = no
auth_mechanisms = plain login
disable_plaintext_auth = no
auth_failure_delay = 0 secs
passdb {
  driver = passwd-file
  args = /etc/dovecot/lmr365-ci-passwd
}
userdb {
  driver = static
  args = uid=postfix gid=postfix home=/nonexistent
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
CONF
  sudo chmod 0644 /etc/dovecot/lmr365-ci-auth.conf
  sudo restorecon -F /etc/dovecot/lmr365-ci-auth.conf
  cat <<'UNIT' | sudo tee /etc/systemd/system/lmr365-ci-auth.service >/dev/null
[Unit]
Description=Disposable Rocky CI-only Dovecot SASL
After=postfix.service
Requires=postfix.service
[Service]
Type=simple
ExecStart=/usr/sbin/dovecot -F -c /etc/dovecot/lmr365-ci-auth.conf
RuntimeDirectory=lmr365-ci-dovecot
RuntimeDirectoryMode=0755
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
  sudo chmod 0644 /etc/systemd/system/lmr365-ci-auth.service
  sudo restorecon -F /etc/systemd/system/lmr365-ci-auth.service
  sudo doveconf -c /etc/dovecot/lmr365-ci-auth.conf -n >/dev/null

  label="$(sudo python3 - <<'PY'
import importlib.util
import subprocess
spec = importlib.util.spec_from_file_location("doctor", "/tmp/lmr365-doctor.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
rules = subprocess.check_output(["semanage","port","-l"], universal_newlines=True, timeout=30)
print(module.port_label(2525, rules))
PY
)"
  if test "$label" = unmapped; then
    sudo semanage port -a -t smtp_port_t -p tcp 2525
  elif test "$label" != smtp_port_t; then
    echo "LMR365_LAB_SELINUX_2525_CONFLICT"
    exit 1
  fi
  sudo postconf -e "smtpd_tls_cert_file = $cert"
  sudo postconf -e "smtpd_tls_key_file = $key"
  sudo postconf -e 'smtpd_tls_auth_only = yes'
  sudo postconf -e 'smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1'
  sudo postconf -M '2525/inet=2525 inet n - n - - smtpd'
  for override in \
    'smtpd_tls_security_level=encrypt' \
    'smtpd_tls_auth_only=yes' \
    'smtpd_sasl_auth_enable=yes' \
    'smtpd_sasl_type=dovecot' \
    'smtpd_sasl_path=private/auth' \
    'smtpd_sasl_security_options=noanonymous' \
    'smtpd_relay_restrictions=permit_sasl_authenticated,reject' \
    'smtpd_recipient_restrictions=permit_sasl_authenticated,reject'; do
    sudo postconf -P "2525/inet/$override"
  done
  sudo postfix check
  sudo systemctl daemon-reload
  sudo systemctl enable --now lmr365-ci-auth.service
  ready=no
  for i in $(seq 1 40); do
    if sudo test -S /var/spool/postfix/private/auth; then ready=yes; break; fi
    if ! sudo systemctl is-active --quiet lmr365-ci-auth.service; then break; fi
    sleep 0.5
  done
  if test "$ready" != yes; then
    echo "LMR365_LAB_DOVECOT_AUTH_SOCKET_UNAVAILABLE"
    sudo systemctl --no-pager status lmr365-ci-auth.service || true
    exit 1
  fi
  sudo systemctl restart postfix.service
fi

sudo systemctl is-active --quiet postfix.service
sudo systemctl is-active --quiet lmr365-ci-auth.service
sudo test -S /var/spool/postfix/private/auth
test "$(sudo stat -c '%U:%G:%a' /etc/dovecot/lmr365-ci-passwd)" = "root:dovecot:640" || {
  echo "LMR365_LAB_PASSFILE_DAC_INVALID"
  exit 1
}
test "$(getenforce)" = Enforcing
test "$(sudo postconf -h inet_interfaces)" = loopback-only
test -z "$(sudo postconf -h relayhost)"
test "$(sudo postconf -P -h 2525/inet/smtpd_tls_security_level)" = encrypt
test "$(sudo postconf -P -h 2525/inet/smtpd_sasl_auth_enable)" = yes
sudo python3 - <<'PY'
import subprocess
p = subprocess.run(["ss","-H","-ltn"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   universal_newlines=True, check=True, timeout=12)
seen = {25:[], 2525:[]}
for line in p.stdout.splitlines():
    fields = line.split()
    if len(fields) < 5:
        raise SystemExit("LMR365_LAB_LISTENER_UNVERIFIED")
    address, _, port = fields[3].rpartition(":")
    if port.isdigit() and int(port) in seen:
        seen[int(port)].append(address)
if seen != {25:["127.0.0.1"],2525:["127.0.0.1"]}:
    raise SystemExit("LMR365_LAB_NON_LOOPBACK_OR_MISSING_LISTENER")
print("LMR365_LAB_SMTP_PORTS=loopback_25_2525")
PY

python3 - "$secret" "$cert" <<'PY'
import smtplib
import ssl
import sys
from pathlib import Path

password = Path(sys.argv[1]).read_text(encoding="ascii").strip()
ctx = ssl.create_default_context(cafile=sys.argv[2])
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
with smtplib.SMTP("127.0.0.1", 2525, timeout=12) as smtp:
    if smtp.ehlo("ci.lab.invalid")[0] != 250:
        raise SystemExit("LMR365_LAB_EHLO_FAILED")
    if not smtp.has_extn("starttls") or smtp.has_extn("auth"):
        raise SystemExit("LMR365_LAB_PRETLS_CAPABILITY_INVALID")
    try:
        smtp.login("lmr365-ci", password)
    except smtplib.SMTPNotSupportedError:
        pass
    else:
        raise SystemExit("LMR365_LAB_AUTH_BEFORE_TLS_ACCEPTED")
    if smtp.starttls(context=ctx)[0] != 220:
        raise SystemExit("LMR365_LAB_STARTTLS_FAILED")
    smtp.ehlo("ci.lab.invalid")
    if not smtp.has_extn("auth"):
        raise SystemExit("LMR365_LAB_AUTH_AFTER_TLS_MISSING")
    if not isinstance(smtp.sock, ssl.SSLSocket) or smtp.sock.version() not in ("TLSv1.2","TLSv1.3"):
        raise SystemExit("LMR365_LAB_TLS_PROTOCOL_UNSAFE")
    try:
        smtp.login("lmr365-ci", "wrong-lab-password")
    except smtplib.SMTPAuthenticationError:
        pass
    else:
        raise SystemExit("LMR365_LAB_WRONG_PASSWORD_ACCEPTED")
    smtp.login("lmr365-ci", password)
print("LMR365_LAB_STARTTLS=validated_cert_san_tls12_plus")
print("LMR365_LAB_PRETLS_AUTH=not_advertised")
print("LMR365_LAB_BAD_PASSWORD=rejected")
print("LMR365_LAB_VALID_PASSWORD=accepted_only_over_tls")
PY
test "$(getenforce)" = Enforcing
test -z "$(sudo postqueue -j)"
echo "LMR365_LAB_MODE=$mode"
echo "LMR365_LAB_SELINUX=enforcing"
echo "LMR365_LAB_QUEUE=empty"
echo "LMR365_LAB_EXTERNAL_MAIL_TESTED=no"
