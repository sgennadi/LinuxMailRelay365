#!/usr/bin/env bash
# Real systemd Postfix under SELinux Enforcing, restricted to VM loopback.
# Never authenticates to Microsoft 365, submits MAIL FROM, RCPT TO or DATA.
set -Eeuo pipefail
test "$(cat /proc/1/comm)" = systemd
test "$(getenforce)" = Enforcing
test "$(cat /sys/fs/selinux/enforce)" = 1

export LC_ALL=C
sudo dnf -y -q install postfix iproute procps-ng
sudo postconf -e 'inet_interfaces = loopback-only'
sudo postconf -e 'inet_protocols = ipv4'
sudo postconf -e 'mynetworks = 127.0.0.0/8'
sudo postconf -e 'smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination'
sudo postconf -e 'relayhost ='
sudo postconf -e 'smtpd_tls_security_level = none'
test "$(sudo postconf -h inet_interfaces)" = "loopback-only"
test -z "$(sudo postconf -h relayhost)"
# Read-only native startup diagnostics, restricted to this disposable VM.
# A writable check as mail_owner does not establish postfix_master_t access.
postfix_data_diagnostic() {
    local phase="$1" data owner
    echo "LMR365_POSTFIX_DATA_DIAGNOSTIC_BEGIN=$phase"
    sudo postconf -x data_directory queue_directory mail_owner daemon_directory || true
    data="$(sudo postconf -xh data_directory 2>/dev/null || true)"
    owner="$(sudo postconf -xh mail_owner 2>/dev/null || true)"
    sudo getenforce || true
    sudo systemctl show postfix.service -p User -p Group -p ProtectSystem \
        -p ReadWritePaths -p InaccessiblePaths -p RootDirectory -p NoNewPrivileges || true
    if test "$data" = /var/lib/postfix && test "$owner" = postfix; then
        sudo id postfix || true
        sudo namei -l /var/lib/postfix/master.lock || true
        sudo ls -ldZ / /var /var/lib /var/lib/postfix /var/spool/postfix || true
        sudo stat -c '%n type=%F mode=%a uid=%u gid=%g inode=%i' /var/lib/postfix || true
        sudo findmnt -T /var/lib/postfix -o TARGET,FSTYPE,OPTIONS || true
        if sudo test -e /var/lib/postfix/master.lock || sudo test -L /var/lib/postfix/master.lock; then
            sudo ls -ldZ /var/lib/postfix/master.lock || true
            sudo stat -c '%n type=%F mode=%a uid=%u gid=%g inode=%i' /var/lib/postfix/master.lock || true
        else
            echo "LMR365_POSTFIX_MASTER_LOCK=absent"
        fi
        if command -v getfacl >/dev/null; then
            sudo getfacl -p /var/lib /var/lib/postfix || true
        fi
        if command -v matchpathcon >/dev/null; then
            sudo matchpathcon -V /var/lib/postfix /var/spool/postfix || true
            sudo matchpathcon /var/lib/postfix/master.lock || true
        fi
        if sudo runuser -u postfix -- test -w /var/lib/postfix &&
           sudo runuser -u postfix -- test -x /var/lib/postfix; then
            echo "LMR365_POSTFIX_MAIL_OWNER_ACCESS=write_search_observed"
        else
            echo "LMR365_POSTFIX_MAIL_OWNER_ACCESS=not_verified"
        fi
    else
        echo "LMR365_POSTFIX_DATA_DIAGNOSTIC_SCOPE=unsupported"
    fi
    # Native package metadata without executing RPM verification scripts.
    sudo rpm -q postfix selinux-policy-targeted || true
    sudo rpm -V --noscripts postfix || true
    echo "LMR365_POSTFIX_DATA_DIAGNOSTIC_END=$phase"
}

postfix_data_diagnostic before_check
sudo postfix check
postfix_data_diagnostic before_start
if ! sudo systemctl enable --now postfix.service ||
   ! sudo systemctl is-active --quiet postfix.service; then
    # Disposable VM only: keep the failed result and capture diagnostics.
    echo "LMR365_POSTFIX_START=failed"
    postfix_data_diagnostic after_failed_start
    sudo journalctl -b -k --no-pager | grep -Ei "avc:|selinux.*denied" | tail -n 60 || true
    sudo systemctl status postfix.service --no-pager -l || true
    sudo journalctl -b -u postfix.service --no-pager -n 100 || true
    sudo journalctl -b SYSLOG_IDENTIFIER=postfix/master --no-pager -n 100 || true
    sudo journalctl -b SYSLOG_IDENTIFIER=postfix/postfix-script --no-pager -n 100 || true
    if test -f /var/log/maillog; then sudo tail -n 60 /var/log/maillog || true; fi
    if command -v ausearch >/dev/null; then sudo ausearch -m AVC,USER_AVC -ts boot -i | tail -n 60 || true; fi
    exit 1
fi

# Confirm an actual process in the Postfix SELinux domain and a strictly
# loopback listener. Any wildcard/public listener fails the acceptance.
sudo python3 - <<'PY'
import subprocess
import sys

p = subprocess.run(["ps", "-eZ"],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   universal_newlines=True, timeout=10, check=True)
if not any("postfix_master_t" in line and "master" in line for line in p.stdout.splitlines()):
    raise SystemExit("LMR365_POSTFIX_PROCESS_SELINUX_CONTEXT_MISSING")
r = subprocess.run(["ss", "-H", "-ltn"], stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, universal_newlines=True,
                   timeout=10, check=True)
ports = []
for line in r.stdout.splitlines():
    fields = line.split()
    if len(fields) < 5:
        raise SystemExit("LMR365_POSTFIX_LISTENER_UNPARSEABLE")
    local = fields[3]
    addr, sep, port = local.rpartition(":")
    if sep and port == "25":
        if addr != "127.0.0.1":
            raise SystemExit("LMR365_POSTFIX_NON_LOOPBACK_LISTENER")
        ports.append(addr)
if ports != ["127.0.0.1"]:
    raise SystemExit("LMR365_POSTFIX_LOOPBACK25_NOT_CONFIRMED")
print("LMR365_POSTFIX_SELINUX_DOMAIN=postfix_master_t")
print("LMR365_POSTFIX_LISTENER=127.0.0.1_25_only")
PY

python3 - <<'PY'
import socket

def reply(reader, expected):
    for _ in range(30):
        line = reader.readline(2049)
        if len(line) < 4 or len(line) > 2048:
            raise SystemExit("LMR365_SMTP_INVALID_REPLY")
        if int(line[:3]) != expected or line[3:4] not in (b"-", b" "):
            raise SystemExit("LMR365_SMTP_UNEXPECTED_CODE")
        if line[3:4] == b" ":
            return
    raise SystemExit("LMR365_SMTP_TOO_MANY_LINES")

with socket.create_connection(("127.0.0.1", 25), timeout=6) as sock:
    sock.settimeout(6)
    reader = sock.makefile("rb")
    reply(reader, 220)
    sock.sendall(b"EHLO lmr365-check.invalid\r\n")
    reply(reader, 250)
    sock.sendall(b"QUIT\r\n")
    reply(reader, 221)
    reader.close()
print("LMR365_POSTFIX_SMTP_GREETING_EHLO_QUIT=passed_without_mail")
PY

test "$(getenforce)" = Enforcing
test -z "$(sudo postqueue -j)"
echo "LMR365_GUEST_POSTFIX_SYSTEMD=active"
echo "LMR365_GUEST_POSTFIX_SELINUX=enforcing"
echo "LMR365_GUEST_POSTFIX_QUEUE=empty"
echo "LMR365_GUEST_POSTFIX_SMTP_AUTH_TESTED=no"
echo "LMR365_GUEST_POSTFIX_EXTERNAL_DELIVERY_TESTED=no"
