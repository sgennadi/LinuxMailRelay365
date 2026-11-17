#!/usr/bin/env bash
# One-time Postfix -> Microsoft 365 XOAUTH2 app-only setup.
# Supports Ubuntu/Debian and RHEL/Oracle Linux 8/9/10-family systems.
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TENANT=''
CLIENT=''
MAILBOX=''
ALLOW_EXISTING=0
PREPARE_ONLY=0
CERT_DAYS=365
ROTATE_ONLY=0
ACTIVATE_ONLY=0
LISTEN_IP=''
TRUSTED_NETWORKS=()
VALIDATE_NETWORK_ONLY=0

usage() {
  cat <<'EOF'
Usage (run as root):
  bash install-postfix-m365-xoauth2.sh \
    --tenant-id GUID --client-id GUID --mailbox alerts@example.com

Optional: --allow-existing   Explicit override for existing Postfix routes.
          --listen-ip IPv4   Bind local IPv4 interface + loopback for SMTP.
          --trusted-network CIDR  Permit client RFC1918 subnet (repeatable).
          --validate-network-only  Validate ingress without modifying anything.
          --prepare-only     Generate certificate and dedicated local account.
          --certificate-days N (1..365, default 365).
          --rotate-only      Prepare a SECOND certificate without disrupting the old one.
          --activate-only    After adding the next certificate in Entra, switch keys.
This installer never automatically removes an existing Sendmail or Exim MTA.

Does not require or store a Microsoft 365 mailbox password, refresh token,
or application client secret. Generates a certificate and private key.
The certificate must be uploaded to the Entra app separately.
EOF
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --tenant-id) TENANT="${2:?}"; shift 2 ;;
    --client-id) CLIENT="${2:?}"; shift 2 ;;
    --mailbox) MAILBOX="${2:?}"; shift 2 ;;
    --allow-existing) ALLOW_EXISTING=1; shift ;;
    --listen-ip) LISTEN_IP="${2:?}"; shift 2 ;;
    --trusted-network) TRUSTED_NETWORKS+=("${2:?}"); shift 2 ;;
    --validate-network-only) VALIDATE_NETWORK_ONLY=1; shift ;;
    --prepare-only) PREPARE_ONLY=1; shift ;;
    --rotate-only) ROTATE_ONLY=1; shift ;;
    --activate-only) ACTIVATE_ONLY=1; shift ;;
    --certificate-days) CERT_DAYS="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
if [ "$PREPARE_ONLY" -ne 1 ] && [ "$ROTATE_ONLY" -ne 1 ] && [ "$ACTIVATE_ONLY" -ne 1 ] && [ "$VALIDATE_NETWORK_ONLY" -ne 1 ]; then
  [ -n "$TENANT" ] && [ -n "$CLIENT" ] && [ -n "$MAILBOX" ] || { usage >&2; exit 2; }
fi
GUID_REGEX='^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$'
MAILBOX_REGEX='^[^[:space:]<>@]+@[^[:space:]<>@]+$'
if [ "$PREPARE_ONLY" -ne 1 ] && [ "$ROTATE_ONLY" -ne 1 ] && [ "$ACTIVATE_ONLY" -ne 1 ] && [[ ! "$TENANT" =~ $GUID_REGEX || ! "$CLIENT" =~ $GUID_REGEX || ! "$MAILBOX" =~ $MAILBOX_REGEX ]]; then
  echo 'Invalid tenant/client GUID or mailbox address' >&2
  exit 2
fi

if ! [[ "$CERT_DAYS" =~ ^[0-9]+$ ]] || [ "$CERT_DAYS" -lt 1 ] || [ "$CERT_DAYS" -gt 365 ]; then
  echo 'Certificate validity must be 1..365 days.' >&2
  exit 2
fi
if [ "$ACTIVATE_ONLY" -eq 1 ] && [ "$ROTATE_ONLY" -eq 1 ]; then
  echo 'Choose only one lifecycle action.' >&2
  exit 2
fi


# Validate before touching Postfix, packages, identities or certificates.
validate_ingress() {
  if [ -z "$LISTEN_IP" ]; then
    if [ "${#TRUSTED_NETWORKS[@]}" -ne 0 ]; then
      echo 'Trusted client networks require an explicit --listen-ip.' >&2; return 2
    fi
    return 0
  fi
  if [ "${#TRUSTED_NETWORKS[@]}" -eq 0 ] || [ "${#TRUSTED_NETWORKS[@]}" -gt 8 ]; then
    echo 'Remote SMTP requires 1..8 trusted RFC1918 CIDRs.' >&2; return 2
  fi
  command -v python3 >/dev/null 2>&1 || {
    echo 'Python 3 is required for SMTP ingress validation.' >&2; return 2;
  }
  python3 - "$LISTEN_IP" "${TRUSTED_NETWORKS[@]}" <<'PY'
import ipaddress, sys
try:
    ip = ipaddress.ip_address(sys.argv[1])
    if not isinstance(ip, ipaddress.IPv4Address) or str(ip) != sys.argv[1] or (
        ip.is_unspecified or ip.is_loopback or ip.is_multicast or
        ip.is_link_local or ip.is_reserved):
        raise ValueError("Listener must be an explicit non-loopback IPv4")
    allowed = [ipaddress.ip_network(s) for s in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    for cidr in sys.argv[2:]:
        network = ipaddress.ip_network(cidr, strict=True)
        if not isinstance(network, ipaddress.IPv4Network) or not any(
            network.subnet_of(private) for private in allowed):
            raise ValueError("Trusted clients must belong to a specific RFC1918 subnet")
except ValueError as exc:
    sys.stderr.write("SMTP ingress policy rejected: " + str(exc) + "\n")
    sys.exit(2)
PY
}
validate_ingress
if [ "$VALIDATE_NETWORK_ONLY" -eq 1 ]; then
  if [ -n "$LISTEN_IP" ]; then
    echo 'VALIDATED: local listener + RFC1918 clients; no changes.'
  else
    echo 'VALIDATED: loopback SMTP only; no changes.'
  fi
  exit 0
fi
[ "$(id -u)" -eq 0 ] || { echo 'Run as root (sudo bash ...)' >&2; exit 1; }
if [ "$PREPARE_ONLY" -eq 1 ] || [ "$ROTATE_ONLY" -eq 1 ] || [ "$ACTIVATE_ONLY" -eq 1 ]; then
  if [ -n "$LISTEN_IP" ] || [ "${#TRUSTED_NETWORKS[@]}" -gt 0 ]; then
    echo 'Listener options apply only during full installation.' >&2; exit 2
  fi
fi
if [ -n "$LISTEN_IP" ]; then
  command -v ip >/dev/null 2>&1 || { echo 'iproute2 is required to check the local interface.' >&2; exit 2; }
  if ! ip -o -4 addr show | awk '{split($4,a,"/");print a[1]}' | grep -Fxq -- "$LISTEN_IP"; then
    echo 'SMTP listener IP is not assigned to a local interface.' >&2; exit 2
  fi
fi

CONF_DIR=/etc/postfix/m365-oauth
if [ "$ACTIVATE_ONLY" -eq 1 ]; then
  [ -f "$CONF_DIR/app.next.key" ] && [ -f "$CONF_DIR/app.next.crt" ] || {
    echo 'No staged certificate. Run --rotate-only and register the public key in Entra first.' >&2
    exit 1
  }
  [ -f "$CONF_DIR/app.key" ] && [ -f "$CONF_DIR/app.crt" ] || exit 1
  test -f "$CONF_DIR/app.json" || { echo 'Postfix app config is missing' >&2; exit 1; }
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  # Keep BOTH previous files as root-only local recovery artifacts.
  cp -p "$CONF_DIR/app.key" "$CONF_DIR/app.old.$stamp.key"
  cp -p "$CONF_DIR/app.crt" "$CONF_DIR/app.old.$stamp.crt"
  cp -p "$CONF_DIR/app.next.key" "$CONF_DIR/app.key"
  cp -p "$CONF_DIR/app.next.crt" "$CONF_DIR/app.crt"
  chown root:m365mailer "$CONF_DIR/app.key" "$CONF_DIR/app.crt"
  chmod 0640 "$CONF_DIR/app.key"
  chmod 0644 "$CONF_DIR/app.crt"
  if command -v runuser >/dev/null 2>&1 &&
     runuser -u m365mailer -- /usr/bin/python3 /usr/local/libexec/m365_xoauth2_transport.py --token-check; then
    rm -f "$CONF_DIR/app.next.key" "$CONF_DIR/app.next.crt"
    echo 'ACTIVE_CERTIFICATE=rotated; previous files kept for rollback.'
  else
    cp -p "$CONF_DIR/app.old.$stamp.key" "$CONF_DIR/app.key"
    cp -p "$CONF_DIR/app.old.$stamp.crt" "$CONF_DIR/app.crt"
    echo 'Activation failed; previous signing key restored. Staged files retained.' >&2
    exit 1
  fi
  exit 0
fi

# Do NOT silently replace Sendmail, Exim, or existing inbound mail flows.
if [ "$PREPARE_ONLY" -ne 1 ] && [ "$ROTATE_ONLY" -ne 1 ] &&
   ! command -v postconf >/dev/null 2>&1 &&
   { [ -f /etc/mail/sendmail.cf ] || command -v exim >/dev/null 2>&1; }; then
  echo 'Existing Sendmail/Exim MTA detected. Automatic migration is intentionally blocked.' >&2
  echo 'Back up and plan a confirmed MTA migration before running this installer.' >&2
  exit 1
fi

# Even default values cannot prove that an existing Postfix is unused.
if [ "$PREPARE_ONLY" -ne 1 ] && [ "$ROTATE_ONLY" -ne 1 ] &&
   command -v postconf >/dev/null 2>&1 && [ "$ALLOW_EXISTING" -eq 0 ]; then
  echo 'Existing Postfix detected. Refusing to change ANY live mail routes by default.' >&2
  echo 'Select Preserve Existing Mail or explicitly approve --allow-existing.' >&2
  exit 1
fi

if [ "$PREPARE_ONLY" -eq 1 ] || [ "$ROTATE_ONLY" -eq 1 ]; then
  command -v openssl >/dev/null || { echo 'OpenSSL is required for preparation.' >&2; exit 1; }
  command -v useradd >/dev/null || { echo 'useradd is required for preparation.' >&2; exit 1; }
elif command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  if ! command -v postconf >/dev/null 2>&1 && command -v debconf-set-selections >/dev/null 2>&1; then
    printf 'postfix postfix/main_mailer_type select Local only\n' | debconf-set-selections
  fi
  apt-get update
  apt-get install -y postfix python3 openssl ca-certificates
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y postfix python3 openssl ca-certificates
else
  echo 'Unsupported package manager. Use Ubuntu, Debian, RHEL or Oracle Linux.' >&2
  exit 1
fi

[ -f "$SCRIPT_DIR/m365_xoauth2_transport.py" ] || {
  echo "Missing $SCRIPT_DIR/m365_xoauth2_transport.py" >&2; exit 1;
}

if ! id m365mailer >/dev/null 2>&1; then
  NOLOGIN="$(command -v nologin || echo /sbin/nologin)"
  useradd --system --home-dir /nonexistent --shell "$NOLOGIN" m365mailer
fi

install -d -o root -g m365mailer -m 0750 "$CONF_DIR"
if [ "$ROTATE_ONLY" -eq 1 ]; then
  [ -f "$CONF_DIR/app.key" ] && [ -f "$CONF_DIR/app.crt" ] || {
    echo 'Active certificate missing; use --prepare-only first.' >&2; exit 1;
  }
  [ ! -e "$CONF_DIR/app.next.key" ] && [ ! -e "$CONF_DIR/app.next.crt" ] || {
    echo 'A pending certificate exists; activate or remove it explicitly first.' >&2; exit 1;
  }
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days "$CERT_DAYS" \
    -subj '/CN=LinuxMailRelay365-rotation' \
    -keyout "$CONF_DIR/app.next.key" -out "$CONF_DIR/app.next.crt" >/dev/null 2>&1
  chown root:m365mailer "$CONF_DIR/app.next.key" "$CONF_DIR/app.next.crt"
  chmod 0640 "$CONF_DIR/app.next.key"
  chmod 0644 "$CONF_DIR/app.next.crt"
  echo 'STAGED_CERT_PATH=/etc/postfix/m365-oauth/app.next.crt'
  echo 'Upload this public certificate to the EXISTING Entra application without removing other keys.'
  exit 0
fi
if [ ! -f "$CONF_DIR/app.key" ] || [ ! -f "$CONF_DIR/app.crt" ]; then
  if [ -e "$CONF_DIR/app.key" ] || [ -e "$CONF_DIR/app.crt" ]; then
    echo 'Incomplete certificate/key pair detected; refusing to overwrite.' >&2
    exit 1
  fi
  echo "Generating a ${CERT_DAYS}-day RSA 3072-bit app certificate..."
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days "$CERT_DAYS" \
    -subj '/CN=LinuxMailRelay365' \
    -keyout "$CONF_DIR/app.key" -out "$CONF_DIR/app.crt" >/dev/null 2>&1
fi
chown root:m365mailer "$CONF_DIR/app.key" "$CONF_DIR/app.crt"
chmod 0640 "$CONF_DIR/app.key"
chmod 0644 "$CONF_DIR/app.crt"

if [ "$PREPARE_ONLY" -eq 1 ]; then
  echo 'Certificate preparation complete; upload PUBLIC app.crt in the Microsoft 365 provisioning step.'
  echo 'PUBLIC_CERT_PATH=/etc/postfix/m365-oauth/app.crt'
  exit 0
fi

python3 - "$TENANT" "$CLIENT" "$MAILBOX" "$CONF_DIR/app.json" <<'PY'
import json,sys,uuid
config = {
 'tenant_id': str(uuid.UUID(sys.argv[1])),
 'client_id': str(uuid.UUID(sys.argv[2])),
 'mailbox': sys.argv[3],
 'certificate': '/etc/postfix/m365-oauth/app.crt',
 'private_key': '/etc/postfix/m365-oauth/app.key',
}
with open(sys.argv[4], 'w', encoding='utf-8') as fh:
    json.dump(config, fh, indent=2)
    fh.write('\n')
PY
chown root:m365mailer "$CONF_DIR/app.json"
chmod 0640 "$CONF_DIR/app.json"

install -D -o root -g root -m 0755 \
  "$SCRIPT_DIR/m365_xoauth2_transport.py" \
  /usr/local/libexec/m365_xoauth2_transport.py

STAMP="$(date -u +'%Y%m%dT%H%M%SZ')"
cp -p /etc/postfix/main.cf "/etc/postfix/main.cf.pre-m365.$STAMP"
cp -p /etc/postfix/master.cf "/etc/postfix/master.cf.pre-m365.$STAMP"

# Fresh Linux stays local-only unless the administrator specifies a listener
# and trusted client CIDRs. Existing Postfix needs explicit approval above.
if [ -n "$LISTEN_IP" ]; then
  postconf -e "inet_interfaces = 127.0.0.1, $LISTEN_IP"
  postconf -e "mynetworks = 127.0.0.0/8 [::1]/128 ${TRUSTED_NETWORKS[*]}"
else
  postconf -e 'inet_interfaces = loopback-only'
  postconf -e 'mynetworks = 127.0.0.0/8 [::1]/128'
fi
postconf -e 'smtpd_client_restrictions = permit_mynetworks, reject'
postconf -e 'smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination'
postconf -e 'mydestination = localhost, localhost.localdomain'
postconf -e 'default_transport = m365xoauth2:'
postconf -e 'relay_transport = m365xoauth2:'
postconf -e 'm365xoauth2_destination_recipient_limit = 1'
postconf -e 'm365xoauth2_destination_concurrency_limit = 2'
postconf -e 'message_size_limit = 26214400'

python3 - <<'PY'
from pathlib import Path
import re
path = Path('/etc/postfix/master.cf')
s = path.read_text()
block = '''# BEGIN POSTFIX-M365-XOAUTH2
m365xoauth2 unix - n n - 2 pipe
  flags=q user=m365mailer argv=/usr/bin/python3 /usr/local/libexec/m365_xoauth2_transport.py --recipient ${recipient}
# END POSTFIX-M365-XOAUTH2
'''
if '# BEGIN POSTFIX-M365-XOAUTH2' in s:
    s = re.sub(r'(?ms)^# BEGIN POSTFIX-M365-XOAUTH2\n.*?^# END POSTFIX-M365-XOAUTH2\n', block, s)
elif re.search(r'(?m)^m365xoauth2\s+unix\s', s):
    raise SystemExit('Existing m365xoauth2 master.cf service found; refusing to overwrite')
else:
    s = s.rstrip() + '\n\n' + block
path.write_text(s)
PY

postfix check
if command -v restorecon >/dev/null 2>&1; then
  restorecon -R "$CONF_DIR" /usr/local/libexec/m365_xoauth2_transport.py || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now postfix
  systemctl restart postfix
else
  postfix reload || postfix start
fi

printf '\nLocal configuration test: '
if command -v runuser >/dev/null 2>&1; then
  runuser -u m365mailer -- /usr/bin/python3 /usr/local/libexec/m365_xoauth2_transport.py --config-check
else
  su -s /bin/sh m365mailer -c '/usr/bin/python3 /usr/local/libexec/m365_xoauth2_transport.py --config-check'
fi

echo
printf '%s\n' 'INSTALLED (Microsoft 365 authorization is not yet completed).' \
 '1) Upload PUBLIC certificate /etc/postfix/m365-oauth/app.crt to the Entra App registration.' \
 '2) On admin PC, assign Application SMTP.SendAsApp using configure-exchange-rbac.ps1.' \
 '3) Test token acquisition:' \
 '   sudo -u m365mailer /usr/bin/python3 /usr/local/libexec/m365_xoauth2_transport.py --token-check' \
 '4) Send test mail using /usr/sbin/sendmail -t.' \
 '5) Monitor queue with postqueue -p and journalctl -u postfix.'
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = 'Enforcing' ]; then
  echo 'SELinux is enforcing: verify AVC logs if the pipe transport cannot read the key or connect to SMTP.'
fi
