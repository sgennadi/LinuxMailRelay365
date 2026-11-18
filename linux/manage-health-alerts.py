#!/usr/bin/env python3
"""Opt-in, privacy-minimized HTTPS alert delivery for isolated SMTP health.

Installed only after explicit review on an already running 15-minute
linuxmailrelay365-health.timer. No email is sent and no Entra, Postfix,
firewall, NAT or primary MTA settings are changed. Python >=3.6.
"""
import argparse
import datetime
import fcntl
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

CONF = Path("/etc/linuxmailrelay365/health-alerts.json")
UNIT = Path("/etc/systemd/system/linuxmailrelay365-health.service")
TIMER = "linuxmailrelay365-health.timer"
PROBE = Path("/usr/local/libexec/linuxmailrelay365-relay-health.py")
INSTALLED = Path("/usr/local/libexec/linuxmailrelay365-health-alerts.py")
DROP_DIR = Path("/etc/systemd/system/linuxmailrelay365-health.service.d")
DROP = DROP_DIR / "20-linuxmailrelay365-alerts.conf"
STATE_DIR = Path("/var/lib/linuxmailrelay365-health-alerts")
STATE = STATE_DIR / "delivery-state.json"
LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")
SHA = re.compile(r"[a-f0-9]{64}\Z")
DNS = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")
LABEL = re.compile(r"[a-z0-9_]{1,75}\Z")
HEALTH_FIELDS = ("HEALTH_STATUS", "HEALTH_ALERTS", "QUEUE_MESSAGES",
                 "QUEUE_DEFERRED", "QUEUE_OLDEST_AGE_MIN",
                 "QUEUE_FREE_MIB", "M365_CERT_REMAINING_DAYS",
                 "TLS_SERVER_CERT_REMAINING_DAYS")


class Refused(Exception):
    pass


def say(key, value):
    print("{}={}".format(key, value))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def owned_regular(path, private=False):
    try:
        st = path.lstat()
    except OSError:
        raise Refused("required_local_file_missing")
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or \
            st.st_mode & (0o077 if private else 0o022):
        raise Refused("unsafe_local_file_permissions")
    return st


def owned_dir(path, private=False):
    try:
        st = path.lstat()
    except OSError:
        raise Refused("required_local_directory_missing")
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or \
            st.st_mode & (0o077 if private else 0o022):
        raise Refused("unsafe_local_directory_permissions")


def call(args, timeout=20):
    try:
        res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=timeout, universal_newlines=True, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("systemd_command_failed")
    if res.returncode:
        raise Refused("systemd_command_failed")
    return res.stdout


def validate_config(raw):
    if not isinstance(raw, dict) or set(raw) != {"url", "timeout_seconds", "repeat_hours"}:
        raise Refused("webhook_configuration_schema_invalid")
    url = raw["url"]
    if not isinstance(url, str) or not 12 <= len(url) <= 1200:
        raise Refused("webhook_url_invalid")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if parsed.scheme != "https" or parsed.port not in (None, 443) or \
                parsed.username or parsed.password or parsed.fragment or \
                not DNS.fullmatch(host) or host.lower().endswith(
                    (".local", ".localhost", ".internal", ".test", ".invalid")):
            raise Refused("public_https_fqdn_required")
        if not parsed.path.startswith("/") or any(ord(c) < 32 for c in url):
            raise Refused("webhook_url_invalid")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise Refused("public_https_fqdn_required")
    except (ValueError, AttributeError):
        raise Refused("webhook_url_invalid")
    timeout = raw["timeout_seconds"]
    repeat = raw["repeat_hours"]
    if type(timeout) is not int or not 3 <= timeout <= 15 or \
            type(repeat) is not int or not 1 <= repeat <= 168:
        raise Refused("webhook_limits_invalid")
    return {"url": url, "timeout": timeout, "repeat": repeat}


def config():
    owned_dir(CONF.parent)
    statinfo = owned_regular(CONF, private=True)
    if not 0 < statinfo.st_size <= 4096:
        raise Refused("webhook_config_size_invalid")
    try:
        raw = CONF.read_bytes()
        result = validate_config(json.loads(raw.decode("utf-8")))
    except (ValueError, UnicodeError, OSError):
        raise Refused("webhook_config_not_valid_json")
    result["sha"] = digest(raw)
    return result


def pinned_external_ip(host):
    try:
        addresses = socket.getaddrinfo(host, 443, 0, socket.SOCK_STREAM,
                                       socket.IPPROTO_TCP)
        ips = sorted({str(ipaddress.ip_address(item[4][0])) for item in addresses})
    except (OSError, ValueError, IndexError):
        raise Refused("webhook_dns_unresolved")
    if not ips or len(ips) > 32 or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise Refused("webhook_dns_not_public")
    return ips[0]


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, pinned_ip, timeout):
        super(PinnedHTTPS, self).__init__(host, port=443, timeout=timeout,
                                         context=ssl.create_default_context())
        self.pinned_ip = pinned_ip

    def connect(self):
        connection = socket.create_connection((self.pinned_ip, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
        except Exception:
            connection.close()
            raise


def webhook_send(settings, payload):
    parsed = urlsplit(settings["url"])
    chosen_ip = pinned_external_ip(parsed.hostname)
    # Pin connection to the *validated* DNS address, verify SNI/certificate
    # for the original public hostname; never follow redirects or use proxies.
    conn = PinnedHTTPS(parsed.hostname, chosen_ip, settings["timeout"])
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    path = parsed.path + ("?" + parsed.query if parsed.query else "")
    try:
        conn.request("POST", path, body=body,
                     headers={"Content-Type": "application/json",
                              "Accept": "application/json",
                              "User-Agent": "LinuxMailRelay365-Health/1"})
        response = conn.getresponse()
        status = response.status
        response.read(512)
        if not 200 <= status <= 299:
            raise Refused("webhook_non_success_http_status")
    except (OSError, ValueError, ssl.SSLError, http.client.HTTPException):
        raise Refused("webhook_tls_or_connectivity_failed")
    finally:
        conn.close()


def health_snapshot(port):
    owned_regular(PROBE)
    spec = importlib.util.spec_from_file_location("lmr365_health_module", str(PROBE))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    values = mod.health(port)
    if not isinstance(values, dict) or values.get("CUSTOM_SMTP_PORT") != str(port):
        raise Refused("health_snapshot_unavailable")
    return values


def filtered_health(data):
    status = data.get("HEALTH_STATUS")
    if status not in ("attention", "local_preflight_only", "not_installed"):
        raise Refused("health_status_unknown")
    alerts = data.get("HEALTH_ALERTS", "")
    if not isinstance(alerts, str) or len(alerts) > 1024:
        raise Refused("invalid_health_alerts")
    names = sorted(set(alerts.split(","))) if alerts and alerts != "none" else []
    if len(names) > 32 or any(not LABEL.fullmatch(name) for name in names):
        raise Refused("invalid_health_alerts")
    safe = {}
    for name in HEALTH_FIELDS[2:]:
        value = data.get(name, "unknown")
        if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9]{1,10}|unknown|not_applicable)", value):
            value = "unknown"
        safe[name.lower()] = value
    return {"schema": "linuxmailrelay365-health-alert/v1",
            "severity": "attention" if status != "local_preflight_only" else "resolved",
            "codes": names, "metrics": safe,
            "privacy": "no_addresses_or_message_content"}


def ensure_state_dir():
    if STATE_DIR.exists() or STATE_DIR.is_symlink():
        owned_dir(STATE_DIR, private=True)
    else:
        STATE_DIR.mkdir(parents=True, mode=0o700)
        os.chmod(str(STATE_DIR), 0o700)


def atomic(path, data, mode=0o600):
    fd, name = tempfile.mkstemp(prefix=".lmr365.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), mode)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, str(path))
    finally:
        if os.path.exists(name):
            os.unlink(name)


def previous():
    if not STATE.exists() and not STATE.is_symlink():
        return {"code": "", "sent": 0}
    owned_regular(STATE, private=True)
    if STATE.stat().st_size > 2048:
        raise Refused("unsafe_delivery_state")
    try:
        obj = json.loads(STATE.read_text(encoding="ascii"))
        if not isinstance(obj, dict) or \
                not isinstance(obj.get("code"), str) or not isinstance(obj.get("sent"), (int, float)):
            raise ValueError()
        return obj
    except (ValueError, OSError):
        raise Refused("delivery_state_invalid")


def dispatch(port, now=None):
    settings = config()
    safe = filtered_health(health_snapshot(port))
    ensure_state_dir()
    old = previous()
    code = digest(json.dumps({"severity": safe["severity"],
                              "codes": safe["codes"]}, sort_keys=True).encode("ascii"))
    now = datetime.datetime.now(datetime.timezone.utc).timestamp() if now is None else now
    if safe["severity"] == "resolved" and old["code"] == "":
        say("HEALTH_WEBHOOK_STATUS", "healthy_no_previous_alert")
        return 0
    if old["code"] == code and now - old["sent"] < settings["repeat"] * 3600:
        say("HEALTH_WEBHOOK_STATUS", "unchanged_suppressed")
        return 0
    webhook_send(settings, safe)
    atomic(STATE, (json.dumps({"code": code, "sent": now}, sort_keys=True) + "\n").encode("ascii"))
    say("HEALTH_WEBHOOK_STATUS", "notification_delivered_https")
    say("HEALTH_WEBHOOK_PRIVACY", "no_addresses_or_secrets")
    return 0


def dropin(port):
    return ("[Service]\n"
            "ExecStartPost=-/usr/bin/python3 {} --dispatch --smtp-port {}\n"
            .format(INSTALLED, port)).encode("ascii")


def service_preflight(port):
    if os.geteuid():
        raise Refused("root_required")
    owned_regular(UNIT)
    owned_regular(PROBE)
    text = UNIT.read_text(encoding="utf-8")
    if "User=root" not in text or \
            "ExecStart=/usr/bin/python3 {} --smtp-port {}".format(PROBE, port) not in text:
        raise Refused("health_timer_unit_port_or_user_mismatch")
    if call(["systemctl", "is-active", TIMER]).strip() != "active":
        raise Refused("health_timer_inactive")


def status(port):
    if os.geteuid():
        raise Refused("root_required")
    if not DROP.exists() and not DROP.is_symlink():
        say("HEALTH_WEBHOOK_STATUS", "not_enabled")
        say("CHANGES_APPLIED", "no")
        return 0
    owned_regular(DROP)
    if DROP.read_bytes() != dropin(port):
        raise Refused("unrecognized_health_alerts_dropin")
    say("HEALTH_WEBHOOK_STATUS", "enabled")
    say("HEALTH_WEBHOOK_PORT", port)
    say("CHANGES_APPLIED", "no")
    return 0


def enable(port, expected):
    service_preflight(port)
    cfg = config()
    if expected != cfg["sha"]:
        raise Refused("webhook_config_changed_since_preview")
    if DROP.exists() or DROP.is_symlink() or INSTALLED.exists() or INSTALLED.is_symlink():
        raise Refused("alerts_already_installed_no_overwrite")
    owned_dir(DROP_DIR.parent)
    DROP_DIR.mkdir(mode=0o755, exist_ok=True)
    owned_dir(DROP_DIR)
    source = Path(__file__).resolve()
    owned_regular(source) if source.stat().st_uid == 0 else None
    # The temporary embedded file may be root-owned; root installation uses
    # a source read and installs its content into the dedicated libexec file.
    try:
        atomic(INSTALLED, source.read_bytes(), 0o755)
        atomic(DROP, dropin(port), 0o644)
        call(["systemctl", "daemon-reload"])
        # No webhook is sent until the next scheduled run.
        say("HEALTH_WEBHOOK_ENABLED", "yes")
        say("HEALTH_WEBHOOK_SCHEDULE", "existing_15min_timer")
        say("HEALTH_WEBHOOK_PRIVATE_CONFIG", "root_only")
        return 0
    except (Refused, OSError):
        if DROP.exists():
            DROP.unlink()
        if INSTALLED.exists():
            INSTALLED.unlink()
        try:
            call(["systemctl", "daemon-reload"])
        except Refused:
            say("HEALTH_WEBHOOK_ROLLBACK", "manual_systemd_review_required")
        raise


def disable(port):
    if os.geteuid():
        raise Refused("root_required")
    owned_regular(DROP)
    if DROP.read_bytes() != dropin(port):
        raise Refused("unrecognized_health_alerts_dropin")
    DROP.unlink()
    call(["systemctl", "daemon-reload"])
    if INSTALLED.exists() and not INSTALLED.is_symlink():
        owned_regular(INSTALLED)
        INSTALLED.unlink()
    say("HEALTH_WEBHOOK_DISABLED", "yes")
    say("HEALTH_WEBHOOK_CONFIG_RETAINED", "yes")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    choice = p.add_mutually_exclusive_group(required=True)
    for action in ("check-only", "enable", "disable", "status", "dispatch", "self-test"):
        choice.add_argument("--" + action, action="store_true")
    p.add_argument("--smtp-port", type=int, default=2525)
    p.add_argument("--expect-config-sha256", default="")
    p.add_argument("--confirm", default="")
    a = p.parse_args()
    if a.self_test:
        say("HEALTH_WEBHOOK_PARSER", "ready")
        return 0
    if not 1024 <= a.smtp_port <= 65535:
        p.error("custom SMTP port must be 1024-65535")
    if a.enable and (a.confirm != "ENABLE_SMTP_HEALTH_WEBHOOK" or
                     not SHA.fullmatch(a.expect_config_sha256)):
        say("HEALTH_WEBHOOK_ERROR", "reviewed_sha_and_confirmation_required")
        return 2
    if a.disable and a.confirm != "DISABLE_SMTP_HEALTH_WEBHOOK":
        say("HEALTH_WEBHOOK_ERROR", "typed_disable_confirmation_required")
        return 2
    try:
        if a.check_only:
            service_preflight(a.smtp_port)
            cfg = config()
            if DROP.exists() or DROP.is_symlink():
                raise Refused("already_installed")
            # External DNS lookup is deliberately not done by Preview.
            say("HEALTH_WEBHOOK_PREFLIGHT", "ready")
            say("HEALTH_WEBHOOK_CONFIG_SHA256", cfg["sha"])
            say("HEALTH_WEBHOOK_DNS", "checked_on_delivery")
            say("HEALTH_WEBHOOK_SECRETS_IN_GUI", "no")
            say("CHANGES_APPLIED", "no")
            return 0
        if a.status:
            return status(a.smtp_port)
        if a.dispatch:
            if os.geteuid():
                raise Refused("root_required")
            return dispatch(a.smtp_port)
        if os.geteuid():
            raise Refused("root_required")
        fd = os.open(str(LOCK), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return enable(a.smtp_port, a.expect_config_sha256) if a.enable else disable(a.smtp_port)
        finally:
            os.close(fd)
    except (Refused, OSError, ValueError, UnicodeError) as exc:
        say("HEALTH_WEBHOOK_RESULT", "refused")
        say("HEALTH_WEBHOOK_ERROR", re.sub("[^a-z0-9_]", "_", str(exc).lower())[:82])
        say("CHANGES_APPLIED", "no" if a.check_only or a.status else "unknown_check_host")
        return 2


if __name__ == "__main__":
    sys.exit(main())
