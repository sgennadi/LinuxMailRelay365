#!/usr/bin/env python3
"""Read-only analysis of the CURRENT Linux MTA's public SMTP and relay policy.

Does not make SMTP connections, send mail or alter configuration.
Only emits bounded status codes. A public SMTP listener is NOT proof of
an open relay or proof of access from the internet through NAT/firewalls.
"""
import argparse
import ipaddress
import re
import shutil
import subprocess

PORTS = {"smtp": 25, "submission": 587, "smtps": 465, "submissions": 465}
SETTINGS = (
    "inet_interfaces", "mynetworks", "smtpd_relay_restrictions",
    "smtpd_recipient_restrictions", "smtpd_sasl_auth_enable",
    "smtpd_tls_security_level", "smtpd_tls_auth_only", "relayhost",
)


def run(args):
    if not shutil.which(args[0]):
        return None
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=8)
        if p.returncode == 0 and len(p.stdout) <= 65536:
            return p.stdout
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        pass
    return None


def services(text):
    result = {}
    if text is None:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or "smtpd" not in line:
            continue
        if "=" in line:
            label, description = line.split("=", 1)
            name, sep, typ = label.strip().partition("/")
        else:
            parts = line.split()
            if len(parts) < 3:
                continue
            name, typ = parts[:2]
            description = " ".join(parts[2:])
        if typ != "inet" or not re.search(r"(^|\s)smtpd($|\s)", description):
            continue
        port = PORTS.get(name)
        if port is None and re.fullmatch(r"[1-9][0-9]{0,4}", name):
            port = int(name)
        if port and port <= 65535:
            result[name + "/inet"] = port
    return result


def overrides(text):
    result = {}
    for line in (text or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        service, sep, field = key.strip().rpartition("/")
        if sep and field in SETTINGS and service.count("/") == 1:
            result.setdefault(service, {})[field] = value.strip()
    return result


def listeners(text):
    if text is None:
        return None
    answer = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "LISTEN":
            continue
        local = parts[3]
        if ":" not in local:
            continue
        addr, port = local.rsplit(":", 1)
        if not port.isdigit():
            continue
        addr = addr.strip("[]")
        if 0 < int(port) <= 65535:
            answer.append((addr, int(port)))
    return answer


def bind_class(addr):
    if addr in ("*", "::", "0.0.0.0"):
        return "potentially_public"
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_global:
        return "potentially_public"
    return "private_or_other"


def wide_networks(value):
    for token in re.split(r"[\s,]+", value.lower()):
        if token in ("0/0", "all"):
            return True
        try:
            net = ipaddress.ip_network(token, strict=False)
            if net.prefixlen == 0:
                return True
        except ValueError:
            continue
    return False


def assessment(config):
    relay = [x.lower() for x in re.split(
        r"[\s,]+", config.get("smtpd_relay_restrictions", "")) if x]
    recipient = [x.lower() for x in re.split(
        r"[\s,]+", config.get("smtpd_recipient_restrictions", "")) if x]
    if wide_networks(config.get("mynetworks", "")) and (
        "permit_mynetworks" in relay or "permit_mynetworks" in recipient):
        return "suspected_unsafe_relay"
    guards = {"reject_unauth_destination", "defer_unauth_destination"}
    # Explicit unconditional permit BEFORE unauthenticated-destination reject
    # is a strong warning; arbitrary lookup rules need manual evaluation.
    for rules in (relay, recipient):
        for word in rules:
            if word in guards:
                break
            if word in ("permit", "permit_all"):
                return "suspected_unsafe_relay"
    if any(word in guards for word in relay):
        return "relay_guard_present"
    if not relay and any(word in guards for word in recipient):
        return "legacy_relay_guard_present"
    return "needs_manual_review"


def analyze(config, srv, service_override, ports, mta="postfix", selected_port=None):
    output = {
        "SMTP_AUDIT_VERSION": "1",
        "SMTP_AUDIT_MTA": mta,
        "SMTP_PUBLIC_BIND": "unknown",
        "SMTP_STANDARD_PORT_SOCKETS": observed_smtp_ports(ports),
        "SMTP_SELECTED_PORT": str(selected_port) if selected_port is not None else "none",
        "SMTP_SELECTED_PORT_SOCKET": selected_port_socket_status(ports, selected_port),
        "SMTP_RELAY_POLICY_RISK": "unknown",
        "SMTP_SMTP_AUTH": "unknown",
        "SMTP_SMTP_TLS": "unknown",
        "SMTP_SERVICE_COUNT": "unknown",
        "SMTP_MATCHED_LISTENER_COUNT": "unknown",
        "SMTP_RELAYHOST_CONFIGURED": "unknown",
        "SMTP_OPEN_RELAY_PROVEN": "no_active_probe_performed",
        "SMTP_EXTERNAL_REACHABILITY": "not_tested_from_internet",
        "SMTP_AUDIT_REQUIRES_MANUAL_REVIEW": "yes",
    }
    if mta != "postfix" or config is None or srv is None or ports is None:
        return output
    output["SMTP_SERVICE_COUNT"] = str(len(srv))
    output["SMTP_RELAYHOST_CONFIGURED"] = "yes" if config.get("relayhost", "").strip() else "no"
    running = [(name, port, ip) for name, port in srv.items()
               for ip, p in ports if p == port]
    # Socket binding alone does not prove that Postfix owns the socket.
    output["SMTP_MATCHED_LISTENER_COUNT"] = str(len(running))
    kinds = {bind_class(ip) for _, _, ip in running}
    if "potentially_public" in kinds:
        output["SMTP_PUBLIC_BIND"] = "potentially_public"
    elif "private_or_other" in kinds:
        output["SMTP_PUBLIC_BIND"] = "private_or_other"
    elif "loopback" in kinds:
        output["SMTP_PUBLIC_BIND"] = "loopback_only"
    else:
        output["SMTP_PUBLIC_BIND"] = "no_matching_listeners"
    if not running:
        output["SMTP_RELAY_POLICY_RISK"] = "not_observed_running"
        return output
    risks = set()
    auth = set()
    tls = set()
    for name, _, _ in running:
        merged = dict(config)
        merged.update(service_override.get(name, {}))
        risks.add(assessment(merged))
        auth.add(merged.get("smtpd_sasl_auth_enable", "").lower())
        tls.add(merged.get("smtpd_tls_security_level", "").lower())
    output["SMTP_RELAY_POLICY_RISK"] = (
        "suspected_unsafe_relay" if "suspected_unsafe_relay" in risks else
        "needs_manual_review" if "needs_manual_review" in risks else
        "relay_guard_present")
    output["SMTP_SMTP_AUTH"] = next(iter(auth)) if len(auth) == 1 and next(iter(auth)) in ("yes", "no") else "mixed_or_unknown"
    output["SMTP_SMTP_TLS"] = next(iter(tls)) if len(tls) == 1 and next(iter(tls)) in ("none", "may", "encrypt", "dane", "fingerprint", "") else "mixed_or_unknown"
    output["SMTP_AUDIT_REQUIRES_MANUAL_REVIEW"] = (
        "high_priority" if output["SMTP_RELAY_POLICY_RISK"] == "suspected_unsafe_relay"
        else "yes")
    return output


def self_test():
    cfg = {
        "relayhost": "[smtp.provider.example]:587",
        "mynetworks": "127.0.0.0/8,10.0.0.0/24",
        "smtpd_relay_restrictions": "permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination",
        "smtpd_recipient_restrictions": "",
        "smtpd_sasl_auth_enable": "yes",
        "smtpd_tls_security_level": "may",
    }
    s = {"smtp/inet": 25, "submission/inet": 587}
    a = analyze(cfg, s, {}, [("0.0.0.0", 25), ("127.0.0.1", 587)])
    assert a["SMTP_PUBLIC_BIND"] == "potentially_public"
    assert a["SMTP_RELAY_POLICY_RISK"] == "relay_guard_present"
    b = analyze({**cfg, "mynetworks": "0.0.0.0/0"}, s, {}, [("0.0.0.0", 25)])
    assert b["SMTP_RELAY_POLICY_RISK"] == "suspected_unsafe_relay"
    c = analyze(cfg, s, {}, [("127.0.0.1", 25)])
    assert c["SMTP_PUBLIC_BIND"] == "loopback_only"
    assert services("smtp/inet= n - n - - smtpd\n2526/inet= n - n - - smtpd") == {
        "smtp/inet": 25, "2526/inet": 2526}
    assert parse_safe_ports() is True
    assert detect_mta(lambda unit: unit == "exim4.service", lambda _: "/usr/sbin/postconf") == "exim_manual_review"
    assert detect_mta(lambda unit: unit == "sendmail.service") == "sendmail_manual_review"
    assert detect_mta(lambda unit: unit in ("postfix.service", "exim.service")) == "multiple_active_mta_manual_review"
    assert observed_smtp_ports([("0.0.0.0", 25)]) == "potentially_public_unattributed"
    assert selected_port_socket_status([("0.0.0.0", 2525)], 2525) == "occupied_potentially_public"
    assert selected_port_socket_status([("127.0.0.1", 2525)], 2525) == "occupied_loopback"
    assert selected_port_socket_status([("127.0.0.1", 2526)], 2525) == "no_listener_observed"
    assert selected_port_socket_status(None, 2525) == "scan_unavailable"
    return True


def parse_safe_ports():
    data = "LISTEN 0 100 0.0.0.0:25 0.0.0.0:*\nLISTEN 0 100 [::1]:587 [::]:*\n"
    return listeners(data) == [("0.0.0.0", 25), ("::1", 587)]



def observed_smtp_ports(ports):
    """Conservative socket-only report: NEVER attributes a socket to an MTA."""
    if ports is None:
        return "unknown"
    classes = {bind_class(address) for address, port in ports
               if port in (25, 465, 587)}
    if "potentially_public" in classes:
        return "potentially_public_unattributed"
    if "unknown" in classes:
        return "unknown_owner_or_bind"
    if "private_or_other" in classes:
        return "private_or_other_unattributed"
    if "loopback" in classes:
        return "loopback_only_unattributed"
    return "no_standard_smtp_listeners_observed"


def selected_port_socket_status(ports, selected_port):
    """Read-only occupancy for the selected inbound SMTP port.

    This cannot identify the process that owns a socket or prove reachability
    through a firewall/NAT.
    """
    if selected_port is None:
        return "not_checked"
    if ports is None:
        return "scan_unavailable"
    kinds = {bind_class(ip) for ip, port in ports if port == selected_port}
    if not kinds:
        return "no_listener_observed"
    if "potentially_public" in kinds:
        return "occupied_potentially_public"
    if "unknown" in kinds:
        return "occupied_unknown"
    if "private_or_other" in kinds:
        return "occupied_private"
    return "occupied_loopback"


MTA_UNITS = {
    "postfix": ("postfix.service",),
    "exim": ("exim4.service", "exim.service"),
    "sendmail": ("sendmail.service",),
}


def unit_active(unit):
    """Distinguish normal inactive/uninstalled units from query errors."""
    if not shutil.which("systemctl"):
        return None
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", unit],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            universal_newlines=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return None
    value = proc.stdout.strip().lower()
    if proc.returncode == 0 and value == "active":
        return True
    if value in ("inactive", "failed", "unknown", "dead"):
        return False
    return None


def detect_mta(unit_runner=unit_active, finder=None):
    """Fail closed if multiple active MTAs or service state is unknown.

    The presence of Postfix CLI binaries cannot prove it is the primary MTA.
    An active Exim/Sendmail is never automatically analyzed as Postfix.
    """
    finder = shutil.which if finder is None else finder
    statuses = {mta: [unit_runner(unit) for unit in units]
                for mta, units in MTA_UNITS.items()}
    if any(state is None for states in statuses.values() for state in states):
        return "mta_service_state_unverified_manual_review"
    active = [mta for mta, states in statuses.items() if any(states)]
    if len(active) > 1:
        return "multiple_active_mta_manual_review"
    if not active:
        return "no_active_mta_verified"
    if active[0] == "postfix":
        return "postfix" if finder("postconf") else "postfix_cli_missing_manual_review"
    return active[0] + "_manual_review"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--smtp-port", type=int, default=None,
                        help="selected custom port 1024..65535 (read-only)")
    args = parser.parse_args()
    if args.smtp_port is not None and not 1024 <= args.smtp_port <= 65535:
        parser.error("--smtp-port must be 1024..65535")
    if args.self_test:
        self_test()
        print("SMTP_AUDIT_SELFTEST=pass")
        return
    mta = detect_mta()
    config = None
    srv = None
    service_override = {}
    if mta == "postfix":
        entries = [run(["postconf", "-h", key]) for key in SETTINGS]
        if all(entry is not None for entry in entries):
            config = dict(zip(SETTINGS, (entry.strip() for entry in entries)))
        srv = services(run(["postconf", "-M"]))
        service_override = overrides(run(["postconf", "-P"]))
    scanned = analyze(config, srv, service_override,
                      listeners(run(["ss", "-H", "-lnt"])), mta,
                      selected_port=args.smtp_port)
    for name, value in scanned.items():
        print(name + "=" + value)


if __name__ == "__main__":
    main()
