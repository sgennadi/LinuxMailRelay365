#!/usr/bin/env python3
"""Read-only comparison of configured MTA binds, Linux interfaces and SMTP sockets.

No mail is sent, services are not restarted, and listener ownership is not
inferred from ss. Admin-UP is distinct from operational carrier-UP.
Python >= 3.6, iproute2 and ss optional: missing tools give UNKNOWN, not safe.
"""
import argparse
import ipaddress
import json
import re
import shutil
import subprocess

IFNAME = re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")
EXIM = re.compile(r"^local_interfaces\s*=\s*(.*?)\s*$")
SAFE = re.compile(r"^[a-zA-Z0-9._:/\[\]+,-]{1,85}$")
PORTS = (25, 465, 587)
MAX_INTERFACES = 16
MAX_ADDRESSES = 24
MAX_SOCKETS = 24


def call(args, cap=32768):
    if not shutil.which(args[0]):
        return None
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, check=False, timeout=7)
        if p.returncode == 0 and len(p.stdout) <= cap:
            return p.stdout
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        pass
    return None


def ip_interfaces(payload):
    if payload is None:
        return None
    try:
        data = json.loads(payload)
        if not isinstance(data, list):
            return None
        interfaces, addresses, assigned, states = [], [], set(), {}
        overflow = False
        for item in data:
            if not isinstance(item, dict):
                return None
            name = item.get("ifname", "")
            if not isinstance(name, str) or not IFNAME.fullmatch(name):
                overflow = True
                continue
            flags = item.get("flags", [])
            if not isinstance(flags, list):
                return None
            admin = "up" if "UP" in flags else "down"
            operation = str(item.get("operstate", "UNKNOWN")).lower()
            if operation not in ("up", "down", "unknown", "dormant", "lowerlayerdown", "notpresent", "testing"):
                operation = "unknown"
            if len(interfaces) >= MAX_INTERFACES:
                overflow = True
                continue
            interfaces.append("{},{},{}".format(name, admin, operation))
            addr_info = item.get("addr_info", [])
            if not isinstance(addr_info, list):
                return None
            for record in addr_info:
                if not isinstance(record, dict):
                    return None
                family = record.get("family")
                if family not in ("inet", "inet6"):
                    continue
                try:
                    address = ipaddress.ip_address(record.get("local", ""))
                    prefix = int(record.get("prefixlen"))
                    if prefix < 0 or prefix > address.max_prefixlen:
                        return None
                except (ValueError, TypeError):
                    return None
                assigned.add(str(address))
                states[str(address)] = (admin, operation)
                if len(addresses) >= MAX_ADDRESSES:
                    overflow = True
                    continue
                scope = record.get("scope", "unknown")
                if scope not in ("global", "host", "link", "site"):
                    scope = "unknown"
                family_str = "ipv4" if address.version == 4 else "ipv6"
                addresses.append("{},{},{}/{},{}".format(
                    name, family_str, address, prefix, scope))
        return interfaces, addresses, assigned, states, overflow
    except (ValueError, TypeError, KeyError):
        return None


def scan_sockets(payload, selected_port, configured_ports=()):
    if payload is None:
        return None
    ports = set(PORTS + (selected_port,) + tuple(configured_ports))
    found = set()
    for line in payload.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ("LISTEN",):
            # ss -H -lnt output on Linux includes LISTEN at the beginning.
            return None
        local = parts[3]
        if ":" not in local:
            return None
        address, port_text = local.rsplit(":", 1)
        if not port_text.isdigit():
            return None
        port = int(port_text)
        if port not in ports:
            continue
        address = address.strip("[]")
        if address == "*":
            # ss may render IPv4 wildcard and IPv6 wildcard as *; family
            # cannot be inferred here.
            token = "wildcard"
        else:
            try:
                token = str(ipaddress.ip_address(address))
            except ValueError:
                return None
        found.add((token, port))
    formatted = []
    for address, port in sorted(found):
        loc = "[" + address + "]" if ":" in address else address
        formatted.append("{}:{}".format(loc, port))
    overflow = len(formatted) > MAX_SOCKETS
    return formatted[:MAX_SOCKETS], found, overflow


def configured_addresses(mta, runner=call):
    if mta == "postfix":
        raw = runner(["postconf", "-h", "inet_interfaces"], cap=2048)
    elif mta == "exim":
        tool = "exim4" if shutil.which("exim4") else "exim"
        raw = runner([tool, "-bP", "local_interfaces"], cap=2048)
        match = EXIM.fullmatch((raw or "").strip())
        raw = match.group(1) if match else None
    else:
        return "not_applicable", []
    if raw is None:
        return "unavailable", []
    raw = raw.strip()
    if not raw:
        return "empty", []
    if raw in ("all", "loopback-only"):
        return raw, []
    addresses = []
    # Colon belongs to IPv6. Exim separates multiple bind targets by
    # a *spaced* colon; a bare colon must never split an IPv6 literal.
    separator = r"[\s,;]+" if mta == "postfix" else r"\s+:\s+|[\s,;]+"
    for token in re.split(separator, raw):
        token = token.strip("[]")
        if not token:
            continue
        try:
            addresses.append(str(ipaddress.ip_address(token)))
        except ValueError:
            # Hostnames, variables, Exim syntax require manual interpretation.
            return "complex_manual_review", []
    return ("explicit_addresses", addresses) if addresses else ("complex_manual_review", [])


def bind_assessment(mta, configured, wanted, ip_data, socket_data, selected_port):
    if ip_data is None or socket_data is None:
        return "network_or_socket_unverified"
    _, _, assigned, states, truncated_interfaces = ip_data
    _, sockets, truncated_sockets = socket_data
    # Truncation means no absence conclusion can be trusted.
    if truncated_interfaces or truncated_sockets:
        return "incomplete_network_or_socket_inventory"
    if mta not in ("postfix", "exim"):
        return "mta_bind_configuration_not_applicable"
    if configured not in ("all", "loopback-only", "explicit_addresses") or (
            configured == "explicit_addresses" and not wanted):
        return "mta_bind_configuration_unverified"
    missing = [address for address in wanted if address not in assigned]
    if missing:
        return "configured_ip_not_assigned"
    if any(states.get(address, ("unknown", "unknown"))[0] == "down"
           for address in wanted):
        return "configured_ip_admin_down"
    if any(states.get(address, ("unknown", "unknown"))[1] in
           ("down", "lowerlayerdown", "notpresent") for address in wanted):
        return "configured_ip_oper_down"
    if any(states.get(address, ("unknown", "unknown"))[1] != "up"
           for address in wanted):
        return "configured_ip_oper_unverified"
    if configured == "all":
        if not sockets:
            return "all_configured_no_smtp_socket_observed"
        if all(address in ("127.0.0.1", "::1") for address, _ in sockets):
            return "all_configured_loopback_sockets_only_review"
    if configured == "loopback-only" and any(
            address not in ("127.0.0.1", "::1") for address, port in sockets
            if port in PORTS):
        return "loopback_configured_other_smtp_socket_unattributed"
    if any(address in ("wildcard", "0.0.0.0", "::") for address, _ in sockets):
        return "wildcard_smtp_socket_unattributed"
    if any(port == selected_port for _, port in sockets):
        return "selected_port_listening_owner_unverified"
    return "observed_no_proof_of_reachability"


def inspect(mta, smtp_port, runner=call, configured_ports=()):
    ip_data = ip_interfaces(runner(["ip", "-j", "address", "show"]))
    socket_data = scan_sockets(runner(["ss", "-H", "-lnt"]), smtp_port, configured_ports)
    configured, wanted = configured_addresses(mta, runner)
    assessment = bind_assessment(mta, configured, wanted, ip_data, socket_data, smtp_port)
    out = {
        "MAIL_HOST_NET_AUDIT_VERSION": "1",
        "MAIL_HOST_NET_STATE": "ok" if ip_data is not None else "unavailable",
        "MAIL_HOST_SOCKET_STATE": "ok" if socket_data is not None else "unavailable",
        "MAIL_HOST_NET_PORT": str(smtp_port),
        "MAIL_HOST_NET_CONFIG_KIND": configured,
        "MAIL_HOST_NET_BIND_RESULT": assessment,
        "MAIL_HOST_SOCKET_OWNER": "unverified",
        "MAIL_HOST_EXTERNAL_REACHABILITY": "not_tested",
    }
    if ip_data is not None:
        interfaces, addresses, _, _, overflow = ip_data
        for i, entry in enumerate(interfaces, 1):
            out["MAIL_HOST_IFACE_{:02d}".format(i)] = entry
        for i, entry in enumerate(addresses, 1):
            out["MAIL_HOST_ADDR_{:02d}".format(i)] = entry
        out["MAIL_HOST_NET_TRUNCATED"] = "yes" if overflow else "no"
    else:
        out["MAIL_HOST_NET_TRUNCATED"] = "unknown"
    if socket_data is not None:
        sockets, _, overflow = socket_data
        for i, entry in enumerate(sockets, 1):
            out["MAIL_HOST_SOCKET_{:02d}".format(i)] = entry
        out["MAIL_HOST_SOCKET_TRUNCATED"] = "yes" if overflow else "no"
    else:
        out["MAIL_HOST_SOCKET_TRUNCATED"] = "unknown"
    return out


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--smtp-port", type=int, default=2525)
    parser.add_argument("--mta", choices=("postfix", "exim", "sendmail", "none", "unknown"),
                        default="unknown")
    parser.add_argument("--configured-ports", default="unverified",
                        help="Read-only discovered MTA port list or unverified status")
    parser.add_argument("--self-test", action="store_true")
    opts = parser.parse_args(argv)
    if not (opts.smtp_port == 25 or 1024 <= opts.smtp_port <= 65535):
        parser.error("custom port must be 25 or 1024..65535")
    if opts.configured_ports in ("unverified", "dynamic_or_unverified", "none_configured"):
        configured_ports = ()
    elif re.fullmatch(r"[1-9][0-9]{0,4}(?:,[1-9][0-9]{0,4}){0,15}",
                      opts.configured_ports):
        configured_ports = tuple(int(value) for value in opts.configured_ports.split(","))
        if any(port > 65535 for port in configured_ports):
            parser.error("invalid configured SMTP port")
    else:
        parser.error("invalid configured SMTP port inventory")
    if opts.self_test:
        ip_data = ip_interfaces(json.dumps([
            {"ifname": "lo", "flags": ["UP"], "operstate": "UNKNOWN",
             "addr_info": [{"family": "inet", "local": "127.0.0.1",
                            "prefixlen": 8, "scope": "host"}]},
            {"ifname": "eth0", "flags": ["UP"], "operstate": "UP",
             "addr_info": [{"family": "inet", "local": "192.168.2.15",
                            "prefixlen": 24, "scope": "global"}]}]))
        socket_data = scan_sockets("LISTEN 0 128 127.0.0.1:2525 0.0.0.0:*\n", 2525)
        assert ip_data[2] == {"127.0.0.1", "192.168.2.15"}
        assert socket_data[0] == ["127.0.0.1:2525"]
        assert bind_assessment("postfix", "explicit_addresses",
                               ["192.168.2.20"], ip_data, socket_data, 2525) == "configured_ip_not_assigned"
        assert bind_assessment("postfix", "all", [],
                               ip_data, socket_data, 2525) == "all_configured_loopback_sockets_only_review"
        assert scan_sockets(None, 2525) is None
        assert scan_sockets("LISTEN 0 128 127.0.0.1:2526 0.0.0.0:*\n", 2525,
                            (2526,))[0] == ["127.0.0.1:2526"]
        print("MAIL_HOST_NET_SELF_TEST=pass")
        return 0
    for key, value in inspect(opts.mta, opts.smtp_port,
                              configured_ports=configured_ports).items():
        print(key + "=" + value)


if __name__ == "__main__":
    raise SystemExit(main())
