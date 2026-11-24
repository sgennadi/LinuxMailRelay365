#!/usr/bin/env python3
"""Read-only preflight for the first offline conditional sender-map transaction.

Python 3.6+. No production activation command. A successful report is not
permission to apply: stop state is a sampled observation, the administrator
must prevent concurrent mail submissions, service starts and config edits.
Only DNS, TCP, EHLO and certificate-verified STARTTLS contact destinations.
"""
import argparse
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import signal
import smtplib
import socket
import ssl
import stat
import subprocess
import sys

_spec = importlib.util.spec_from_file_location(
    "conditional_transaction", str(pathlib.Path(__file__).with_name(
        "conditional-postfix-transaction.py")))
T = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(T)
M = T.M
Refused = M.Refused
CONFIG = "/etc/postfix"
QUEUE = "/var/spool/postfix"
EMPTY_SETTINGS = (
    "transport_maps", "sender_dependent_relayhost_maps",
    "sender_dependent_default_transport_maps", "multi_instance_directories",
    "smtp_tls_policy_maps", "smtp_tls_per_site", "smtp_fallback_relay",
    "smtp_sasl_password_maps", "smtp_generic_maps", "sender_canonical_maps",
    "canonical_maps", "masquerade_domains", "content_filter",
)
FIXED_SETTINGS = {
    "config_directory": CONFIG, "queue_directory": QUEUE,
    "multi_instance_enable": "no", "default_transport": "smtp",
    "relay_transport": "relay", "smtp_sasl_auth_enable": "no",
    "smtp_sender_dependent_authentication": "no",
    "smtp_tls_security_level": "secure", "smtp_tls_wrappermode": "no",
    "smtp_tls_secure_cert_match": "nexthop",
    "mail_owner": "postfix",
}
EXTRA_SETTINGS = ("smtp_tls_CAfile", "smtp_tls_CApath", "relayhost",
                  "mydestination", "virtual_mailbox_domains",
                  "virtual_alias_domains", "relay_domains",
                  "local_transport", "virtual_transport", "inet_interfaces",
                  "inet_protocols", "proxy_interfaces", "recipient_delimiter")
KEYS = tuple(sorted(set(EMPTY_SETTINGS) | set(FIXED_SETTINGS) | set(EXTRA_SETTINGS)))
QUEUE_DIRS = ("active", "deferred", "incoming", "maildrop", "hold", "corrupt",
              "bounce", "defer", "trace", "saved")
MAX_ENDPOINTS = 4
MAX_ADDRESSES = 8
SYSTEM_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def trusted_tool(name):
    paths = {"systemctl": ("/usr/bin/systemctl", "/bin/systemctl"),
             "ip": ("/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"),
             "matchpathcon": ("/usr/sbin/matchpathcon", "/usr/bin/matchpathcon")}
    for candidate in paths[name]:
        if not os.path.exists(candidate):
            continue
        path = os.path.realpath(candidate)
        need(path.startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")),
             "untrusted_system_tool_path")
        folder = os.path.dirname(path)
        while True:
            meta = os.stat(folder, follow_symlinks=False)
            need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and
                 not meta.st_mode & 0o022, "untrusted_system_tool_directory")
            if folder == "/":
                break
            folder = os.path.dirname(folder)
        meta = os.stat(path)
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
             not meta.st_mode & 0o022 and meta.st_mode & 0o111,
             "untrusted_system_tool")
        return path
    raise Refused("required_system_tool_missing")


def system_command(name, args):
    try:
        result = subprocess.run([trusted_tool(name)] + args, input=b"",
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=SYSTEM_ENV, timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("system_inspection_failed")
    need(result.returncode == 0 and len(result.stdout) <= 131072,
         "system_inspection_unverified")
    return result.stdout.decode("utf-8", "strict")


def open_directory(path, uid=0, strict=True):
    fd = os.open("/", M.DIR_FLAGS)
    try:
        for component in path.strip("/").split("/"):
            if strict:
                M.check_directory(fd, uid)
            child = os.open(component, M.DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        if strict:
            M.check_directory(fd, uid)
        return fd
    except BaseException:
        os.close(fd)
        raise


def key_values(raw, expected):
    values = {}
    for line in raw.splitlines():
        key, sep, value = line.partition("=")
        key = key.strip()
        need(sep and key in expected and key not in values and
             len(value) <= 8192 and not any(ord(c) < 32 and c != "\t" for c in value),
             "invalid_native_parameter_output")
        values[key] = value.strip()
    need(set(values) == set(expected), "incomplete_native_parameter_output")
    return values


def policy_file_label(path, command=system_command):
    """Read the installed file-context policy, not a guessed type.

    Force regular-file matching for a destination that does not exist yet.
    -N requests the raw, untranslated label; no relabel or policy mutation.
    """
    need(path in (CONFIG + "/main.cf", CONFIG + "/master.cf") or
         re.fullmatch(r"/etc/postfix/lmr365-conditional-[a-f0-9]{64}-sender"
                      r"\.(?:db|lmdb)", path), "invalid_selinux_policy_path")
    raw = command("matchpathcon", ["-N", "-n", "-m", "file", path])
    lines = raw.splitlines()
    need(len(lines) == 1 and lines[0] == lines[0].strip(),
         "selinux_policy_label_unverified")
    return T.checked_label(lines[0].encode("ascii") + b"\0")


def review_selinux_labels(config, plan, backend, uid, command=system_command):
    # Not wired to production Apply: actual Enforcing VM acceptance is
    # required. Refuse non-default/custom unexpected labels; never relabel
    # a working configuration in order to make it pass.
    name, suffix = T.checked_name(plan, backend)
    for filename in ("main.cf", "master.cf"):
        _, meta = T.config_file(config, filename, uid)
        actual = meta.get("selinux")
        expected = policy_file_label(CONFIG + "/" + filename, command)
        need(actual is not None and
             T.label_bytes(actual).rstrip(b"\0") ==
             T.label_bytes(expected).rstrip(b"\0"), "selinux_config_label_mismatch")
    return policy_file_label(CONFIG + "/" + name + suffix, command)


def postconf_values(runner=M.native_command):
    code, raw = runner("postconf", ["-c", CONFIG, "-x"] + list(KEYS))
    need(code == 0, "effective_postfix_config_unavailable")
    return key_values(raw.decode("utf-8", "strict"), KEYS)


def inspect_policy(values):
    need(set(values) == set(KEYS), "incomplete_effective_policy")
    need(all(not values[key] for key in EMPTY_SETTINGS),
         "existing_maps_or_rewriting_conflict")
    need(all(values[key] == value for key, value in FIXED_SETTINGS.items()),
         "unsupported_scope_transport_or_security_policy")
    need(values["local_transport"].startswith("local:") and
         values["virtual_transport"] in ("virtual", "virtual:"),
         "nonstandard_local_delivery_transport")
    # CApath or additional verification policy needs separate acceptance.
    need(not values["smtp_tls_CApath"] and values["smtp_tls_CAfile"] in
         ("/etc/ssl/certs/ca-certificates.crt",
          "/etc/pki/tls/certs/ca-bundle.crt"), "unsupported_trust_store")
    return values["smtp_tls_CAfile"]


def inspect_master(runner=M.native_command):
    services = {"smtp": "smtp", "relay": "smtp", "rewrite": "trivial-rewrite"}
    code, raw = runner("postconf", ["-c", CONFIG, "-M",
                                   "smtp/unix", "relay/unix", "rewrite/unix"])
    need(code == 0, "native_smtp_services_unverified")
    seen = set()
    for line in raw.decode("ascii").splitlines():
        columns = line.split()
        need(len(columns) >= 8 and columns[0] in services and
             columns[0] not in seen and columns[1] == "unix" and
             columns[7] == services[columns[0]], "nonstandard_outbound_service")
        # No chroot/extra delivery command except ordinary -o settings,
        # which are independently enumerated by postconf -P.
        need(columns[4] == "n", "outbound_chroot_needs_separate_acceptance")
        need(all(not part.startswith(("-c", "-D")) for part in columns[8:]),
             "custom_outbound_service_arguments")
        seen.add(columns[0])
    need(seen == set(services), "outbound_services_missing")
    code, raw = runner("postconf", ["-c", CONFIG, "-P"])
    need(code == 0, "master_overrides_unverified")
    for line in raw.decode("utf-8", "strict").splitlines():
        key, sep, _ = line.partition("=")
        parts = key.strip().split("/")
        need(sep and len(parts) == 3, "master_override_unverified")
        # Conservative allowlist: only harmless logging-name overrides.
        # This also refuses custom cleanup, rewrite and qmgr route settings.
        need(parts[2] == "syslog_name", "master_service_override_needs_review")


def stopped_units(command=system_command):
    for unit, required in (("postfix.service", True), ("postfix@-.service", False)):
        raw = command("systemctl", ["show", unit, "--property=LoadState",
                                   "--property=ActiveState", "--property=SubState"])
        values = key_values(raw, ("LoadState", "ActiveState", "SubState"))
        if not required and values["LoadState"] == "not-found":
            continue
        need(values == {"LoadState": "loaded", "ActiveState": "inactive",
                        "SubState": "dead"}, "postfix_not_confirmed_stopped")
    # An additional instance, template or auxiliary service may still run.
    raw = command("systemctl", ["list-units", "--all", "--type=service",
                  "--no-legend", "--no-pager", "--plain", "postfix*.service"])
    for line in raw.splitlines():
        columns = line.split()
        need(len(columns) >= 4 and columns[0].endswith(".service") and
             columns[2] == "inactive" and columns[3] == "dead",
             "another_postfix_unit_not_stopped")


def no_postfix_processes(proc="/proc"):
    seen = 0
    for entry in os.scandir(proc):
        if not entry.name.isdigit():
            continue
        seen += 1
        need(seen <= 131072, "process_inventory_oversized")
        try:
            executable = os.readlink(os.path.join(entry.path, "exe"))
        except FileNotFoundError:
            # Exited process or kernel thread. Kernel threads have no exe.
            continue
        except ProcessLookupError:
            continue
        except OSError:
            raise Refused("process_inventory_unverified")
        need(not (executable.startswith(("/usr/lib/postfix/",
                                         "/usr/libexec/postfix/")) or
                  os.path.basename(executable).split(" ")[0] in
                  ("postfix", "postdrop", "postqueue", "postsuper", "sendmail",
                   "postlog", "postalias", "postmap", "master", "qmgr", "pickup",
                   "cleanup", "trivial-rewrite", "smtpd", "proxymap", "tlsmgr")),
             "mail_process_running_or_unverified")


def empty_queue(fd):
    # Never open message files. Missing standard queue directories, symlinks,
    # sockets, unknown entries or bounded traversal exhaustion fail closed.
    visited = [0]
    def scan(directory, depth):
        need(depth <= 6, "queue_depth_unverified")
        for name in os.listdir(directory):
            visited[0] += 1
            need(visited[0] <= 16384, "queue_inventory_oversized")
            meta = os.stat(name, dir_fd=directory, follow_symlinks=False)
            need(stat.S_ISDIR(meta.st_mode), "queue_not_empty_or_unverified")
            child = os.open(name, M.DIR_FLAGS, dir_fd=directory)
            try:
                current = os.fstat(child)
                need((current.st_dev, current.st_ino) == (meta.st_dev, meta.st_ino),
                     "queue_directory_changed")
                scan(child, depth + 1)
            finally:
                os.close(child)
    for name in QUEUE_DIRS:
        # saved is optional on some package versions; the message queues are not.
        try:
            child = os.open(name, M.DIR_FLAGS, dir_fd=fd)
        except FileNotFoundError:
            if name == "saved":
                continue
            raise Refused("required_queue_directory_missing")
        try:
            scan(child, 0)
        finally:
            os.close(child)


def local_addresses(command=system_command):
    raw = json.loads(command("ip", ["-j", "address", "show"]))
    need(type(raw) is list and 1 <= len(raw) <= 256, "interface_inventory_unverified")
    result = set()
    for iface in raw:
        need(type(iface) is dict and type(iface.get("addr_info")) is list,
             "interface_inventory_unverified")
        for item in iface["addr_info"]:
            need(type(item) is dict and type(item.get("local")) is str,
                 "interface_inventory_unverified")
            result.add(address(item["local"]))
    need(bool(result), "interface_inventory_empty")
    return result


def address(raw):
    ip = ipaddress.ip_address(raw.split("%", 1)[0])
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def safe_destination(ip, local):
    return not (ip in local or ip.is_loopback or ip.is_unspecified or
                ip.is_multicast or ip.is_link_local or
                (ip.version == 4 and int(ip) == 0xffffffff))


class PinnedSMTP(smtplib.SMTP):
    def __init__(self, host, port, peer):
        self.peer = str(peer)
        smtplib.SMTP.__init__(self, host, port, timeout=8,
                              local_hostname="lmr365-preflight.example.invalid")

    def _get_socket(self, host, port, timeout):
        return socket.create_connection((self.peer, port), timeout)


def tls_peer(host, port, peer, context):
    client = None
    try:
        client = PinnedSMTP(host, port, peer)
        need(address(client.sock.getpeername()[0]) == peer,
             "connected_peer_changed")
        code, _ = client.ehlo()
        need(code == 250 and client.has_extn("starttls"), "starttls_unavailable")
        client.starttls(context=context)
        code, _ = client.ehlo()
        need(code == 250, "tls_smtp_protocol_failed")
        certificate = client.sock.getpeercert(binary_form=True)
        need(bool(certificate), "tls_peer_certificate_missing")
        return M.digest(certificate)
    except (OSError, smtplib.SMTPException, ssl.SSLError):
        raise Refused("destination_tls_verification_failed")
    finally:
        if client is not None:
            client.close()


def trust_store_digest(path):
    # This file is a public CA bundle, not a server private key.
    resolved = os.path.realpath(path)
    need(resolved.startswith(("/etc/ssl/", "/etc/pki/")),
         "trust_store_path_unverified")
    meta = os.stat(resolved)
    need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
         not meta.st_mode & 0o022 and 0 < meta.st_size <= 8 * 1024 * 1024,
         "trust_store_metadata_unverified")
    with open(resolved, "rb") as stream:
        data = stream.read(8 * 1024 * 1024 + 1)
    need(len(data) == meta.st_size, "trust_store_size_changed")
    return M.digest(data)


def network_evidence(rules, ca, local, resolve=socket.getaddrinfo, check=tls_peer):
    endpoints = sorted({(item["host"], item["port"]) for item in rules})
    need(1 <= len(endpoints) <= MAX_ENDPOINTS, "too_many_preflight_destinations")
    trust = trust_store_digest(ca)
    ctx = ssl.create_default_context(cafile=ca)
    seen, total = [], 0
    for host, port in endpoints:
        peers = {address(row[4][0]) for row in
                 resolve(host, port, type=socket.SOCK_STREAM)}
        total += len(peers)
        need(bool(peers) and total <= MAX_ADDRESSES,
             "destination_resolution_unverified_or_oversized")
        need(all(safe_destination(ip, local) for ip in peers),
             "destination_resolves_to_local_or_invalid_address")
        certs = []
        for ip in sorted(peers, key=str):
            sha = check(host, port, ip, ctx)
            need(type(sha) is str and M.HEX.fullmatch(sha), "invalid_tls_evidence")
            certs.append((str(ip), sha))
        seen.append({"host": host, "port": port, "peers": certs})
    need(trust_store_digest(ca) == trust, "trust_store_changed")
    return M.digest(M.canonical({"trust": trust, "endpoints": seen})), len(endpoints)


def review(parent, config, queue, plan, expected_compiled):
    need(type(expected_compiled) is str and M.HEX.fullmatch(expected_compiled),
         "invalid_reviewed_compiled_sha")
    original = None
    def guard():
        stopped_units()
        no_postfix_processes()
        empty_queue(queue)
        values = postconf_values()
        ca = inspect_policy(values)
        inspect_master()
        if original is not None:
            need(values == original, "effective_policy_drift")
        return values, ca

    original, ca = guard()
    stage_sha, compiled_sha, backend, _ = M.verify_compiled(parent, plan, 0)
    need(compiled_sha == expected_compiled, "compiled_candidate_changed")
    stage_check, files = M.load_stage(parent, plan, 0)
    need(stage_check == stage_sha, "staged_candidate_changed")
    rules = M.validate(M.decode(files["plan.json"]))
    need(all(item["selector"] != "recipient-domain" for item in rules),
         "recipient_activation_not_supported")
    actual_backend, dbs, actual_sha = M.read_compiled(parent, plan, stage_sha, files, 0)
    need(actual_backend == backend and actual_sha == compiled_sha and
         set(dbs) == {"sender-candidates.txt" + M.MAP_SUFFIX[backend]},
         "sender_candidate_unverified")
    transaction = T.preview(
        config, plan, backend, stage_sha, compiled_sha,
        dbs["sender-candidates.txt" + M.MAP_SUFFIX[backend]], 0, guard)
    transaction_sha = transaction[0]
    network_sha, count = network_evidence(rules, ca, local_addresses())
    final_transaction = T.preview(
        config, plan, backend, stage_sha, compiled_sha,
        dbs["sender-candidates.txt" + M.MAP_SUFFIX[backend]], 0, guard)
    need(final_transaction == transaction, "config_changed_during_tls_check")
    current_stage, current_files = M.load_stage(parent, plan, 0)
    current_backend, current_db, current_sha = M.read_compiled(
        parent, plan, current_stage, current_files, 0)
    need((current_stage, current_files, current_backend, current_db, current_sha) ==
         (stage_sha, files, backend, dbs, compiled_sha),
         "candidate_changed_during_tls_check")
    evidence = M.digest(M.canonical({
        "version": 1, "transaction_sha256": transaction_sha,
        "effective_policy_sha256": M.digest(M.canonical(original)),
        "destination_sha256": network_sha, "plan_sha256": plan,
        "compiled_sha256": compiled_sha,
    }))
    return transaction, evidence, count, original, rules


def preflight(parent, config, queue, plan, expected_compiled):
    transaction, evidence, count, _, _ = review(
        parent, config, queue, plan, expected_compiled)
    return transaction[0], evidence, count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--compiled-sha256", required=True)
    args = parser.parse_args(argv)
    descriptors = []
    def timed_out(signum, frame):
        raise Refused("preflight_timeout")
    try:
        need(os.geteuid() == 0, "root_required")
        need(bool(M.HEX.fullmatch(args.plan_sha256)), "invalid_plan_sha")
        os.umask(0o077)
        signal.signal(signal.SIGALRM, timed_out)
        signal.alarm(100)
        for path in ("/var/lib", CONFIG, QUEUE):
            descriptors.append(open_directory(path, strict=path != QUEUE))
        txn, evidence, count = preflight(*descriptors, args.plan_sha256,
                                         args.compiled_sha256)
        print("CONDITIONAL_PREFLIGHT_STATUS=offline_reviewed")
        print("CONDITIONAL_PREFLIGHT_PLAN_SHA256=" + args.plan_sha256)
        print("CONDITIONAL_PREFLIGHT_COMPILED_SHA256=" + args.compiled_sha256)
        print("CONDITIONAL_PREFLIGHT_TRANSACTION_SHA256=" + txn)
        print("CONDITIONAL_PREFLIGHT_EVIDENCE_SHA256=" + evidence)
        print("CONDITIONAL_PREFLIGHT_TLS_DESTINATIONS=" + str(count))
        print("CONDITIONAL_PREFLIGHT_APPLY_ALLOWED=no")
        print("CONDITIONAL_PREFLIGHT_POSTFIX_CHANGED=no")
        print("CONDITIONAL_PREFLIGHT_MAIL_SENT=no")
        return 0
    except Refused as error:
        # Refused codes are fixed literals in these modules; do not expose
        # unexpected exception text, file content or upstream SMTP replies.
        reason = str(error)
        print("CONDITIONAL_PREFLIGHT_STATUS=blocked")
        print("CONDITIONAL_PREFLIGHT_REASON=" +
              (reason if re.fullmatch(r"[a-z0-9_]{1,100}", reason) else "unverified"))
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, IndexError):
        print("CONDITIONAL_PREFLIGHT_STATUS=blocked")
        print("CONDITIONAL_PREFLIGHT_REASON=unverified")
    finally:
        signal.alarm(0)
        for fd in reversed(descriptors):
            os.close(fd)
    print("CONDITIONAL_PREFLIGHT_APPLY_ALLOWED=no")
    print("CONDITIONAL_PREFLIGHT_POSTFIX_CHANGED=no")
    print("CONDITIONAL_PREFLIGHT_MAIL_SENT=no")
    return 2


if __name__ == "__main__":
    sys.exit(main())
