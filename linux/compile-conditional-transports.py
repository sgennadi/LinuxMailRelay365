#!/usr/bin/env python3
"""Native compiler for isolated sender-specific SMTP transport profiles.

Python 3.6+. Separate from the proven STARTTLS/no-AUTH stage/transaction.
Does not install a transport, contact a provider, submit mail, or run a
Postfix service. Credentials are accepted only for explicit compilation,
via stdin, and are compiled into private temporary maps on verified tmpfs.
"""
import argparse
import importlib.util
import os
import pathlib
import re
import resource
import signal
import stat
import sys
import tempfile

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location(
    "conditional_stage", str(pathlib.Path(__file__).with_name(
        "stage-conditional-postfix-maps.py")))
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)
Refused = M.Refused
MAX_RULES = 8
CONFIRM = "COMPILE_PRIVATE_TRANSPORTS_ONLY"
ROUTE_MAP = "sender-transport"
PARAMETER = "sender_dependent_default_transport_maps"
CA_FILES = ("/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt")


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def plan(request):
    need(type(request) is list and 1 <= len(request) <= MAX_RULES,
         "unsupported_transport_rule_count")
    normalized = []
    for item in request:
        need(type(item) is dict and set(item) == set(M.FIELDS),
             "invalid_transport_rule")
        need(item["selector"] in M.SELECTORS[:2], "sender_rules_only")
        need(item["tls"] in ("starttls", "implicit") and
             item["auth"] in ("none", "password"),
             "unsupported_transport_security")
        # Reuse the existing exact sender/domain, endpoint and overlap checks,
        # without widening the separately approved no-AUTH transaction.
        normalized.append(dict(item, tls="starttls", auth="none"))
    rules = M.validate(normalized)
    for i, rule in enumerate(rules):
        rule["tls"] = request[i]["tls"]
        rule["auth"] = request[i]["auth"]
    sha = M.plan_sha(rules)
    return rules, sha


def credentials(rules, items):
    need(type(items) is list and len(items) == len(rules),
         "one_credential_slot_per_rule_required")
    checked = []
    for rule, item in zip(rules, items):
        if rule["auth"] == "none":
            need(item is None, "unexpected_credential")
            checked.append(None)
            continue
        need(type(item) is dict and set(item) == {"username", "password"},
             "password_credential_required")
        user, password = item["username"], item["password"]
        # Conservative first native map format. No whitespace, delimiters in
        # usernames, control characters or non-ASCII normalization surprises.
        need(type(user) is str and type(password) is str and
             re.fullmatch(r"[!-~]{1,254}", user) is not None and ":" not in user and
             re.fullmatch(r"[!-~]{1,256}", password) is not None,
             "unsupported_credential_format")
        checked.append(user + ":" + password)
    return checked


def profile_name(sha, index):
    need(M.HEX.fullmatch(sha) and 1 <= index <= MAX_RULES,
         "invalid_transport_identity")
    return "lmr365-" + sha[:20] + "-" + str(index)


def endpoint(rule):
    return "[{}]:{}".format(rule["host"], rule["port"])


def render(rules, sha, work, backend, ca):
    # Called only for validated rules. The path is generated locally, not
    # supplied by a remote request. Every profile has its own map namespace.
    need(M.HEX.fullmatch(sha) and sha == M.plan_sha(rules) and
         backend in M.MAP_SUFFIX and ca in CA_FILES and
         re.fullmatch(r"/[A-Za-z0-9_./-]+", work) and
         all(x not in ("", ".", "..") for x in work.split("/")[1:]),
         "invalid_transport_render_context")
    routes, services, auth_maps = {}, {}, {}
    master = []
    for i, rule in enumerate(rules, 1):
        service = profile_name(sha, i)
        target = endpoint(rule)
        key = rule["pattern"]
        if rule["selector"] == M.SELECTORS[1]:
            key = "@" + key
        routes[key] = service + ":" + target
        enabled = rule["auth"] == "password"
        filename = service + "-sasl"
        if enabled:
            auth_maps[i] = filename
        options = {
            "smtp_tls_security_level": "secure",
            "smtp_tls_secure_cert_match": "nexthop",
            "smtp_tls_wrappermode": "yes" if rule["tls"] == "implicit" else "no",
            "smtp_tls_CAfile": ca,
            "smtp_tls_CApath": "",
            "smtp_tls_policy_maps": "",
            "smtp_tls_per_site": "",
            "smtp_tls_mandatory_protocols": "!SSLv2,!SSLv3,!TLSv1,!TLSv1.1",
            "smtp_tls_loglevel": "0",
            "smtp_sasl_auth_enable": "yes" if enabled else "no",
            "smtp_sender_dependent_authentication": "no",
            "smtp_sasl_password_maps": backend + ":" + work + "/" + filename
                                       if enabled else "",
            "smtp_sasl_type": "cyrus",
            "smtp_sasl_mechanism_filter": "plain,login",
            "smtp_sasl_security_options": "noplaintext,noanonymous",
            "smtp_sasl_tls_security_options": "noplaintext,noanonymous",
            "smtp_sasl_tls_verified_security_options": "noanonymous",
            "smtp_sasl_auth_cache_name": "",
            "smtp_connection_cache_on_demand": "no",
            "smtp_connection_cache_destinations": "",
            "smtp_tls_session_cache_database": "",
            "smtp_fallback_relay": "",
        }
        services[service] = options
        # UNIX delivery transport only, never an inet listener.
        master.append(service + " unix - - n - - smtp\n")
        for name, value in sorted(options.items()):
            master.append("    -o " + name + "=" + value + "\n")
    main = (b"myhostname = lmr365-transport.example.invalid\n"
            b"mydomain = example.invalid\n"
            b"meta_directory = /etc/postfix\n" +
            ("queue_directory = " + work + "/queue\n" +
             "data_directory = " + work + "/data\n" +
             PARAMETER + " = " + backend + ":" + work + "/" + ROUTE_MAP +
             "\n").encode("ascii"))
    return main, "".join(master).encode("ascii"), routes, services, auth_maps


def rows(data):
    # Map values are already validated. Do not put a secret in an error.
    return "".join(k + "\t" + v + "\n" for k, v in sorted(data.items())).encode("ascii")


def command(runner, tool, args, data=None, failure="native_transport_check_failed"):
    code, result = runner(tool, args, data)
    need(code == 0 and len(result) <= M.MAX_BYTES, failure)
    return result


def parameters(raw):
    out = {}
    for line in raw.decode("ascii").splitlines():
        key, sep, value = line.partition("=")
        key = key.strip()
        need(bool(sep) and key not in out, "invalid_native_parameter_output")
        out[key] = value.strip()
    return out


def compile_map(fd, work, backend, filename, expected, uid, runner, secret=False):
    # An empty/comment-only source establishes private file permissions for
    # postmap -i. Password material is supplied exclusively via stdin.
    source = b"# private stdin-only credential input\n" if secret else rows(expected)
    M.write_file(fd, filename, source)
    database = filename + M.MAP_SUFFIX[backend]
    need(database not in os.listdir(fd), "database_already_exists")
    spec = backend + ":" + work + "/" + filename
    prefix = ["-c", work]
    if secret:
        command(runner, "postmap", prefix + ["-i", spec], rows(expected),
                "private_credential_compilation_failed")
    else:
        command(runner, "postmap", prefix + [spec],
                failure="route_map_compilation_failed")
    before = M.read_file(fd, database, uid, M.MAX_DB_BYTES)
    found = command(runner, "postmap", prefix + ["-s", spec])
    need(M.native_rows(found) == expected, "compiled_map_enumeration_mismatch")
    keys = ("\n".join(sorted(expected)) + "\n").encode("ascii")
    found = command(runner, "postmap", prefix + ["-q", "-", spec], keys)
    need(M.native_rows(found) == expected, "compiled_map_lookup_mismatch")
    code, found = runner("postmap", prefix + ["-q", M.NEGATIVE_KEY, spec], None)
    need(code == 1 and not found.strip(), "compiled_map_negative_lookup_failed")
    need(M.read_file(fd, database, uid, M.MAX_DB_BYTES) == before and
         M.read_file(fd, filename, uid) == source,
         "native_compilation_modified_candidate")
    return database


def verify_services(work, services, backend, runner):
    prefix = ["-c", work]
    definitions = command(runner, "postconf", prefix + ["-M"]).decode("ascii")
    seen = set()
    for line in definitions.splitlines():
        fields = line.split()
        need(len(fields) >= 8 and fields[0] in services and fields[0] not in seen
             and fields[1:8] == ["unix", "-", "-", "n", "-", "-", "smtp"],
             "native_transport_service_mismatch")
        seen.add(fields[0])
    need(seen == set(services), "native_transport_service_missing")
    expected = {service + "/unix/" + key: value
                for service, options in services.items() for key, value in options.items()}
    actual = parameters(command(runner, "postconf", prefix + ["-P"]))
    need(actual == expected, "native_transport_override_mismatch")
    # postconf -P alone may accept unknown service override names. Require
    # every chosen setting to be a real parameter in the installed package.
    names = sorted({key for options in services.values() for key in options})
    defaults = parameters(command(runner, "postconf", prefix + ["-d"] + names))
    need(set(defaults) == set(names), "native_transport_parameter_unsupported")
    effective = parameters(command(runner, "postconf", prefix + ["-x", PARAMETER]))
    need(effective == {PARAMETER: backend + ":" + work + "/" + ROUTE_MAP},
         "native_sender_transport_parameter_mismatch")


def tmpfs_parent():
    # No credential DB should be staged on a persistent filesystem by this
    # experimental compiler. The kernel may still swap tmpfs pages; a killed
    # process can leave a root-only scratch directory until manual cleanup.
    root = "/dev/shm"
    info = os.stat(root, follow_symlinks=False)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
         bool(info.st_mode & stat.S_ISVTX), "private_tmpfs_unavailable")
    with open("/proc/self/mountinfo", "rt", encoding="ascii") as stream:
        lines = stream.read(2 * 1024 * 1024 + 1)
    need(len(lines) <= 2 * 1024 * 1024, "mount_inventory_oversized")
    types = []
    for line in lines.splitlines():
        left, sep, right = line.partition(" - ")
        fields = left.split()
        if sep and len(fields) >= 6 and fields[4] == root:
            types.append(right.split()[0])
    need(types == ["tmpfs"], "credential_tmpfs_unverified")
    return root


def installed_ca():
    for path in CA_FILES:
        if os.path.isfile(path):
            return path
    raise Refused("system_ca_bundle_missing")


def compile_profiles(request, approved, confirmation, uid, scratch_parent,
                     ca, runner=M.native_command, forced_backend=None):
    need(type(request) is dict and set(request) == {"rules", "credentials"},
         "invalid_transport_compile_request")
    rules, sha = plan(request["rules"])
    need(approved == sha and confirmation == CONFIRM,
         "reviewed_plan_confirmation_required")
    passwords = credentials(rules, request["credentials"])
    with tempfile.TemporaryDirectory(prefix="lmr365-transports-", dir=scratch_parent) as work:
        fd = os.open(work, M.DIR_FLAGS)
        try:
            M.check_directory(fd, uid, True)
            for name in ("queue", "data"):
                os.mkdir(name, 0o700, dir_fd=fd)
            # Bootstrap native map type discovery before rendering the final
            # isolated config. No global configuration files are touched.
            bootstrap = ("myhostname = lmr365-transport.example.invalid\n"
                         "mydomain = example.invalid\nmeta_directory = /etc/postfix\n"
                         "queue_directory = " + work + "/queue\n"
                         "data_directory = " + work + "/data\n").encode("ascii")
            M.write_file(fd, "main.cf", bootstrap)
            M.write_file(fd, "master.cf", b"# no services yet\n")
            types = command(runner, "postconf", ["-c", work, "-m"]).decode("ascii").split()
            backend = forced_backend or next((x for x in ("hash", "lmdb") if x in types), None)
            need(backend in M.MAP_SUFFIX and backend in types,
                 "native_indexed_map_backend_unavailable")
            if passwords.count(None) != len(passwords):
                available = command(runner, "postconf", ["-c", work, "-A"]).decode("ascii").split()
                need("cyrus" in available, "native_client_sasl_unavailable")
            main, master, routes, services, auth_maps = render(rules, sha, work, backend, ca)
            # These two files belong to the private command-only fixture.
            for name, contents in (("main.cf", main), ("master.cf", master)):
                os.unlink(name, dir_fd=fd)
                M.write_file(fd, name, contents)
            compile_map(fd, work, backend, ROUTE_MAP, routes, uid, runner)
            for index, filename in sorted(auth_maps.items()):
                compile_map(fd, work, backend, filename,
                            {endpoint(rules[index - 1]): passwords[index - 1]},
                            uid, runner, secret=True)
            verify_services(work, services, backend, runner)
            # Public receipt intentionally contains no credential checksum,
            # endpoint, account name, secret, or credential DB bytes.
            return sha, backend, len(services), len(auth_maps)
        finally:
            os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--compile", action="store_true")
    parser.add_argument("--approve-sha256")
    parser.add_argument("--confirm")
    args = parser.parse_args(argv)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
        def timeout(signum, frame):
            raise Refused("native_transport_compile_timeout")
        signal.signal(signal.SIGALRM, timeout)
        signal.alarm(180)
        request = M.decode(sys.stdin.buffer.read(M.MAX_BYTES + 1))
        if args.plan:
            need(args.approve_sha256 is None and args.confirm is None,
                 "unexpected_write_approval")
            rules, sha = plan(request)
            count = len(rules)
            auth = sum(x["auth"] == "password" for x in rules)
            print("CONDITIONAL_TRANSPORT_STATUS=plan_only")
        else:
            need(os.geteuid() == 0, "root_required")
            sha, backend, count, auth = compile_profiles(
                request, args.approve_sha256, args.confirm, 0, tmpfs_parent(), installed_ca())
            print("CONDITIONAL_TRANSPORT_STATUS=native_compiled_ephemeral")
            print("CONDITIONAL_TRANSPORT_BACKEND=" + backend)
        print("CONDITIONAL_TRANSPORT_PLAN_SHA256=" + sha)
        print("CONDITIONAL_TRANSPORT_COUNT=" + str(count))
        print("CONDITIONAL_TRANSPORT_AUTH_MAPS=" + str(auth))
        print("CONDITIONAL_TRANSPORT_ACTIVE=no")
        print("CONDITIONAL_TRANSPORT_POSTFIX_CHANGED=no")
        print("CONDITIONAL_TRANSPORT_MAIL_SENT=no")
        return 0
    except Exception:
        # No tracebacks, native stderr, config values or credentials.
        print("CONDITIONAL_TRANSPORT_STATUS=refused_or_failed", file=sys.stderr)
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
