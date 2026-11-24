#!/usr/bin/env python3
"""Immutable, root-only conditional Postfix map staging, never installation.

Python 3.6+. Accept only the initial disjoint STARTTLS/no-AUTH subset.
The staged text maps are disconnected from Postfix. No service, queue,
credential, live map, configuration or network operation is performed.
Optional native compilation/verification works only on private copies.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tempfile

BASE_NAME = "linuxmailrelay365-conditional-stage"
COMPILED_BASE = "linuxmailrelay365-conditional-compiled"
COMPILED_MANIFEST = "compiled-manifest.json"
NATIVE_CONFIG = (b"myhostname = lmr365-map-stage.example.invalid\n"
                 b"mydomain = example.invalid\n"
                 b"meta_directory = /etc/postfix\n"
                 b"queue_directory = $config_directory/queue\n"
                 b"data_directory = $config_directory/data\n")
MAP_SUFFIX = {"hash": ".db", "lmdb": ".lmdb"}
MAX_DB_BYTES = 4 * 1024 * 1024
NEGATIVE_KEY = "__lmr365_stage_missing_key__"
HEX = re.compile(r"[0-9a-f]{64}\Z")
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN = re.compile(LABEL + r"(?:\." + LABEL + r")+\Z")
MAILBOX = re.compile(r"[a-z0-9][a-z0-9._+%-]{0,62}@" + DOMAIN.pattern)
MAX_BYTES = 32768
SELECTORS = ("exact-envelope-sender", "envelope-sender-domain",
             "recipient-domain")
FIELDS = ("selector", "pattern", "host", "port", "tls", "auth")
FILES = ("plan.json", "sender-candidates.txt", "recipient-candidates.txt")
MANIFEST = "manifest.json"
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class Refused(Exception):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused("duplicate_json_field")
        result[key] = value
    return result


def decode(data):
    if not data or len(data) > MAX_BYTES:
        raise Refused("invalid_request_size")
    try:
        return json.loads(data.decode("ascii"), object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, RecursionError):
        raise Refused("invalid_json")


def domain(value):
    if (type(value) is not str or len(value) > 253 or
            not DOMAIN.fullmatch(value)):
        raise Refused("invalid_domain")
    return value


def destination(value):
    if type(value) is not str:
        raise Refused("invalid_destination")
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", value):
            raise Refused("invalid_destination")
        name = domain(value)
        if name.endswith(".localhost"):
            raise Refused("local_destination")
        return name
    if (ip.is_loopback or ip.is_unspecified or ip.is_multicast or
            ip.is_link_local or int(ip) == 0xffffffff):
        raise Refused("local_or_invalid_destination")
    return str(ip)


def validate(request):
    if type(request) is not list or not 1 <= len(request) <= 24:
        raise Refused("invalid_rule_count")
    rules = []
    seen = set()
    for item in request:
        if type(item) is not dict or set(item) != set(FIELDS):
            raise Refused("invalid_rule_fields")
        selector, pattern, host, port, tls, auth = (item[k] for k in FIELDS)
        if selector not in SELECTORS or type(selector) is not str:
            raise Refused("invalid_selector")
        if selector == SELECTORS[0]:
            if (type(pattern) is not str or len(pattern) > 254 or
                    not MAILBOX.fullmatch(pattern)):
                raise Refused("invalid_sender")
            local, suffix = pattern.rsplit("@", 1)
            if ".." in local or local.endswith("."):
                raise Refused("invalid_sender")
            domain(suffix)
        else:
            domain(pattern)
        if type(port) is not int or not 1 <= port <= 65535:
            raise Refused("invalid_port")
        # The original wizard can preview other modes. This stage intentionally
        # does not pretend that a map line configures TLS or SMTP authentication.
        if tls != "starttls" or auth != "none":
            raise Refused("stage_supports_only_starttls_no_auth")
        key = (selector, pattern)
        if key in seen:
            raise Refused("duplicate_rule")
        seen.add(key)
        rules.append(dict(zip(FIELDS, (selector, pattern, destination(host),
                                       port, tls, auth))))
    for index, a in enumerate(rules):
        for b in rules[index + 1:]:
            sa, sb = a["selector"], b["selector"]
            pa, pb = a["pattern"], b["pattern"]
            if (sa == SELECTORS[2]) != (sb == SELECTORS[2]):
                raise Refused("mixed_sender_recipient_precedence_unverified")
            if sa == sb == SELECTORS[2]:
                if pa.endswith("." + pb) or pb.endswith("." + pa):
                    raise Refused("parent_recipient_domain_overlap")
            if sa == SELECTORS[0] and sb == SELECTORS[1] and pa.endswith("@" + pb):
                raise Refused("sender_domain_overlap")
            if sb == SELECTORS[0] and sa == SELECTORS[1] and pb.endswith("@" + pa):
                raise Refused("sender_domain_overlap")
    return rules


def plan_sha(rules):
    # Identical ASCII length-prefix algorithm to AdvancedRoutePlanner.PlanSha256
    # for the supported canonical lowercase subset.
    text = "LMR365-COND-ROUTES-V1\n"
    for item in rules:
        for key in FIELDS:
            value = str(item[key])
            text += "{}:{}\n".format(len(value), value)
    return digest(text.encode("ascii"))


def build(request):
    rules = validate(request)
    sha = plan_sha(rules)
    sender, recipient = [], []
    for item in rules:
        endpoint = "[{}]:{}".format(item["host"], item["port"])
        key = item["pattern"]
        if item["selector"] == SELECTORS[2]:
            recipient.append(key + "\t" + "smtp:" + endpoint + "\n")
        else:
            if item["selector"] == SELECTORS[1]:
                key = "@" + key
            sender.append(key + "\t" + endpoint + "\n")
    header = "# STAGED CANDIDATES ONLY - NOT ACTIVE POSTFIX CONFIGURATION\n"
    files = {
        "plan.json": canonical(rules),
        "sender-candidates.txt": (header + "".join(sender)).encode("ascii"),
        "recipient-candidates.txt": (header + "".join(recipient)).encode("ascii"),
    }
    files[MANIFEST] = canonical({
        "format": "LMR365-CONDITIONAL-STAGE-V1",
        "plan_sha256": sha,
        "active": False,
        "files": {name: digest(files[name]) for name in FILES},
    })
    return sha, files


def check_directory(fd, uid, private=False):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or
            (stat.S_IMODE(info.st_mode) != 0o700 if private else
             bool(info.st_mode & 0o022))):
        raise Refused("untrusted_stage_directory")


def open_parent():
    # Fixed CLI location; no path or root override from user input.
    fd = os.open("/", DIR_FLAGS)
    try:
        for part in ("var", "lib"):
            check_directory(fd, 0)
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        check_directory(fd, 0)
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_base(parent, uid, create=False, name=BASE_NAME):
    check_directory(parent, uid)
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
    fd = os.open(name, DIR_FLAGS, dir_fd=parent)
    try:
        check_directory(fd, uid, True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_file(fd, name, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    handle = os.open(name, flags, 0o600, dir_fd=fd)
    with os.fdopen(handle, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def read_file(fd, name, uid, maximum=MAX_BYTES):
    handle = os.open(name, READ_FLAGS, dir_fd=fd)
    with os.fdopen(handle, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or
                stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or
                not 0 < before.st_size <= maximum):
            raise Refused("untrusted_stage_file")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_uid, info.st_mode,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (len(data) != before.st_size or identity(before) != identity(after) or
                identity(before) != identity(observed)):
            raise Refused("changed_stage_file")
        return data


def read_verified_stage(fd, sha, uid):
    check_directory(fd, uid, True)
    if set(os.listdir(fd)) != set(FILES) | {MANIFEST}:
        raise Refused("incomplete_or_extra_stage_files")
    actual = {name: read_file(fd, name, uid) for name in FILES + (MANIFEST,)}
    recomputed_sha, expected = build(decode(actual["plan.json"]))
    if recomputed_sha != sha or actual != expected:
        raise Refused("stage_hash_or_manifest_mismatch")
    return digest(actual[MANIFEST]), actual


def verify_directory(fd, sha, uid):
    return read_verified_stage(fd, sha, uid)[0]


def load_stage(parent, sha, uid):
    if type(sha) is not str or not HEX.fullmatch(sha):
        raise Refused("invalid_plan_sha")
    base = open_base(parent, uid)
    try:
        fd = os.open(sha, DIR_FLAGS, dir_fd=base)
        try:
            return read_verified_stage(fd, sha, uid)
        finally:
            os.close(fd)
    finally:
        os.close(base)


def verify(parent, sha, uid):
    if type(sha) is not str or not HEX.fullmatch(sha):
        raise Refused("invalid_plan_sha")
    base = open_base(parent, uid)
    try:
        fd = os.open(sha, DIR_FLAGS, dir_fd=base)
        try:
            return verify_directory(fd, sha, uid)
        finally:
            os.close(fd)
    finally:
        os.close(base)


def stage(parent, request, approved_sha, confirmation, uid):
    sha, files = build(request)
    if approved_sha != sha or confirmation != "STAGE_CONDITIONAL_MAPS_ONLY":
        raise Refused("reviewed_sha_and_confirmation_required")
    base = open_base(parent, uid, create=True)
    try:
        # mkdir exclusively reserves this immutable candidate. No overwriting,
        # including an incomplete candidate from a crashed process.
        os.mkdir(sha, 0o700, dir_fd=base)
        os.fsync(base)
        fd = os.open(sha, DIR_FLAGS, dir_fd=base)
        try:
            check_directory(fd, uid, True)
            for name in FILES:
                write_file(fd, name, files[name])
            # Manifest written last is the completion marker. An interrupted
            # stage is not accepted by verify and is never resumed/overwritten.
            write_file(fd, MANIFEST, files[MANIFEST])
            os.fsync(fd)
            receipt = verify_directory(fd, sha, uid)
            os.fsync(base)
            return sha, receipt
        finally:
            os.close(fd)
    finally:
        os.close(base)


def trusted_postfix_tool(name):
    if name not in ("postmap", "postconf"):
        raise Refused("unsupported_native_tool")
    path = os.path.realpath("/usr/sbin/" + name)
    if not path.startswith(("/usr/sbin/", "/usr/libexec/postfix/",
                            "/usr/lib/postfix/")):
        raise Refused("native_tool_outside_trusted_path")
    info = os.stat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_mode & 0o022 or not info.st_mode & 0o111):
        raise Refused("native_tool_not_root_managed")
    folder = os.path.dirname(path)
    while True:
        info = os.stat(folder, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022):
            raise Refused("native_tool_directory_untrusted")
        if folder == "/":
            break
        folder = os.path.dirname(folder)
    return path


def native_command(tool, arguments, input_data=None):
    # No shell, inherited MAIL_CONFIG, PATH search, live maps or SMTP actions.
    try:
        result = subprocess.run(
            [trusted_postfix_tool(tool)] + arguments,
            input=input_data if input_data is not None else b"",
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("native_postfix_tool_unavailable")
    if len(result.stdout) > MAX_BYTES:
        raise Refused("native_postfix_output_oversized")
    return result.returncode, result.stdout


def candidate_rows(source):
    rows = {}
    for line in source.decode("ascii").splitlines():
        if line.startswith("#"):
            continue
        key, value = line.split("\t", 1)
        if key in rows:
            raise Refused("duplicate_candidate_key")
        rows[key] = value
    return rows


def native_rows(output):
    try:
        rows = {}
        for line in output.decode("ascii").splitlines():
            key, value = line.split(None, 1)
            if key in rows:
                raise Refused("duplicate_native_key")
            rows[key] = value
        return rows
    except (UnicodeError, ValueError):
        raise Refused("malformed_native_lookup")


def source_maps(stage_files):
    return {name: stage_files[name] for name in FILES[1:]
            if candidate_rows(stage_files[name])}


def db_names(stage_files, backend):
    if backend not in MAP_SUFFIX:
        raise Refused("unsupported_database_backend")
    return {name + MAP_SUFFIX[backend] for name in source_maps(stage_files)}


def compile_manifest(sha, stage_sha, backend, stage_files, databases):
    if set(databases) != db_names(stage_files, backend):
        raise Refused("unexpected_compiled_file_set")
    return canonical({
        "format": "LMR365-CONDITIONAL-COMPILED-V1",
        "plan_sha256": sha,
        "stage_manifest_sha256": stage_sha,
        "active": False,
        "backend": backend,
        "lookup_count": sum(len(candidate_rows(data))
                            for data in source_maps(stage_files).values()),
        "files": {name: digest(data) for name, data in databases.items()},
    })


def native_check(stage_files, scratch_parent, uid, backend=None,
                 databases=None, runner=native_command):
    """Compile fresh copies or verify copies of existing candidate databases.

    postmap -c uses only our minimal isolated main.cf. postmap -s and -q
    check raw dictionary keys, not complete Postfix delivery precedence.
    A missing backend, failed positive/negative lookup or unexpected row
    fails closed. No generated database is attached to any running MTA.
    """
    if (backend is None) != (databases is None):
        raise Refused("invalid_native_check_mode")
    maps = source_maps(stage_files)
    if not maps:
        raise Refused("empty_map_candidate")
    with tempfile.TemporaryDirectory(prefix="lmr365-map-check-",
                                     dir=scratch_parent) as work:
        fd = os.open(work, DIR_FLAGS)
        try:
            check_directory(fd, uid, True)
            # Keep configuration, queue and data paths distinct. A packaged
            # Postfix may require master.cf even for a command-only instance.
            # No services are defined or launched in this fixture.
            os.mkdir("queue", 0o700, dir_fd=fd)
            os.mkdir("data", 0o700, dir_fd=fd)
            write_file(fd, "main.cf", NATIVE_CONFIG)
            write_file(fd, "master.cf", b"# command-only candidate instance\n")
            result, supported = runner("postconf", ["-c", work, "-m"])
            if result:
                raise Refused("native_backend_inventory_failed")
            types = supported.decode("ascii").split()
            if backend is None:
                backend = next((key for key in ("hash", "lmdb")
                                if key in types), None)
            if backend not in MAP_SUFFIX or backend not in types:
                raise Refused("supported_indexed_backend_missing")
            suffix = MAP_SUFFIX[backend]
            checked = {}
            for name, source in maps.items():
                write_file(fd, name, source)
                database_name = name + suffix
                specification = backend + ":" + os.path.join(work, name)
                prefix = ["-c", work]
                if databases is None:
                    code, _ = runner("postmap", prefix + [specification])
                    if code:
                        raise Refused("native_map_compilation_failed")
                else:
                    write_file(fd, database_name, databases[database_name])
                # A newly created DB must be regular, private and root-owned.
                before = read_file(fd, database_name, uid, MAX_DB_BYTES)
                wanted = candidate_rows(source)
                code, found = runner("postmap", prefix + ["-s", specification])
                if code or native_rows(found) != wanted:
                    raise Refused("native_map_enumeration_mismatch")
                keys = ("\n".join(wanted) + "\n").encode("ascii")
                code, found = runner("postmap", prefix + ["-q", "-", specification],
                                     keys)
                if code or native_rows(found) != wanted:
                    raise Refused("native_positive_lookup_mismatch")
                code, found = runner("postmap", prefix + [
                    "-q", NEGATIVE_KEY, specification])
                if code != 1 or found.strip():
                    raise Refused("native_negative_lookup_mismatch")
                after = read_file(fd, database_name, uid, MAX_DB_BYTES)
                if after != before:
                    raise Refused("native_lookup_modified_database")
                checked[database_name] = after
            if set(checked) != db_names(stage_files, backend):
                raise Refused("unexpected_compiled_file_set")
            return backend, checked
        finally:
            os.close(fd)


def read_compiled(parent, sha, stage_sha, stage_files, uid):
    base = open_base(parent, uid, name=COMPILED_BASE)
    try:
        fd = os.open(sha, DIR_FLAGS, dir_fd=base)
        try:
            check_directory(fd, uid, True)
            manifest = read_file(fd, COMPILED_MANIFEST, uid)
            info = decode(manifest)
            if type(info) is not dict or type(info.get("backend")) is not str:
                raise Refused("invalid_compiled_manifest")
            backend = info["backend"]
            names = db_names(stage_files, backend)
            if set(os.listdir(fd)) != names | {COMPILED_MANIFEST}:
                raise Refused("incomplete_or_extra_compiled_files")
            databases = {name: read_file(fd, name, uid, MAX_DB_BYTES)
                         for name in names}
            if manifest != compile_manifest(sha, stage_sha, backend,
                                            stage_files, databases):
                raise Refused("compiled_manifest_or_database_mismatch")
            return backend, databases, digest(manifest)
        finally:
            os.close(fd)
    finally:
        os.close(base)


def compile_stage(parent, sha, approved_stage_sha, confirmation, uid,
                  scratch_parent="/var/lib", runner=native_command):
    stage_sha, stage_files = load_stage(parent, sha, uid)
    if (approved_stage_sha != stage_sha or
            confirmation != "COMPILE_CONDITIONAL_MAPS_ONLY"):
        raise Refused("reviewed_stage_manifest_and_confirmation_required")
    # Never replace an existing compiled candidate, even if interrupted.
    try:
        existing = open_base(parent, uid, name=COMPILED_BASE)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        try:
            if sha in os.listdir(existing):
                raise Refused("compiled_candidate_already_exists")
        finally:
            os.close(existing)
    backend, databases = native_check(stage_files, scratch_parent, uid,
                                      runner=runner)
    # Re-read the immutable stage after native work; bind compiled files to
    # the exact manifest and source data that were reviewed.
    current_sha, current_files = load_stage(parent, sha, uid)
    if current_sha != stage_sha or current_files != stage_files:
        raise Refused("stage_changed_during_compilation")
    manifest = compile_manifest(sha, stage_sha, backend, stage_files, databases)
    base = open_base(parent, uid, create=True, name=COMPILED_BASE)
    try:
        os.mkdir(sha, 0o700, dir_fd=base)
        os.fsync(base)
        fd = os.open(sha, DIR_FLAGS, dir_fd=base)
        try:
            check_directory(fd, uid, True)
            for name, data in databases.items():
                write_file(fd, name, data)
            write_file(fd, COMPILED_MANIFEST, manifest)
            os.fsync(fd)
            os.fsync(base)
        finally:
            os.close(fd)
    finally:
        os.close(base)
    actual_backend, actual_db, compiled_sha = read_compiled(
        parent, sha, stage_sha, stage_files, uid)
    if actual_backend != backend or actual_db != databases:
        raise Refused("compiled_stage_changed")
    return stage_sha, compiled_sha, backend, decode(manifest)["lookup_count"]


def verify_compiled(parent, sha, uid, scratch_parent="/var/lib",
                    runner=native_command):
    stage_sha, files = load_stage(parent, sha, uid)
    backend, databases, compiled_sha = read_compiled(parent, sha, stage_sha, files, uid)
    # Re-run the actual native queries against temporary copies, not the
    # original staged DBs. Verification never modifies retained candidates.
    check_backend, checked = native_check(files, scratch_parent, uid, backend,
                                          databases, runner)
    if check_backend != backend or checked != databases:
        raise Refused("compiled_native_verification_failed")
    current_stage_sha, current_files = load_stage(parent, sha, uid)
    current_backend, current_db, current_sha = read_compiled(
        parent, sha, current_stage_sha, current_files, uid)
    if (current_stage_sha != stage_sha or current_files != files or
            current_backend != backend or current_db != databases or
            current_sha != compiled_sha):
        raise Refused("compiled_candidate_changed_during_verification")
    count = sum(len(candidate_rows(data)) for data in source_maps(files).values())
    return stage_sha, compiled_sha, backend, count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan", action="store_true")
    group.add_argument("--stage", action="store_true")
    group.add_argument("--verify", metavar="SHA256")
    group.add_argument("--compile", metavar="SHA256")
    group.add_argument("--verify-compiled", metavar="SHA256")
    parser.add_argument("--approve-sha256")
    parser.add_argument("--approve-manifest-sha256")
    parser.add_argument("--confirm")
    args = parser.parse_args(argv)
    try:
        if (not args.stage and args.approve_sha256 is not None or
                args.compile is None and args.approve_manifest_sha256 is not None or
                not args.stage and args.compile is None and args.confirm is not None):
            raise Refused("unexpected_write_approval")
        os.umask(0o077)
        if args.plan:
            sha, _ = build(decode(sys.stdin.buffer.read(MAX_BYTES + 1)))
            print("CONDITIONAL_STAGE_STATUS=plan_only")
        else:
            if os.geteuid() != 0:
                raise Refused("root_required")
            parent = open_parent()
            try:
                if args.stage:
                    sha, receipt = stage(parent, decode(sys.stdin.buffer.read(MAX_BYTES + 1)),
                                         args.approve_sha256, args.confirm, 0)
                    print("CONDITIONAL_STAGE_STATUS=staged_verified")
                elif args.compile is not None or args.verify_compiled is not None:
                    sha = args.compile if args.compile is not None else args.verify_compiled
                    if args.compile is not None:
                        receipt, compiled_sha, backend, count = compile_stage(
                            parent, sha, args.approve_manifest_sha256, args.confirm, 0)
                        print("CONDITIONAL_STAGE_STATUS=compiled_verified")
                    else:
                        receipt, compiled_sha, backend, count = verify_compiled(
                            parent, sha, 0)
                        print("CONDITIONAL_STAGE_STATUS=compiled_verified_read_only")
                    print("CONDITIONAL_STAGE_COMPILED_SHA256=" + compiled_sha)
                    print("CONDITIONAL_STAGE_MAP_BACKEND=" + backend)
                    print("CONDITIONAL_STAGE_LOOKUP_COUNT=" + str(count))
                else:
                    sha = args.verify
                    receipt = verify(parent, sha, 0)
                    print("CONDITIONAL_STAGE_STATUS=verified_read_only")
                print("CONDITIONAL_STAGE_MANIFEST_SHA256=" + receipt)
            finally:
                os.close(parent)
        print("CONDITIONAL_STAGE_PLAN_SHA256=" + sha)
        print("CONDITIONAL_STAGE_ACTIVE=no")
        print("CONDITIONAL_STAGE_POSTFIX_CHANGED=no")
        return 0
    except (Refused, OSError, ValueError, UnicodeError):
        # Do not print paths, addresses, JSON, or underlying exception details.
        print("CONDITIONAL_STAGE_STATUS=refused_or_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
