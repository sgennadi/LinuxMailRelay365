#!/usr/bin/env python3
"""Immutable, root-only conditional Postfix map staging, never installation.

Python 3.6+. Accept only the initial disjoint STARTTLS/no-AUTH subset.
The staged text maps are disconnected from Postfix. No service, queue,
credential, live map, configuration or network operation is performed.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys

BASE_NAME = "linuxmailrelay365-conditional-stage"
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


def open_base(parent, uid, create=False):
    check_directory(parent, uid)
    if create:
        try:
            os.mkdir(BASE_NAME, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
    fd = os.open(BASE_NAME, DIR_FLAGS, dir_fd=parent)
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


def read_file(fd, name, uid):
    handle = os.open(name, READ_FLAGS, dir_fd=fd)
    with os.fdopen(handle, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or
                stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or
                not 0 < before.st_size <= MAX_BYTES):
            raise Refused("untrusted_stage_file")
        data = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
        observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_uid, info.st_mode,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (len(data) != before.st_size or identity(before) != identity(after) or
                identity(before) != identity(observed)):
            raise Refused("changed_stage_file")
        return data


def verify_directory(fd, sha, uid):
    check_directory(fd, uid, True)
    if set(os.listdir(fd)) != set(FILES) | {MANIFEST}:
        raise Refused("incomplete_or_extra_stage_files")
    actual = {name: read_file(fd, name, uid) for name in FILES + (MANIFEST,)}
    recomputed_sha, expected = build(decode(actual["plan.json"]))
    if recomputed_sha != sha or actual != expected:
        raise Refused("stage_hash_or_manifest_mismatch")
    return digest(actual[MANIFEST])


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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan", action="store_true")
    group.add_argument("--stage", action="store_true")
    group.add_argument("--verify", metavar="SHA256")
    parser.add_argument("--approve-sha256")
    parser.add_argument("--confirm")
    args = parser.parse_args(argv)
    try:
        if not args.stage and (args.approve_sha256 is not None or args.confirm is not None):
            raise Refused("unexpected_write_approval")
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
    except (Refused, OSError, ValueError):
        # Do not print paths, addresses, JSON, or underlying exception details.
        print("CONDITIONAL_STAGE_STATUS=refused_or_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
