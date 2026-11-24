#!/usr/bin/env python3
"""Read-only multi-transport SELinux label preflight, Python 3.6+.

Checks actual configuration directory/file labels against installed policy
and derives the exact Hash/LMDB destinations from validated nonsecret rules.
Does not read password map contents, contact providers, relabel anything,
install policy, or authorize writes. Enforcing runtime acceptance is separate.
"""
import argparse
import importlib.util
import os
import pathlib
import pwd
import stat
import sys

sys.dont_write_bytecode = True


def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(pathlib.Path(__file__).with_name(filename)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = sibling("multi_label_preflight", "inspect-conditional-postfix-activation.py")
C = sibling("multi_label_compiler", "compile-conditional-transports.py")
T, M = P.T, P.M
Refused = P.Refused


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def destinations(rules, backend):
    need(backend in M.MAP_SUFFIX, "unsupported_label_backend")
    try:
        normalized, plan = C.plan(rules)
    except C.Refused:
        raise Refused("invalid_label_plan") from None
    sources = ["lmr365-" + plan + "-sender-transport"]
    sources.extend(C.profile_name(plan, i) + "-sasl"
                   for i, rule in enumerate(normalized, 1) if rule["auth"] == "password")
    return plan, tuple(sources)


def context(raw):
    value = T.label_bytes(raw).rstrip(b"\0")
    fields = value.decode("ascii").split(":")
    need(fields[2] not in ("default_t", "unlabeled_t", "etc_t", "file_t"),
         "generic_or_unsafe_postfix_policy_type")
    return value


def query_label(path, mode, command):
    # Only callers below may supply these derived paths. No operator-supplied
    # path is ever sent to matchpathcon. Do not follow a symlink or relabel.
    raw = command("matchpathcon", ["-N", "-n", "-m", mode, path])
    lines = raw.splitlines()
    need(len(lines) == 1 and lines[0] == lines[0].strip(),
         "selinux_policy_label_unverified")
    value = T.checked_label(lines[0].encode("ascii") + b"\0")
    context(value)
    return value


def policy_labels(rules, backend, command=P.system_command):
    """Read actual packaged file-context policy, also usable offline in CI."""
    plan, sources = destinations(rules, backend)
    result = {".": query_label(P.CONFIG, "dir", command)}
    for name in ("main.cf", "master.cf") + tuple(
            source + M.MAP_SUFFIX[backend] for source in sources):
        result[name] = query_label(P.CONFIG + "/" + name, "file", command)
    return plan, sources, result


def private_policy_labels(info, revision, command=P.system_command):
    """Read packaged policy for exact derived recovery paths, without writes."""
    private = sibling("private_store_policy", "conditional-transport-private-store.py")
    result = {}
    for relative, mode in private.policy_paths(info, revision).items():
        # Private storage may legitimately use var_lib_t; do not impose
        # the mail-specific label or infer access from a type name.
        raw = command("matchpathcon", ["-N", "-n", "-m", mode, "/var/lib/" + relative])
        lines = raw.splitlines()
        need(len(lines) == 1 and lines[0] == lines[0].strip(),
             "private_policy_label_unverified")
        value = T.checked_label(lines[0].encode("ascii") + b"\0")
        private.raw_context(value)
        result[relative] = value
    return result


def identity(info):
    # Ignore atime; include ctime, permissions and group to detect relabel
    # or replacement. Only metadata is inspected, never database bytes.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def label_for_fd(fd):
    # Reuse the strict xattr reader: any ACL/capability/integrity attribute
    # alongside SELinux is unsupported and must block this preflight.
    raw = T.file_label(fd)
    need(raw is not None, "selinux_label_missing")
    return context(raw)


def actual_directory(config, uid, expected):
    before = os.fstat(config)
    need(stat.S_ISDIR(before.st_mode) and before.st_uid == uid and
         not before.st_mode & 0o022, "untrusted_config_directory")
    need(label_for_fd(config) == context(expected), "selinux_directory_label_mismatch")
    need(identity(os.fstat(config)) == identity(before), "config_directory_changed")
    return identity(before)


def actual_file(config, name, uid, expected, map_gid=None):
    fd = os.open(name, M.READ_FLAGS, dir_fd=config)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == uid and
             before.st_nlink == 1 and not before.st_mode & 0o7022 and before.st_size > 0,
             "untrusted_labeled_file")
        if map_gid is not None:
            need(stat.S_IMODE(before.st_mode) == 0o640 and before.st_gid == map_gid,
                 "untrusted_labeled_map")
        need(label_for_fd(fd) == context(expected), "selinux_file_label_mismatch")
        need(identity(os.fstat(fd)) == identity(before) ==
             identity(os.stat(name, dir_fd=config, follow_symlinks=False)),
             "labeled_file_changed")
        return identity(before)
    finally:
        os.close(fd)


def observe(config, rules, backend, uid, gid, installed, guard,
            command=P.system_command):
    """Private observation for future label-preserving transactions.

    The caller must prove directory binding; actual write safety and native
    route ownership are not established by label matching alone.
    """
    need(type(installed) is bool and type(gid) is int and gid >= 0,
         "invalid_label_review_context")
    guard()
    plan, sources, labels = policy_labels(rules, backend, command)
    suffix = M.MAP_SUFFIX[backend]

    def current():
        result = {".": actual_directory(config, uid, labels["."])}
        for name in ("main.cf", "master.cf"):
            result[name] = actual_file(config, name, uid, labels[name])
        for source in sources:
            name = source + suffix
            need(not T.exists(config, source), "unexpected_managed_source_file")
            if installed:
                result[name] = actual_file(config, name, uid, labels[name], gid)
            else:
                need(not T.exists(config, name), "managed_map_destination_exists")
        return result

    first = current()
    guard()
    need(policy_labels(rules, backend, command) == (plan, sources, labels) and
         current() == first, "selinux_policy_or_metadata_changed")
    guard()
    need(current() == first, "selinux_metadata_changed")
    return {"plan": plan, "backend": backend, "labels": labels,
            "identities": first, "installed": installed}


def selinux_mode():
    path = pathlib.Path("/sys/fs/selinux/enforce")
    try:
        value = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return "inactive_or_unavailable"
    return {"0": "permissive", "1": "enforcing"}.get(value, "unverified")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--backend", choices=("hash", "lmdb"), required=True)
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args(argv)
    fd = None
    try:
        need(os.geteuid() == 0, "root_required")
        mode = selinux_mode()
        need(mode in ("enforcing", "permissive"), "active_selinux_required")
        raw = sys.stdin.buffer.read(M.MAX_BYTES + 1)
        need(0 < len(raw) <= M.MAX_BYTES, "invalid_label_request")
        rules = M.decode(raw)
        fd = P.open_directory(P.CONFIG)
        account = pwd.getpwnam("postfix")

        def guard():
            need(selinux_mode() == mode and
                 (os.fstat(fd).st_dev, os.fstat(fd).st_ino) ==
                 (os.stat(P.CONFIG, follow_symlinks=False).st_dev,
                  os.stat(P.CONFIG, follow_symlinks=False).st_ino) and
                 pwd.getpwnam("postfix") == account, "label_review_context_changed")

        reviewed = observe(fd, rules, args.backend, 0, account.pw_gid,
                           args.installed, guard)
        print("MULTI_SELINUX_LABEL_STATUS=policy_match_read_only")
        print("MULTI_SELINUX_MODE=" + mode)
        print("MULTI_SELINUX_PLAN=" + reviewed["plan"])
        print("MULTI_SELINUX_BACKEND=" + reviewed["backend"])
        print("MULTI_SELINUX_MAP_COUNT=" + str(len(reviewed["labels"]) - 3))
        status = 0
    except Exception:
        # Do not export actual contexts, native output, paths or request input.
        print("MULTI_SELINUX_LABEL_STATUS=unverified")
        status = 2
    finally:
        if fd is not None:
            os.close(fd)
    print("MULTI_SELINUX_WRITE_ALLOWED=no")
    print("MULTI_SELINUX_RUNTIME_VERIFIED=no")
    print("CHANGES_APPLIED=no")
    return status


if __name__ == "__main__":
    sys.exit(main())
