#!/usr/bin/env python3
"""Multi-transport configuration review and private recovery snapshot.

Library only. No live configuration writes or credential persistence.
Caller must establish exclusive maintenance and native policy compatibility.
"""
import importlib.util
import os
import pathlib
import re
import secrets
import sys

sys.dont_write_bytecode = True


def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(pathlib.Path(__file__).with_name(filename)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = sibling("conditional_transports", "compile-conditional-transports.py")
T = sibling("conditional_transaction", "conditional-postfix-transaction.py")
M = T.M
Refused = M.Refused
BASE = "linuxmailrelay365-transport-recovery"
FILES = ("main.before", "master.before", "main.after", "master.after")
MANIFEST = "transaction.json"
CONFIRM = "BACKUP_STOPPED_POSTFIX_TRANSPORTS"
CONFLICTS = ("transport_maps", "sender_dependent_default_transport_maps",
             "sender_dependent_relayhost_maps")


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def valid_sha(value):
    return type(value) is str and M.HEX.fullmatch(value) is not None


def append(original, fragment):
    return original + (b"" if original.endswith(b"\n") else b"\n") + b"\n" + fragment


def proposal(main, master, rules, backend, ca):
    rules, sha = C.plan(rules)
    need(backend in M.MAP_SUFFIX and ca in C.CA_FILES and
         all(type(x) is bytes and b"\0" not in x and b"\r" not in x
             for x in (main, master)), "invalid_config_or_backend")
    for key in CONFLICTS:
        need(not re.search(rb"(?mi)^[ \t]*" + key.encode("ascii") +
                           rb"[ \t]*=", main), "existing_routing_map_assignment")
    _, fragment, _, services, auth = C.render(rules, sha, "/etc/postfix", backend, ca)
    for name in services:
        need(not re.search(rb"(?m)^[ \t]*" + name.encode("ascii") +
                           rb"[ \t]+", master), "existing_transport_service")
    route = "lmr365-" + sha + "-sender-transport"
    maps = [route] + sorted(auth.values())
    heading = ("# LinuxMailRelay365 transport set " + sha + "\n").encode("ascii")
    parameter = (C.PARAMETER + " = " + backend + ":/etc/postfix/" +
                 route + "\n").encode("ascii")
    after = (append(main, heading + parameter), append(master, heading + fragment))
    need(all(len(x) <= T.LIMIT for x in after), "proposed_config_oversized")
    return rules, sha, after, maps


def observe(config, rules, backend, ca, uid, guard):
    guard()
    need(not os.listxattr(config), "extended_directory_metadata_unsupported")
    identity = T.context(config, uid)
    pair = tuple(T.config_file(config, name, uid) for name in ("main.cf", "master.cf"))
    for _, meta in pair:
        T.valid_meta(meta, False)
    original = tuple(x[0] for x in pair)
    normalized, sha, after, maps = proposal(*original, rules, backend, ca)
    for name in maps:
        need(not T.exists(config, name) and
             not T.exists(config, name + M.MAP_SUFFIX[backend]),
             "managed_map_destination_exists")
    files = dict(zip(FILES, original + after))
    info = {"format": "LMR365-TRANSPORT-BACKUP-V1", "plan": sha,
            "rules": normalized, "backend": backend, "ca": ca,
            "identity": identity, "metadata": [x[1] for x in pair],
            "map_names": maps,
            "files": {key: M.digest(value) for key, value in files.items()}}
    guard()
    need(T.context(config, uid) == identity and
         tuple(T.config_file(config, name, uid) for name in ("main.cf", "master.cf")) == pair,
         "configuration_drift")
    for name in maps:
        need(not T.exists(config, name) and
             not T.exists(config, name + M.MAP_SUFFIX[backend]),
             "managed_map_destination_exists")
    return info, files


def validate(info, files):
    need(type(info) is dict and set(info) == {
        "format", "plan", "rules", "backend", "ca", "identity", "metadata",
        "map_names", "files"} and info["format"] == "LMR365-TRANSPORT-BACKUP-V1"
        and type(info["identity"]) is list and len(info["identity"]) == 2
        and all(type(x) is int and x >= 0 for x in info["identity"])
        and type(info["metadata"]) is list and len(info["metadata"]) == 2,
        "invalid_snapshot_manifest")
    for meta in info["metadata"]:
        T.valid_meta(meta, False)
    need(set(files) == set(FILES) and
         info["files"] == {key: M.digest(value) for key, value in files.items()},
         "snapshot_hash_mismatch")
    rules, sha, after, maps = proposal(files["main.before"], files["master.before"],
                                      info["rules"], info["backend"], info["ca"])
    need(rules == info["rules"] and sha == info["plan"] and maps == info["map_names"]
         and after == (files["main.after"], files["master.after"]),
         "snapshot_plan_mismatch")


def load(parent, revision, uid):
    need(valid_sha(revision), "invalid_revision")
    base = M.open_base(parent, uid, name=BASE)
    try:
        fd = os.open(revision, M.DIR_FLAGS, dir_fd=base)
        try:
            M.check_directory(fd, uid, True)
            need(set(os.listdir(fd)) == set(FILES) | {MANIFEST}, "incomplete_snapshot")
            raw = M.read_file(fd, MANIFEST, uid)
            record = M.decode(raw)
            need(type(record) is dict and set(record) == {"revision", "snapshot"} and
                 record["revision"] == revision and M.canonical(record) == raw,
                 "invalid_snapshot_record")
            files = {name: M.read_file(fd, name, uid, T.LIMIT) for name in FILES}
            validate(record["snapshot"], files)
            return record["snapshot"], files
        finally:
            os.close(fd)
    finally:
        os.close(base)


def backup(config, parent, reviewed, confirmation, uid, guard, fresh_review):
    need(confirmation == CONFIRM, "typed_backup_confirmation_required")
    guard()
    need(fresh_review() == reviewed, "review_changed")
    info, files = reviewed
    validate(info, files)
    need(T.context(config, uid) == info["identity"], "wrong_config_directory")
    revision = secrets.token_hex(32)
    base = M.open_base(parent, uid, create=True, name=BASE)
    try:
        os.mkdir(revision, 0o700, dir_fd=base)
        os.fsync(base)
        fd = os.open(revision, M.DIR_FLAGS, dir_fd=base)
        try:
            M.check_directory(fd, uid, True)
            for name in FILES:
                M.write_file(fd, name, files[name])
            M.write_file(fd, MANIFEST, M.canonical({"revision": revision, "snapshot": info}))
            os.fsync(fd)
            os.fsync(base)
        finally:
            os.close(fd)
    finally:
        os.close(base)
    need(load(parent, revision, uid) == reviewed, "snapshot_verification_failed")
    guard()
    need(fresh_review() == reviewed, "configuration_changed_after_backup")
    return revision


if __name__ == "__main__":
    raise SystemExit("Library only; activation is not exposed.")
