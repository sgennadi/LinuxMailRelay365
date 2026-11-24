#!/usr/bin/env python3
"""Multi-transport configuration review and private recovery snapshot.

Library only. Snapshot and journal storage for guarded offline transactions.
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
ACTIVATION = "activation"
CONFIRM = "BACKUP_STOPPED_POSTFIX_TRANSPORTS"
LEGACY_FORMAT = "LMR365-TRANSPORT-BACKUP-V1"
LABELED_FORMAT = "LMR365-TRANSPORT-BACKUP-V2"
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


def labeled(info):
    return info is not None and info.get("format") == LABELED_FORMAT


def label_context(value):
    raw = T.label_bytes(value).rstrip(b"\0")
    kind = raw.decode("ascii").split(":")[2]
    need(kind not in ("default_t", "unlabeled_t", "etc_t", "file_t"),
         "generic_or_unsafe_postfix_policy_type")
    return raw


def directory_metadata(config, info=None):
    # A legacy snapshot cannot be used on a labeled directory, and a
    # labeled snapshot must retain the exact originally observed label.
    if not labeled(info):
        need(not os.listxattr(config), "extended_directory_metadata_unsupported")
    else:
        need(T.file_label(config) == info["directory_selinux"],
             "transport_directory_label_changed")


def observe(config, rules, backend, ca, uid, guard, policy_labels=None):
    """Optional internal V2 metadata path; host CLI still refuses active SELinux.

    policy_labels must originate from a trusted exact-path policy review.
    The mandatory caller guard must recheck policy throughout publication.
    This is not a substitute for real enforcing-domain acceptance.
    """
    guard()
    if policy_labels is None:
        directory_metadata(config)
    identity = T.context(config, uid)
    pair = tuple(T.config_file(config, name, uid) for name in ("main.cf", "master.cf"))
    for _, meta in pair:
        T.valid_meta(meta, policy_labels is not None)
    original = tuple(x[0] for x in pair)
    normalized, sha, after, maps = proposal(*original, rules, backend, ca)
    label_fields = {}
    if policy_labels is not None:
        names = [name + M.MAP_SUFFIX[backend] for name in maps]
        need(type(policy_labels) is dict and set(policy_labels) ==
             {".", "main.cf", "master.cf"} | set(names),
             "invalid_transport_label_policy")
        for value in policy_labels.values():
            label_context(value)
        directory_label = T.file_label(config)
        need(directory_label is not None and
             label_context(directory_label) == label_context(policy_labels["."]),
             "transport_directory_label_mismatch")
        for filename, (_, meta) in zip(("main.cf", "master.cf"), pair):
            need(label_context(meta["selinux"]) == label_context(policy_labels[filename]),
                 "transport_config_label_mismatch")
        label_fields = {"directory_selinux": directory_label,
                        "map_selinux": {name: policy_labels[name] for name in names}}
    for name in maps:
        need(not T.exists(config, name) and
             not T.exists(config, name + M.MAP_SUFFIX[backend]),
             "managed_map_destination_exists")
    files = dict(zip(FILES, original + after))
    info = {"format": LABELED_FORMAT if label_fields else LEGACY_FORMAT, "plan": sha,
            "rules": normalized, "backend": backend, "ca": ca,
            "identity": identity, "metadata": [x[1] for x in pair],
            "map_names": maps,
            "files": {key: M.digest(value) for key, value in files.items()}}
    info.update(label_fields)
    validate(info, files)
    guard()
    directory_metadata(config, info)
    need(T.context(config, uid) == identity and
         tuple(T.config_file(config, name, uid) for name in ("main.cf", "master.cf")) == pair,
         "configuration_drift")
    for name in maps:
        need(not T.exists(config, name) and
             not T.exists(config, name + M.MAP_SUFFIX[backend]),
             "managed_map_destination_exists")
    return info, files


def validate(info, files):
    common = {"format", "plan", "rules", "backend", "ca", "identity",
              "metadata", "map_names", "files"}
    need(type(info) is dict and info.get("format") in (LEGACY_FORMAT, LABELED_FORMAT) and
         set(info) == (common | {"directory_selinux", "map_selinux"} if labeled(info) else common)
        and type(info["identity"]) is list and len(info["identity"]) == 2
        and all(type(x) is int and x >= 0 for x in info["identity"])
        and type(info["metadata"]) is list and len(info["metadata"]) == 2,
        "invalid_snapshot_manifest")
    for meta in info["metadata"]:
        T.valid_meta(meta, labeled(info))
        if labeled(info):
            label_context(meta["selinux"])
    need(set(files) == set(FILES) and
         info["files"] == {key: M.digest(value) for key, value in files.items()},
         "snapshot_hash_mismatch")
    rules, sha, after, maps = proposal(files["main.before"], files["master.before"],
                                      info["rules"], info["backend"], info["ca"])
    need(rules == info["rules"] and sha == info["plan"] and maps == info["map_names"]
         and after == (files["main.after"], files["master.after"]),
         "snapshot_plan_mismatch")
    if labeled(info):
        label_context(info["directory_selinux"])
        need(type(info["map_selinux"]) is dict and
             set(info["map_selinux"]) == {name + M.MAP_SUFFIX[info["backend"]] for name in maps},
             "invalid_snapshot_map_labels")
        for value in info["map_selinux"].values():
            label_context(value)


def load(parent, revision, uid, allow_activation=False):
    need(valid_sha(revision), "invalid_revision")
    base = M.open_base(parent, uid, name=BASE)
    try:
        fd = os.open(revision, M.DIR_FLAGS, dir_fd=base)
        try:
            M.check_directory(fd, uid, True)
            names = set(os.listdir(fd))
            required = set(FILES) | {MANIFEST}
            need(names == required or
                 (allow_activation and names == required | {ACTIVATION}),
                 "incomplete_snapshot")
            if ACTIVATION in names:
                child = os.open(ACTIVATION, M.DIR_FLAGS, dir_fd=fd)
                try:
                    M.check_directory(child, uid, True)
                finally:
                    os.close(child)
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
    directory_metadata(config, info)
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
