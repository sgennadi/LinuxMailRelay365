#!/usr/bin/env python3
"""Experimental two-file transaction core; CLI in manage-primary-mailbox-offline.py.

Mandatory caller guards must establish exclusive maintenance, stopped
single primary Postfix, empty queues, trusted installed OAuth runtime and
fresh no-mail SMTP AUTH. Only unlabelled files without extended metadata.
"""
import importlib.util
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, str(HERE / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


R = load("primary_route_preview", "preview-primary-mailbox-route.py")
T = load("primary_route_file_transaction", "conditional-postfix-transaction.py")
M = T.M
Refused = T.Refused
BASE = "linuxmailrelay365-primary-mailbox-recovery"
NAMES = ("main.cf", "master.cf")
FILES = ("main.before", "master.before", "main.after", "master.after")
MANIFEST = "transaction.json"
APPLY = "APPLY_STOPPED_PRIMARY_MAILBOX_ROUTE"
RESTORE = "RESTORE_STOPPED_PRIMARY_MAILBOX_ROUTE"


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def sha(value):
    return type(value) is str and R.SHA.fullmatch(value) is not None


def digest(value):
    return M.digest(M.canonical(value))


def snapshot(config, uid):
    result = tuple(T.config_file(config, name, uid) for name in NAMES)
    for _, meta in result:
        T.valid_meta(meta, False)
    return result


def exact_phase(info, files, phase):
    return ((files["main."+phase], info["main_meta"]),
            (files["master."+phase], info["master_meta"]))


def review(config, uid, mailbox, guard, runtime_guard, sampler=R.sample,
           identity_reader=R.identity_snapshot, native_compare=R.native_candidate_snapshots):
    """runtime_guard(mailbox) returns a stable trusted runtime/SMTP AUTH SHA.

    The experimental manage-primary-mailbox-offline.py CLI
    supplies the software-PEM or managed persistent TPM2 implementation of this callback.
    """
    R.parse(R.encode({"mailbox": mailbox, "nonce": "0"*64}))
    guard()
    context = T.context(config, uid)
    current = snapshot(config, uid)
    raw = tuple(item[0] for item in current)
    sampled = sampler()
    need(sampled[0] == R.E.digest(b"\0".join(raw)), "configuration_changed_before_review")
    classification = R.classify(sampled)
    need(classification["scope"] == "primary_only" and
         classification["route"] == "migration_candidate" and
         sampled[1]["default_transport"] in ("smtp", "smtp:") and
         sampled[1]["relay_transport"] in ("relay", "relay:", "smtp", "smtp:"),
         "primary_route_not_simple_migration")
    need(not any(line.split()[:1] == ["m365xoauth2"] for line in sampled[2].splitlines()),
         "existing_oauth_pipe_requires_manual_review")
    identity = identity_reader(mailbox)
    need(type(identity) is tuple and len(identity) == 3 and
         identity[0] == "mailbox_matches" and all(sha(v) for v in identity[1:]),
         "installed_mailbox_identity_not_verified")
    runtime = runtime_guard(mailbox)
    need(sha(runtime), "runtime_auth_evidence_missing")
    candidate, changes = R.candidate_configs(raw, sampled)
    need(candidate[0] != raw[0] and candidate[1] != raw[1] and
         "master.cf:m365xoauth2" in changes, "expected_two_file_candidate_missing")
    before, after = native_compare(raw, candidate)
    R.compare_native_candidate(before, after)
    files = dict(zip(FILES, raw + candidate))
    info = {"version": 1, "mailbox": mailbox, "config_identity": context,
            "main_meta": current[0][1], "master_meta": current[1][1],
            "identity_sha256": identity[1], "certificate_sha256": identity[2],
            "runtime_sha256": runtime, "native_before_sha256": digest(before),
            "native_after_sha256": digest(after),
            "files": {k: M.digest(v) for k,v in files.items()}}
    guard()
    need(T.context(config, uid) == context and snapshot(config, uid) == current and
         sampler() == sampled and identity_reader(mailbox) == identity and
         runtime_guard(mailbox) == runtime and snapshot(config, uid) == current,
         "review_context_changed")
    return digest(info), info, files


def validate_backup(revision, info, files):
    keys = {"version","mailbox","config_identity","main_meta","master_meta",
            "identity_sha256","certificate_sha256","runtime_sha256",
            "native_before_sha256","native_after_sha256","files"}
    need(sha(revision) and type(info) is dict and set(info) == keys and
         type(info["version"]) is int and info["version"] == 1 and
         digest(info) == revision, "invalid_backup_manifest")
    R.parse(R.encode({"mailbox": info["mailbox"], "nonce": "0"*64}))
    need(type(info["config_identity"]) is list and len(info["config_identity"]) == 2 and
         all(type(x) is int and x >= 0 for x in info["config_identity"]),
         "invalid_backup_directory_identity")
    for key in ("identity_sha256","certificate_sha256","runtime_sha256",
                "native_before_sha256","native_after_sha256"):
        need(sha(info[key]), "invalid_backup_evidence")
    T.valid_meta(info["main_meta"], False)
    T.valid_meta(info["master_meta"], False)
    need(set(files) == set(FILES) and all(type(v) is bytes and 0 < len(v) <= T.LIMIT
         for v in files.values()) and info["files"] == {k:M.digest(v) for k,v in files.items()},
         "backup_file_integrity_failed")
    need(files["main.before"] != files["main.after"] and
         files["master.after"] == files["master.before"] +
         (b"" if files["master.before"].endswith(b"\n") else b"\n") + R.PIPE,
         "invalid_two_file_backup_transition")


def save_backup(parent, revision, info, files, uid):
    validate_backup(revision, info, files)
    base = M.open_base(parent, uid, create=True, name=BASE)
    try:
        os.mkdir(revision, 0o700, dir_fd=base)
        os.fsync(base)
        folder = os.open(revision, M.DIR_FLAGS, dir_fd=base)
        try:
            M.check_directory(folder, uid, True)
            for name in FILES:
                M.write_file(folder, name, files[name])
            M.write_file(folder, MANIFEST, M.canonical(info))
            os.fsync(folder)
            os.fsync(base)
        finally:
            os.close(folder)
    finally:
        os.close(base)


def load_backup(parent, revision, uid):
    need(sha(revision), "invalid_recovery_sha")
    base = M.open_base(parent, uid, name=BASE)
    try:
        folder = os.open(revision, M.DIR_FLAGS, dir_fd=base)
        try:
            M.check_directory(folder, uid, True)
            need(set(os.listdir(folder)) == set(FILES) | {MANIFEST},
                 "incomplete_or_foreign_backup")
            raw = M.read_file(folder, MANIFEST, uid)
            info = M.decode(raw)
            need(M.canonical(info) == raw, "noncanonical_backup_manifest")
            files = {name: M.read_file(folder, name, uid, T.LIMIT) for name in FILES}
            validate_backup(revision, info, files)
            return info, files
        finally:
            os.close(folder)
    finally:
        os.close(base)


def phase(config, uid, info, files):
    need(T.context(config, uid) == info["config_identity"], "configuration_directory_changed")
    current = snapshot(config, uid)
    old, new = exact_phase(info, files, "before"), exact_phase(info, files, "after")
    if current == old:
        return "before"
    if current == new:
        return "after"
    if current == (old[0], new[1]):
        return "pipe_only"
    raise Refused("foreign_or_impossible_configuration_drift")


def verify(config, uid, info, files, expected, guard, read_native):
    guard()
    need(phase(config, uid, info, files) == expected, "unexpected_configuration_phase")
    need(digest(read_native()) == info["native_"+expected+"_sha256"],
         "native_effective_configuration_mismatch")
    guard()
    need(phase(config, uid, info, files) == expected, "configuration_changed_during_native_readback")


def replace(config, uid, info, files, before, after, name, target, guard):
    key = ("main", "master")[NAMES.index(name)]
    def before_replace(_prepared):
        guard()
        need(phase(config, uid, info, files) == before, "drift_before_atomic_replace")
    before_replace(None)
    T.atomic_write(config, name, files[key+"."+target], info[key+"_meta"],
                   uid, True, before_replace=before_replace)
    guard()
    need(phase(config, uid, info, files) == after, "post_replace_integrity_failed")


def restore(config, parent, revision, uid, confirmation, guard, read_native):
    need(confirmation == RESTORE, "typed_restore_confirmation_required")
    info, files = load_backup(parent, revision, uid)
    guard()
    current = phase(config, uid, info, files)
    if current == "after":
        replace(config, uid, info, files, "after", "pipe_only", "main.cf", "before", guard)
        current = "pipe_only"
    if current == "pipe_only":
        replace(config, uid, info, files, "pipe_only", "before", "master.cf", "before", guard)
    verify(config, uid, info, files, "before", guard, read_native)
    return revision


def apply(config, parent, reviewed, uid, confirmation, guard, fresh, read_native,
          runtime_guard):
    need(confirmation == APPLY and sha(reviewed), "typed_reviewed_apply_required")
    revision, info, files = fresh()
    need(revision == reviewed, "reviewed_plan_changed")
    save_backup(parent, revision, info, files, uid)
    need(load_backup(parent, revision, uid) == (info, files), "backup_verification_failed")
    need(fresh() == (revision, info, files), "drift_during_backup")
    verify(config, uid, info, files, "before", guard, read_native)
    need(runtime_guard(info["mailbox"]) == info["runtime_sha256"], "runtime_changed_before_apply")
    try:
        replace(config, uid, info, files, "before", "pipe_only", "master.cf", "after", guard)
        need(runtime_guard(info["mailbox"]) == info["runtime_sha256"],
             "runtime_changed_before_route_switch")
        replace(config, uid, info, files, "pipe_only", "after", "main.cf", "after", guard)
        verify(config, uid, info, files, "after", guard, read_native)
        need(runtime_guard(info["mailbox"]) == info["runtime_sha256"], "runtime_changed_after_apply")
        guard()
        need(phase(config, uid, info, files) == "after", "post_apply_integrity_failed")
    except Exception:
        try:
            restore(config, parent, revision, uid, RESTORE, guard, read_native)
        except Exception as error:
            raise T.RollbackRequired("manual_recovery_required; backup="+revision) from error
        raise
    return revision


if __name__ == "__main__":
    raise SystemExit("Transaction core only; use the explicitly approved offline manager.")
