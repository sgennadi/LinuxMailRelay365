#!/usr/bin/env python3
"""Guarded multi-map transaction library; no production CLI or GUI entry point.

The caller must hold exclusive offline maintenance, prove the native
effective policy and credential provenance, and supply mandatory verification.
Only new sender-transport sets are supported; no existing map is replaced.
"""
import importlib.util
import os
import pathlib
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "transport_recovery", str(pathlib.Path(__file__).with_name(
        "conditional-transport-recovery.py")))
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
C, T, M = R.C, R.T, R.M
Refused = M.Refused
APPLY = "APPLY_NEW_STOPPED_POSTFIX_TRANSPORTS"
RESTORE = "RESTORE_STOPPED_POSTFIX_TRANSPORTS"
JOURNAL = "maps.json"
ROTATION_CURRENT = "rotation-current.json"
ROTATION_PENDING = "rotation-pending.json"
EDIT_BASE = "linuxmailrelay365-transport-edit"
EDIT_PENDING = "pending.json"
CONFIGS = ("main", "master")


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def pair(config, uid):
    need(not os.listxattr(config), "extended_directory_metadata_unsupported")
    result = tuple(T.config_file(config, name + ".cf", uid) for name in CONFIGS)
    for _, meta in result:
        T.valid_meta(meta, False)
    return result


def expected_pair(info, files, phase):
    return tuple((files[name + phase], meta)
                 for name, meta in zip(CONFIGS, info["metadata"]))


def assert_pair(config, info, files, phase, uid):
    need(T.context(config, uid) == info["identity"] and
         pair(config, uid) == expected_pair(info, files, phase),
         "transport_configuration_changed")


def map_names(info):
    return [name + M.MAP_SUFFIX[info["backend"]] for name in info["map_names"]]


def source_name(info, name):
    return name[:-len(M.MAP_SUFFIX[info["backend"]])]


def map_meta(journal):
    return {"mode": 0o640, "gid": journal["gid"]}


def receipt_name(name):
    return name + ".published.json"


def activation_fd(parent, revision, uid, create=False):
    need(R.valid_sha(revision), "invalid_revision")
    base = M.open_base(parent, uid, name=R.BASE)
    try:
        record = os.open(revision, M.DIR_FLAGS, dir_fd=base)
        try:
            M.check_directory(record, uid, True)
            if create:
                os.mkdir(R.ACTIVATION, 0o700, dir_fd=record)
                os.fsync(record)
            fd = os.open(R.ACTIVATION, M.DIR_FLAGS, dir_fd=record)
            try:
                M.check_directory(fd, uid, True)
                return fd
            except BaseException:
                os.close(fd)
                raise
        finally:
            os.close(record)
    finally:
        os.close(base)


def native_database_set(info, databases):
    # Compiler keys omit suffixes. Only the sender routing map is renamed.
    mapping = dict(zip([C.ROUTE_MAP] + info["map_names"][1:], map_names(info)))
    need(type(databases) is dict and set(databases) == set(mapping) and
         all(type(v) is bytes and 0 < len(v) <= M.MAX_DB_BYTES
             for v in databases.values()), "invalid_verified_database_set")
    return {mapping[key]: value for key, value in databases.items()}


def journal_for(revision, info, files, maps, gid):
    need(type(gid) is int and gid >= 0, "invalid_map_group")
    return {"format": "LMR365-TRANSPORT-PUBLICATION-V1",
            "revision": revision,
            "snapshot_sha256": M.digest(M.canonical(info)),
            "gid": gid,
            "maps": {name: M.digest(data) for name, data in maps.items()}}


def read_receipt(fd, revision, name, uid):
    filename = receipt_name(name)
    if not T.exists(fd, filename):
        return None
    raw = M.read_file(fd, filename, uid)
    value = M.decode(raw)
    need(type(value) is dict and set(value) == {"revision", "name", "identity"} and
         value["revision"] == revision and value["name"] == name and
         type(value["identity"]) is list and len(value["identity"]) == 5 and
         all(type(x) is int and x >= 0 for x in value["identity"]) and
         M.canonical(value) == raw, "invalid_map_publication_receipt")
    return value["identity"]


def auth_names(info):
    return {name + M.MAP_SUFFIX[info["backend"]] for name in info["map_names"][1:]}


def record_digest(journal, receipts):
    # Private metadata only, never a public plan/approval ID.
    return M.digest(M.canonical({"journal": journal, "receipts": receipts}))


def valid_identity(value):
    return (type(value) is list and len(value) == 5 and
            all(type(x) is int and x >= 0 for x in value))


def rotation_overlay(fd, info, journal, receipts, uid):
    if not T.exists(fd, ROTATION_CURRENT):
        return journal, receipts
    raw = M.read_file(fd, ROTATION_CURRENT, uid)
    overlay = M.decode(raw)
    need(type(overlay) is dict and set(overlay) ==
         {"format", "revision", "base", "generation", "maps", "receipts"} and
         overlay["format"] == "LMR365-CREDENTIAL-CURRENT-V1" and
         overlay["revision"] == journal["revision"] and
         overlay["base"] == record_digest(journal, receipts) and
         R.valid_sha(overlay["generation"]) and M.canonical(overlay) == raw,
         "invalid_rotation_overlay")
    maps, current = overlay["maps"], overlay["receipts"]
    need(type(maps) is dict and type(current) is dict and
         set(maps) == set(journal["maps"]) == set(current) == set(receipts) and
         all(R.valid_sha(v) for v in maps.values()) and
         all(valid_identity(v) for v in current.values()) and
         all(valid_identity(v) for v in receipts.values()), "invalid_rotation_map_set")
    for name in set(maps) - auth_names(info):
        need(maps[name] == journal["maps"][name] and current[name] == receipts[name],
             "rotation_changed_noncredential_map")
    return dict(journal, maps=maps), current


def assert_no_edit_pending(parent, uid):
    # Fail closed even on an unexpected scratch file or malformed marker.
    # Only the explicit edit recovery library may bypass this gate.
    try:
        fd = M.open_base(parent, uid, name=EDIT_BASE)
    except FileNotFoundError:
        return
    try:
        need(not os.listdir(fd), "transport_edit_recovery_required")
    finally:
        os.close(fd)


def load(parent, revision, uid, allow_pending=False, allow_edit_pending=False):
    if not allow_edit_pending:
        assert_no_edit_pending(parent, uid)
    info, files = R.load(parent, revision, uid, allow_activation=True)
    fd = activation_fd(parent, revision, uid)
    try:
        raw = M.read_file(fd, JOURNAL, uid)
        journal = M.decode(raw)
        names = map_names(info)
        need(type(journal) is dict and set(journal) ==
             {"format", "revision", "snapshot_sha256", "gid", "maps"} and
             journal["format"] == "LMR365-TRANSPORT-PUBLICATION-V1" and
             journal["revision"] == revision and
             journal["snapshot_sha256"] == M.digest(M.canonical(info)) and
             type(journal["gid"]) is int and journal["gid"] >= 0 and
             type(journal["maps"]) is dict and set(journal["maps"]) == set(names) and
             all(R.valid_sha(v) for v in journal["maps"].values()) and
             M.canonical(journal) == raw, "invalid_transport_journal")
        entries = set(os.listdir(fd))
        allowed = {JOURNAL, ROTATION_CURRENT, ROTATION_PENDING} | {
            receipt_name(name) for name in names}
        need(JOURNAL in entries and entries <= allowed, "unexpected_journal_files")
        need(allow_pending or ROTATION_PENDING not in entries,
             "credential_rotation_recovery_required")
        receipts = {name: read_receipt(fd, revision, name, uid) for name in names}
        journal, receipts = rotation_overlay(fd, info, journal, receipts, uid)
        need(set(os.listdir(fd)) == entries, "journal_changed")
        if not allow_edit_pending:
            assert_no_edit_pending(parent, uid)
        return info, files, journal, receipts
    finally:
        os.close(fd)


def checked_map(config, name, journal, receipt, uid):
    need(receipt is not None, "map_publication_unproven")
    before = T.file_identity(os.stat(name, dir_fd=config, follow_symlinks=False))
    data, meta = T.config_file(config, name, uid, M.MAX_DB_BYTES)
    need(before == receipt and meta == map_meta(journal) and
         M.digest(data) == journal["maps"][name] and
         T.file_identity(os.stat(name, dir_fd=config, follow_symlinks=False)) == receipt,
         "map_identity_or_content_changed")


def publish(config, parent, revision, name, data, journal, uid):
    need(M.digest(data) == journal["maps"][name], "verified_database_changed")
    prepared = []
    T.atomic_write(config, name, data, map_meta(journal), uid, False, prepared.append)
    identity = T.file_identity(os.stat(name, dir_fd=config, follow_symlinks=False))
    need(prepared == [identity[:4]], "published_map_replaced")
    checked_map(config, name, journal, identity, uid)
    fd = activation_fd(parent, revision, uid)
    try:
        M.write_file(fd, receipt_name(name), M.canonical({
            "revision": revision, "name": name, "identity": identity}))
        os.fsync(fd)
        need(read_receipt(fd, revision, name, uid) == identity,
             "publication_receipt_changed")
    finally:
        os.close(fd)


def check_sources(config, info):
    for name in map_names(info):
        need(not T.exists(config, source_name(info, name)),
             "unexpected_managed_source_file")


def restorable(config, info, files, journal, receipts, uid):
    need(T.context(config, uid) == info["identity"], "wrong_config_directory")
    current = pair(config, uid)
    for index, name in enumerate(CONFIGS):
        data, meta = current[index]
        need(meta == info["metadata"][index] and
             data in (files[name + ".before"], files[name + ".after"]),
             "unrelated_configuration_drift")
    check_sources(config, info)
    for name in map_names(info):
        if T.exists(config, name):
            checked_map(config, name, journal, receipts[name], uid)
    return current


def restore(config, parent, revision, confirmation, uid, guard, verify):
    need(confirmation == RESTORE, "typed_restore_confirmation_required")
    guard()
    record = load(parent, revision, uid)
    info, files, journal, receipts = record
    current = restorable(config, *record, uid)
    guard()
    need(load(parent, revision, uid) == record and
         restorable(config, *record, uid) == current, "recovery_drift")
    # Disconnect routes first; do not remove a service still referenced by
    # the main configuration. Each write is atomic, not a two-file atomic swap.
    state = list(current)
    for index, name in enumerate(CONFIGS):
        guard()
        need(pair(config, uid) == tuple(state), "configuration_drift_before_restore")
        data, meta = state[index]
        original = files[name + ".before"]
        if data != original:
            T.atomic_write(config, name + ".cf", original, meta, uid, True)
        state[index] = (original, meta)
    assert_pair(config, info, files, ".before", uid)
    verify(False, info)
    assert_pair(config, info, files, ".before", uid)
    for name in map_names(info):
        guard()
        assert_pair(config, info, files, ".before", uid)
        need(load(parent, revision, uid) == record, "recovery_journal_changed")
        check_sources(config, info)
        if T.exists(config, name):
            checked_map(config, name, journal, receipts[name], uid)
            os.unlink(name, dir_fd=config)
            os.fsync(config)
    guard()
    assert_pair(config, info, files, ".before", uid)
    return revision


class ApplyFailed(Refused):
    def __init__(self, revision, rolled_back):
        self.revision = revision
        self.rolled_back = rolled_back
        super().__init__(("rolled_back" if rolled_back else
                          "manual_recovery_required") + "; revision=" + revision)


def apply(config, parent, reviewed, databases, gid, confirmation, uid,
          guard, verify, fresh_review):
    """All DB bytes must come from the verified compiler consumer. The
    caller must recheck native runtime constraints in guard/fresh_review.
    No DB content, private journal hash or credential is a public receipt.
    """
    need(confirmation == APPLY, "typed_apply_confirmation_required")
    guard()
    assert_no_edit_pending(parent, uid)
    need(fresh_review() == reviewed, "review_changed")
    info, files = reviewed
    R.validate(info, files)
    maps = native_database_set(info, databases)
    assert_pair(config, info, files, ".before", uid)
    revision = R.backup(config, parent, reviewed, R.CONFIRM, uid, guard, fresh_review)
    journal = journal_for(revision, info, files, maps, gid)
    # A durable complete snapshot + journal must exist before any live write.
    fd = activation_fd(parent, revision, uid, create=True)
    try:
        M.write_file(fd, JOURNAL, M.canonical(journal))
        os.fsync(fd)
    finally:
        os.close(fd)
    need(load(parent, revision, uid) ==
         (info, files, journal, dict.fromkeys(maps)), "journal_verification_failed")
    try:
        guard()
        need(fresh_review() == reviewed, "review_changed_after_journal")
        for name, data in sorted(maps.items()):
            guard()
            assert_pair(config, info, files, ".before", uid)
            check_sources(config, info)
            publish(config, parent, revision, name, data, journal, uid)
        record = load(parent, revision, uid)
        need(record[:3] == (info, files, journal), "journal_changed")
        receipts = record[3]
        for name in maps:
            checked_map(config, name, journal, receipts[name], uid)
        guard()
        assert_pair(config, info, files, ".before", uid)
        T.atomic_write(config, "master.cf", files["master.after"],
                       info["metadata"][1], uid, True)
        guard()
        need(pair(config, uid) == (expected_pair(info, files, ".before")[0],
                                  expected_pair(info, files, ".after")[1]),
             "configuration_changed_before_main_publication")
        check_sources(config, info)
        for name in maps:
            checked_map(config, name, journal, receipts[name], uid)
        T.atomic_write(config, "main.cf", files["main.after"],
                       info["metadata"][0], uid, True)
        assert_pair(config, info, files, ".after", uid)
        verify(True, info)
        guard()
        assert_pair(config, info, files, ".after", uid)
        need(load(parent, revision, uid) == record, "journal_changed")
        check_sources(config, info)
        for name in maps:
            checked_map(config, name, journal, receipts[name], uid)
    except Exception as error:
        try:
            restore(config, parent, revision, RESTORE, uid, guard, verify)
        except Exception as rollback:
            raise ApplyFailed(revision, False) from rollback
        raise ApplyFailed(revision, True) from error
    return revision


if __name__ == "__main__":
    raise SystemExit("Transaction library only; no production activation CLI.")
