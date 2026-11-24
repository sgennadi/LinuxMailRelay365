#!/usr/bin/env python3
"""Credential rotation core for one owned, stopped Postfix transport.

No CLI entry point. Caller supplies freshly verified installed record, an
exclusive stopped-host guard, a native-compiled single credential DB and
mandatory native verification. The previous DB lives only in process memory
for automatic rollback. Abrupt termination leaves a private pending marker
and blocks normal management until explicit recovery is implemented.
"""
import importlib.util
import os
import pathlib
import secrets
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "rotation_transaction", str(pathlib.Path(__file__).with_name(
        "conditional-transport-transaction.py")))
X = importlib.util.module_from_spec(spec)
spec.loader.exec_module(X)
T, M, C, R = X.T, X.M, X.C, X.R
Refused = X.Refused
CONFIRM = "ROTATE_ONE_STOPPED_POSTFIX_CREDENTIAL"
FORMAT = "LMR365-CREDENTIAL-ROTATION-PENDING-V1"


class RotationFailed(Refused):
    def __init__(self, revision, rolled_back):
        self.revision = revision
        self.rolled_back = rolled_back
        super().__init__(("credential_rotation_rolled_back" if rolled_back else
                          "credential_rotation_recovery_required") + "; revision=" + revision)


def target_name(info, index):
    X.need(type(index) is int and 1 <= index <= len(info["rules"]) and
           info["rules"][index - 1]["auth"] == "password", "password_transport_required")
    name = C.profile_name(info["plan"], index) + "-sasl" + M.MAP_SUFFIX[info["backend"]]
    X.need(name in X.auth_names(info), "unknown_credential_map")
    return name


def assert_installed(config, record, uid, skip=None):
    info, files, journal, receipts = record
    X.assert_pair(config, info, files, ".after", uid)
    X.check_sources(config, info)
    X.need(all(X.valid_identity(v) for v in receipts.values()),
           "publication_identity_unverified")
    for name in X.map_names(info):
        if name != skip:
            X.checked_map(config, name, journal, receipts[name], uid)


def private_write(fd, name, data, uid):
    # Only the rotation overlay and pending marker are replaced, never the
    # immutable original publication journal or its receipts.
    T.atomic_write(fd, name, M.canonical(data), {"mode": 0o600, "gid": os.getegid()},
                   uid, True)
    X.need(M.read_file(fd, name, uid) == M.canonical(data), "rotation_metadata_not_durable")


def base_digest(fd, info, revision, uid):
    raw = M.read_file(fd, X.JOURNAL, uid)
    journal = M.decode(raw)
    receipts = {name: X.read_receipt(fd, revision, name, uid) for name in X.map_names(info)}
    return X.record_digest(journal, receipts)


def commit_overlay(fd, record, name, digest, identity, uid, generation):
    info, _, journal, receipts = record
    X.need(X.valid_identity(identity) and R.valid_sha(digest), "invalid_rotation_identity")
    overlay = {"format": "LMR365-CREDENTIAL-CURRENT-V1", "revision": journal["revision"],
               "base": base_digest(fd, info, journal["revision"], uid),
               "generation": generation, "maps": dict(journal["maps"], **{name: digest}),
               "receipts": dict(receipts, **{name: identity})}
    private_write(fd, X.ROTATION_CURRENT, overlay, uid)
    return (info, record[1], dict(journal, maps=overlay["maps"]), overlay["receipts"])


def map_identity(config, name, uid, meta, digest, prepared=None, exact=None):
    before = T.file_identity(os.stat(name, dir_fd=config, follow_symlinks=False))
    data, actual = T.config_file(config, name, uid, M.MAX_DB_BYTES)
    X.need(actual == meta and M.digest(data) == digest and
           T.file_identity(os.stat(name, dir_fd=config, follow_symlinks=False)) == before and
           (prepared is None or before[:4] == prepared) and
           (exact is None or before == exact), "rotation_map_identity_or_content_changed")
    return before


def rotate(config, parent, revision, index, reviewed, database, gid, confirmation,
           uid, guard, verify, fresh_review):
    """Rotate one existing SASL map without rewriting either config file.

    Candidate database must be native-verified for this exact target.
    verify(active, info, name, data) checks the new or restored old map
    under the real Postfix account, and must not print credentials.
    """
    X.need(confirmation == CONFIRM, "typed_rotation_confirmation_required")
    X.need(type(database) is bytes and 0 < len(database) <= M.MAX_DB_BYTES,
           "invalid_verified_credential_database")
    guard()
    X.need(fresh_review() == reviewed and X.load(parent, revision, uid) == reviewed,
           "installed_review_changed")
    info, files, journal, receipts = reviewed
    name = target_name(info, index)
    X.need(journal["gid"] == gid, "postfix_group_changed")
    assert_installed(config, reviewed, uid)
    old, meta = T.config_file(config, name, uid, M.MAX_DB_BYTES)
    old_hash, new_hash = M.digest(old), M.digest(database)
    X.need(old_hash == journal["maps"][name] and meta == X.map_meta(journal),
           "old_credential_database_changed")
    X.need(new_hash != old_hash, "credential_database_unchanged")
    fd = X.activation_fd(parent, revision, uid)
    generation = secrets.token_hex(32)
    marker = {"format": FORMAT, "revision": revision, "generation": generation,
              "name": name, "old_hash": old_hash, "old_identity": receipts[name],
              "new_hash": new_hash, "before": X.record_digest(journal, receipts),
              "prepared": None, "phase": "replace"}
    try:
        # Durable exclusive marker before any live replacement.
        M.write_file(fd, X.ROTATION_PENDING, M.canonical(marker))
        os.fsync(fd)
        X.need(M.read_file(fd, X.ROTATION_PENDING, uid) == M.canonical(marker),
               "rotation_marker_not_durable")
        prepared = []
        overlay_attempted = False

        def before_replace(identity):
            guard()
            X.need(X.load(parent, revision, uid, allow_pending=True) == reviewed,
                   "rotation_review_changed")
            assert_installed(config, reviewed, uid)
            marker["prepared"] = identity
            private_write(fd, X.ROTATION_PENDING, marker, uid)
            prepared[:] = [identity]

        def finish(expected):
            guard()
            assert_installed(config, expected, uid)
            X.need(X.load(parent, revision, uid, allow_pending=True) == expected and
                   M.read_file(fd, X.ROTATION_PENDING, uid) == M.canonical(marker),
                   "rotation_record_changed")
            os.unlink(X.ROTATION_PENDING, dir_fd=fd)
            os.fsync(fd)
            X.need(X.load(parent, revision, uid) == expected, "rotation_commit_unverified")

        try:
            guard()
            assert_installed(config, reviewed, uid)
            T.atomic_write(config, name, database, meta, uid, True,
                           before_replace=before_replace)
            X.need(len(prepared) == 1, "replacement_identity_missing")
            identity = map_identity(config, name, uid, meta, new_hash, prepared=prepared[0])
            assert_installed(config, reviewed, uid, skip=name)
            verify(True, info, name, database)
            guard()
            map_identity(config, name, uid, meta, new_hash, exact=identity)
            assert_installed(config, reviewed, uid, skip=name)
            X.need(X.load(parent, revision, uid, allow_pending=True) == reviewed and
                   M.read_file(fd, X.ROTATION_PENDING, uid) == M.canonical(marker),
                   "rotation_record_changed")
            overlay_attempted = True
            result = commit_overlay(fd, reviewed, name, new_hash, identity, uid, generation)
            finish(result)
            return generation
        except Exception as error:
            try:
                # Once overlay publication was attempted, never guess which
                # record is durable. Require explicit recovery.
                X.need(not overlay_attempted, "rotation_commit_outcome_uncertain")
                guard()
                X.need(X.load(parent, revision, uid, allow_pending=True) == reviewed and
                       M.read_file(fd, X.ROTATION_PENDING, uid) == M.canonical(marker),
                       "rotation_record_changed")
                assert_installed(config, reviewed, uid, skip=name)
                actual = T.file_identity(os.stat(name, dir_fd=config, follow_symlinks=False))
                if actual == receipts[name]:
                    map_identity(config, name, uid, meta, old_hash, exact=actual)
                    verify(False, info, name, old)
                    finish(reviewed)
                else:
                    X.need(len(prepared) == 1, "replacement_identity_missing")
                    map_identity(config, name, uid, meta, new_hash, prepared=prepared[0])
                    rollback_prepared = []

                    def before_rollback(identity):
                        guard()
                        assert_installed(config, reviewed, uid, skip=name)
                        map_identity(config, name, uid, meta, new_hash, exact=actual)
                        marker["phase"] = "rollback"
                        marker["prepared"] = identity
                        private_write(fd, X.ROTATION_PENDING, marker, uid)
                        rollback_prepared[:] = [identity]

                    T.atomic_write(config, name, old, meta, uid, True,
                                   before_replace=before_rollback)
                    X.need(len(rollback_prepared) == 1, "rollback_identity_missing")
                    restored = map_identity(config, name, uid, meta, old_hash,
                                            prepared=rollback_prepared[0])
                    verify(False, info, name, old)
                    guard()
                    map_identity(config, name, uid, meta, old_hash, exact=restored)
                    result = commit_overlay(fd, reviewed, name, old_hash, restored, uid, generation)
                    finish(result)
            except Exception as rollback:
                raise RotationFailed(revision, False) from rollback
            raise RotationFailed(revision, True) from error
    finally:
        os.close(fd)


if __name__ == "__main__":
    raise SystemExit("Credential rotation library only; production entry point is not exposed.")
