#!/usr/bin/env python3
"""Credential rotation core for one owned, stopped Postfix transport.

No CLI entry point. Caller supplies freshly verified installed record, an
exclusive stopped-host guard, a native-compiled single credential DB and
mandatory native verification. The previous DB lives only in process memory
for automatic rollback. Abrupt termination leaves a private pending marker
and blocks normal management until explicit, verified recovery.
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
LEGACY_FORMAT = "LMR365-CREDENTIAL-ROTATION-PENDING-V1"
FORMAT = "LMR365-CREDENTIAL-ROTATION-PENDING-V2"
RECOVER = "RECOVER_ONE_STOPPED_POSTFIX_CREDENTIAL"


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
              "prepared": None, "phase": "replace", "replacement_identity": None}
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
                        marker["replacement_identity"] = actual
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



def valid_prepared(value):
    return (type(value) is list and len(value) == 4 and
            all(type(x) is int and x >= 0 for x in value))


def read_marker(fd, revision, info, uid):
    raw = M.read_file(fd, X.ROTATION_PENDING, uid)
    marker = M.decode(raw)
    fields = {"format", "revision", "generation", "name", "old_hash", "old_identity",
              "new_hash", "before", "prepared", "phase"}
    X.need(type(marker) is dict and marker.get("format") in (FORMAT, LEGACY_FORMAT),
           "invalid_rotation_marker")
    modern = marker["format"] == FORMAT
    X.need(set(marker) == (fields | {"replacement_identity"} if modern else fields) and
           M.canonical(marker) == raw and marker["revision"] == revision and
           marker["name"] in X.auth_names(info) and
           all(R.valid_sha(marker[k]) for k in ("generation", "old_hash", "new_hash", "before")) and
           marker["old_hash"] != marker["new_hash"] and
           X.valid_identity(marker["old_identity"]) and
           marker["phase"] in ("replace", "rollback") and
           (marker["prepared"] is None or valid_prepared(marker["prepared"])),
           "invalid_rotation_marker")
    if marker["phase"] == "rollback":
        X.need(valid_prepared(marker["prepared"]) and
               (not modern or X.valid_identity(marker["replacement_identity"])),
               "invalid_rollback_marker")
    elif modern:
        X.need(marker["replacement_identity"] is None, "invalid_replacement_marker")
    return marker


def no_orphan_scratch(config, fd):
    X.need(not any(name.startswith(".lmr365-txn-") for name in os.listdir(config)) and
           not any(name.startswith(".lmr365-txn-") for name in os.listdir(fd)),
           "rotation_scratch_requires_manual_review")


def pending_review(config, parent, revision, uid, gid):
    """Private observation; never serialize to a client."""
    record = X.load(parent, revision, uid, allow_pending=True)
    info, _, journal, receipts = record
    X.need(journal["gid"] == gid, "postfix_group_changed")
    fd = X.activation_fd(parent, revision, uid)
    try:
        no_orphan_scratch(config, fd)
        marker = read_marker(fd, revision, info, uid)
        name = marker["name"]
        assert_installed(config, record, uid, skip=name)
        actual = T.file_identity(os.stat(name, dir_fd=config, follow_symlinks=False))
        data, meta = T.config_file(config, name, uid, M.MAX_DB_BYTES)
        digest = M.digest(data)
        X.need(meta == X.map_meta(journal), "rotation_map_metadata_changed")
        map_identity(config, name, uid, meta, digest, exact=actual)
        if actual == marker["old_identity"] and digest == marker["old_hash"]:
            status = "old_retained"
        elif (marker["phase"] == "replace" and valid_prepared(marker["prepared"]) and
              actual[:4] == marker["prepared"] and digest == marker["new_hash"]):
            status = "new_retained"
        elif (marker["phase"] == "rollback" and
              X.valid_identity(marker.get("replacement_identity")) and
              actual == marker["replacement_identity"] and digest == marker["new_hash"]):
            status = "new_retained"
        elif (marker["phase"] == "rollback" and valid_prepared(marker["prepared"]) and
              actual[:4] == marker["prepared"] and digest == marker["old_hash"]):
            status = "old_restored"
        else:
            raise Refused("rotation_map_publication_unproven")
        prior = dict(journal, maps=dict(journal["maps"], **{name: marker["old_hash"]}))
        prior_receipts = dict(receipts, **{name: marker["old_identity"]})
        X.need(X.record_digest(prior, prior_receipts) == marker["before"],
               "rotation_prior_record_changed")
        if X.record_digest(journal, receipts) != marker["before"]:
            overlay = M.decode(M.read_file(fd, X.ROTATION_CURRENT, uid))
            X.need(overlay["generation"] == marker["generation"] and
                   journal["maps"][name] == digest and receipts[name] == actual,
                   "rotation_overlay_outcome_unverified")
        X.need(X.load(parent, revision, uid, allow_pending=True) == record and
               read_marker(fd, revision, info, uid) == marker,
               "rotation_observation_changed")
        assert_installed(config, record, uid, skip=name)
        map_identity(config, name, uid, meta, digest, exact=actual)
        no_orphan_scratch(config, fd)
        return record, marker, actual, status
    finally:
        os.close(fd)


def recover(config, parent, revision, reviewed, gid, confirmation, uid, guard, verify):
    """Reconcile a proven retained map; do not recreate lost credentials."""
    X.need(confirmation == RECOVER, "typed_rotation_recovery_required")
    guard()
    observed = pending_review(config, parent, revision, uid, gid)
    X.need(observed == reviewed, "rotation_recovery_review_changed")
    record, marker, identity, status = observed
    info, _, journal, receipts = record
    name = marker["name"]
    data, meta = T.config_file(config, name, uid, M.MAX_DB_BYTES)
    digest = marker["new_hash"] if status == "new_retained" else marker["old_hash"]
    X.need(M.digest(data) == digest and meta == X.map_meta(journal),
           "rotation_recovery_candidate_changed")
    map_identity(config, name, uid, meta, digest, exact=identity)
    verify(status == "new_retained", info, name, data)
    guard()
    X.need(pending_review(config, parent, revision, uid, gid) == observed,
           "rotation_recovery_changed_after_verify")
    fd = X.activation_fd(parent, revision, uid)
    try:
        no_orphan_scratch(config, fd)
        if journal["maps"][name] != digest or receipts[name] != identity:
            expected = commit_overlay(fd, record, name, digest, identity, uid,
                                      marker["generation"])
        else:
            expected = record
        guard()
        X.need(pending_review(config, parent, revision, uid, gid) ==
               (expected, marker, identity, status), "rotation_recovery_commit_unverified")
        assert_installed(config, expected, uid)
        no_orphan_scratch(config, fd)
        X.need(read_marker(fd, revision, info, uid) == marker, "rotation_marker_changed")
        os.unlink(X.ROTATION_PENDING, dir_fd=fd)
        os.fsync(fd)
        X.need(X.load(parent, revision, uid) == expected, "rotation_recovery_unverified")
        return status
    finally:
        os.close(fd)


def compile_rotation_candidate(info, index, credential):
    """Compile only the selected account with the existing native compiler.

    The verified callback receives temporary DBs, but only the SASL bytes
    for this rule leave the scratch directory. No other passwords, stored
    credentials, or active config files are read. No production writes.
    """
    try:
        target_name(info, index)
        rules, plan = C.plan(info["rules"])
        X.need(rules == info["rules"] and plan == info["plan"] and
               info["backend"] in M.MAP_SUFFIX and info["ca"] in C.CA_FILES,
               "invalid_rotation_compile_context")
        rule = rules[index - 1]
        C.credentials([rule], [credential])
        selected, selected_plan = C.plan([rule])
        source = C.profile_name(selected_plan, 1) + "-sasl"
        captured = []

        def consume(checked, digest, backend, ca, databases):
            X.need(not captured and (checked, digest, backend, ca) ==
                   (selected, selected_plan, info["backend"], info["ca"]) and
                   type(databases) is dict and set(databases) == {C.ROUTE_MAP, source},
                   "rotation_compiler_context_changed")
            database = databases[source]
            X.need(type(database) is bytes and 0 < len(database) <= M.MAX_DB_BYTES,
                   "invalid_rotation_database")
            captured.append(database)

        receipt = C.compile_profiles({"rules": selected, "credentials": [credential]},
                                     selected_plan, C.CONFIRM, os.geteuid(),
                                     C.tmpfs_parent(), info["ca"],
                                     forced_backend=info["backend"],
                                     verified_consumer=consume)
        X.need(receipt == (selected_plan, info["backend"], 1, 1) and len(captured) == 1,
               "rotation_compiler_receipt_unverified")
        return captured[0]
    except Exception:
        # Native output, credential values, and DB bytes are private.
        raise Refused("rotation_candidate_compilation_failed") from None


def verify_retained_native(config, directory, info, name, data, uid, identity,
                           native_unprivileged, credential=None):
    """Check one exact retained map as the Postfix account, without logging it.

    `directory` is a trusted caller-supplied config directory (production or
    disposable CI fixture). The caller must hold exclusive maintenance and
    prove the stopped-host/effective-policy guard. The descriptor is checked
    against the absolute directory before and after native reads. With a new
    credential, compare its exact value; on recovery validate the retained
    single endpoint and supported credential format. No SMTP AUTH or mail.
    """
    try:
        matches = [r for i, r in enumerate(info["rules"], 1)
                   if r["auth"] == "password" and target_name(info, i) == name]
        X.need(len(matches) == 1 and type(directory) is str and
               os.path.isabs(directory) and os.path.realpath(directory) == directory,
               "invalid_rotation_native_target")
        rule = matches[0]
        expected_meta = {"mode": 0o640, "gid": identity[1]}
        digest = M.digest(data)
        initial = map_identity(config, name, uid, expected_meta, digest)

        def check_directory():
            a = os.fstat(config)
            b = os.stat(directory, follow_symlinks=False)
            X.need((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) and
                   os.path.realpath(directory) == directory,
                   "rotation_native_directory_changed")

        check_directory()
        suffix = M.MAP_SUFFIX[info["backend"]]
        source = name[:-len(suffix)]
        spec = info["backend"] + ":" + directory + "/" + source
        prefix = ["-c", "/etc/postfix"]
        key = C.endpoint(rule)
        code, found = native_unprivileged(prefix + ["-s", spec], identity)
        X.need(code == 0 and len(found) <= M.MAX_BYTES, "rotation_native_enumeration_failed")
        rows = M.native_rows(found)
        X.need(set(rows) == {key}, "rotation_native_endpoint_mismatch")
        user, sep, secret = rows[key].partition(":")
        X.need(bool(sep) and C.credentials([rule], [{"username": user, "password": secret}]) ==
               [rows[key]], "rotation_native_credential_format_invalid")
        if credential is not None:
            X.need(C.credentials([rule], [credential]) == [rows[key]],
                   "rotation_native_credential_mismatch")
        code, found = native_unprivileged(prefix + ["-q", "-", spec], identity,
                                          (key + "\n").encode("ascii"))
        X.need(code == 0 and len(found) <= M.MAX_BYTES and M.native_rows(found) == rows,
               "rotation_native_lookup_failed")
        code, found = native_unprivileged(prefix + ["-q", M.NEGATIVE_KEY, spec], identity)
        X.need(code == 1 and not found.strip(), "rotation_native_negative_lookup_failed")
        check_directory()
        map_identity(config, name, uid, expected_meta, digest, exact=initial)
    except Exception:
        raise Refused("rotation_native_map_verification_failed") from None


if __name__ == "__main__":
    raise SystemExit("Credential rotation library only; production entry point is not exposed.")
