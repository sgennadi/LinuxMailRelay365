#!/usr/bin/env python3
"""Guarded two-generation transport edit, library only.

New and old maps coexist temporarily in the protected config directory.
A durable private marker blocks normal manager operations until explicit
commit or rollback. No automatic service control, mail, queue manipulation,
or persistent extra credential backups. Caller must prove exclusive stopped
maintenance and full native verification of the selected generation.
"""
import importlib.util
import os
import pathlib
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "edit_preparation", str(pathlib.Path(__file__).with_name(
        "conditional-transport-edit.py")))
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)
Q, X, R, C, T, M = E.Q, E.X, E.R, E.C, E.T, E.M
Refused = X.Refused
BEGIN = "SWITCH_STOPPED_POSTFIX_TRANSPORTS"
COMMIT = "COMMIT_STOPPED_POSTFIX_TRANSPORT_EDIT"
ROLLBACK = "ROLLBACK_STOPPED_POSTFIX_TRANSPORT_EDIT"
FORMAT = "LMR365-TRANSPORT-EDIT-V1"


def load_record(parent, revision, uid):
    return X.load(parent, revision, uid, allow_edit_pending=True)


def checked_present(config, record, uid):
    info, _, journal, receipts = record
    X.check_sources(config, info)
    present = []
    for name in X.map_names(info):
        if T.exists(config, name):
            X.checked_map(config, name, journal, receipts[name], uid)
            present.append(name)
    return tuple(present)


def full(record, names):
    return set(names) == set(X.map_names(record[0]))


def marker_read(fd, uid):
    X.need(set(os.listdir(fd)) == {X.EDIT_PENDING}, "edit_marker_unverified")
    raw = M.read_file(fd, X.EDIT_PENDING, uid)
    marker = M.decode(raw)
    X.need(type(marker) is dict and set(marker) ==
           {"format", "old", "new", "old_record", "new_journal", "phase"} and
           marker["format"] == FORMAT and marker["phase"] in ("pending", "commit", "rollback") and
           all(R.valid_sha(marker[key]) for key in ("old", "new", "old_record", "new_journal")) and
           marker["old"] != marker["new"] and M.canonical(marker) == raw,
           "edit_marker_unverified")
    return marker


def observe(config, parent, uid, gid, guard):
    """Private recovery observation; never serialize hashes or DB metadata."""
    guard()
    fd = M.open_base(parent, uid, name=X.EDIT_BASE)
    try:
        Q.no_orphan_scratch(config, fd)
        marker = marker_read(fd, uid)
        old = load_record(parent, marker["old"], uid)
        new = load_record(parent, marker["new"], uid)
        oi, of, oj, ore = old
        ni, nf, nj, nre = new
        X.need(X.record_digest(oj, ore) == marker["old_record"] and
               M.digest(M.canonical(nj)) == marker["new_journal"] and
               oj["gid"] == nj["gid"] == gid and
               oi["identity"] == ni["identity"] == T.context(config, uid) and
               oi["metadata"] == ni["metadata"] and
               oi["backend"] == ni["backend"] and oi["ca"] == ni["ca"] and
               all(of[name + ".before"] == nf[name + ".before"] for name in X.CONFIGS),
               "edit_records_changed")
        expected, files, _ = E.proposal(old, ni["rules"])
        X.need((expected, files) == new[:2] and
               not (set(X.map_names(oi)) & set(X.map_names(ni))),
               "edit_proposal_changed")
        X.need(all(X.valid_identity(v) for v in ore.values()),
               "old_publication_unproven")
        old_pair = X.expected_pair(oi, of, ".after")
        new_pair = X.expected_pair(ni, nf, ".after")
        current = X.pair(config, uid)
        X.need(all(item in (old_pair[i], new_pair[i])
                   for i, item in enumerate(current)), "edit_configuration_drift")
        old_present = checked_present(config, old, uid)
        new_present = checked_present(config, new, uid)
        if marker["phase"] == "commit":
            X.need(current == new_pair and full(new, new_present),
                   "committed_generation_unverified")
        elif marker["phase"] == "rollback":
            X.need(current == old_pair and full(old, old_present),
                   "rollback_generation_unverified")
        else:
            X.need(full(old, old_present), "old_generation_incomplete")
        guard()
        X.need(marker_read(fd, uid) == marker and
               load_record(parent, marker["old"], uid) == old and
               load_record(parent, marker["new"], uid) == new and
               X.pair(config, uid) == current and
               checked_present(config, old, uid) == old_present and
               checked_present(config, new, uid) == new_present,
               "edit_observation_changed")
        Q.no_orphan_scratch(config, fd)
        return marker, old, new, current, old_present, new_present
    finally:
        os.close(fd)


def require_native(config, record, uid, verify):
    info, files, _, _ = record
    X.assert_pair(config, info, files, ".after", uid)
    X.need(full(record, checked_present(config, record, uid)),
           "selected_generation_incomplete")
    # No permissive default; callback must prove native effective policy,
    # exact service overrides, route map and every selected SASL map.
    X.need(verify(record) is True, "edit_native_verification_failed")
    X.assert_pair(config, info, files, ".after", uid)
    X.need(full(record, checked_present(config, record, uid)),
           "selected_generation_changed")


def switch_pair(config, parent, state, target, uid, gid, guard):
    marker, old, new, _, _, _ = state
    wanted = old if target == "old" else new
    pair = X.expected_pair(wanted[0], wanted[1], ".after")
    for i in (1, 0):  # exclusive stopped maintenance; master before main
        now = observe(config, parent, uid, gid, guard)
        X.need(now[:3] == (marker, old, new), "edit_records_changed")
        X.need(full(wanted, now[4 if target == "old" else 5]),
               "selected_generation_incomplete")
        if now[3][i] != pair[i]:
            data, meta = pair[i]

            # The atomic writer creates a private scratch file. The
            # before-replace callback cannot call observe(), which rejects
            # that expected scratch. Recheck exact configs, records and maps
            # directly while still inside the exclusive maintenance window.
            def check_before_replace(_identity):
                guard()
                X.need(X.pair(config, uid) == now[3] and
                       load_record(parent, marker["old"], uid) == old and
                       load_record(parent, marker["new"], uid) == new and
                       checked_present(config, old, uid) == now[4] and
                       checked_present(config, new, uid) == now[5],
                       "edit_configuration_changed_before_replace")
                fd = M.open_base(parent, uid, name=X.EDIT_BASE)
                try:
                    X.need(marker_read(fd, uid) == marker, "edit_marker_changed")
                finally:
                    os.close(fd)

            T.atomic_write(config, X.CONFIGS[i] + ".cf", data, meta, uid, True,
                           before_replace=check_before_replace)
    final = observe(config, parent, uid, gid, guard)
    X.need(final[:3] == (marker, old, new) and final[3] == pair,
           "edit_switch_unverified")
    return final


class SwitchFailed(Refused):
    def __init__(self, revision):
        self.revision = revision
        super().__init__("transport_edit_recovery_required; revision=" + revision)


def begin(config, parent, directory, revision, reviewed, slots, uid, identity,
          guard, native_review, native_unprivileged, verify, confirmation):
    """Prepare and switch, retaining old maps until separate resolution.

    If any post-marker operation fails, leave the durable pending state and
    both generations for guarded explicit rollback/recovery. Never guess
    ownership or delete a map lacking a publication receipt.
    """
    X.need(confirmation == BEGIN, "typed_edit_confirmation_required")
    guard()
    X.assert_no_edit_pending(parent, uid)
    old, new, files, _ = reviewed
    gid = identity[1]

    def fresh():
        X.need(E.review(config, parent, revision, new["rules"], uid, gid,
                        guard, native_review) == reviewed, "edit_review_changed")
        return new, files

    fresh()
    databases = E.prepare(config, parent, directory, revision, reviewed, slots,
                          uid, identity, guard, native_review, native_unprivileged)
    maps = X.native_database_set(new, databases)
    fresh()
    # The new ordinary snapshot retains the original pre-manager pair,
    # so a later normal Restore of the committed generation still works.
    replacement = R.backup(config, parent, (new, files), R.CONFIRM, uid, guard, fresh)
    journal = X.journal_for(replacement, new, files, maps, gid)
    fd = X.activation_fd(parent, replacement, uid, create=True)
    try:
        M.write_file(fd, X.JOURNAL, M.canonical(journal))
        os.fsync(fd)
    finally:
        os.close(fd)
    X.need(X.load(parent, replacement, uid) ==
           (new, files, journal, dict.fromkeys(maps)), "edit_journal_unverified")
    fresh()
    marker = {"format": FORMAT, "old": revision, "new": replacement,
              "old_record": X.record_digest(old[2], old[3]),
              "new_journal": M.digest(M.canonical(journal)), "phase": "pending"}
    fd = M.open_base(parent, uid, create=True, name=X.EDIT_BASE)
    try:
        X.need(not os.listdir(fd), "transport_edit_recovery_required")
        M.write_file(fd, X.EDIT_PENDING, M.canonical(marker))
        os.fsync(fd)
        X.need(marker_read(fd, uid) == marker, "edit_marker_unverified")
    finally:
        os.close(fd)
    try:
        for name, data in sorted(maps.items()):
            state = observe(config, parent, uid, gid, guard)
            X.need(state[0] == marker and state[1] == old and
                   state[3] == X.expected_pair(old[0], old[1], ".after") and
                   name not in state[5], "edit_publication_context_changed")
            X.publish(config, parent, replacement, name, data, journal, uid)
        state = observe(config, parent, uid, gid, guard)
        X.need(full(state[2], state[5]), "replacement_publication_incomplete")
        switched = switch_pair(config, parent, state, "new", uid, gid, guard)
        require_native(config, switched[2], uid, verify)
        X.need(observe(config, parent, uid, gid, guard) == switched,
               "edit_switch_changed_after_verification")
    except Exception:
        raise SwitchFailed(replacement) from None
    return replacement


def resolve(config, parent, reviewed, uid, gid, guard, verify, confirmation):
    """Explicitly commit new or roll back old, with resumable cleanup.

    The irreversible cleanup direction is persisted before the first unlink.
    After interruption only the same direction is allowed. Unknown maps,
    scratch files, native failures and unrelated edits always block cleanup.
    """
    phase = {COMMIT: "commit", ROLLBACK: "rollback"}.get(confirmation)
    X.need(phase is not None, "typed_edit_resolution_required")
    state = observe(config, parent, uid, gid, guard)
    X.need(state == reviewed, "edit_recovery_review_changed")
    marker, old, new, current, old_present, new_present = state
    X.need(marker["phase"] in ("pending", phase), "edit_resolution_direction_fixed")
    selected, discarded = (new, old) if phase == "commit" else (old, new)
    if marker["phase"] == "pending" and phase == "rollback":
        state = switch_pair(config, parent, state, "old", uid, gid, guard)
    # Commit never silently finishes a partially switched pair. Inspect and
    # roll back instead if the new generation was not fully installed.
    require_native(config, selected, uid, verify)
    X.need(observe(config, parent, uid, gid, guard) == state,
           "edit_recovery_changed_after_verification")
    fd = M.open_base(parent, uid, name=X.EDIT_BASE)
    try:
        if marker["phase"] == "pending":
            marker = dict(marker, phase=phase)
            Q.private_write(fd, X.EDIT_PENDING, marker, uid)
        for name in X.map_names(discarded[0]):
            now = observe(config, parent, uid, gid, guard)
            X.need(now[:3] == (marker, old, new), "edit_cleanup_record_changed")
            if name in now[4 if phase == "commit" else 5]:
                X.checked_map(config, name, discarded[2], discarded[3][name], uid)
                os.unlink(name, dir_fd=config)
                os.fsync(config)
        now = observe(config, parent, uid, gid, guard)
        X.need(now[:3] == (marker, old, new) and
               not now[4 if phase == "commit" else 5], "edit_cleanup_incomplete")
        require_native(config, selected, uid, verify)
        X.need(observe(config, parent, uid, gid, guard) == now and
               marker_read(fd, uid) == marker, "edit_cleanup_changed")
        os.unlink(X.EDIT_PENDING, dir_fd=fd)
        os.fsync(fd)
        X.assert_no_edit_pending(parent, uid)
        kept = marker["new"] if phase == "commit" else marker["old"]
        X.need(X.load(parent, kept, uid) == selected, "edit_resolution_unverified")
        return kept
    finally:
        os.close(fd)


if __name__ == "__main__":
    raise SystemExit("Private stopped-host edit transaction library only.")
