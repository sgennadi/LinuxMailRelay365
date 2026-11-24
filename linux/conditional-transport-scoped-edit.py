#!/usr/bin/env python3
"""Two-generation edit using the scoped SELinux private recovery store.

Internal API only. Caller must supply a real stopped maintenance guard,
trusted policy readers and mandatory native effective-policy verification.
No service control, SMTP authentication, mail submission or queue mutation.
"""
import importlib.util
import os
import pathlib
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "scoped_edit_preparation", str(pathlib.Path(__file__).with_name(
        "conditional-transport-edit.py")))
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)

BEGIN = "SWITCH_STOPPED_POSTFIX_TRANSPORTS"
COMMIT = "COMMIT_STOPPED_POSTFIX_TRANSPORT_EDIT"
ROLLBACK = "ROLLBACK_STOPPED_POSTFIX_TRANSPORT_EDIT"


class SwitchFailed(Exception):
    def __init__(self, revision):
        self.revision = revision
        super().__init__("transport_edit_recovery_required; revision=" + revision)


class ScopedEdit:
    def __init__(self, old_store, config, read_policy):
        self.old = old_store
        self.config = config
        self.policy = read_policy
        self.x = old_store.transaction_core()
        self.t, self.m, self.r = self.x.T, self.x.M, self.x.R
        self.uid = old_store.uid
        self.marker_path = self.x.EDIT_BASE + "/" + self.x.EDIT_PENDING

    def same_scope(self, new):
        self.x.need(new.transaction_core() is self.x and new.anchor == self.old.anchor and
                    new.uid == self.uid and new.gid == self.old.gid and
                    new.revision != self.old.revision, "edit_store_scope_changed")
        self.old.check_anchor()
        new.check_anchor()

    def present(self, record, publication=None):
        info, _, journal, receipts = record
        self.x.check_sources(self.config, info)
        names = []
        for name in self.x.map_names(info):
            if not self.t.exists(self.config, name):
                self.x.need(publication is None or name != publication[0],
                            "edit_publication_missing")
                continue
            if publication is not None and name == publication[0]:
                # Only the just-linked inode from this process may be checked
                # before its receipt exists. Never adopt an interrupted map.
                self.x.need(receipts[name] is None, "edit_publication_already_recorded")
                self.x.checked_map(self.config, name, journal, publication[1], self.uid)
            else:
                self.x.checked_map(self.config, name, journal, receipts[name], self.uid)
                names.append(name)
        return tuple(names)

    def full(self, record, names):
        return set(names) == set(self.x.map_names(record[0]))

    def installed(self, store, record, evidence=None, prepared=None):
        store.live_guard(self.config, record[0], self.policy, prepared, evidence)
        self.x.assert_pair(self.config, record[0], record[1], ".after", self.uid)
        self.x.need(self.full(record, self.present(record)),
                    "installed_generation_incomplete")

    def proposed(self, record, draft):
        try:
            labels = self.policy(draft, record[0]["backend"])
            result = E.proposal(record, draft, labels)
            E.check_policy(result[0], self.policy)
            return result
        except E.Refused:
            raise self.x.Refused("invalid_labeled_edit_proposal") from None

    def review(self, draft, gid, verify):
        """No persistent changes, no retained credential extraction."""
        self.x.need(callable(verify), "native_edit_review_required")
        state = self.old._activation_state(False)
        record = state[0]
        self.x.need(record[2]["gid"] == gid, "postfix_group_changed")
        self.installed(self.old, record)
        new, files, retain = self.proposed(record, draft)
        E.destination_check(self.config, record[0], new)
        self.x.need(verify(record) is True, "installed_native_policy_unverified")
        self.installed(self.old, record)
        self.x.need(self.old._activation_state(False) == state and
                    self.proposed(record, draft) == (new, files, retain),
                    "edit_review_changed")
        E.destination_check(self.config, record[0], new)
        return state, new, files, retain

    def prepare(self, reviewed, slots, directory, identity, verify, native_unprivileged):
        """Compile new maps and retain only exact approved password rules."""
        state, new, files, retain = reviewed
        record = state[0]

        def fresh():
            self.x.need(self.review(new["rules"], identity[1], verify) == reviewed,
                        "edit_review_changed")

        try:
            fresh()
            selected = E.credential_choices((record, new, files, retain), slots)
            result = {E.C.ROUTE_MAP: E.compile_route(new)}
            for index, (mode, value) in enumerate(selected, 1):
                fresh()
                if mode == "none":
                    continue
                if mode == "retain":
                    data = E.retained_database(self.config, directory, record, value,
                                               self.uid, identity, native_unprivileged)
                else:
                    data = E.Q.compile_rotation_candidate(new, index, value)
                result[E.C.profile_name(new["plan"], index) + "-sasl"] = data
            fresh()
            self.x.native_database_set(new, result)
            return result
        except Exception:
            raise self.x.Refused("edit_candidate_preparation_failed") from None

    def _observe(self, new, prepared=None, publication=None):
        """Private read of both revisions; optional in-process publication proof."""
        self.same_scope(new)
        evidence = self.old.observe_edit_marker()
        self.x.need(evidence is not None, "no_pending_edit")
        marker = self.x.parse_edit_marker(evidence[1][0])
        self.x.need(marker["old"] == self.old.revision and marker["new"] == new.revision,
                    "edit_revision_not_bound")
        os_, ns = (store._activation_state(False, evidence) for store in (self.old, new))
        old_record, new_record = os_[0], ns[0]
        oi, of, oj, ore = old_record
        ni, nf, nj, nre = new_record
        self.x.need(self.x.record_digest(oj, ore) == marker["old_record"] and
                    self.m.digest(self.m.canonical(nj)) == marker["new_journal"] and
                    self.x.ROTATION_CURRENT not in ns[1][1] and
                    oj["gid"] == nj["gid"] and
                    oi["identity"] == ni["identity"] == self.t.context(self.config, self.uid) and
                    oi["directory_selinux"] == ni["directory_selinux"] and
                    oi["metadata"] == ni["metadata"] and
                    not (set(self.x.map_names(oi)) & set(self.x.map_names(ni))) and
                    all(self.x.valid_identity(v) for v in ore.values()),
                    "edit_records_changed")
        proposal = self.proposed(old_record, ni["rules"])
        self.x.need(proposal[:2] == new_record[:2], "edit_proposal_changed")
        for store, info in ((self.old, oi), (new, ni)):
            store.live_guard(self.config, info, self.policy, prepared, evidence)
        old_pair = self.x.expected_pair(oi, of, ".after")
        new_pair = self.x.expected_pair(ni, nf, ".after")
        current = self.x.pair(self.config, self.uid, oi)
        self.x.need(all(item in (old_pair[i], new_pair[i]) for i, item in enumerate(current)),
                    "edit_configuration_drift")
        op = self.present(old_record)
        np = self.present(new_record, publication)
        if marker["phase"] == "commit":
            self.x.need(current == new_pair and self.full(new_record, np),
                        "committed_generation_unverified")
        elif marker["phase"] == "rollback":
            self.x.need(current == old_pair and self.full(old_record, op),
                        "rollback_generation_unverified")
        else:
            self.x.need(self.full(old_record, op), "old_generation_incomplete")
        self.x.need(self.old._activation_state(False, evidence) == os_ and
                    new._activation_state(False, evidence) == ns and
                    self.x.pair(self.config, self.uid, oi) == current and
                    self.present(old_record) == op and self.present(new_record, publication) == np,
                    "edit_observation_changed")
        self.old._check_edit_context(evidence)
        new._check_edit_context(evidence)
        return evidence, os_, ns, current, op, np

    def observe(self, new):
        """Review pending recovery without permission to publish or clean up."""
        return self._observe(new)

    def publish(self, new, state, name, data):
        evidence, os_, ns, current, op, np = state
        marker = self.x.parse_edit_marker(evidence[1][0])
        old_record, record = os_[0], ns[0]
        info, files, journal, receipts = record
        self.x.need(marker["phase"] == "pending" and
                    current == self.x.expected_pair(old_record[0], old_record[1], ".after") and
                    name in receipts and receipts[name] is None and name not in np and
                    self.m.digest(data) == journal["maps"][name] and
                    self.observe(new) == state and not self.t.exists(self.config, name),
                    "edit_map_publication_not_reviewed")
        prepared, published = [], []

        def before_link(identity):
            self.x.need(self._observe(new, prepared=identity) == state and
                        not self.t.exists(self.config, name), "edit_publication_context_changed")
            prepared[:] = [identity]

        self.t.atomic_write(self.config, name, data, self.x.map_meta(journal, name),
                            self.uid, False, published.append, before_publish=before_link)
        identity = self.t.file_identity(os.stat(name, dir_fd=self.config, follow_symlinks=False))
        self.x.need(prepared == published == [identity[:4]] and
                    self._observe(new, publication=(name, identity)) == state,
                    "edit_map_publication_unproven")
        path = new.snapshot + "/" + self.r.ACTIVATION + "/" + self.x.receipt_name(name)
        value = {"revision": new.revision, "name": name, "identity": identity}
        receipt = new._write(path, self.m.canonical(value))
        now = self.observe(new)
        expected = (info, files, journal, dict(receipts, **{name: identity}))
        expected_records = dict(ns[1][1], **{self.x.receipt_name(name): receipt})
        self.x.need(now[0] == evidence and now[1] == os_ and
                    now[2] == (expected, (ns[1][0], expected_records),
                               (ns[2][0], dict(ns[2][1], **{name: identity}))) and
                    now[3:5] == state[3:5] and
                    set(now[5]) == set(np) | {name}, "edit_map_receipt_unverified")
        return now

    def switch(self, new, state, target):
        self.x.need(target in ("old", "new"), "invalid_edit_target")
        record = state[1 if target == "old" else 2][0]
        pair = self.x.expected_pair(record[0], record[1], ".after")
        for index in (1, 0):
            self.x.need(self.observe(new) == state and
                        self.full(record, state[4 if target == "old" else 5]),
                        "selected_generation_incomplete")
            if state[3][index] == pair[index]:
                continue

            def before_replace(identity):
                self.x.need(self._observe(new, prepared=identity) == state,
                            "edit_configuration_changed_before_replace")

            data, meta = pair[index]
            self.t.atomic_write(self.config, self.x.CONFIGS[index] + ".cf",
                                data, meta, self.uid, True, before_replace=before_replace)
            current = list(state[3])
            current[index] = pair[index]
            wanted = state[:3] + (tuple(current),) + state[4:]
            self.x.need(self.observe(new) == wanted, "edit_switch_unverified")
            state = wanted
        self.x.need(state[3] == pair, "edit_switch_unverified")
        return state

    def begin(self, new, reviewed, slots, directory, identity, verify_old,
              native_unprivileged, verify_new, confirmation):
        self.x.need(confirmation == BEGIN and callable(verify_new),
                    "typed_edit_confirmation_required")
        self.same_scope(new)
        state, info, files, _ = reviewed

        def fresh():
            self.x.need(self.review(info["rules"], identity[1], verify_old) == reviewed,
                        "edit_review_changed")

        fresh()
        databases = self.prepare(reviewed, slots, directory, identity,
                                 verify_old, native_unprivileged)
        maps = self.x.native_database_set(info, databases)
        fresh()
        new.live_guard(self.config, info, self.policy)
        new.create_snapshot(info, files)
        journal = new.create_activation(databases, identity[1])
        fresh()
        if not self.t.exists(self.old.parent, self.x.EDIT_BASE):
            self.old.create_directory(self.x.EDIT_BASE)
        self.old.no_edit_pending()
        new.no_edit_pending()
        self.x.need(new.read_activation() == (info, files, journal, dict.fromkeys(maps)),
                    "edit_journal_unverified")
        marker = {"format": self.x.EDIT_FORMAT, "old": self.old.revision,
                  "new": new.revision, "old_record": self.x.record_digest(*state[0][2:]),
                  "new_journal": self.m.digest(self.m.canonical(journal)), "phase": "pending"}
        try:
            receipt = self.old.write_json(self.marker_path, marker)
            pending = self.observe(new)
            self.x.need(pending[0][1] == receipt and pending[1] == state and
                        pending[2][0] == (info, files, journal, dict.fromkeys(maps)) and
                        not pending[5], "edit_marker_unverified")
            for name, data in sorted(maps.items()):
                pending = self.publish(new, pending, name, data)
            pending = self.switch(new, pending, "new")
            self.x.need(verify_new(pending[2][0]) is True and
                        self.observe(new) == pending, "edit_native_verification_failed")
        except Exception:
            raise SwitchFailed(new.revision) from None
        return new.revision

    def resolve(self, new, reviewed, verify, confirmation):
        phase = {COMMIT: "commit", ROLLBACK: "rollback"}.get(confirmation)
        self.x.need(phase is not None and callable(verify), "typed_edit_resolution_required")
        state = self.observe(new)
        self.x.need(state == reviewed, "edit_recovery_review_changed")
        marker = self.x.parse_edit_marker(state[0][1][0])
        self.x.need(marker["phase"] in ("pending", phase), "edit_resolution_direction_fixed")
        keep_index, discard_index = (2, 1) if phase == "commit" else (1, 2)
        keep_present, discard_present = (5, 4) if phase == "commit" else (4, 5)
        selected, discarded = state[keep_index][0], state[discard_index][0]
        if phase == "rollback" and marker["phase"] == "pending":
            state = self.switch(new, state, "old")
        self.x.need(state[3] == self.x.expected_pair(selected[0], selected[1], ".after") and
                    self.full(selected, state[keep_present]) and
                    verify(selected) is True and self.observe(new) == state,
                    "edit_native_verification_failed")
        if marker["phase"] == "pending":
            marker = dict(marker, phase=phase)
            receipt = self.old.write_json(self.marker_path, marker, state[0][1])
            expected = ((state[0][0], receipt),) + state[1:]
            self.x.need(self.observe(new) == expected, "edit_resolution_marker_unverified")
            state = expected
        for name in self.x.map_names(discarded[0]):
            self.x.need(self.observe(new) == state, "edit_cleanup_record_changed")
            if name not in state[discard_present]:
                continue
            self.x.checked_map(self.config, name, discarded[2], discarded[3][name], self.uid)
            os.unlink(name, dir_fd=self.config)
            os.fsync(self.config)
            expected = list(state)
            expected[discard_present] = tuple(n for n in state[discard_present] if n != name)
            state = tuple(expected)
            self.x.need(self.observe(new) == state, "edit_cleanup_changed")
        self.x.need(not state[discard_present] and verify(selected) is True and
                    self.observe(new) == state, "edit_cleanup_unverified")
        self.old.remove_edit_marker(state[0])
        kept = new if phase == "commit" else self.old
        self.x.need(kept._activation_state(False) == state[keep_index],
                    "edit_resolution_unverified")
        self.installed(kept, selected)
        return kept.revision


if __name__ == "__main__":
    raise SystemExit("Internal policy-bound transport edit library only.")
