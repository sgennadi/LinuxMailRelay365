#!/usr/bin/env python3
"""Policy-bound labeled single-account rotation and explicit recovery.

Internal library. The caller must prove exclusive stopped maintenance,
actual policy, native compiled map and native account lookup. No CLI.
"""
import importlib.util
import os
import pathlib
import secrets
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "rotation_marker_schema", str(pathlib.Path(__file__).with_name(
        "conditional-transport-rotation.py")))
Q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(Q)

CONFIRM = Q.CONFIRM
RECOVER = Q.RECOVER


class ScopedRotation:
    def __init__(self, store, config, read_policy):
        self.s, self.config, self.policy = store, config, read_policy
        # Use the exact same transaction module as the scoped store. It owns
        # xattr checks and exceptions, including synthetic filesystem tests.
        self.x = store_module(store)
        self.m, self.r, self.t = self.x.M, self.x.R, self.x.T
        self.uid = store.uid
        self.activation = store.snapshot + "/" + self.r.ACTIVATION

    def state(self):
        return self.s._activation_state(True)

    def live(self, record, skip=None, prepared=None):
        info, files, journal, receipts = record
        self.s.live_guard(self.config, info, self.policy, prepared)
        self.x.assert_pair(self.config, info, files, ".after", self.uid)
        self.x.check_sources(self.config, info)
        self.x.need(all(self.x.valid_identity(v) for v in receipts.values()),
                    "publication_identity_unverified")
        for name in self.x.map_names(info):
            if name != skip:
                self.x.checked_map(self.config, name, journal, receipts[name], self.uid)

    def map(self, record, name, digest, exact=None, prepared=None):
        journal = record[2]
        data, meta = self.t.config_file(self.config, name, self.uid, self.m.MAX_DB_BYTES)
        identity = self.t.file_identity(os.stat(name, dir_fd=self.config,
                                                follow_symlinks=False))
        self.x.need(meta == self.x.map_meta(journal, name) and
                    self.m.digest(data) == digest and
                    (exact is None or exact == identity) and
                    (prepared is None or identity[:4] == prepared),
                    "rotation_map_identity_or_content_changed")
        candidate = dict(journal, maps=dict(journal["maps"], **{name: digest}))
        self.x.checked_map(self.config, name, candidate, identity, self.uid)
        return data, identity

    def update(self, state, name, value, record=None):
        """Exact scoped metadata replacement and verification of all neighbors."""
        self.x.need(self.state() == state, "rotation_private_state_changed")
        relative = self.activation + "/" + name
        observed = state[1]
        previous = observed[1].get(name)
        receipt = self.s.write_json(relative, value, previous)
        records = dict(observed[1], **{name: receipt})
        wanted = (state[0] if record is None else record,
                  (observed[0], records), state[2])
        self.x.need(self.state() == wanted, "rotation_private_state_changed")
        return wanted

    def overlay(self, state, name, digest, identity, generation):
        record, _, base = state
        info, files, journal, receipts = record
        value = {"format": "LMR365-CREDENTIAL-CURRENT-V1",
                 "revision": self.s.revision,
                 "base": self.x.record_digest(*base),
                 "generation": generation,
                 "maps": dict(journal["maps"], **{name: digest}),
                 "receipts": dict(receipts, **{name: identity})}
        parsed = self.x.parse_rotation_overlay(self.m.canonical(value), info, *base)
        wanted = (info, files, parsed[0], parsed[1])
        return self.update(state, self.x.ROTATION_CURRENT, value, wanted)

    def finish(self, state):
        self.live(state[0])
        self.x.need(self.state() == state, "rotation_private_state_changed")
        self.s.remove_rotation_marker(state[1][1][self.x.ROTATION_PENDING])
        self.x.need(self.s.read_activation() == state[0],
                    "rotation_commit_unverified")
        self.live(state[0])

    def rotate(self, index, reviewed, database, gid, confirmation, verify, fresh_review):
        self.x.need(confirmation == CONFIRM and callable(verify) and callable(fresh_review),
                    "typed_rotation_confirmation_required")
        self.x.need(type(database) is bytes and 0 < len(database) <= self.m.MAX_DB_BYTES,
                    "invalid_verified_credential_database")
        state = self.state()
        self.x.need(state[0] == reviewed and fresh_review() == reviewed and
                    self.x.ROTATION_PENDING not in state[1][1] and
                    reviewed[2]["gid"] == gid, "installed_review_changed")
        info, files, journal, receipts = reviewed
        name = Q.target_name(info, index)
        self.live(reviewed)
        old_hash, new_hash = journal["maps"][name], self.m.digest(database)
        self.x.need(old_hash != new_hash, "credential_database_unchanged")
        old, old_identity = self.map(reviewed, name, old_hash, exact=receipts[name])
        generation = secrets.token_hex(32)
        marker = {"format": Q.FORMAT, "revision": self.s.revision, "generation": generation,
                  "name": name, "old_hash": old_hash, "old_identity": old_identity,
                  "new_hash": new_hash, "before": self.x.record_digest(journal, receipts),
                  "prepared": None, "phase": "replace", "replacement_identity": None}
        self.live(reviewed)
        Q.parse_marker(self.m.canonical(marker), self.s.revision, info)
        state = self.update(state, self.x.ROTATION_PENDING, marker)
        prepared = []
        overlay_attempted = False

        def before_replace(identity):
            nonlocal state
            self.live(reviewed, prepared=identity)
            self.x.need(self.state() == state, "rotation_private_state_changed")
            marker["prepared"] = identity
            state = self.update(state, self.x.ROTATION_PENDING, marker)
            self.live(reviewed, prepared=identity)
            prepared[:] = [identity]

        try:
            self.live(reviewed)
            self.x.need(self.state() == state, "rotation_private_state_changed")
            self.t.atomic_write(self.config, name, database, self.x.map_meta(journal, name),
                                self.uid, True, before_replace=before_replace)
            self.x.need(len(prepared) == 1, "replacement_identity_missing")
            _, identity = self.map(reviewed, name, new_hash, prepared=prepared[0])
            self.live(reviewed, skip=name)
            self.x.need(verify(True, info, name, database) is True,
                        "rotation_native_verification_failed")
            self.map(reviewed, name, new_hash, exact=identity)
            self.live(reviewed, skip=name)
            self.x.need(self.state() == state, "rotation_private_state_changed")
            overlay_attempted = True
            state = self.overlay(state, name, new_hash, identity, generation)
            self.finish(state)
        except Exception:
            try:
                self.x.need(not overlay_attempted and self.state() == state,
                            "rotation_commit_outcome_uncertain")
                self.live(reviewed, skip=name)
                actual = self.t.file_identity(os.stat(name, dir_fd=self.config,
                                                      follow_symlinks=False))
                if actual == old_identity:
                    self.map(reviewed, name, old_hash, exact=actual)
                else:
                    self.x.need(len(prepared) == 1, "replacement_identity_missing")
                    self.map(reviewed, name, new_hash, exact=actual, prepared=prepared[0])
                    rollback_prepared = []

                    def before_rollback(identity):
                        nonlocal state
                        self.live(reviewed, skip=name, prepared=identity)
                        self.map(reviewed, name, new_hash, exact=actual)
                        self.x.need(self.state() == state, "rotation_private_state_changed")
                        marker.update(phase="rollback", replacement_identity=actual,
                                      prepared=identity)
                        state = self.update(state, self.x.ROTATION_PENDING, marker)
                        self.live(reviewed, skip=name, prepared=identity)
                        rollback_prepared[:] = [identity]

                    self.t.atomic_write(self.config, name, old, self.x.map_meta(journal, name),
                                        self.uid, True, before_replace=before_rollback)
                    self.x.need(len(rollback_prepared) == 1, "rollback_identity_missing")
                    _, actual = self.map(reviewed, name, old_hash,
                                         prepared=rollback_prepared[0])
                self.x.need(verify(False, info, name, old) is True,
                            "rotation_native_rollback_unverified")
                self.map(reviewed, name, old_hash, exact=actual)
                self.live(reviewed, skip=name)
                self.x.need(self.state() == state, "rotation_private_state_changed")
                if actual != old_identity:
                    state = self.overlay(state, name, old_hash, actual, generation)
                self.finish(state)
            except Exception:
                raise Q.RotationFailed(self.s.revision, False) from None
            raise Q.RotationFailed(self.s.revision, True) from None
        return generation

    def pending_review(self):
        state = self.state()
        record, observed, _ = state
        info, _, journal, receipts = record
        self.x.need(self.x.ROTATION_PENDING in observed[1], "no_pending_rotation")
        marker = Q.parse_marker(observed[1][self.x.ROTATION_PENDING][0],
                                self.s.revision, info)
        name = marker["name"]
        self.live(record, skip=name)
        data, _ = self.t.config_file(self.config, name, self.uid, self.m.MAX_DB_BYTES)
        digest = self.m.digest(data)
        _, actual = self.map(record, name, digest)
        if actual == marker["old_identity"] and digest == marker["old_hash"]:
            status = "old_retained"
        elif (marker["phase"] == "replace" and Q.valid_prepared(marker["prepared"]) and
              actual[:4] == marker["prepared"] and digest == marker["new_hash"]):
            status = "new_retained"
        elif (marker["phase"] == "rollback" and
              self.x.valid_identity(marker.get("replacement_identity")) and
              actual == marker["replacement_identity"] and digest == marker["new_hash"]):
            status = "new_retained"
        elif (marker["phase"] == "rollback" and Q.valid_prepared(marker["prepared"]) and
              actual[:4] == marker["prepared"] and digest == marker["old_hash"]):
            status = "old_restored"
        else:
            raise self.x.Refused("rotation_map_publication_unproven")
        prior = dict(journal, maps=dict(journal["maps"], **{name: marker["old_hash"]}))
        prior_ids = dict(receipts, **{name: marker["old_identity"]})
        self.x.need(self.x.record_digest(prior, prior_ids) == marker["before"],
                    "rotation_prior_record_changed")
        if self.x.record_digest(journal, receipts) != marker["before"]:
            overlay = self.m.decode(observed[1][self.x.ROTATION_CURRENT][0])
            self.x.need(overlay["generation"] == marker["generation"] and
                        journal["maps"][name] == digest and receipts[name] == actual,
                        "rotation_overlay_outcome_unverified")
        self.live(record, skip=name)
        self.map(record, name, digest, exact=actual)
        self.x.need(self.state() == state, "rotation_private_state_changed")
        return state, marker, actual, status

    def recover(self, reviewed, gid, confirmation, verify):
        self.x.need(confirmation == RECOVER and callable(verify),
                    "typed_rotation_recovery_required")
        current = self.pending_review()
        self.x.need(current == reviewed, "rotation_recovery_review_changed")
        state, marker, identity, status = current
        info, _, journal, receipts = state[0]
        self.x.need(journal["gid"] == gid, "postfix_group_changed")
        name = marker["name"]
        digest = marker["new_hash"] if status == "new_retained" else marker["old_hash"]
        data, _ = self.map(state[0], name, digest, exact=identity)
        self.x.need(verify(status == "new_retained", info, name, data) is True,
                    "rotation_recovery_native_unverified")
        self.x.need(self.pending_review() == current, "rotation_recovery_review_changed")
        if journal["maps"][name] != digest or receipts[name] != identity:
            state = self.overlay(state, name, digest, identity, marker["generation"])
        self.x.need(self.pending_review() == (state, marker, identity, status),
                    "rotation_recovery_commit_unverified")
        self.finish(state)
        return status


def store_module(store):
    """The private store exposes its already bound transaction primitives."""
    return store.transaction_core()


if __name__ == "__main__":
    raise SystemExit("Internal policy-bound credential rotation library only.")
