#!/usr/bin/env python3
"""Experimental stopped-host managed transport edit CLI.

No SMTP AUTH, mail submission, automatic daemon control or queue mutation.
Review reads only nonsecret rule input. Switch uses protected stdin for new
credentials. Recovery can find a pending edit even if the SSH reply was lost.
"""
import argparse
import importlib.util
import os
import pathlib
import resource
import signal
import sys

sys.dont_write_bytecode = True


def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(pathlib.Path(__file__).with_name(filename)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EditHost:
    def __init__(self, switch, inventory, config, parent, identity, uid, guard):
        self.s, self.i = switch, inventory
        self.e, self.x, self.q = switch.E, switch.X, switch.Q
        self.m, self.r, self.t = switch.M, switch.R, switch.T
        self.h = inventory.H
        self.config, self.parent = config, parent
        self.identity, self.uid, self.guard = identity, uid, guard

    def need(self, condition, reason):
        self.x.need(condition, reason)

    def config_ids(self):
        return [self.t.file_identity(os.stat(name, dir_fd=self.config,
                                             follow_symlinks=False))
                for name in ("main.cf", "master.cf")]

    def lookup(self, spec, rows):
        return self.i.route_lookup(spec, rows, self.identity)

    def verify_policy(self, record, state):
        self.need(self.i.verify_installed_policy(record, state, self.lookup) == record,
                  "installed_native_policy_unverified")
        return True

    def unmanaged(self, record, state):
        """Compare non-managed native configuration in memory, never export it."""
        info = record[0]
        values, extra, explicit, services, overrides = state
        names = {self.s.C.profile_name(info["plan"], i)
                 for i in range(1, len(info["rules"]) + 1)}
        parameter = self.s.C.PARAMETER
        return (dict(values, **{parameter: ""}), extra,
                {k: v for k, v in explicit.items() if k != parameter},
                {k: v for k, v in services.items() if k[0] not in names},
                {k: v for k, v in overrides.items() if k.split("/")[0] not in names})

    def review_edit(self, revision, draft):
        self.need(self.r.valid_sha(revision), "invalid_revision")
        self.guard()
        baseline, ids = self.h.state(), self.config_ids()

        def native(record):
            self.guard()
            self.need(self.h.state() == baseline and self.config_ids() == ids,
                      "native_state_changed")
            self.verify_policy(record, baseline)
            self.guard()
            self.need(self.h.state() == baseline and self.config_ids() == ids,
                      "native_state_changed")
            return True

        private = self.e.review(self.config, self.parent, revision, draft,
                                self.uid, self.identity[1], self.guard, native)
        old, new, _, retain = private
        self.need(self.h.backend_for(new["rules"], new["backend"]) == new["backend"],
                  "native_backend_changed")
        proof, count = self.h.network(new["rules"], new["ca"], self.h.P.local_addresses())
        self.need(self.r.valid_sha(proof) and count == len({
            (r["host"], r["port"], r["tls"]) for r in new["rules"]}),
            "tls_review_unverified")
        self.need(self.e.review(self.config, self.parent, revision, new["rules"],
                                self.uid, self.identity[1], self.guard, native) == private,
                  "edit_review_changed")
        # Only nonsecret identifiers enter the public approval. Never hash a
        # private journal, config content or credential-derived database hash.
        token = self.m.digest(self.m.canonical({
            "format": "LMR365-EDIT-REVIEW-V1", "revision": revision,
            "old_plan": old[0]["plan"], "new_plan": new["plan"],
            "backend": new["backend"], "account": list(self.identity),
            "directory": new["identity"], "config_ids": ids,
            "map_ids": old[3], "retain": list(retain), "tls": proof}))
        return {"private": private, "state": baseline, "ids": ids, "proof": proof,
                "count": count, "token": token}

    def review_receipt(self, revision, reviewed):
        old, new, _, retain = reviewed["private"]
        return {"old_revision": revision, "old_plan": old[0]["plan"],
                "new_plan": new["plan"], "backend": new["backend"],
                "review_sha256": reviewed["token"], "tls_destinations": reviewed["count"],
                "retain_indices": ",".join(str(i or 0) for i in retain)}

    def verify_generation(self, record, unmanaged=None, expected=None):
        """Native readback of all maps without returning account names or secrets."""
        self.guard()
        info, files, journal, receipts = record
        ids, baseline = self.config_ids(), self.h.state()
        self.q.assert_installed(self.config, record, self.uid)
        self.verify_policy(record, baseline)
        if unmanaged is not None:
            self.need(self.unmanaged(record, baseline) == unmanaged,
                      "unmanaged_native_policy_changed")
        for index, rule in enumerate(info["rules"], 1):
            if rule["auth"] != "password":
                continue
            name = self.q.target_name(info, index)
            self.x.checked_map(self.config, name, journal, receipts[name], self.uid)
            data, meta = self.t.config_file(self.config, name, self.uid, self.m.MAX_DB_BYTES)
            self.need(self.m.digest(data) == journal["maps"][name] and
                      meta == self.x.map_meta(journal), "credential_map_changed")
            self.q.verify_retained_native(self.config, self.h.P.CONFIG, info, name, data,
                                          self.uid, self.identity, self.i.O.native_unprivileged,
                                          None if expected is None else expected.get(index))
        self.guard()
        self.need(self.h.state() == baseline and self.config_ids() == ids,
                  "native_state_changed_after_verification")
        self.q.assert_installed(self.config, record, self.uid)
        return True

    def switch(self, revision, request, approved, plan):
        self.need(type(request) is dict and set(request) == {"rules", "credentials"} and
                  self.r.valid_sha(approved) and self.r.valid_sha(plan), "invalid_switch_request")
        reviewed = self.review_edit(revision, request["rules"])
        private = reviewed["private"]
        self.need(reviewed["token"] == approved and private[1]["plan"] == plan,
                  "edit_review_changed")
        choices = self.e.credential_choices(private, request["credentials"])
        expected = {i: value for i, (mode, value) in enumerate(choices, 1) if mode == "new"}
        unmanaged = self.unmanaged(private[0], reviewed["state"])

        def native(record):
            self.guard()
            self.need(record == private[0] and self.h.state() == reviewed["state"] and
                      self.config_ids() == reviewed["ids"], "edit_review_changed")
            return self.verify_policy(record, reviewed["state"])

        def prepublish():
            self.need(self.review_edit(revision, private[1]["rules"]) == reviewed,
                      "edit_review_changed_after_compilation")

        return self.s.begin(self.config, self.parent, self.h.P.CONFIG, revision,
                            private, request["credentials"], self.uid, self.identity,
                            self.guard, native, self.i.O.native_unprivileged,
                            lambda record: self.verify_generation(record, unmanaged, expected),
                            self.s.BEGIN, prepublish=prepublish)

    def pending(self):
        self.guard()
        try:
            fd = self.m.open_base(self.parent, self.uid, name=self.x.EDIT_BASE)
        except FileNotFoundError:
            return None
        try:
            if not os.listdir(fd):
                return None
        finally:
            os.close(fd)
        observation = self.s.observe(self.config, self.parent, self.uid,
                                     self.identity[1], self.guard)
        marker, old, new, current, old_present, new_present = observation
        ids = self.config_ids()
        old_pair = self.x.expected_pair(old[0], old[1], ".after")
        new_pair = self.x.expected_pair(new[0], new[1], ".after")
        layout = "old" if current == old_pair else "new" if current == new_pair else "mixed"
        commit = (marker["phase"] in ("pending", "commit") and layout == "new" and
                  self.s.full(new, new_present))
        rollback = (marker["phase"] in ("pending", "rollback") and
                    self.s.full(old, old_present))
        token = self.m.digest(self.m.canonical({
            "format": "LMR365-EDIT-RECOVERY-REVIEW-V1",
            "old_revision": marker["old"], "new_revision": marker["new"],
            "old_plan": old[0]["plan"], "new_plan": new[0]["plan"],
            "phase": marker["phase"], "layout": layout,
            "account": list(self.identity), "directory": old[0]["identity"],
            "config_ids": ids, "old_map_ids": old[3], "new_map_ids": new[3],
            "old_present": list(old_present), "new_present": list(new_present)}))
        self.guard()
        self.need(self.s.observe(self.config, self.parent, self.uid,
                                 self.identity[1], self.guard) == observation and
                  self.config_ids() == ids, "edit_recovery_observation_changed")
        receipt = {"old_revision": marker["old"], "new_revision": marker["new"],
                   "old_plan": old[0]["plan"], "new_plan": new[0]["plan"],
                   "backend": new[0]["backend"], "phase": marker["phase"],
                   "layout": layout, "review_sha256": token,
                   "commit_candidate": "yes" if commit else "no",
                   "rollback_candidate": "yes" if rollback else "no"}
        return observation, receipt

    def resolve(self, revision, approved, decision):
        current = self.pending()
        self.need(current is not None, "no_pending_edit")
        observation, receipt = current
        self.need(decision in ("commit", "rollback") and receipt["new_revision"] == revision and
                  receipt["review_sha256"] == approved and
                  receipt[decision + "_candidate"] == "yes", "edit_recovery_review_changed")
        confirm = self.s.COMMIT if decision == "commit" else self.s.ROLLBACK
        # Recovery may start with a mixed pair. The library restores the
        # selected complete generation before mandatory native verification.
        return self.s.resolve(self.config, self.parent, observation, self.uid,
                              self.identity[1], self.guard, self.verify_generation, confirm)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Invalid edit arguments. See --help.\n")


def arguments(argv=None):
    p = SafeParser(description=__doc__, allow_abbrev=False)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--review", metavar="OLD_REVISION")
    group.add_argument("--switch", metavar="OLD_REVISION")
    group.add_argument("--review-recovery", action="store_true")
    group.add_argument("--commit", metavar="NEW_REVISION")
    group.add_argument("--rollback", metavar="NEW_REVISION")
    p.add_argument("--approve-review-sha256")
    p.add_argument("--approve-plan-sha256")
    p.add_argument("--confirm")
    p.add_argument("--maintenance-confirmation", required=True)
    return p.parse_args(argv)


def validate_args(args, s, maintenance):
    s.X.need(args.maintenance_confirmation == maintenance, "exclusive_maintenance_required")
    revision = args.review or args.switch or args.commit or args.rollback
    s.X.need(args.review_recovery or s.R.valid_sha(revision), "invalid_revision")
    if args.review is not None or args.review_recovery:
        s.X.need(all(v is None for v in (args.confirm, args.approve_review_sha256,
                                        args.approve_plan_sha256)), "unexpected_write_approval")
    else:
        confirm = s.BEGIN if args.switch is not None else s.COMMIT if args.commit is not None else s.ROLLBACK
        s.X.need(args.confirm == confirm and s.R.valid_sha(args.approve_review_sha256) and
                 (s.R.valid_sha(args.approve_plan_sha256) if args.switch is not None
                  else args.approve_plan_sha256 is None), "invalid_write_approval")


def output(status, **fields):
    print("EDIT_STATUS=" + status)
    for key, value in fields.items():
        print("EDIT_" + key.upper() + "=" + str(value))
    for name in ("SERVICE_STARTED", "MAIL_SENT", "QUEUE_MODIFIED", "SMTP_AUTH_ATTEMPTED"):
        print("EDIT_" + name + "=no")


def run(args, s, i, read_input, emit=output):
    o, p = i.O, i.P
    fds = []
    attempted = False
    try:
        s.X.need(os.geteuid() == 0, "root_required")
        validate_args(args, s, o.MAINTENANCE)
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        fds.append(o.route_lock())
        for path in ("/var/lib", p.CONFIG, p.QUEUE):
            fds.append(p.open_directory(path, strict=path != p.QUEUE))
        _, parent, config, queue = fds
        identity = o.mail_identity()

        def guard():
            o.maintenance(config, queue, identity)
            o.same_directory(parent, "/var/lib")

        guard()
        host = EditHost(s, i, config, parent, identity, 0, guard)
        if args.review is not None or args.switch is not None:
            raw = read_input(s.M.MAX_BYTES + 1)
            s.X.need(type(raw) is bytes and 0 < len(raw) <= s.M.MAX_BYTES,
                     "invalid_request_size")
            request = s.M.decode(raw)
            if args.review is not None:
                reviewed = host.review_edit(args.review, request)
                emit("reviewed_experimental", **host.review_receipt(args.review, reviewed),
                     postfix_changed="no")
            else:
                attempted = True
                revision = host.switch(args.switch, request, args.approve_review_sha256,
                                       args.approve_plan_sha256)
                s.X.need(s.R.valid_sha(revision), "invalid_replacement_revision")
                emit("switched_pending_resolution", old_revision=args.switch,
                     new_revision=revision, postfix_changed="pending")
        elif args.review_recovery:
            pending = host.pending()
            if pending is None:
                emit("no_pending_edit", postfix_changed="no")
            else:
                emit("recovery_reviewed_experimental", **pending[1], postfix_changed="no")
        else:
            attempted = True
            decision = "commit" if args.commit is not None else "rollback"
            kept = host.resolve(args.commit or args.rollback, args.approve_review_sha256, decision)
            s.X.need(s.R.valid_sha(kept), "invalid_resolved_revision")
            emit("committed_offline_not_started" if decision == "commit" else "rolled_back_offline_not_started",
                 kept_revision=kept, postfix_changed="resolved")
        return 0
    except s.SwitchFailed as exc:
        emit("manual_recovery_required", new_revision=exc.revision, postfix_changed="unknown")
    except Exception:
        # Never echo native output, passwords, config, private digests or exceptions.
        emit("refused_or_failed", postfix_changed="inspect_recovery" if attempted else "no")
    finally:
        for fd in reversed(fds):
            os.close(fd)
    return 2


def main(argv=None):
    args = arguments(argv)
    try:
        s = sibling("switch_core", "conditional-transport-edit-transaction.py")
        i = sibling("installed_inventory", "inspect-conditional-transport-recovery.py")
        def timeout(signum, frame):
            raise TimeoutError("edit_timeout")
        signal.signal(signal.SIGALRM, timeout)
        signal.alarm(600)
        return run(args, s, i, sys.stdin.buffer.read)
    except Exception:
        output("refused_or_failed", postfix_changed="inspect_recovery")
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
