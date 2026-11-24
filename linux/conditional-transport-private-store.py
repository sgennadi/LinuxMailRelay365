#!/usr/bin/env python3
"""Private recovery-store SELinux metadata primitives (library only).

No production caller yet. Explicit exact-path policy reader and exclusive
maintenance guard are mandatory. Never copy a mail-map label to a journal.
"""
import importlib.util
import os
import pathlib
import stat
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "private_store_transaction", str(pathlib.Path(__file__).with_name(
        "conditional-transport-transaction.py")))
X = importlib.util.module_from_spec(spec)
spec.loader.exec_module(X)
R, T, M = X.R, X.T, X.M
Refused = X.Refused


def policy_paths(info, revision):
    """Return only derived relative paths; never accept a free-form filename."""
    X.need(R.valid_sha(revision), "invalid_private_revision")
    rules, plan = X.C.plan(info["rules"])
    X.need(rules == info["rules"] and plan == info["plan"] and
           info["backend"] in M.MAP_SUFFIX, "invalid_private_plan")
    sources = ["lmr365-" + plan + "-sender-transport"]
    sources += sorted(X.C.profile_name(plan, i) + "-sasl"
                      for i, rule in enumerate(rules, 1) if rule["auth"] == "password")
    X.need(sources == info["map_names"], "invalid_private_map_names")
    base = R.BASE
    snapshot = base + "/" + revision
    activation = snapshot + "/" + R.ACTIVATION
    edit = X.EDIT_BASE
    dirs = (base, snapshot, activation, edit)
    files = [snapshot + "/" + name for name in R.FILES + (R.MANIFEST,)]
    files += [activation + "/" + name for name in
              (X.JOURNAL, X.ROTATION_CURRENT, X.ROTATION_PENDING)]
    files += [activation + "/" + X.receipt_name(name)
              for name in X.map_names(info)]
    files.append(edit + "/" + X.EDIT_PENDING)
    return dict([(name, "dir") for name in dirs] +
                [(name, "file") for name in files])


def raw_context(value):
    raw = T.label_bytes(value)
    kind = raw.rstrip(b"\0").decode("ascii").split(":")[2]
    X.need(kind not in ("unlabeled_t", "default_t", "file_t"),
           "unsafe_private_policy_label")
    return raw.rstrip(b"\0")


def file_identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_size, st.st_nlink, st.st_mtime_ns, st.st_ctime_ns)


class PrivateStore:
    """A bound private-store scope. It never changes a parent directory.

    policy(relative, mode) returns a trusted raw-context hex string. Production
    adapters must bind relative paths to /var/lib and use real matchpathcon.
    The supplied guard must prove exclusive maintenance and that binding.
    """

    def __init__(self, parent, info, revision, uid, gid, guard, policy):
        X.need(callable(guard) and callable(policy) and type(gid) is int and gid >= 0,
               "private_policy_reader_required")
        self.parent, self.uid, self.gid = parent, uid, gid
        self.guard, self.policy = guard, policy
        self.paths = policy_paths(info, revision)
        self.revision = revision
        self.snapshot = R.BASE + "/" + revision
        self.anchor = self.parent_identity()

    def parent_identity(self):
        st = os.fstat(self.parent)
        X.need(stat.S_ISDIR(st.st_mode) and st.st_uid == self.uid and
               not st.st_mode & 0o022, "untrusted_private_parent")
        return (st.st_dev, st.st_ino, st.st_uid, st.st_mode, st.st_gid,
                T.file_label(self.parent))

    def check_anchor(self):
        self.guard()
        X.need(self.parent_identity() == self.anchor, "private_parent_changed")

    def label(self, relative, mode):
        X.need(self.paths.get(relative) == mode, "private_path_not_allowed")
        value = self.policy(relative, mode)
        raw_context(value)
        return value

    def directory(self, fd, relative):
        expected = self.label(relative, "dir")
        before = os.fstat(fd)
        X.need(stat.S_ISDIR(before.st_mode) and before.st_uid == self.uid and
               stat.S_IMODE(before.st_mode) == 0o700 and before.st_gid == self.gid,
               "untrusted_private_directory")
        actual = T.file_label(fd)
        X.need(actual is not None and raw_context(actual) == raw_context(expected) and
               file_identity(before) == file_identity(os.fstat(fd)),
               "private_directory_label_mismatch")
        return (before.st_dev, before.st_ino, before.st_mode,
                before.st_uid, before.st_gid, actual)

    def open_parent(self, relative, mode="file"):
        X.need(self.paths.get(relative) == mode, "private_path_not_allowed")
        parts = relative.split("/")
        fd = os.dup(self.parent)
        try:
            for index, part in enumerate(parts[:-1]):
                child = os.open(part, M.DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
                self.directory(fd, "/".join(parts[:index + 1]))
            return fd, parts[-1]
        except BaseException:
            os.close(fd)
            raise

    def open_directory(self, relative):
        parent, name = self.open_parent(relative, "dir")
        try:
            fd = os.open(name, M.DIR_FLAGS, dir_fd=parent)
            try:
                self.directory(fd, relative)
                return fd
            except BaseException:
                os.close(fd)
                raise
        finally:
            os.close(parent)

    def observe_directory(self, relative):
        self.check_anchor()
        fd = self.open_directory(relative)
        try:
            first = self.directory(fd, relative)
            self.check_anchor()
            other = self.open_directory(relative)
            try:
                X.need(self.directory(other, relative) == first,
                       "private_directory_changed")
            finally:
                os.close(other)
            return first
        finally:
            os.close(fd)

    def create_directory(self, relative):
        """Exclusive creation of a derived directory with its own label.

        Existing directories are never relabeled. An interrupted creation
        may leave a root-only incomplete directory, which is NOT considered
        a completed recovery record and requires explicit inspection.
        """
        self.check_anchor()
        parent, name = self.open_parent(relative, "dir")
        try:
            expected = self.label(relative, "dir")
            X.need(not T.exists(parent, name), "private_directory_already_exists")
            self.check_anchor()
            other, target = self.open_parent(relative, "dir")
            try:
                X.need(target == name and
                       (os.fstat(parent).st_dev, os.fstat(parent).st_ino) ==
                       (os.fstat(other).st_dev, os.fstat(other).st_ino) and
                       self.label(relative, "dir") == expected,
                       "private_directory_publication_context_changed")
            finally:
                os.close(other)
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
            fd = os.open(name, M.DIR_FLAGS, dir_fd=parent)
            try:
                created = os.fstat(fd)
                X.need(stat.S_ISDIR(created.st_mode) and created.st_uid == self.uid and
                       not created.st_mode & 0o077 and not os.listdir(fd),
                       "private_directory_creation_unverified")
                X.need(file_identity(created) ==
                       file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                       "private_directory_replaced")
                os.fchown(fd, self.uid, self.gid)
                os.fchmod(fd, 0o700)
                T.restore_file_metadata(fd, {"mode": 0o700, "gid": self.gid,
                                             "selinux": expected})
                os.fsync(fd)
                os.fsync(parent)
                result = self.directory(fd, relative)
                X.need(result[:2] == (created.st_dev, created.st_ino) and
                       self.label(relative, "dir") == expected and
                       self.observe_directory(relative) == result,
                       "private_directory_publication_unverified")
                return result
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    def limit(self, relative):
        return T.LIMIT if relative in {
            self.snapshot + "/" + name for name in R.FILES} else M.MAX_BYTES

    def metadata(self, fd, name, relative):
        expected = self.label(relative, "file")
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        data, meta = T.config_file(fd, name, self.uid, self.limit(relative))
        X.need(meta.get("mode") == 0o600 and meta.get("gid") == self.gid and
               meta.get("selinux") is not None and
               raw_context(meta["selinux"]) == raw_context(expected) and
               file_identity(before) ==
               file_identity(os.stat(name, dir_fd=fd, follow_symlinks=False)),
               "private_file_label_mismatch")
        return data, meta, file_identity(before)

    def observe(self, relative):
        """Read a bounded private record; return private evidence only."""
        self.check_anchor()
        fd, name = self.open_parent(relative)
        try:
            first = self.metadata(fd, name, relative)
            self.check_anchor()
            other, target = self.open_parent(relative)
            try:
                X.need((os.fstat(fd).st_dev, os.fstat(fd).st_ino) ==
                       (os.fstat(other).st_dev, os.fstat(other).st_ino) and
                       self.metadata(other, target, relative) == first,
                       "private_observation_changed")
            finally:
                os.close(other)
            return first
        finally:
            os.close(fd)

    def write_json(self, relative, value, previous=None):
        """Publish only mutable markers/overlay; no generic snapshot rewrite.

        previous=None requires absent target and exclusive creation. Otherwise
        the caller supplies its exact private observe() result. Existing raw
        label is preserved. Newly created files receive their own policy label.
        """
        allowed = ("/" + X.ROTATION_PENDING, "/" + X.ROTATION_CURRENT)
        X.need(relative in self.paths and
               (relative == X.EDIT_BASE + "/" + X.EDIT_PENDING or
                relative.endswith(allowed)), "private_record_not_mutable")
        return self._write(relative, M.canonical(value), previous)

    def _write(self, relative, data, previous=None):
        X.need(self.paths.get(relative) == "file" and type(data) is bytes and
               0 < len(data) <= self.limit(relative), "private_record_oversized_or_unknown")
        self.check_anchor()
        fd, name = self.open_parent(relative)
        try:
            policy = self.label(relative, "file")
            if previous is None:
                X.need(not T.exists(fd, name), "private_record_already_exists")
                meta = {"mode": 0o600, "gid": self.gid, "selinux": policy}
            else:
                X.need(self.metadata(fd, name, relative) == previous,
                       "private_record_changed")
                meta = previous[1]

            prepared = []

            def recheck(identity=None):
                self.check_anchor()
                other, target = self.open_parent(relative)
                try:
                    X.need((os.fstat(fd).st_dev, os.fstat(fd).st_ino) ==
                           (os.fstat(other).st_dev, os.fstat(other).st_ino) and
                           self.label(relative, "file") == policy,
                           "private_publication_context_changed")
                    if previous is None:
                        X.need(not T.exists(other, target), "private_record_already_exists")
                    else:
                        X.need(self.metadata(other, target, relative) == previous,
                               "private_record_changed")
                finally:
                    os.close(other)
                if identity is not None:
                    prepared[:] = identity

            recheck()
            T.atomic_write(fd, name, data, meta, self.uid, previous is not None,
                           before_replace=recheck if previous is not None else None,
                           before_publish=recheck if previous is None else None)
            # A post-publication mismatch must leave evidence for recovery;
            # never unlink an object whose identity/label is not proven.
            self.check_anchor()
            result = self.observe(relative)
            identity = result[2]
            X.need(prepared == [identity[0], identity[1], identity[5], identity[7]] and
                   result[0] == data and result[1] == meta and
                   self.label(relative, "file") == policy,
                   "private_record_publication_unverified")
            return result
        finally:
            os.close(fd)

    def snapshot_entries(self, allow_activation):
        self.check_anchor()
        fd = self.open_directory(self.snapshot)
        try:
            before = self.directory(fd, self.snapshot)
            entries = set(os.listdir(fd))
            required = set(R.FILES) | {R.MANIFEST}
            X.need(entries == required or
                   (allow_activation and entries == required | {R.ACTIVATION}),
                   "private_snapshot_incomplete")
            if R.ACTIVATION in entries:
                self.observe_directory(self.snapshot + "/" + R.ACTIVATION)
            X.need(set(os.listdir(fd)) == entries and
                   self.observe_directory(self.snapshot) == before,
                   "private_snapshot_directory_changed")
            return before, entries
        finally:
            os.close(fd)

    def read_snapshot(self, allow_activation=False):
        """Read and validate a complete private snapshot, including metadata."""
        before = self.snapshot_entries(allow_activation)
        names = R.FILES + (R.MANIFEST,)
        observed = {name: self.observe(self.snapshot + "/" + name) for name in names}
        raw = observed[R.MANIFEST][0]
        manifest = M.decode(raw)
        X.need(type(manifest) is dict and set(manifest) == {"revision", "snapshot"} and
               manifest["revision"] == self.revision and M.canonical(manifest) == raw,
               "invalid_private_snapshot_manifest")
        info = manifest["snapshot"]
        files = {name: observed[name][0] for name in R.FILES}
        R.validate(info, files)
        X.need(policy_paths(info, self.revision) == self.paths,
               "private_snapshot_scope_changed")
        X.need(self.snapshot_entries(allow_activation) == before and
               all(self.observe(self.snapshot + "/" + name) == observed[name]
                   for name in names) and self.snapshot_entries(allow_activation) == before,
               "private_snapshot_changed")
        return info, files

    def create_snapshot(self, info, files):
        """Publish an immutable snapshot before any live configuration writes.

        No credential DBs or map sources are included. If creation is
        interrupted, the incomplete revision is retained; it cannot be
        accepted by read_snapshot. Never overwrite an existing revision.
        """
        R.validate(info, files)
        X.need(R.labeled(info) and policy_paths(info, self.revision) == self.paths,
               "invalid_private_snapshot_scope")
        manifest = M.canonical({"revision": self.revision, "snapshot": info})
        X.need(len(manifest) <= M.MAX_BYTES and
               all(type(files[name]) is bytes and 0 < len(files[name]) <= T.LIMIT
                   for name in R.FILES), "private_snapshot_oversized")
        self.check_anchor()
        if T.exists(self.parent, R.BASE):
            self.observe_directory(R.BASE)
        else:
            self.create_directory(R.BASE)
        self.create_directory(self.snapshot)
        for name in R.FILES:
            self._write(self.snapshot + "/" + name, files[name])
        # Manifest is last: only a fully validated complete set can load.
        self._write(self.snapshot + "/" + R.MANIFEST, manifest)
        X.need(self.read_snapshot() == (info, files),
               "private_snapshot_publication_unverified")
        return self.revision

    def activation_observation(self):
        relative = self.snapshot + "/" + R.ACTIVATION
        self.check_anchor()
        fd = self.open_directory(relative)
        try:
            identity = self.directory(fd, relative)
            entries = set(os.listdir(fd))
            allowed = {path.rsplit("/", 1)[1] for path, mode in self.paths.items()
                       if mode == "file" and path.startswith(relative + "/")}
            X.need(X.JOURNAL in entries and entries <= allowed,
                   "private_activation_incomplete_or_foreign")
            records = {name: self.observe(relative + "/" + name)
                       for name in sorted(entries)}
            X.need(set(os.listdir(fd)) == entries and
                   self.observe_directory(relative) == identity and
                   all(self.observe(relative + "/" + name) == value
                       for name, value in records.items()) and
                   set(os.listdir(fd)) == entries,
                   "private_activation_changed")
            return identity, records
        finally:
            os.close(fd)

    def no_edit_pending(self):
        self.check_anchor()
        if T.exists(self.parent, X.EDIT_BASE):
            fd = self.open_directory(X.EDIT_BASE)
            try:
                X.need(not os.listdir(fd), "transport_edit_recovery_required")
                X.need(self.observe_directory(X.EDIT_BASE) ==
                       self.directory(fd, X.EDIT_BASE), "private_edit_directory_changed")
            finally:
                os.close(fd)

    def read_activation(self):
        """Read a complete, labeled journal with optional partial map receipts.

        Pending rotations/edits are refused; a future dedicated recovery
        reader must validate their marker schema and selected generations.
        Missing receipts are represented as None, never inferred from bytes.
        """
        self.no_edit_pending()
        info, files = self.read_snapshot(allow_activation=True)
        X.need(R.labeled(info), "private_activation_requires_v2")
        observed = self.activation_observation()
        records = observed[1]
        X.need(X.ROTATION_PENDING not in records, "credential_rotation_recovery_required")
        journal = X.parse_journal(records[X.JOURNAL][0], info, self.revision)
        receipts = {}
        for name in X.map_names(info):
            receipt = records.get(X.receipt_name(name))
            receipts[name] = (None if receipt is None else
                              X.parse_receipt(receipt[0], self.revision, name))
        if X.ROTATION_CURRENT in records:
            journal, receipts = X.parse_rotation_overlay(
                records[X.ROTATION_CURRENT][0], info, journal, receipts)
        self.no_edit_pending()
        X.need(self.read_snapshot(allow_activation=True) == (info, files) and
               self.activation_observation() == observed, "private_activation_changed")
        self.no_edit_pending()
        return info, files, journal, receipts

    def create_activation(self, databases, map_gid):
        """Create immutable labeled publication journal before live writes.

        databases must be the caller's already native-verified compiler result.
        Only digests are written; no database, source or password is stored.
        """
        self.no_edit_pending()
        info, files = self.read_snapshot()
        X.need(R.labeled(info), "private_activation_requires_v2")
        maps = X.native_database_set(info, databases)
        journal = X.journal_for(self.revision, info, files, maps, map_gid)
        raw = M.canonical(journal)
        X.parse_journal(raw, info, self.revision)
        relative = self.snapshot + "/" + R.ACTIVATION
        self.create_directory(relative)
        self._write(relative + "/" + X.JOURNAL, raw)
        X.need(self.read_activation() ==
               (info, files, journal, dict.fromkeys(maps)),
               "private_activation_publication_unverified")
        return journal

    def publish_map(self, config, name, data, reviewed, live_guard=None):
        """Exclusive first-install map publication and exact ownership receipt.

        Caller must still enforce stopped maintenance, native plan and
        exact live map policy in guard. This does not activate routing or
        modify either configuration file. A lost receipt is never recreated
        by adopting an equal-byte file; unknown maps require manual review.
        """
        self.no_edit_pending()
        record = self.read_activation()
        X.need(record == reviewed, "private_activation_review_changed")
        info, files, journal, receipts = record
        X.need(name in X.map_names(info) and receipts[name] is None and
               type(data) is bytes and 0 < len(data) <= M.MAX_DB_BYTES and
               M.digest(data) == journal["maps"][name],
               "private_map_publication_not_reviewed")
        activation = self.snapshot + "/" + R.ACTIVATION
        X.need(X.ROTATION_CURRENT not in self.activation_observation()[1],
               "private_map_publication_after_rotation")
        X.assert_pair(config, info, files, ".before", self.uid)
        X.check_sources(config, info)
        X.need(not T.exists(config, name), "managed_map_destination_exists")
        for present in X.map_names(info):
            if receipts[present] is None:
                X.need(not T.exists(config, present), "map_publication_unproven")
            else:
                X.checked_map(config, present, journal, receipts[present], self.uid)
        prepared, published = [], []

        def before_link(identity):
            self.check_anchor()
            if live_guard is not None:
                live_guard(identity)
            X.need(self.read_activation() == record and
                   not T.exists(config, name), "private_map_publication_context_changed")
            X.assert_pair(config, info, files, ".before", self.uid)
            X.check_sources(config, info)
            for other in X.map_names(info):
                if receipts[other] is None:
                    X.need(not T.exists(config, other), "map_publication_unproven")
                else:
                    X.checked_map(config, other, journal, receipts[other], self.uid)
            prepared[:] = [identity]

        T.atomic_write(config, name, data, X.map_meta(journal, name), self.uid, False,
                       published.append, before_publish=before_link)
        identity = T.file_identity(os.stat(name, dir_fd=config, follow_symlinks=False))
        X.need(prepared == published == [identity[:4]], "private_map_publication_unproven")
        self.check_anchor()
        if live_guard is not None:
            live_guard()
        X.need(self.read_activation() == record, "private_activation_review_changed")
        X.assert_pair(config, info, files, ".before", self.uid)
        X.check_sources(config, info)
        X.checked_map(config, name, journal, identity, self.uid)
        value = {"revision": self.revision, "name": name, "identity": identity}
        receipt_path = activation + "/" + X.receipt_name(name)
        self._write(receipt_path, M.canonical(value))
        expected = (info, files, journal, dict(receipts, **{name: identity}))
        X.need(self.read_activation() == expected, "private_map_receipt_unverified")
        X.checked_map(config, name, journal, identity, self.uid)
        return identity

    def live_guard(self, config, info, read_policy, prepared=None):
        """Recheck the exact prospective live policy, not only stored labels.

        The bound host guard still must prove stopped maintenance, the
        directory binding, empty queues and exclusive access. No kernel
        authorization or service-start permission is inferred from labels.
        """
        self.check_anchor()
        self.no_edit_pending()
        X.need(R.labeled(info) and callable(read_policy) and
               policy_paths(info, self.revision) == self.paths,
               "labeled_live_policy_required")
        X.need(T.context(config, self.uid) == info["identity"],
               "wrong_config_directory")
        R.directory_metadata(config, info)
        expected = dict(info["map_selinux"])
        expected["."] = info["directory_selinux"]
        for name, meta in zip(X.CONFIGS, info["metadata"]):
            expected[name + ".cf"] = meta["selinux"]
        current = read_policy(info["rules"], info["backend"])
        X.need(type(current) is dict and set(current) == set(expected) and
               all(R.label_context(current[name]) == R.label_context(value)
                   for name, value in expected.items()), "live_selinux_policy_changed")
        scratch = [name for name in os.listdir(config)
                   if name.startswith(".lmr365-txn-")]
        if prepared is None:
            X.need(not scratch, "orphan_live_transaction_scratch")
        else:
            X.need(len(scratch) == 1 and
                   T.file_identity(os.stat(scratch[0], dir_fd=config,
                                           follow_symlinks=False))[:4] == prepared,
                   "unexpected_live_transaction_scratch")
        self.check_anchor()

    def live_record(self, config, reviewed, read_policy, prepared=None):
        self.live_guard(config, reviewed[0], read_policy, prepared)
        X.need(self.read_activation() == reviewed, "private_activation_review_changed")
        state = X.restorable(config, *reviewed, self.uid)
        self.live_guard(config, reviewed[0], read_policy, prepared)
        return state

    def replace_configuration(self, config, reviewed, state, index, data,
                              read_policy, require_all_maps=False):
        """One atomic configuration replacement with fresh policy/readback."""
        info, files, journal, receipts = reviewed

        def check(prepared=None):
            X.need(self.live_record(config, reviewed, read_policy, prepared) == state,
                   "live_configuration_changed")
            if require_all_maps:
                for name in X.map_names(info):
                    X.checked_map(config, name, journal, receipts[name], self.uid)

        check()
        name = X.CONFIGS[index] + ".cf"
        meta = state[index][1]
        if state[index][0] != data:
            T.atomic_write(config, name, data, meta, self.uid, True,
                           before_replace=check)
        result = list(state)
        result[index] = (data, meta)
        result = tuple(result)
        X.need(self.live_record(config, reviewed, read_policy) == result,
               "live_configuration_publication_unverified")
        return result

    def restore_reviewed(self, config, reviewed, read_policy, verify, confirmation):
        """Offline restore using labeled private journal and map receipts.

        Only an exact reviewed record may be restored. Refuses unknown maps
        before modifying configuration. Disconnect routes before removing
        services/maps. Failed or interrupted cleanup can be reviewed again.
        """
        X.need(confirmation == X.RESTORE and callable(verify),
               "typed_restore_confirmation_required")
        info, files, journal, receipts = reviewed
        state = self.live_record(config, reviewed, read_policy)
        for index, name in enumerate(X.CONFIGS):
            state = self.replace_configuration(
                config, reviewed, state, index, files[name + ".before"], read_policy)
        expected = X.expected_pair(info, files, ".before")
        X.need(state == expected and verify(False, info) is True,
               "restored_native_policy_unverified")
        X.need(self.live_record(config, reviewed, read_policy) == expected,
               "restored_configuration_changed")
        for name in X.map_names(info):
            X.need(self.live_record(config, reviewed, read_policy) == expected,
                   "recovery_drift_before_cleanup")
            if T.exists(config, name):
                X.checked_map(config, name, journal, receipts[name], self.uid)
                os.unlink(name, dir_fd=config)
                os.fsync(config)
        X.need(self.live_record(config, reviewed, read_policy) == expected and
               not any(T.exists(config, name) for name in X.map_names(info)) and
               verify(False, info) is True, "restored_generation_unverified")
        X.need(self.live_record(config, reviewed, read_policy) == expected and
               not any(T.exists(config, name) for name in X.map_names(info)),
               "restored_generation_changed")
        return self.revision

    def apply_reviewed(self, config, reviewed, databases, map_gid, read_policy,
                       verify, fresh_review, confirmation):
        """First-install labeled transaction; deliberately library-only.

        Native-verified candidate DBs, real policy readers and maintenance
        guard must be supplied by a trusted caller. No daemon control,
        package install, SMTP delivery or policy modification occurs.
        """
        X.need(confirmation == X.APPLY and callable(verify) and callable(fresh_review),
               "typed_apply_confirmation_required")
        info, files = reviewed
        R.validate(info, files)
        maps = X.native_database_set(info, databases)
        X.need(type(map_gid) is int and map_gid >= 0, "invalid_map_group")

        def fresh():
            self.live_guard(config, info, read_policy)
            X.need(fresh_review() == reviewed, "review_changed")
            X.assert_pair(config, info, files, ".before", self.uid)
            X.check_sources(config, info)
            X.need(not any(T.exists(config, name) for name in maps),
                   "managed_map_destination_exists")

        fresh()
        self.create_snapshot(info, files)
        journal = self.create_activation(databases, map_gid)
        record = self.read_activation()
        X.need(record == (info, files, journal, dict.fromkeys(maps)),
               "private_activation_publication_unverified")
        try:
            fresh()
            for name, data in sorted(maps.items()):
                self.live_guard(config, info, read_policy)
                identity = self.publish_map(
                    config, name, data, record,
                    live_guard=lambda prepared=None: self.live_guard(
                        config, info, read_policy, prepared))
                record = (info, files, journal, dict(record[3], **{name: identity}))
                X.need(self.read_activation() == record,
                       "private_map_receipt_unverified")
            state = self.live_record(config, record, read_policy)
            X.need(state == X.expected_pair(info, files, ".before"),
                   "live_configuration_changed")
            for index in (1, 0):
                name = X.CONFIGS[index]
                state = self.replace_configuration(
                    config, record, state, index, files[name + ".after"],
                    read_policy, require_all_maps=True)
            expected = X.expected_pair(info, files, ".after")
            X.need(state == expected and verify(True, info) is True,
                   "installed_native_policy_unverified")
            X.need(self.live_record(config, record, read_policy) == expected,
                   "installed_generation_changed")
            for name in maps:
                X.checked_map(config, name, journal, record[3][name], self.uid)
        except Exception:
            try:
                self.restore_reviewed(config, self.read_activation(), read_policy,
                                      verify, X.RESTORE)
            except Exception:
                # Never log private configuration, database bytes or policy
                # diagnostics in an exception returned to a future host CLI.
                raise X.ApplyFailed(self.revision, False) from None
            raise X.ApplyFailed(self.revision, True) from None
        return self.revision


if __name__ == "__main__":
    raise SystemExit("Private policy-bound recovery store library only.")
