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

    def open_parent(self, relative):
        X.need(self.paths.get(relative) == "file", "private_path_not_allowed")
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

    def metadata(self, fd, name, relative):
        expected = self.label(relative, "file")
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        data, meta = T.config_file(fd, name, self.uid, M.MAX_BYTES)
        X.need(meta.get("mode") == 0o600 and meta.get("gid") == self.gid and
               meta.get("selinux") is not None and
               raw_context(meta["selinux"]) == raw_context(expected) and
               file_identity(before) ==
               file_identity(os.stat(name, dir_fd=fd, follow_symlinks=False)),
               "private_file_label_mismatch")
        return data, meta, file_identity(before)

    def observe(self, relative):
        """Read a single bounded private JSON file; return private evidence only."""
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
        data = M.canonical(value)
        X.need(0 < len(data) <= M.MAX_BYTES, "private_record_oversized")
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

            def recheck(_prepared=None):
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

            recheck()
            T.atomic_write(fd, name, data, meta, self.uid, previous is not None,
                           before_replace=recheck if previous is not None else None)
            # A post-publication mismatch must leave evidence for recovery;
            # never unlink an object whose identity/label is not proven.
            self.check_anchor()
            result = self.observe(relative)
            X.need(result[0] == data and result[1] == meta and
                   self.label(relative, "file") == policy,
                   "private_record_publication_unverified")
            return result
        finally:
            os.close(fd)


if __name__ == "__main__":
    raise SystemExit("Private policy-bound recovery store library only.")
