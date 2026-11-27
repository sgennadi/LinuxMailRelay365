#!/usr/bin/env python3
"""Experimental two-file transaction core; CLI in manage-primary-mailbox-offline.py.

Mandatory caller guards must establish exclusive maintenance, stopped
single primary Postfix, empty queues, trusted installed OAuth runtime and
fresh no-mail SMTP AUTH. Unlabelled v1 or explicitly policy-bound SELinux v2.
The production CLI still refuses active SELinux until native acceptance.
"""
from contextlib import contextmanager
import importlib.util
import os
import stat
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


def normalized_label(value):
    raw = T.label_bytes(value).rstrip(b"\0")
    need(raw.decode("ascii").split(":")[2] not in
         ("default_t", "unlabeled_t", "file_t", "etc_t", "usr_t"),
         "unsafe_transaction_policy_context")
    return raw


def same_label(actual, expected):
    need(actual is not None and normalized_label(actual) == normalized_label(expected),
         "selinux_label_policy_mismatch")


def valid_selinux_evidence(value):
    need(type(value) is dict and set(value) == {
        "mode", "config_directory", "recovery_parent", "recovery_parent_identity", "recovery_gid"
    } and value["mode"] == "enforcing", "invalid_selinux_transaction_evidence")
    normalized_label(value["config_directory"])
    normalized_label(value["recovery_parent"])
    identity = value["recovery_parent_identity"]
    need(type(identity) is list and len(identity) == 2 and
         all(type(v) is int and v >= 0 for v in identity) and
         type(value["recovery_gid"]) is int and value["recovery_gid"] >= 0,
         "invalid_selinux_recovery_anchor")


class SelinuxPolicy:
    """Private v2 adapter; NOT wired into the production CLI.

    Only a bound Enforcing host, exact current file contexts and a uniform
    non-generic recovery-tree policy are accepted. The caller supplies a
    trusted exact-path matchpathcon reader, live mode reader and exclusive
    maintenance guard. The policy reader returns the raw context as hex.
    Existing labels are never repaired. Only newly created objects may be
    labelled, and only with their independently verified destination context.
    """
    def __init__(self, config, parent, uid, mode_reader, policy_reader):
        need(callable(mode_reader) and callable(policy_reader), "explicit_policy_reader_required")
        self.config, self.parent, self.uid = config, parent, uid
        self.mode_reader, self.policy_reader = mode_reader, policy_reader
        self.config_anchor = T.context(config, uid)
        self.parent_anchor = T.context(parent, uid)
        self.gid = os.fstat(parent).st_gid
        self.initial = self.evidence()

    def policy(self, path, kind):
        value = self.policy_reader(path, kind)
        normalized_label(value)
        return value

    def directory(self, fd, path, private=False):
        M.check_directory(fd, self.uid, private)
        before = os.fstat(fd)
        label = T.file_label(fd)
        same_label(label, self.policy(path, "dir"))
        if private:
            need(before.st_gid == self.gid, "private_recovery_group_mismatch")
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid) ==
             (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid) and
             T.file_label(fd) == label, "selinux_directory_metadata_changed")
        return label

    def evidence(self):
        need(self.mode_reader() == "enforcing", "selinux_enforcing_required")
        need(T.context(self.config, self.uid) == self.config_anchor and
             T.context(self.parent, self.uid) == self.parent_anchor and
             os.fstat(self.parent).st_gid == self.gid, "selinux_anchor_changed")
        config_label = self.directory(self.config, "/etc/postfix")
        parent_label = self.directory(self.parent, "/var/lib")
        same_label(parent_label, self.policy("/var/lib/"+BASE, "dir"))
        need(self.mode_reader() == "enforcing", "selinux_mode_changed")
        result = {"mode":"enforcing","config_directory":config_label,
                  "recovery_parent":parent_label,"recovery_parent_identity":self.parent_anchor,
                  "recovery_gid":self.gid}
        valid_selinux_evidence(result)
        return result

    def check(self, config, uid, current, info=None):
        need(config == self.config and uid == self.uid, "selinux_config_binding_changed")
        evidence = self.evidence()
        need(evidence == self.initial, "selinux_policy_anchor_changed")
        for name, (_, meta) in zip(NAMES, current):
            T.valid_meta(meta, True)
            same_label(meta["selinux"], self.policy("/etc/postfix/"+name,"file"))
        if info is not None:
            need(info.get("version")==2 and info.get("selinux")==evidence and
                 current[0][1]==info["main_meta"] and current[1][1]==info["master_meta"],
                 "selinux_reviewed_metadata_changed")
        need(self.evidence() == evidence, "selinux_policy_changed")
        return evidence

    def recovery_label(self, relative, kind):
        # Only fixed derived paths reach the trusted policy reader. Pin the
        # uniform private-tree policy to the original /var/lib raw context.
        label = self.initial["recovery_parent"]
        same_label(label, self.policy("/var/lib/"+relative,kind))
        return label

    def private_paths(self, revision):
        need(sha(revision), "invalid_recovery_sha")
        folder = BASE+"/"+revision
        paths = {BASE:"dir",folder:"dir"}
        paths.update({folder+"/"+name:"file" for name in FILES+(MANIFEST,)})
        for path,kind in paths.items():
            self.recovery_label(path,kind)
        return folder

    def check_private_dir(self, fd, relative):
        expected = self.recovery_label(relative,"dir")
        need(self.directory(fd,"/var/lib/"+relative,True)==expected,
             "private_recovery_directory_label_changed")

    def open_private_dir(self, parent, name, relative, create, existing_ok=False):
        expected = self.recovery_label(relative,"dir")
        created = False
        if create:
            try:
                os.mkdir(name,0o700,dir_fd=parent)
                created=True
                os.fsync(parent)
            except FileExistsError:
                need(existing_ok,"recovery_revision_already_exists")
        fd=os.open(name,M.DIR_FLAGS,dir_fd=parent)
        try:
            if created:
                st=os.fstat(fd)
                M.check_directory(fd,self.uid,True)
                need(not os.listdir(fd) and
                     [st.st_dev,st.st_ino]==T.context(fd,self.uid) and
                     (st.st_dev,st.st_ino)==self.path_identity(parent,name),
                     "private_directory_creation_unverified")
                os.fchown(fd,self.uid,self.gid)
                os.fchmod(fd,0o700)
                T.restore_file_metadata(fd,{"mode":0o700,"gid":self.gid,"selinux":expected})
                os.fsync(fd)
                os.fsync(parent)
            self.check_private_dir(fd,relative)
            need(tuple(T.context(fd,self.uid))==self.path_identity(parent,name),
                 "private_directory_replaced")
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def path_identity(parent,name):
        st=os.stat(name,dir_fd=parent,follow_symlinks=False)
        need(stat.S_ISDIR(st.st_mode),"private_directory_replaced")
        return (st.st_dev,st.st_ino)

    @contextmanager
    def folder(self, parent, revision, uid, create=False):
        need(parent==self.parent and uid==self.uid and self.evidence()==self.initial,
             "selinux_recovery_binding_changed")
        relative=self.private_paths(revision)
        base=self.open_private_dir(parent,BASE,BASE,create,existing_ok=True)
        try:
            fd=self.open_private_dir(base,revision,relative,create)
            try:
                def verify():
                    need(self.evidence()==self.initial,"selinux_recovery_policy_changed")
                    self.private_paths(revision)
                    self.check_private_dir(base,BASE)
                    self.check_private_dir(fd,relative)
                    need(tuple(T.context(base,uid))==self.path_identity(parent,BASE) and
                         tuple(T.context(fd,uid))==self.path_identity(base,revision),
                         "private_recovery_path_changed")
                verify()
                yield fd,relative,verify
                verify()
            finally:
                os.close(fd)
        finally:
            os.close(base)

    def read_private(self, fd, relative, name, limit):
        expected=self.recovery_label(relative+"/"+name,"file")
        data,meta=T.config_file(fd,name,self.uid,limit)
        need(meta=={"mode":0o600,"gid":self.gid,"selinux":expected},
             "private_recovery_file_metadata_changed")
        return data

    def save(self,parent,revision,info,files,uid):
        self.check(self.config,uid,snapshot(self.config,uid,self),info)
        with self.folder(parent,revision,uid,create=True) as (fd,relative,verify):
            for name in FILES+(MANIFEST,):
                verify()
                expected=self.recovery_label(relative+"/"+name,"file")
                data=files[name] if name!=MANIFEST else M.canonical(info)
                def before_publish(_):
                    verify()
                    need(self.recovery_label(relative+"/"+name,"file")==expected and
                         not T.exists(fd,name),"private_publication_context_changed")
                T.atomic_write(fd,name,data,{"mode":0o600,"gid":self.gid,"selinux":expected},
                               uid,False,before_publish=before_publish)
                need(self.read_private(fd,relative,name,T.LIMIT if name!=MANIFEST else M.MAX_BYTES)==data,
                     "private_recovery_file_readback_failed")
            os.fsync(fd)


def snapshot(config, uid, selinux=None):
    result = tuple(T.config_file(config, name, uid) for name in NAMES)
    for _, meta in result:
        T.valid_meta(meta, selinux is not None)
    if selinux is not None:
        selinux.check(config, uid, result)
    return result


def exact_phase(info, files, phase):
    return ((files["main."+phase], info["main_meta"]),
            (files["master."+phase], info["master_meta"]))


def review(config, uid, mailbox, guard, runtime_guard, sampler=R.sample,
           identity_reader=R.identity_snapshot, native_compare=R.native_candidate_snapshots,
           selinux=None):
    """runtime_guard(mailbox) returns a stable trusted runtime/SMTP AUTH SHA.

    The experimental manage-primary-mailbox-offline.py CLI
    supplies the software-PEM or managed persistent TPM2 implementation of this callback.
    """
    R.parse(R.encode({"mailbox": mailbox, "nonce": "0"*64}))
    guard()
    context = T.context(config, uid)
    current = snapshot(config, uid, selinux)
    labels = selinux.check(config,uid,current) if selinux is not None else None
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
    info = {"version": 2 if labels is not None else 1, "mailbox": mailbox, "config_identity": context,
            "main_meta": current[0][1], "master_meta": current[1][1],
            "identity_sha256": identity[1], "certificate_sha256": identity[2],
            "runtime_sha256": runtime, "native_before_sha256": digest(before),
            "native_after_sha256": digest(after),
            "files": {k: M.digest(v) for k,v in files.items()}}
    if labels is not None:
        info["selinux"]=labels
    guard()
    need(T.context(config, uid) == context and snapshot(config, uid, selinux) == current and
         sampler() == sampled and identity_reader(mailbox) == identity and
         runtime_guard(mailbox) == runtime and snapshot(config, uid, selinux) == current,
         "review_context_changed")
    if selinux is not None:
        selinux.check(config,uid,current,info)
    return digest(info), info, files


def validate_backup(revision, info, files):
    keys = {"version","mailbox","config_identity","main_meta","master_meta",
            "identity_sha256","certificate_sha256","runtime_sha256",
            "native_before_sha256","native_after_sha256","files"}
    need(sha(revision) and type(info) is dict and type(info.get("version")) is int and
         info["version"] in (1,2) and
         set(info) == (keys | {"selinux"} if info["version"]==2 else keys) and
         digest(info) == revision, "invalid_backup_manifest")
    labeled=info["version"]==2
    if labeled:
        valid_selinux_evidence(info["selinux"])
    R.parse(R.encode({"mailbox": info["mailbox"], "nonce": "0"*64}))
    need(type(info["config_identity"]) is list and len(info["config_identity"]) == 2 and
         all(type(x) is int and x >= 0 for x in info["config_identity"]),
         "invalid_backup_directory_identity")
    for key in ("identity_sha256","certificate_sha256","runtime_sha256",
                "native_before_sha256","native_after_sha256"):
        need(sha(info[key]), "invalid_backup_evidence")
    for key in ("main_meta","master_meta"):
        T.valid_meta(info[key],labeled)
        if labeled:
            normalized_label(info[key]["selinux"])
    need(set(files) == set(FILES) and all(type(v) is bytes and 0 < len(v) <= T.LIMIT
         for v in files.values()) and info["files"] == {k:M.digest(v) for k,v in files.items()},
         "backup_file_integrity_failed")
    need(files["main.before"] != files["main.after"] and
         files["master.after"] == files["master.before"] +
         (b"" if files["master.before"].endswith(b"\n") else b"\n") + R.PIPE,
         "invalid_two_file_backup_transition")


def save_backup(parent, revision, info, files, uid, selinux=None):
    validate_backup(revision, info, files)
    need((info["version"]==2)==(selinux is not None),"explicit_backup_policy_required")
    if selinux is not None:
        return selinux.save(parent,revision,info,files,uid)
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


def load_backup(parent, revision, uid, selinux=None):
    need(sha(revision), "invalid_recovery_sha")
    if selinux is not None:
        with selinux.folder(parent,revision,uid) as (fd,relative,verify):
            need(set(os.listdir(fd))==set(FILES)|{MANIFEST},"incomplete_or_foreign_backup")
            raw=selinux.read_private(fd,relative,MANIFEST,M.MAX_BYTES)
            info=M.decode(raw)
            need(M.canonical(info)==raw,"noncanonical_backup_manifest")
            files={name:selinux.read_private(fd,relative,name,T.LIMIT) for name in FILES}
            validate_backup(revision,info,files)
            need(info["version"]==2,"explicit_backup_policy_required")
            selinux.check(selinux.config,uid,snapshot(selinux.config,uid,selinux),info)
            verify()
            need(set(os.listdir(fd))==set(FILES)|{MANIFEST},"incomplete_or_foreign_backup")
            return info,files
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
            need(info["version"]==1,"explicit_backup_policy_required")
            return info, files
        finally:
            os.close(folder)
    finally:
        os.close(base)


def phase(config, uid, info, files, selinux=None):
    need((info["version"]==2)==(selinux is not None),"explicit_transaction_policy_required")
    need(T.context(config, uid) == info["config_identity"], "configuration_directory_changed")
    current = snapshot(config, uid, selinux)
    if selinux is not None:
        selinux.check(config,uid,current,info)
    old, new = exact_phase(info, files, "before"), exact_phase(info, files, "after")
    if current == old:
        return "before"
    if current == new:
        return "after"
    if current == (old[0], new[1]):
        return "pipe_only"
    raise Refused("foreign_or_impossible_configuration_drift")


def verify(config, uid, info, files, expected, guard, read_native, selinux=None):
    guard()
    need(phase(config, uid, info, files, selinux) == expected, "unexpected_configuration_phase")
    need(digest(read_native()) == info["native_"+expected+"_sha256"],
         "native_effective_configuration_mismatch")
    guard()
    need(phase(config, uid, info, files, selinux) == expected, "configuration_changed_during_native_readback")


def replace(config, uid, info, files, before, after, name, target, guard, selinux=None):
    key = ("main", "master")[NAMES.index(name)]
    def before_replace(_prepared):
        guard()
        need(phase(config, uid, info, files, selinux) == before, "drift_before_atomic_replace")
    before_replace(None)
    T.atomic_write(config, name, files[key+"."+target], info[key+"_meta"],
                   uid, True, before_replace=before_replace)
    guard()
    need(phase(config, uid, info, files, selinux) == after, "post_replace_integrity_failed")


def restore(config, parent, revision, uid, confirmation, guard, read_native, selinux=None):
    need(confirmation == RESTORE, "typed_restore_confirmation_required")
    info, files = load_backup(parent, revision, uid, selinux)
    guard()
    current = phase(config, uid, info, files, selinux)
    if current == "after":
        replace(config, uid, info, files, "after", "pipe_only", "main.cf", "before", guard, selinux)
        current = "pipe_only"
    if current == "pipe_only":
        replace(config, uid, info, files, "pipe_only", "before", "master.cf", "before", guard, selinux)
    verify(config, uid, info, files, "before", guard, read_native, selinux)
    return revision


def apply(config, parent, reviewed, uid, confirmation, guard, fresh, read_native,
          runtime_guard, selinux=None):
    need(confirmation == APPLY and sha(reviewed), "typed_reviewed_apply_required")
    revision, info, files = fresh()
    need(revision == reviewed, "reviewed_plan_changed")
    save_backup(parent, revision, info, files, uid, selinux)
    need(load_backup(parent, revision, uid, selinux) == (info, files), "backup_verification_failed")
    need(fresh() == (revision, info, files), "drift_during_backup")
    verify(config, uid, info, files, "before", guard, read_native, selinux)
    need(runtime_guard(info["mailbox"]) == info["runtime_sha256"], "runtime_changed_before_apply")
    try:
        replace(config, uid, info, files, "before", "pipe_only", "master.cf", "after", guard, selinux)
        need(runtime_guard(info["mailbox"]) == info["runtime_sha256"],
             "runtime_changed_before_route_switch")
        replace(config, uid, info, files, "pipe_only", "after", "main.cf", "after", guard, selinux)
        verify(config, uid, info, files, "after", guard, read_native, selinux)
        need(runtime_guard(info["mailbox"]) == info["runtime_sha256"], "runtime_changed_after_apply")
        guard()
        need(phase(config, uid, info, files, selinux) == "after", "post_apply_integrity_failed")
    except Exception:
        try:
            restore(config, parent, revision, uid, RESTORE, guard, read_native, selinux)
        except Exception as error:
            raise T.RollbackRequired("manual_recovery_required; backup="+revision) from error
        raise
    return revision


if __name__ == "__main__":
    raise SystemExit("Transaction core only; use the explicitly approved offline manager.")
