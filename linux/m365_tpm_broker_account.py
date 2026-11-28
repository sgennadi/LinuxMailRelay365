"""Native dedicated account stage for the disabled primary TPM broker.

No CLI. The coordinator must reserve reviewed local numeric IDs, persist the
AccountSpec, hold exclusive maintenance and journal intent, and verify that
no unrelated file ownership or external account references use those IDs.
The backend refuses ambiguous partial or drifted states; it never repairs
accounts or deletes home directories. Linux/Python 3.6+.
"""
from collections import namedtuple
import grp
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

import m365_tpm_broker_service as service
import m365_tpm_broker_transaction as tx

SIGNER = service.SIGNER_ACCOUNT
MAIL = service.MAIL_ACCOUNT
HOME = "/nonexistent"
SHELL = "/sbin/nologin"
COMMENT = "LinuxMailRelay365 TPM broker"
TOOLS = {"groupadd": "/usr/sbin/groupadd", "useradd": "/usr/sbin/useradd",
         "userdel": "/usr/sbin/userdel", "groupdel": "/usr/sbin/groupdel"}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"}
LOCKED = {"!", "!!", "*"}
LIMIT = 4 * 1024 * 1024
Spec = namedtuple("AccountSpec", "uid gid mail_uid mail_gid mail_members")
Refused = tx.Refused
need = tx.need


def validate(spec):
    need(isinstance(spec, Spec) and
         all(type(n) is int and 0 < n < 65536 for n in spec[:4]) and
         201 <= spec.uid <= 999 and 201 <= spec.gid <= 999 and
         spec.uid != spec.mail_uid and spec.gid != spec.mail_gid and
         type(spec.mail_members) is tuple and spec.mail_members in ((), (MAIL,)),
         "broker_account_invalid_spec")
    return spec


def read_root_file(path, private=False):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
         before.st_nlink == 1 and not before.st_mode & 0o6022 and
         (not private or not before.st_mode & 0o007) and
         0 <= before.st_size <= LIMIT, "broker_account_unsafe_local_database")
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        stamp = tx.metadata(before)
        need(tx.metadata(os.fstat(stream.fileno())) == stamp,
             "broker_account_database_changed")
        raw = stream.read(LIMIT + 1)
        need(len(raw) == before.st_size and len(raw) <= LIMIT and
             tx.metadata(os.fstat(stream.fileno())) == stamp and
             tx.metadata(path.lstat()) == stamp, "broker_account_database_changed")
    return raw.decode("utf-8", "strict")


def rows(raw, fields):
    result = {}
    for line in raw.splitlines():
        if not line:
            continue
        parts = line.split(":")
        name = parts[0]
        need(len(parts) == fields and re.fullmatch(r"[A-Za-z0-9_.-]+\$?", name) and
             name not in result, "broker_account_local_database_unverified")
        result[name] = tuple(parts[1:])
    return result


def members(raw):
    result = tuple(sorted(raw.split(","))) if raw else ()
    need(len(result) == len(set(result)) and all(result),
         "broker_account_group_members_unverified")
    return result


def local_inventory():
    # No password values leave the private local inventory. Only fixed
    # structural/locked-state checks are used in the stage fingerprint.
    etc = Path("/etc")
    meta = etc.lstat()
    need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and
         not meta.st_mode & 0o6022, "broker_account_unsafe_etc")
    return (rows(read_root_file(etc / "passwd"), 7),
            rows(read_root_file(etc / "group"), 4),
            rows(read_root_file(etc / "shadow", private=True), 9),
            rows(read_root_file(etc / "gshadow", private=True), 4))


def numeric(value):
    need(re.fullmatch(r"[0-9]{1,10}", value) is not None,
         "broker_account_numeric_id_unverified")
    return int(value)


def no_extra_local_references(spec, passwd, groups):
    need(all(name == SIGNER or numeric(row[1]) != spec.uid
             for name, row in passwd.items()) and
         all(name == SIGNER or numeric(row[2]) != spec.gid
             for name, row in passwd.items()) and
         all(name == SIGNER or numeric(row[1]) != spec.gid
             for name, row in groups.items()) and
         all(name == MAIL or SIGNER not in members(row[2])
             for name, row in groups.items()), "broker_account_local_id_or_membership_conflict")


def classify_local(spec, inventory):
    validate(spec)
    passwd, groups, shadow, gshadow = inventory
    no_extra_local_references(spec, passwd, groups)
    need(MAIL in passwd and MAIL in groups and MAIL in gshadow and
         numeric(passwd[MAIL][1]) == spec.mail_uid and
         numeric(passwd[MAIL][2]) == spec.mail_gid and
         numeric(groups[MAIL][1]) == spec.mail_gid and
         groups[MAIL][0] == "x" and gshadow[MAIL][0] in LOCKED and
         gshadow[MAIL][1] == "" and
         members(groups[MAIL][2]) == members(gshadow[MAIL][2]),
         "broker_account_mail_group_unverified")
    user, group = SIGNER in passwd, SIGNER in groups
    need((SIGNER in shadow) == user and (SIGNER in gshadow) == group and
         (not user or group), "broker_account_partial_or_foreign")
    expected_members = tuple(sorted(spec.mail_members + ((SIGNER,) if user else ())))
    need(members(groups[MAIL][2]) == expected_members,
         "broker_account_mail_membership_changed")
    if group:
        need(groups[SIGNER] == ("x", str(spec.gid), "") and
             gshadow[SIGNER][0] in LOCKED and gshadow[SIGNER][1:] == ("", ""),
             "broker_account_signer_group_changed")
    if user:
        expected = ("x", str(spec.uid), str(spec.gid), COMMENT, HOME, SHELL)
        s = shadow[SIGNER]
        # System user: locked password, no aging/expiry/inactivity settings.
        # Different distro-generated lock markers and last-change dates are
        # equivalent only while the account remains locked and non-login.
        need(passwd[SIGNER] == expected and s[0] in LOCKED and
             (s[1] == "" or re.fullmatch(r"[0-9]{1,10}", s[1])) and
             s[2:] == ("",) * 6, "broker_account_signer_user_changed")
        return "installed"
    return "group_only" if group else "absent"


def lookup(function, argument):
    try:
        return function(argument)
    except KeyError:
        return None


def verify_nss(spec, state):
    mail = pwd.getpwnam(MAIL)
    group = grp.getgrnam(MAIL)
    expected_members = tuple(sorted(spec.mail_members +
                             ((SIGNER,) if state == "installed" else ())))
    need((mail.pw_uid, mail.pw_gid, group.gr_gid) ==
         (spec.mail_uid, spec.mail_gid, spec.mail_gid) and
         tuple(sorted(group.gr_mem)) == expected_members and
         set(os.getgrouplist(MAIL, spec.mail_gid)) == {spec.mail_gid} and
         pwd.getpwuid(spec.mail_uid).pw_name == MAIL and
         grp.getgrgid(spec.mail_gid).gr_name == MAIL,
         "broker_account_nss_mail_conflict")
    user = lookup(pwd.getpwnam, SIGNER)
    numeric_user = lookup(pwd.getpwuid, spec.uid)
    signer_group = lookup(grp.getgrnam, SIGNER)
    numeric_group = lookup(grp.getgrgid, spec.gid)
    if state == "installed":
        need(user is not None and numeric_user == user and
             (user.pw_name, user.pw_passwd, user.pw_uid, user.pw_gid,
              user.pw_gecos, user.pw_dir, user.pw_shell) ==
             (SIGNER, "x", spec.uid, spec.gid, COMMENT, HOME, SHELL) and
             set(os.getgrouplist(SIGNER, spec.gid)) == {spec.gid, spec.mail_gid},
             "broker_account_nss_signer_conflict")
    else:
        need(user is None and numeric_user is None, "broker_account_uid_conflict")
    if state == "absent":
        need(signer_group is None and numeric_group is None, "broker_account_gid_conflict")
    else:
        need(signer_group is not None and numeric_group == signer_group and
             signer_group.gr_name == SIGNER and signer_group.gr_gid == spec.gid and
             not signer_group.gr_mem, "broker_account_nss_group_conflict")
    # Enumeration is additional evidence; directory services with incomplete
    # enumeration still require the coordinator's external identity review.
    need(all(p.pw_name == SIGNER or
             (p.pw_uid != spec.uid and p.pw_gid != spec.gid) for p in pwd.getpwall()) and
         all((g.gr_name == SIGNER or g.gr_gid != spec.gid) and
             (g.gr_name == MAIL or SIGNER not in g.gr_mem) for g in grp.getgrall()),
         "broker_account_nss_alias_conflict")


def check_side_effects(spec):
    # No home, mail spool or subordinate ID allocation is owned by this
    # stage. Existing/unexpected objects require manual review, not deletion.
    for path in (Path(HOME), Path("/var/spool/mail") / SIGNER, Path("/var/mail") / SIGNER):
        need(not os.path.lexists(str(path)), "broker_account_home_or_spool_conflict")
    for name in ("subuid", "subgid"):
        path = Path("/etc") / name
        if not os.path.lexists(str(path)):
            continue
        for line in read_root_file(path).splitlines():
            if not line:
                continue
            fields = line.split(":")
            need(len(fields) == 3 and fields[0] not in (SIGNER, str(spec.uid)) and
                 numeric(fields[2]) > 0, "broker_account_subordinate_id_conflict")
            start, count = numeric(fields[1]), numeric(fields[2])
            value = spec.uid if name == "subuid" else spec.gid
            need(not start <= value < start + count, "broker_account_subordinate_id_conflict")


def verify_system_ranges(spec):
    keys = ("SYS_UID_MIN", "SYS_UID_MAX", "SYS_GID_MIN", "SYS_GID_MAX")
    result = {}
    for line in read_root_file(Path("/etc/login.defs")).splitlines():
        fields = line.split("#", 1)[0].split()
        if fields and fields[0] in keys:
            need(len(fields) == 2 and fields[0] not in result,
                 "broker_account_system_range_unverified")
            result[fields[0]] = numeric(fields[1])
    need(set(result) == set(keys) and
         result["SYS_UID_MIN"] <= spec.uid <= result["SYS_UID_MAX"] and
         result["SYS_GID_MIN"] <= spec.gid <= result["SYS_GID_MAX"],
         "broker_account_outside_system_ranges")


def observe_native(spec):
    need(os.geteuid() == 0, "broker_account_root_required")
    try:
        verify_system_ranges(spec)
        check_side_effects(spec)
        first = local_inventory()
        state = classify_local(spec, first)
        verify_nss(spec, state)
        need(local_inventory() == first, "broker_account_database_changed")
        return state
    except (OSError, KeyError, UnicodeError, OverflowError):
        raise Refused("broker_account_native_inspection_failed") from None


def ensure_idle(spec):
    # Never signal/kill anything. Check all four kernel UIDs/GIDs and
    # supplementary groups, including a stale process using a free ID.
    count = 0
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        count += 1
        need(count <= 131072, "broker_account_process_inventory_limit")
        try:
            text = (Path(entry.path) / "status").read_text(encoding="utf-8")
        except (FileNotFoundError, ProcessLookupError):
            continue
        values = {}
        for line in text.splitlines():
            key, sep, raw = line.partition(":")
            if sep and key in ("Uid", "Gid", "Groups"):
                need(key not in values, "broker_account_process_inventory_unverified")
                values[key] = tuple(numeric(n) for n in raw.split())
        need(set(values) == {"Uid", "Gid", "Groups"} and
             len(values["Uid"]) == len(values["Gid"]) == 4,
             "broker_account_process_inventory_unverified")
        need(spec.uid not in values["Uid"] and spec.gid not in values["Gid"] and
             spec.gid not in values["Groups"], "broker_account_process_in_use")


def run_native(name, args):
    need(name in TOOLS and os.geteuid() == 0, "broker_account_command_refused")
    path = Path(TOOLS[name])
    for directory in path.parents:
        info = directory.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
             not info.st_mode & 0o6022, "broker_account_untrusted_tool")
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
         not info.st_mode & 0o6022 and info.st_mode & 0o111,
         "broker_account_untrusted_tool")
    try:
        result = subprocess.run([str(path)] + list(args), input=b"",
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=30, env=ENV, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("broker_account_command_failed") from None
    need(result.returncode == 0, "broker_account_command_failed")


class AccountStage:
    """Exact before/after account adapter; caller persists the reviewed spec."""
    def __init__(self, spec, guard, observe=observe_native, idle=ensure_idle, run=run_native):
        self.spec = validate(spec)
        need(all(callable(fn) for fn in (guard, observe, idle, run)),
             "broker_account_guard_required")
        self.guard, self.observe, self.idle, self.run = guard, observe, idle, run

    def fingerprint(self, state):
        return tx.digest({"stage": "account", "state": state,
                          "spec": self.spec._asdict(), "home": HOME,
                          "shell": SHELL, "comment": COMMENT})

    def stage_plan(self):
        return {"name": "account", "before": self.fingerprint("absent"),
                "after": self.fingerprint("installed")}

    def probe(self):
        state = self.observe(self.spec)
        need(state in ("absent", "installed"), "broker_account_partial_requires_review")
        return self.fingerprint(state)

    def mutate(self, direction):
        need(direction in ("install", "rollback"), "broker_account_operation_refused")
        self.guard("account", direction)
        self.idle(self.spec)
        before = "absent" if direction == "install" else "installed"
        need(self.observe(self.spec) == before, "broker_account_unexpected_state")
        s = self.spec
        if direction == "install":
            self.run("groupadd", ["--system", "--gid", str(s.gid), SIGNER])
            need(self.observe(s) == "group_only", "broker_account_group_create_unverified")
            self.guard("account", direction)
            self.idle(s)
            self.run("useradd", ["--system", "--uid", str(s.uid),
                     "--gid", SIGNER, "--no-user-group", "--groups", MAIL,
                     "--no-create-home", "--no-log-init", "--home-dir", HOME,
                     "--shell", SHELL, "--comment", COMMENT, SIGNER])
            expected = "installed"
        else:
            self.run("userdel", [SIGNER])
            state = self.observe(s)
            need(state in ("absent", "group_only"), "broker_account_user_remove_unverified")
            if state == "group_only":
                self.guard("account", direction)
                self.idle(s)
                need(self.observe(s) == "group_only", "broker_account_group_changed")
                self.run("groupdel", [SIGNER])
            expected = "absent"
        self.guard("account", direction)
        self.idle(s)
        need(self.observe(s) == expected, "broker_account_mutation_unverified")
