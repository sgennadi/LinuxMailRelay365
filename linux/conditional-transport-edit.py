#!/usr/bin/env python3
"""Private, read-only preparation of a replacement managed transport set.

Not a CLI. No publication, journal mutation, service control or mail.
The caller must prove exclusive stopped maintenance and native installed
policy. Never serialize the private review, database set or credentials.
"""
import importlib.util
import os
import pathlib
import sys
import tempfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "edit_rotation", str(pathlib.Path(__file__).with_name(
        "conditional-transport-rotation.py")))
Q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(Q)
X, R, C, T, M = Q.X, Q.R, Q.C, Q.T, Q.M
Refused = X.Refused


def destination_check(config, old, new):
    old_sources = set(old["map_names"])
    new_sources = set(new["map_names"])
    old_names = old_sources | set(X.map_names(old))
    new_names = new_sources | set(X.map_names(new))
    X.need(not old_names.intersection(new_names), "replacement_namespace_collision")
    old_services = {C.profile_name(old["plan"], i)
                    for i in range(1, len(old["rules"]) + 1)}
    new_services = {C.profile_name(new["plan"], i)
                    for i in range(1, len(new["rules"]) + 1)}
    X.need(not old_services.intersection(new_services), "replacement_service_collision")
    for name in new_names:
        X.need(not T.exists(config, name), "replacement_destination_exists")


def proposal(record, draft):
    old, files, _, _ = record
    # Always rebuild from the exact pre-manager snapshot. Never search for
    # comment markers in, or append a second set to, the active configuration.
    try:
        rules, plan, after, names = R.proposal(
            files["main.before"], files["master.before"], draft,
            old["backend"], old["ca"])
    except C.Refused:
        # The compiler is loaded separately and owns its exception class.
        raise Refused("invalid_replacement_plan") from None
    X.need(plan != old["plan"], "replacement_plan_unchanged")
    values = dict(files, **{"main.after": after[0], "master.after": after[1]})
    new = dict(old, plan=plan, rules=rules, map_names=names,
               files={key: M.digest(value) for key, value in values.items()})
    R.validate(new, values)
    # Exact full rule equality only. A selector/host/port/TLS/auth change
    # requires a new explicit credential. Reordering can retain an account.
    sources = {tuple(rule[key] for key in M.FIELDS): i
               for i, rule in enumerate(old["rules"], 1)
               if rule["auth"] == "password"}
    retain = tuple(sources.get(tuple(rule[key] for key in M.FIELDS))
                   if rule["auth"] == "password" else None for rule in rules)
    return new, values, retain


def review(config, parent, revision, draft, uid, gid, guard, native_review):
    """Private exact observation. native_review(record) must prove policy.

    Only an owned, fully published, non-pending set may be edited. Review
    never extracts a password or writes to the configuration directory.
    """
    guard()
    record = X.load(parent, revision, uid)
    X.need(record[2]["gid"] == gid, "postfix_group_changed")
    Q.assert_installed(config, record, uid)
    X.need(native_review(record) is True, "installed_native_policy_unverified")
    new, files, retain = proposal(record, draft)
    destination_check(config, record[0], new)
    guard()
    X.need(X.load(parent, revision, uid) == record, "installed_edit_review_changed")
    Q.assert_installed(config, record, uid)
    X.need(native_review(record) is True, "installed_native_policy_unverified")
    guard()
    X.need(X.load(parent, revision, uid) == record, "installed_edit_review_changed")
    Q.assert_installed(config, record, uid)
    destination_check(config, record[0], new)
    return record, new, files, retain


def credential_choices(reviewed, slots):
    _, new, _, retain = reviewed
    X.need(type(slots) is list and len(slots) == len(new["rules"]),
           "one_edit_credential_slot_per_rule_required")
    selected = []
    for rule, previous, slot in zip(new["rules"], retain, slots):
        if rule["auth"] == "none":
            X.need(slot is None, "unexpected_edit_credential")
            selected.append(("none", None))
        elif type(slot) is dict and slot == {"mode": "retain"}:
            X.need(previous is not None, "credential_reuse_not_permitted")
            selected.append(("retain", previous))
        else:
            X.need(type(slot) is dict and set(slot) == {"mode", "credential"} and
                   slot["mode"] == "new", "explicit_edit_credential_required")
            C.credentials([rule], [slot["credential"]])
            selected.append(("new", slot["credential"]))
    return selected


def compile_route(new):
    """Native route map and complete generated-service verification in tmpfs."""
    uid = os.geteuid()
    X.need(uid == 0, "root_required")
    backend, ca, plan = new["backend"], new["ca"], new["plan"]
    with tempfile.TemporaryDirectory(prefix="lmr365-edit-", dir=C.tmpfs_parent()) as work:
        fd = os.open(work, M.DIR_FLAGS)
        try:
            M.check_directory(fd, uid, True)
            for name in ("queue", "data"):
                os.mkdir(name, 0o700, dir_fd=fd)
            main, master, routes, services, auth = C.render(
                new["rules"], plan, work, backend, ca)
            M.write_file(fd, "main.cf", main)
            M.write_file(fd, "master.cf", master)
            types = C.command(M.native_command, "postconf", ["-c", work, "-m"])
            X.need(backend in types.decode("ascii").split(),
                   "native_indexed_map_backend_unavailable")
            if auth:
                available = C.command(M.native_command, "postconf", ["-c", work, "-A"])
                X.need("cyrus" in available.decode("ascii").split(),
                       "native_client_sasl_unavailable")
            name = C.compile_map(fd, work, backend, C.ROUTE_MAP, routes, uid,
                                 M.native_command)
            C.verify_services(work, services, backend, M.native_command)
            return M.read_file(fd, name, uid, M.MAX_DB_BYTES)
        finally:
            os.close(fd)


def retained_database(config, directory, record, index, uid, identity, native_unprivileged):
    old, _, journal, receipts = record
    name = Q.target_name(old, index)
    X.checked_map(config, name, journal, receipts[name], uid)
    data, meta = T.config_file(config, name, uid, M.MAX_DB_BYTES)
    X.need(M.digest(data) == journal["maps"][name] and meta == X.map_meta(journal),
           "retained_credential_changed")
    # Exact endpoint, one-row lookup and negative lookup under the real
    # Postfix account. No credential string is returned from verification.
    Q.verify_retained_native(config, directory, old, name, data, uid,
                             identity, native_unprivileged)
    X.checked_map(config, name, journal, receipts[name], uid)
    return data


def prepare(config, parent, directory, revision, reviewed, slots, uid, identity,
            guard, native_review, native_unprivileged):
    """Prepare a private in-memory native DB set; no persistent publication.

    A later transaction must repeat all ownership, native policy and
    credential provenance checks before committing. No password files
    are backed up. Retaining a database is not provider AUTH verification.
    """
    try:
        old_record, new, _, _ = reviewed

        def fresh():
            guard()
            X.need(review(config, parent, revision, new["rules"], uid,
                          identity[1], guard, native_review) == reviewed,
                   "installed_edit_review_changed")

        fresh()
        selected = credential_choices(reviewed, slots)
        # Validate every choice before native work or reading a retained DB.
        databases = {C.ROUTE_MAP: compile_route(new)}
        for index, (mode, value) in enumerate(selected, 1):
            fresh()
            if mode == "none":
                continue
            if mode == "retain":
                data = retained_database(config, directory, old_record, value,
                                         uid, identity, native_unprivileged)
            else:
                data = Q.compile_rotation_candidate(new, index, value)
            databases[C.profile_name(new["plan"], index) + "-sasl"] = data
        fresh()
        X.native_database_set(new, databases)
        return databases
    except Exception:
        # Never expose native diagnostics, credential input or DB contents.
        raise Refused("edit_candidate_preparation_failed") from None


if __name__ == "__main__":
    raise SystemExit("Private replacement preparation library only.")
