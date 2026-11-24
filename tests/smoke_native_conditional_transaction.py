#!/usr/bin/env python3
"""Exercise the real offline transaction with native Postfix in a CI fixture.

Maintenance and remote TLS evidence are deliberately fixture-only. No live
configuration or queue writes, service starts/reloads or SMTP sessions occur.
The default package config is only used by the unprivileged postmap reader.
"""
import hashlib
import importlib.util
import os
import pathlib
import stat
import tempfile

if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("Disposable root CI only")

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "offline_native", str(ROOT / "linux/manage-conditional-postfix-offline.py"))
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
P, T, M = C.P, C.T, C.M
os.umask(0o077)
identity = C.mail_identity()
protected = [pathlib.Path(P.CONFIG) / name for name in ("main.cf", "master.cf")]


def protected_state():
    return [(hashlib.sha256(path.read_bytes()).hexdigest(),
             path.stat().st_ino, path.stat().st_mode, path.stat().st_uid,
             path.stat().st_gid) for path in protected]


before = protected_state()


def check_case(root, failure):
    case = root / ("rollback" if failure else "restore")
    case.mkdir(mode=0o755)
    case.chmod(0o755)
    folder = case / "postfix"
    folder.mkdir(mode=0o755)
    folder.chmod(0o755)
    for directory in ("queue", "data"):
        (folder / directory).mkdir(mode=0o700)
    # Explicitly choose the existing narrow policy, not production defaults.
    values = dict.fromkeys(P.KEYS, "")
    values.update(P.FIXED_SETTINGS)
    values.update(myhostname="lmr365-transaction.example.invalid",
                  mydomain="example.invalid",
                  mydestination="localhost, lmr365-transaction.example.invalid",
                  local_transport="local:$myhostname", virtual_transport="virtual",
                  relayhost="[fallback.example.net]:25",
                  inet_interfaces="loopback-only", inet_protocols="ipv4",
                  smtp_tls_CAfile="/etc/ssl/certs/ca-certificates.crt",
                  meta_directory="/etc/postfix",
                  queue_directory=str(folder / "queue"),
                  data_directory=str(folder / "data"))
    values.pop("config_directory")
    # The transaction deliberately refuses pre-existing explicit assignments.
    values.pop(T.PARAMETER)
    original_main = "".join("{} = {}\n".format(k, v)
                            for k, v in sorted(values.items())).encode("ascii")
    original_master = (b"smtp unix - - n - - smtp\n"
                       b"relay unix - - n - - smtp\n"
                       b"rewrite unix - - n - - trivial-rewrite\n")
    for name, data in (("main.cf", original_main), ("master.cf", original_master)):
        path = folder / name
        path.write_bytes(data)
        path.chmod(0o644)

    parent = os.open(str(case), M.DIR_FLAGS)
    config = os.open(str(folder), M.DIR_FLAGS)
    try:
        rules = [
            dict(selector="exact-envelope-sender", pattern="alpha@example.org",
                 host="first.example.net", port=25, tls="starttls", auth="none"),
            dict(selector="envelope-sender-domain", pattern="other.example.org",
                 host="second.example.net", port=46500, tls="starttls", auth="none"),
        ]
        plan, _ = M.build(rules)
        _, stage = M.stage(parent, rules, plan, "STAGE_CONDITIONAL_MAPS_ONLY", 0)
        receipt = M.compile_stage(parent, plan, stage,
                                  "COMPILE_CONDITIONAL_MAPS_ONLY", 0, str(case))
        assert M.verify_compiled(parent, plan, 0, str(case)) == receipt
        _, compiled, backend, count = receipt
        assert count == 2
        _, stage_files = M.load_stage(parent, plan, 0)
        _, databases, _ = M.read_compiled(parent, plan, stage, stage_files, 0)
        database = databases["sender-candidates.txt" + M.MAP_SUFFIX[backend]]
        name, suffix = T.checked_name(plan, backend)
        target = folder / (name + suffix)
        live_spec = backend + ":/etc/postfix/" + name

        def guard():
            # Fixture path only; never mistake this for actual maintenance
            # or substitute it in the real CLI.
            assert folder.parent == case and root in case.parents
            assert protected_state() == before

        def fixture_postconf(tool, arguments, data=None):
            assert tool == "postconf" and arguments[:2] == ["-c", P.CONFIG]
            return M.native_command(tool, ["-c", str(folder)] + arguments[2:], data)

        def policy():
            observed = P.postconf_values(fixture_postconf)
            assert observed["config_directory"] == str(folder)
            assert observed["queue_directory"] == str(folder / "queue")
            # Only these two location fields are translated to the logical
            # primary-instance values; every other effective value is native.
            observed["config_directory"] = P.CONFIG
            observed["queue_directory"] = P.QUEUE
            return observed

        baseline = policy()
        P.inspect_policy(baseline)

        def master():
            P.inspect_master(fixture_postconf)

        master()

        def reviewer(parent_arg, config_arg, queue_arg, plan_arg,
                     compiled_arg, identity_arg, guard_arg):
            assert (parent_arg, config_arg, plan_arg, compiled_arg, identity_arg) == (
                parent, config, plan, compiled, identity)
            guard_arg()
            assert policy() == baseline
            master()
            assert M.verify_compiled(parent, plan, 0, str(case)) == receipt
            txn = T.preview(config, plan, backend, stage, compiled, database, 0, guard_arg)
            # No network acceptance is claimed in this native file test.
            return txn, C.review_digest("a" * 64, identity), count, baseline, rules

        lookups = []

        def lookup(spec, checked_rules, account):
            assert spec == live_spec
            assert account == identity
            assert target.read_bytes() == database
            info = target.stat()
            assert info.st_uid == 0 and info.st_gid == identity[1]
            assert stat.S_IMODE(info.st_mode) == 0o640
            assert (folder / "master.cf").read_bytes() == original_master

            def native_fixture(args, account_arg, data=None):
                assert args[:2] == ["-c", P.CONFIG] and args[-1] == live_spec
                # The packaged default configuration is read only. The only
                # queried dictionary is the new file inside the fixture.
                mapped = backend + ":" + str(folder / name)
                return C.native_unprivileged(args[:-1] + [mapped], account_arg, data)

            C.verify_active_map(spec, checked_rules, account, native_fixture)
            lookups.append(spec)
            if failure:
                raise M.Refused("ci_injected_post_write_failure")

        txn, evidence, _, _, _ = reviewer(parent, config, None, plan,
                                           compiled, identity, guard)
        sha = txn[0]
        try:
            result = C.apply_reviewed(parent, config, None, plan, compiled,
                                      sha, evidence, identity, guard, reviewer,
                                      lookup, policy, master)
        except M.Refused as exc:
            assert failure and str(exc) == "ci_injected_post_write_failure", str(exc)
            assert len(lookups) == 1
            assert not target.exists()
            print("NATIVE_CONDITIONAL_FAULT_ROLLBACK=PASS", flush=True)
        else:
            assert not failure and result == sha and len(lookups) == 1
            assert target.is_file()
            expected = dict(baseline, sender_dependent_relayhost_maps=live_spec)
            assert policy() == expected
            assert C.restore_reviewed(parent, config, sha, identity, guard,
                                      policy, master) == sha
            print("NATIVE_CONDITIONAL_APPLY_RESTORE=PASS", flush=True)

        assert not target.exists()
        assert (folder / "main.cf").read_bytes() == original_main
        assert (folder / "master.cf").read_bytes() == original_master
        assert stat.S_IMODE((folder / "main.cf").stat().st_mode) == 0o644
        assert policy() == baseline
        assert T.load_backup(parent, sha, 0) == (txn[1], txn[2])
        guard()
    finally:
        os.close(config)
        os.close(parent)


with tempfile.TemporaryDirectory(prefix="lmr365-native-transaction-", dir="/var/lib") as temp:
    root = pathlib.Path(temp)
    root.chmod(0o755)  # Postfix account must be able to traverse fixture parents.
    for fail in (False, True):
        check_case(root, fail)

assert protected_state() == before
print("NATIVE_CONDITIONAL_TRANSACTION=PASS_PRIMARY_UNCHANGED", flush=True)
