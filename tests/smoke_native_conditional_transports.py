#!/usr/bin/env python3
"""Native compilation of dedicated transport services using synthetic accounts."""
import hashlib
import importlib.util
import os
import pathlib
from unittest.mock import patch

if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("Disposable root CI only")
ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "transport_compiler", str(ROOT / "linux/compile-conditional-transports.py"))
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
os.umask(0o077)
protected = [pathlib.Path("/etc/postfix") / x for x in ("main.cf", "master.cf")]
before = [hashlib.sha256(x.read_bytes()).hexdigest() for x in protected]
rules = [
    dict(selector="exact-envelope-sender", pattern="first@example.org",
         host="relay.example.net", port=587, tls="starttls", auth="password"),
    dict(selector="exact-envelope-sender", pattern="second@example.org",
         host="relay.example.net", port=587, tls="starttls", auth="password"),
    dict(selector="envelope-sender-domain", pattern="other.example.org",
         host="relay.example.net", port=465, tls="implicit", auth="password"),
    dict(selector="exact-envelope-sender", pattern="fourth@example.org",
         host="custom.example.net", port=46500, tls="starttls", auth="none"),
]
request = {"rules": rules, "credentials": [
    {"username": "fixture-a", "password": "synthetic-A"},
    {"username": "fixture-b", "password": "synthetic-B"},
    {"username": "fixture-c", "password": "synthetic-C"}, None]}
_, sha = T.plan(rules)
# Exercise every installed backend, rather than testing only the
# preferred one and leaving its fallback unverified.
import tempfile
with tempfile.TemporaryDirectory(prefix="lmr365-types-", dir=T.tmpfs_parent()) as work:
    fd = os.open(work, T.M.DIR_FLAGS)
    try:
        T.M.write_file(fd, "main.cf", T.M.NATIVE_CONFIG)
        T.M.write_file(fd, "master.cf", b"# no services\n")
        for name in ("queue", "data"):
            os.mkdir(name, 0o700, dir_fd=fd)
        code, output = T.M.native_command("postconf", ["-c", work, "-m"])
        assert code == 0
        supported = [x for x in ("hash", "lmdb") if x in output.decode("ascii").split()]
    finally:
        os.close(fd)
assert supported
def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / "linux" / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


X = sibling("multi_transport_transaction", "conditional-transport-transaction.py")
O = sibling("offline_native_reader", "manage-conditional-postfix-offline.py")
Q = sibling("credential_rotation", "conditional-transport-rotation.py")
identity = O.mail_identity()


def primary_guard():
    assert before == [hashlib.sha256(x.read_bytes()).hexdigest() for x in protected]


def native_transaction(rules, plan, backend, ca, databases, folder, fail):
    """Only a disposable alternate config and synthetic credentials.

    This tests file transactions and native lookup as postfix, not actual
    queue manager sender selection, daemon maintenance or SMTP delivery.
    """
    folder.mkdir(mode=0o755)
    folder.chmod(0o755)
    for name in ("queue", "data"):
        (folder / name).mkdir(mode=0o700)
    original_main = (
        "myhostname = lmr365-multi-transaction.example.invalid\n"
        "mydomain = example.invalid\n"
        "mydestination = localhost, $myhostname\n"
        "inet_interfaces = loopback-only\n"
        "inet_protocols = ipv4\n"
        "meta_directory = /etc/postfix\n"
        "queue_directory = " + str(folder / "queue") + "\n"
        "data_directory = " + str(folder / "data") + "\n"
        "relayhost = [fallback.example.net]:25\n").encode("ascii")
    original_master = b"smtp unix - - n - - smtp\n"
    for name, content in (("main.cf", original_main), ("master.cf", original_master)):
        p = folder / name
        p.write_bytes(content)
        p.chmod(0o644)
    parent = os.open(str(folder.parent), X.M.DIR_FLAGS)
    config = os.open(str(folder), X.M.DIR_FLAGS)
    try:
        def guard():
            assert folder.is_dir() and folder.parent.parent == pathlib.Path("/var/lib")
            primary_guard()

        def native(args):
            code, value = T.M.native_command("postconf", ["-c", str(folder)] + args)
            assert code == 0, "native fixture postconf failed"
            return value

        def effective(name):
            return native(["-x", name]).decode("ascii").strip().partition("=")[2].strip()

        def check_fixture():
            assert effective("myhostname") == "lmr365-multi-transaction.example.invalid"
            assert effective("queue_directory") == str(folder / "queue")
            assert effective("data_directory") == str(folder / "data")
            assert effective("inet_interfaces") == "loopback-only"
            assert effective("relayhost") == "[fallback.example.net]:25"

        check_fixture()
        baseline_services = native(["-M"])
        baseline_overrides = T.parameters(native(["-P"]))
        baseline_route = effective(T.PARAMETER)
        assert not baseline_route
        _, _, routes, services, auth_maps = T.render(rules, plan, "/etc/postfix", backend, ca)
        secrets = T.credentials(rules, request["credentials"])

        def fresh():
            guard()
            return X.R.observe(config, rules, backend, ca, 0, guard)

        reviewed = fresh()
        info, files = reviewed
        maps = X.native_database_set(info, databases)
        route_name = info["map_names"][0]
        checked = []

        def check_map(name, expected):
            target = folder / (name + T.M.MAP_SUFFIX[backend])
            st = target.stat()
            assert st.st_uid == 0 and st.st_gid == identity[1]
            assert st.st_mode & 0o777 == 0o640
            spec = backend + ":" + str(folder / name)
            # Use packaged primary config only as a read-only postmap
            # context; the map path itself is exclusively in the fixture.
            prefix = ["-c", "/etc/postfix"]
            code, result = O.native_unprivileged(prefix + ["-s", spec], identity)
            assert code == 0 and T.M.native_rows(result) == expected
            keys = ("\n".join(sorted(expected)) + "\n").encode("ascii")
            code, result = O.native_unprivileged(prefix + ["-q", "-", spec], identity, keys)
            assert code == 0 and T.M.native_rows(result) == expected
            code, result = O.native_unprivileged(
                prefix + ["-q", T.M.NEGATIVE_KEY, spec], identity)
            assert code == 1 and not result.strip()

        def verify(active, recorded):
            assert recorded == info
            guard()
            check_fixture()
            if not active:
                assert native(["-M"]) == baseline_services
                assert T.parameters(native(["-P"])) == baseline_overrides
                assert effective(T.PARAMETER) == baseline_route
                return
            assert effective(T.PARAMETER) == backend + ":/etc/postfix/" + route_name
            actual = T.parameters(native(["-P"]))
            expected = dict(baseline_overrides)
            expected.update({service + "/unix/" + key: value
                             for service, options in services.items()
                             for key, value in options.items()})
            assert actual == expected
            lines = [line.split() for line in native(["-M"]).decode("ascii").splitlines()]
            assert len(lines) == len(services) + 1
            assert {line[0] for line in lines} == set(services) | {"smtp"}
            for line in lines:
                assert line[1:8] == ["unix", "-", "-", "n", "-", "-", "smtp"]
            check_map(route_name, routes)
            for index, name in auth_maps.items():
                check_map(name, {T.endpoint(rules[index - 1]): secrets[index - 1]})
            checked.append(True)
            if fail:
                raise X.Refused("fixture_injected_native_failure")

        def exercise_rotation(revision):
            # Account 2 shares an endpoint with account 1, but its private
            # map must be the only file changed throughout credential rotation.
            index = 2
            target = Q.target_name(info, index)
            first_record = Q.X.load(parent, revision, 0)
            preserved = {name: ((folder / name).read_bytes(),
                                Q.T.file_identity((folder / name).stat()))
                         for name in ("main.cf", "master.cf", *maps)
                         if name != target}
            current = request["credentials"][index - 1]
            private_candidates = []

            def review():
                return Q.X.load(parent, revision, 0)

            def unchanged():
                guard()
                for name, (data, file_id) in preserved.items():
                    path = folder / name
                    assert path.read_bytes() == data
                    assert Q.T.file_identity(path.stat()) == file_id
                check_fixture()

            def native_target(data, credential):
                Q.verify_retained_native(config, str(folder), info, target, data,
                                         0, identity, O.native_unprivileged, credential)
                unchanged()

            def rotate(new_credential, mode):
                nonlocal current
                record = review()
                old = (folder / target).read_bytes()
                native_target(old, current)
                candidate = Q.compile_rotation_candidate(info, index, new_credential)
                assert candidate != old
                private_candidates.append(candidate)

                def verify_rotation(active, recorded, name, data):
                    assert recorded == info and name == target
                    assert data == (candidate if active else old)
                    native_target(data, new_credential if active else current)
                    if active and mode == "rollback":
                        raise Q.Refused("fixture_injected_rotation_verification_failure")

                def apply_rotation():
                    return Q.rotate(config, parent, revision, index, record, candidate,
                                    identity[1], Q.CONFIRM, 0, guard, verify_rotation, review)

                if mode == "success":
                    assert Q.R.valid_sha(apply_rotation())
                    current = new_credential
                    expected = candidate
                elif mode == "rollback":
                    try:
                        apply_rotation()
                    except Q.RotationFailed as error:
                        assert error.rolled_back
                    else:
                        raise AssertionError("Expected native rotation rollback")
                    expected = old
                else:
                    if mode == "new_retained":
                        # Simulate an interrupted ownership-overlay commit
                        # after publication of the replacement map.
                        with patch.object(Q, "commit_overlay", side_effect=OSError("fixture interruption")):
                            try:
                                apply_rotation()
                            except Q.RotationFailed as error:
                                assert not error.rolled_back
                            else:
                                raise AssertionError("Expected pending rotation")
                    else:
                        assert mode == "old_retained"
                        original_write = Q.T.atomic_write

                        def interrupt(fd, name, *args, **kwargs):
                            if name == target:
                                raise KeyboardInterrupt()
                            return original_write(fd, name, *args, **kwargs)

                        with patch.object(Q.T, "atomic_write", side_effect=interrupt):
                            try:
                                apply_rotation()
                            except KeyboardInterrupt:
                                pass
                            else:
                                raise AssertionError("Expected interrupted rotation")
                    try:
                        review()
                    except Q.Refused as error:
                        assert str(error) == "credential_rotation_recovery_required"
                    else:
                        raise AssertionError("Pending rotation was not blocked")
                    pending = Q.pending_review(config, parent, revision, 0, identity[1])
                    assert pending[3] == mode
                    assert Q.recover(config, parent, revision, pending, identity[1],
                                     Q.RECOVER, 0, guard, verify_rotation) == mode
                    if mode == "new_retained":
                        current = new_credential
                        expected = candidate
                    else:
                        expected = old

                actual = review()
                assert actual[:2] == first_record[:2]
                assert (folder / target).read_bytes() == expected
                assert actual[2]["maps"][target] == hashlib.sha256(expected).hexdigest()
                assert actual[3][target] == Q.T.file_identity((folder / target).stat())
                for name in maps:
                    if name != target:
                        assert actual[2]["maps"][name] == first_record[2]["maps"][name]
                        assert actual[3][name] == first_record[3][name]
                native_target(expected, current)
                print("NATIVE_MULTI_TRANSPORT_ROTATION=" + backend + ":" + mode + ":PASS",
                      flush=True)

            for mode in ("success", "rollback", "new_retained", "old_retained"):
                rotate({"username": "fixture-rotated", "password": "synthetic-" + mode}, mode)
            # Another normal rotation after recovery must still work.
            rotate({"username": "fixture-final", "password": "synthetic-final"}, "success")
            return private_candidates

        rotated_candidates = []
        try:
            revision = X.apply(config, parent, reviewed, databases, identity[1],
                               X.APPLY, 0, guard, verify, fresh)
        except X.ApplyFailed as error:
            assert fail and error.rolled_back and checked == [True]
            revision = error.revision
            print("NATIVE_MULTI_TRANSPORT_ROLLBACK=" + backend + ":PASS", flush=True)
        else:
            assert not fail and checked == [True]
            rotated_candidates = exercise_rotation(revision)
            assert X.restore(config, parent, revision, X.RESTORE, 0, guard, verify) == revision
            print("NATIVE_MULTI_TRANSPORT_APPLY_RESTORE=" + backend + ":PASS", flush=True)

        assert (folder / "main.cf").read_bytes() == original_main
        assert (folder / "master.cf").read_bytes() == original_master
        assert not any((folder / name).exists() for name in maps)
        assert X.load(parent, revision, 0)[:2] == reviewed
        # Ensure actual native database bytes were not duplicated in recovery.
        recovery = folder.parent / X.R.BASE / revision
        for p in recovery.rglob("*"):
            if p.is_file():
                assert p.stat().st_mode & 0o777 == 0o600
                assert not any(data in p.read_bytes()
                               for data in (*maps.values(), *rotated_candidates))
        primary_guard()
    finally:
        os.close(config)
        os.close(parent)


def exercise_transaction(rules, plan, backend, ca, databases):
    with tempfile.TemporaryDirectory(prefix="lmr365-multi-transaction-", dir="/var/lib") as work:
        root = pathlib.Path(work)
        root.chmod(0o755)
        for fail in (False, True):
            native_transaction(rules, plan, backend, ca, databases,
                               root / ("rollback" if fail else "restore"), fail)


for backend in supported:
    result = T.compile_profiles(request, sha, T.CONFIRM, 0,
                                T.tmpfs_parent(), T.installed_ca(),
                                forced_backend=backend,
                                verified_consumer=exercise_transaction)
    assert result == (sha, backend, 4, 3)
    print("NATIVE_DEDICATED_TRANSPORT_BACKEND=" + backend + ":PASS", flush=True)
assert before == [hashlib.sha256(x.read_bytes()).hexdigest() for x in protected]
print("NATIVE_DEDICATED_TRANSPORTS_AND_PRIVATE_AUTH_MAPS=PASS")
print("NATIVE_DEDICATED_TRANSPORTS_PRIMARY_CONFIG_UNCHANGED=PASS")
