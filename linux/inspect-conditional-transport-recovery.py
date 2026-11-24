#!/usr/bin/env python3
"""Bounded read-only multi-transport recovery inventory.

No map queries, credentials, config bytes or private hashes in output.
An observation is not authorization to restore or start a service.
"""
import argparse
import importlib.util
import os
import pathlib
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "multi_host", str(pathlib.Path(__file__).with_name(
        "manage-conditional-transports-offline.py")))
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
X, R, M, O, P = H.X, H.R, H.M, H.O, H.P
MAX_RECORDS = 64


def observe(config, parent, revision, uid, gid):
    try:
        info, files = R.load(parent, revision, uid, allow_activation=True)
        if X.T.context(config, uid) != info["identity"]:
            return "different_config_directory"
        current = X.pair(config, uid)
        before = X.expected_pair(info, files, ".before")
        after = X.expected_pair(info, files, ".after")
        for idx, item in enumerate(current):
            if item not in (before[idx], after[idx]):
                return "configuration_drift"
        X.check_sources(config, info)
        names = X.map_names(info)
        present = [name for name in names if X.T.exists(config, name)]
        try:
            fd = X.activation_fd(parent, revision, uid)
        except FileNotFoundError:
            return ("snapshot_only" if current == before and not present
                    else "publication_unverified")
        else:
            try:
                if X.T.exists(fd, X.ROTATION_PENDING):
                    return "credential_rotation_pending"
            finally:
                os.close(fd)
        record = X.load(parent, revision, uid)
        if record[:2] != (info, files) or record[2]["gid"] != gid:
            return "publication_unverified"
        X.restorable(config, *record, uid)
        if current == before:
            return "original_owned_maps" if present else "original_no_maps"
        if current == after:
            return "configured_owned_maps" if len(present) == len(names) else "configured_maps_missing"
        return "partial_configuration"
    except Exception:
        # Missing, malformed, foreign, or changed objects never authorize writes.
        return "unverified"


def inventory(config, parent, uid, gid):
    try:
        base = M.open_base(parent, uid, name=R.BASE)
    except FileNotFoundError:
        return []
    try:
        names = sorted(os.listdir(base))
        if len(names) > MAX_RECORDS or not all(R.valid_sha(name) for name in names):
            raise R.Refused("recovery_inventory_unverified")
        result = []
        for name in names:
            first = observe(config, parent, name, uid, gid)
            second = observe(config, parent, name, uid, gid)
            result.append((name, first if first == second else "unstable"))
        if sorted(os.listdir(base)) != names:
            raise R.Refused("recovery_inventory_changed")
        return result
    finally:
        os.close(base)


def installed_record(config, parent, uid, gid, revision, baseline, lookup):
    record = X.load(parent, revision, uid)
    info, files, journal, receipts = record
    X.assert_pair(config, info, files, ".after", uid)
    X.check_sources(config, info)
    H.need(journal["gid"] == gid and all(receipts.values()),
           "publication_identity_unverified")
    for name in X.map_names(info):
        X.checked_map(config, name, journal, receipts[name], uid)

    return verify_installed_policy(record, baseline, lookup)


def verify_installed_policy(record, baseline, lookup):
    info, files, journal, receipts = record
    values, extra, explicit, services, overrides = baseline
    backend, rules, plan = info["backend"], info["rules"], info["plan"]
    spec = backend + ":" + P.CONFIG + "/" + info["map_names"][0]
    H.need(values[H.C.PARAMETER] == spec and explicit.get(H.C.PARAMETER) == spec,
           "effective_route_map_changed")
    original = dict(values, **{H.C.PARAMETER: ""})
    H.need(P.inspect_policy(original) == info["ca"] and not values["proxy_interfaces"] and
           all(not extra[key] for key in H.EMPTY_EXTRA) and
           extra["smtp_host_lookup"] == "dns" and extra["disable_dns_lookups"] == "no",
           "inherited_policy_unverified")
    _, _, routes, generated, _ = H.C.render(rules, plan, P.CONFIG, backend, info["ca"])
    actual = {k: v for k, v in overrides.items() if k.split("/")[0] in generated}
    expected = {service + "/unix/" + key: value
                for service, options in generated.items() for key, value in options.items()}
    H.need(actual == expected, "generated_service_policy_changed")
    for key in overrides:
        parts = key.split("/")
        H.need(len(parts) == 3 and (parts[0] in generated or parts[2] == "syslog_name"),
               "foreign_service_override_unverified")
    H.need({k for k in services if k[0].startswith("lmr365-")} ==
           {(name, "unix") for name in generated}, "managed_service_inventory_changed")
    for name in generated:
        H.need(services[(name, "unix")].split()[1:8] ==
               ["unix", "-", "-", "n", "-", "-", "smtp"], "generated_service_changed")
    for name, command in (("smtp", "smtp"), ("relay", "smtp"), ("rewrite", "trivial-rewrite")):
        parts = services[(name, "unix")].split()
        H.need(len(parts) >= 8 and parts[4] == "n" and parts[7] == command and
               all(not part.startswith(("-c", "-D")) for part in parts[8:]),
               "existing_service_unverified")
    H.need(lookup(spec, routes), "native_sender_map_changed")
    return record


def route_lookup(spec, expected, identity):
    # Only the exact owned route map, never a password map. Native output
    # stays in memory and is not printed or attached to error messages.
    args = ["-c", P.CONFIG]
    code, result = O.native_unprivileged(args + ["-s", spec], identity)
    if code != 0 or M.native_rows(result) != expected:
        return False
    keys = ("\n".join(sorted(expected)) + "\n").encode("ascii")
    code, result = O.native_unprivileged(args + ["-q", "-", spec], identity, keys)
    if code != 0 or M.native_rows(result) != expected:
        return False
    code, result = O.native_unprivileged(args + ["-q", M.NEGATIVE_KEY, spec], identity)
    return code == 1 and not result.strip()


def installed(config, parent, uid, identity, read_state=H.state, lookup=None):
    """Discover a single exact manager-owned installed set, not runtime health."""
    if lookup is None:
        def lookup(spec, rows):
            return route_lookup(spec, rows, identity)
    first = read_state()
    route = first[0][H.C.PARAMETER]
    if not route:
        H.need(read_state() == first, "native_state_changed")
        return {"status": "no_effective_transport_map"}
    matches = [revision for revision, status in inventory(config, parent, uid, identity[1])
               if status == "configured_owned_maps"]
    if len(matches) != 1:
        return {"status": "external_or_unverified"}
    revision = matches[0]
    record = installed_record(config, parent, uid, identity[1], revision, first, lookup)
    H.need(read_state() == first and installed_record(
        config, parent, uid, identity[1], revision, first, lookup) == record,
        "installed_observation_changed")
    H.need(read_state() == first, "native_state_changed")
    info = record[0]
    return {"status": "installed_owned", "revision": revision, "plan": info["plan"],
            "backend": info["backend"], "rules": info["rules"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args(argv)
    fds = []
    try:
        if os.geteuid() != 0:
            raise R.Refused("root_required")
        for path in ("/var/lib", P.CONFIG):
            fds.append(P.open_directory(path))
        parent, config = fds
        identity = O.mail_identity()
        result = installed(config, parent, 0, identity) if args.installed else None
        entries = [] if args.installed else inventory(config, parent, 0, identity[1])
        O.same_directory(parent, "/var/lib")
        O.same_directory(config, P.CONFIG)
        if O.mail_identity() != identity:
            raise R.Refused("postfix_account_changed")
        if args.installed:
            print("MULTI_INSTALLED_JSON=" + M.canonical(result).decode("ascii").strip())
            return 0
        print("MULTI_RECOVERY_STATUS=observed_read_only")
        print("MULTI_RECOVERY_COUNT=" + str(len(entries)))
        for revision, status in entries:
            print("MULTI_RECOVERY_ENTRY=" + revision + ":" + status)
        print("MULTI_RECOVERY_WRITE_ALLOWED=no")
        print("MULTI_RECOVERY_POSTFIX_CHANGED=no")
        return 0
    except Exception:
        if args.installed:
            print('MULTI_INSTALLED_JSON={"status":"external_or_unverified"}')
        else:
            print("MULTI_RECOVERY_STATUS=unverified")
        return 2
    finally:
        for fd in reversed(fds):
            os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
