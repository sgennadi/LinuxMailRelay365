#!/usr/bin/env python3
"""Bounded read-only multi-transport recovery inventory.

No map queries, credentials, config bytes or private hashes in output.
An observation is not authorization to restore or start a service.
"""
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


def main():
    fds = []
    try:
        if os.geteuid() != 0:
            raise R.Refused("root_required")
        for path in ("/var/lib", P.CONFIG):
            fds.append(P.open_directory(path))
        parent, config = fds
        identity = O.mail_identity()
        entries = inventory(config, parent, 0, identity[1])
        O.same_directory(parent, "/var/lib")
        O.same_directory(config, P.CONFIG)
        if O.mail_identity() != identity:
            raise R.Refused("postfix_account_changed")
        print("MULTI_RECOVERY_STATUS=observed_read_only")
        print("MULTI_RECOVERY_COUNT=" + str(len(entries)))
        for revision, status in entries:
            print("MULTI_RECOVERY_ENTRY=" + revision + ":" + status)
        print("MULTI_RECOVERY_WRITE_ALLOWED=no")
        print("MULTI_RECOVERY_POSTFIX_CHANGED=no")
        return 0
    except Exception:
        print("MULTI_RECOVERY_STATUS=unverified")
        return 2
    finally:
        for fd in reversed(fds):
            os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
