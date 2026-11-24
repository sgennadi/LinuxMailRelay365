#!/usr/bin/env python3
"""Read-only recovery inventory for experimental offline sender-map changes.

Reports snapshots of retained recovery records. This is not permission to
restore, proof of an active route, or proof that Postfix may be started.
Never starts/stops a service, writes a file, or queries a mail map.
"""
import argparse
import importlib.util
import os
import pathlib
import sys

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location(
    "offline_recovery_manager", str(pathlib.Path(__file__).with_name(
        "manage-conditional-postfix-offline.py")))
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)
P, T, M = C.P, C.T, C.M
Refused = M.Refused
MAX_BACKUPS = 64


def observe(config, parent, sha, info, files, uid, map_gid):
    if T.context(config, uid) != info["config_identity"]:
        return "different_config_directory"
    name, suffix = T.checked_name(info["plan"], info["backend"])
    target = name + suffix
    if T.exists(config, name):
        return "unexpected_source_file"
    main, meta = T.config_file(config, "main.cf", uid)
    master = T.config_file(config, "master.cf", uid)
    if (meta != info["main_meta"] or
            master != (files["master.before"], info["master_meta"]) or
            main not in (files["main.before"], files["main.after"])):
        return "config_drift"
    original = main == files["main.before"]
    if not T.exists(config, target):
        return "original_no_map" if original else "configured_map_missing"
    receipt = T.publication_receipt(parent, sha, uid)
    if receipt is None:
        return "map_ownership_unproven"
    try:
        T.checked_published_map(config, target, uid, files["candidate.db"],
                                T.map_metadata(info, map_gid), receipt)
    except (Refused, OSError, ValueError):
        return "map_identity_or_content_changed"
    return "original_owned_map" if original else "configured_owned_map"


def inspect(config, parent, sha, uid, map_gid):
    if not C.sha(sha):
        raise Refused("invalid_backup_sha")
    try:
        info, files = T.load_backup(parent, sha, uid)
    except (Refused, OSError, ValueError, TypeError, KeyError, IndexError):
        return "invalid_or_missing_backup"
    try:
        first = observe(config, parent, sha, info, files, uid, map_gid)
        if T.load_backup(parent, sha, uid) != (info, files):
            return "unstable_observation"
        second = observe(config, parent, sha, info, files, uid, map_gid)
        return first if first == second else "unstable_observation"
    except (Refused, OSError, ValueError, TypeError, KeyError, IndexError):
        return "state_unverified"


def list_recovery(config, parent, uid, map_gid):
    # Never create a recovery directory merely to inspect it.
    try:
        base = M.open_base(parent, uid, name=T.BACKUP_BASE)
    except FileNotFoundError:
        return []
    try:
        names = os.listdir(base)
        if len(names) > MAX_BACKUPS or not all(C.sha(name) for name in names):
            raise Refused("recovery_inventory_limit_or_unrecognized_entry")
        # Missing or incomplete per-backup data is shown, not silently skipped.
        result = [(name, inspect(config, parent, name, uid, map_gid))
                  for name in sorted(names)]
        if set(os.listdir(base)) != set(names):
            raise Refused("recovery_inventory_changed")
        return result
    finally:
        os.close(base)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true")
    group.add_argument("--inspect", metavar="BACKUP_SHA256")
    args = parser.parse_args(argv)
    fds = []
    try:
        if os.geteuid() != 0:
            raise Refused("root_required")
        if args.inspect is not None and not C.sha(args.inspect):
            raise Refused("invalid_backup_sha")
        # No maintenance lock is created: this command is observational only.
        # An in-progress writer or drift can make the observation stale.
        for path in ("/var/lib", P.CONFIG):
            fds.append(P.open_directory(path))
        parent, config = fds
        identity = C.mail_identity()
        if args.list:
            entries = list_recovery(config, parent, 0, identity[1])
        else:
            entries = [(args.inspect, inspect(config, parent, args.inspect, 0, identity[1]))]
        C.same_directory(config, P.CONFIG)
        C.same_directory(parent, "/var/lib")
        if C.mail_identity() != identity:
            raise Refused("postfix_account_changed")
        print("CONDITIONAL_RECOVERY_STATUS=observed_read_only")
        print("CONDITIONAL_RECOVERY_COUNT=" + str(len(entries)))
        for sha, state in entries:
            print("CONDITIONAL_RECOVERY_ENTRY=" + sha + ":" + state)
        print("CONDITIONAL_RECOVERY_WRITE_ALLOWED=no")
        print("CONDITIONAL_RECOVERY_POSTFIX_CHANGED=no")
        return 0
    except (Refused, OSError, ValueError, TypeError, KeyError, IndexError):
        print("CONDITIONAL_RECOVERY_STATUS=unverified")
        print("CONDITIONAL_RECOVERY_WRITE_ALLOWED=no")
        print("CONDITIONAL_RECOVERY_POSTFIX_CHANGED=no")
        return 2
    finally:
        for fd in reversed(fds):
            os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
