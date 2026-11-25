#!/usr/bin/env python3
"""CI-only real Sendmail queue previews. No delivery or host spool writes."""
import hashlib
import importlib.util
import os
import pwd
import grp
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile

HELPER = Path(__file__).resolve().parents[1] / "linux/inspect-mail-queue.py"
QUEUES = {}
PACKAGE_LAYOUTS = {
    "mta": ("-Am", "sendmail.cf", ("/var/spool/mqueue",)),
    "msp": ("-Ac", "submit.cf", ("/var/spool/clientmqueue", "/var/spool/mqueue-client")),
}
RECIPIENT = "lmr365-queue-fixture@[192.0.2.1]"
SHA = re.compile(r"[a-f0-9]{64}")
CONFIRM = {"retry": "RETRY_SELECTED_SENDMAIL_MESSAGE",
           "flush": "RUN_SELECTED_SENDMAIL_QUEUE_ONCE"}


def require(ok, reason):
    if not ok:
        raise AssertionError(reason)


def run(args, data=None, check=True):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, universal_newlines=True,
                            timeout=90, check=False,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    require(not check or result.returncode == 0,
            "native_command_failed:" + Path(args[0]).name)
    return result


def container_isolation():
    """PID 1 in a disposable Docker image with no network or host spools."""
    require(os.getpid() == 1 and Path("/.dockerenv").is_file()
            and not Path("/run/systemd/system").exists(),
            "disposable_container_required")
    cmdline = Path("/proc/1/cmdline").read_bytes().split(b"\0")
    require(len(cmdline) >= 2 and cmdline[1].endswith(
            b"smoke_native_sendmail_queue_preview.py"), "unexpected_container_entrypoint")
    roots = []
    mountpoints = set()
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        parts = line.split()
        require(len(parts) > 8 and "-" in parts, "invalid_mountinfo")
        mountpoints.add(parts[4])
        if parts[4] == "/":
            roots.append(parts[parts.index("-") + 1])
    require(roots == ["overlay"], "disposable_overlay_required")
    protected = [Path("/etc/mail"), Path("/var/spool")]
    for _, _, allowed in PACKAGE_LAYOUTS.values():
        protected.extend(Path(path) for path in allowed)
    for root in protected:
        for path in [root] + list(root.parents):
            require(str(path) == "/" or (str(path) not in mountpoints
                    and not path.is_symlink()), "host_mount_or_alias_refused")
    # Reject nested mounts anywhere under the test spools or configuration.
    require(not any(m.startswith(str(root) + "/") for m in mountpoints
                    for root in protected), "nested_host_mount_refused")
    for task in Path("/proc").iterdir():
        if not task.name.isdigit():
            continue
        try:
            name = (task / "comm").read_text().strip()
        except FileNotFoundError:
            continue
        require(not name.startswith("sendmail"), "sendmail_process_present")
    print("NATIVE_SENDMAIL_FIXTURE_CONTAINER=verified_overlay_network_none", flush=True)


def vm_isolation():
    """Only the explicitly marked Rocky KVM guest, with real Enforcing."""
    release = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if line.startswith(("ID=", "VERSION_ID=")):
            key, value = line.split("=", 1)
            require(key not in release, "ambiguous_vm_os_release")
            release[key] = value.strip().strip("'\"")
    require(release == {"ID": "rocky", "VERSION_ID": "9.9"}
            and Path("/proc/1/comm").read_text().strip() == "systemd"
            and not Path("/.dockerenv").exists()
            and socket.gethostname().split(".")[0] == "rocky-selinux-ci",
            "disposable_rocky_vm_required")
    require(run(["systemd-detect-virt", "--vm"]).stdout.strip() == "kvm",
            "real_kvm_required")
    require(Path("/sys/fs/selinux/enforce").read_text().strip() == "1"
            and run(["getenforce"]).stdout.strip() == "Enforcing",
            "selinux_enforcing_required")
    marker = Path("/run/lmr365-disposable-sendmail-queue-vm")
    st = marker.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
            and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size <= 64,
            "vm_marker_not_root_private")
    require(marker.read_text(encoding="ascii").strip() ==
            Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
            "vm_marker_boot_mismatch")
    # The host primary Postfix remains running outside the network namespace.
    # Both Sendmail units must be inactive and the package queue runners absent.
    require(run(["systemctl", "is-active", "--quiet", "postfix.service"],
                check=False).returncode == 0, "primary_postfix_not_active")
    for unit in ("sendmail.service", "sm-client.service"):
        require(run(["systemctl", "is-active", "--quiet", unit],
                    check=False).returncode != 0, "sendmail_unit_active")
    print("NATIVE_SENDMAIL_VM_SELINUX=enforcing_verified", flush=True)


def vm_mount_records(mountinfo, path):
    """Exact mountpoint evidence, including same-filesystem bind mounts.

    Queue paths are fixed ASCII paths with no mountinfo escape characters.
    Reject a pre-existing stacked or nested mount instead of hiding it.
    """
    require(path in ("/var/spool/mqueue", "/var/spool/clientmqueue",
                     "/var/spool/mqueue-client"), "vm_mount_path_unsupported")
    matches = []
    for line in mountinfo.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and "-" in fields and fields[0].isdigit(),
                "vm_mountinfo_invalid")
        separator = fields.index("-")
        require(separator >= 6 and len(fields) >= separator + 4,
                "vm_mountinfo_invalid")
        mountpoint = fields[4]
        require(not mountpoint.startswith(path + "/"), "vm_nested_queue_mount")
        if mountpoint == path:
            matches.append(int(fields[0]))
    require(len(matches) <= 1, "vm_stacked_queue_mount")
    return matches


def vm_bind_empty_spool(path, metadata):
    """Bind a private, correctly labeled on-disk spool over the native path.

    The original directory is not renamed or written. Never use a context=
    tmpfs mount (which would hide real on-disk labels and type transitions).
    The caller already holds private mount/network namespaces and has
    verified the disposable guest and inactive native Sendmail services.
    """
    def mounted():
        return vm_mount_records(Path("/proc/self/mountinfo").read_text(encoding="ascii"), path)
    require(not mounted(), "vm_native_queue_is_mount")
    run(["matchpathcon", "-V", path])
    label = os.getxattr(path, "security.selinux", follow_symlinks=False)
    require(bool(label), "vm_native_queue_label_missing")
    original = Path(path)
    # Only an empty queue or the RPM-owned client statistics file is allowed.
    for item in original.iterdir():
        item_stat = item.lstat()
        require(path == "/var/spool/clientmqueue" and item.name == "sm-client.st"
                and stat.S_ISREG(item_stat.st_mode) and item_stat.st_nlink == 1
                and run(["rpm", "-qf", "--qf", "%{NAME}", str(item)]).stdout.strip() == "sendmail",
                "vm_original_queue_not_empty")
    private = tempfile.mkdtemp(prefix="lmr365-ci-queue-", dir="/var/spool")
    os.chown(private, metadata.st_uid, metadata.st_gid)
    os.chmod(private, stat.S_IMODE(metadata.st_mode))
    run(["chcon", "--reference=" + path, private])
    require(os.getxattr(private, "security.selinux", follow_symlinks=False) == label,
            "vm_fixture_queue_label_mismatch")
    private_stat = os.lstat(private)
    require((private_stat.st_dev, private_stat.st_ino) !=
            (metadata.st_dev, metadata.st_ino), "vm_fixture_aliases_original")
    run(["mount", "--bind", private, path])
    # os.path.ismount() misses same-device bind mounts. Require an exact
    # mountinfo entry AND the mounted directory's identity to match our
    # private directory, not the original queue. No relaxed fallback.
    require(len(mounted()) == 1, "vm_private_spool_mountinfo_unverified")
    mounted_stat = os.lstat(path)
    require(stat.S_ISDIR(mounted_stat.st_mode)
            and (mounted_stat.st_dev, mounted_stat.st_ino) ==
                (private_stat.st_dev, private_stat.st_ino)
            and (mounted_stat.st_uid, mounted_stat.st_gid, stat.S_IMODE(mounted_stat.st_mode)) ==
                (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)),
            "vm_private_spool_inode_unverified")
    require(os.getxattr(path, "security.selinux", follow_symlinks=False) == label,
            "vm_private_spool_not_verified")
    print("NATIVE_SENDMAIL_VM_BIND_IDENTITY=verified", flush=True)
    run(["matchpathcon", "-V", path])
    require(not list(Path(path).iterdir()), "vm_private_spool_not_empty")
    # The disposable VM disk is discarded by the outer KVM harness. No
    # explicit file removal, mount of a host path, or service change here.


def verify_vm_message_labels():
    require(Path("/sys/fs/selinux/enforce").read_text().strip() == "1",
            "selinux_changed_during_queue_test")
    for _, path in QUEUES.values():
        run(["matchpathcon", "-V", path])
        for item in Path(path).iterdir():
            st = item.lstat()
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
                    "vm_unexpected_message_artifact")
            run(["matchpathcon", "-V", str(item)])
    print("NATIVE_SENDMAIL_VM_QUEUE_LABELS=verified_policy_match", flush=True)


def isolated_spools():
    require(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and bool(os.environ.get("RUNNER_TEMP")), "disposable_host_required")
    require({name for _, name in socket.if_nameindex()} == {"lo"},
            "isolated_network_required")
    container = os.environ.get("LMR365_CI_DISPOSABLE_CONTAINER") == "1"
    vm = os.environ.get("LMR365_CI_KVM_QUEUE_FIXTURE") == "1"
    require(not (container and vm), "ambiguous_fixture_isolation")
    if container:
        container_isolation()
    else:
        for ns in ("mnt", "net"):
            require(os.readlink("/proc/self/ns/" + ns) != os.readlink("/proc/1/ns/" + ns),
                    "private_namespace_required:" + ns)
        require(run(["systemctl", "is-active", "--quiet", "sendmail.service"],
                    check=False).returncode != 0, "sendmail_service_active")
        require(run(["pgrep", "-x", "sendmail"], check=False).returncode == 1,
                "sendmail_process_present")
        run(["mount", "--make-rprivate", "/"])
        if vm:
            vm_isolation()
    for queue, (mode, config, allowed) in PACKAGE_LAYOUTS.items():
        # Do not create a guessed directory or use an arbitrary config path.
        # Establish the independent native fixture layout before any submission.
        text = (Path("/etc/mail") / config).read_text(encoding="utf-8")
        candidates = re.findall(r"(?m)^O\s+QueueDirectory\s*=\s*([^\s#]+)", text)
        require(len(candidates) == 1, "fixture_queue_directory_ambiguous:" + queue)
        path = candidates[0]
        if path.endswith("/"):
            path = path[:-1]
        require(path in allowed, "fixture_queue_directory_unsupported:" + queue)
        require(Path(path).is_dir() and not Path(path).is_symlink(),
                "fixture_queue_directory_missing:" + queue + ":" + path)
        QUEUES[queue] = (mode, path)
        meta = os.lstat(path)
        print("NATIVE_SENDMAIL_FIXTURE_LAYOUT=" + queue + ":" + path +
              ":uid=" + str(meta.st_uid) + ":gid=" + str(meta.st_gid) +
              ":owner=" + pwd.getpwuid(meta.st_uid).pw_name +
              ":group=" + grp.getgrgid(meta.st_gid).gr_name +
              ":mode=" + format(stat.S_IMODE(meta.st_mode), "o"), flush=True)
    for queue, (_, path) in QUEUES.items():
        meta = os.lstat(path)
        require(stat.S_ISDIR(meta.st_mode) and not meta.st_mode & 0o007,
                "unexpected_package_queue_directory")
        options = "size=16m,nosuid,nodev,noexec,mode={:o},uid={},gid={}".format(
            stat.S_IMODE(meta.st_mode), meta.st_uid, meta.st_gid)
        if vm:
            vm_bind_empty_spool(path, meta)
        elif not container:
            run(["mount", "-t", "tmpfs", "-o", options, "tmpfs", path])
            require(run(["findmnt", "-n", "-o", "FSTYPE", "--mountpoint", path]).stdout.strip()
                    == "tmpfs", "fixture_spool_not_mounted")
        else:
            require(not os.path.ismount(path), "external_queue_mount_refused")
        entries = list(Path(path).iterdir())
        if container and queue == "msp" and path == "/var/spool/clientmqueue":
            # EL RPMs ship sm-client.st (client statistics), not a message.
            # Keep it intact, verify package ownership and regular-file metadata.
            # Never remove, ignore or seed any actual queue file.
            for entry in entries:
                st = entry.lstat()
                require(entry.name == "sm-client.st" and stat.S_ISREG(st.st_mode)
                        and st.st_nlink == 1 and st.st_uid == meta.st_uid
                        and st.st_gid == meta.st_gid and not st.st_mode & 0o007,
                        "unexpected_package_spool_artifact")
                owner = run(["rpm", "-qf", "--qf", "%{NAME}", str(entry)]).stdout.strip()
                require(owner == "sendmail", "unowned_package_spool_artifact")
            print("NATIVE_SENDMAIL_FIXTURE_MSP_STATISTICS=" +
                  ("package_verified" if entries else "absent"), flush=True)
        else:
            require(not entries, "fixture_spool_not_empty:" + queue)
    print("NATIVE_SENDMAIL_FIXTURE_PRIVATE_MOUNTS=" +
          ("disposable_overlay" if container else "labeled_vm_bind" if vm else "ready"), flush=True)
    spec = importlib.util.spec_from_file_location("sendmail_fixture_product", str(HELPER))
    product = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(product)
    for queue in QUEUES:
        stages = []
        try:
            product.sendmail_action_context(queue, diagnostic=stages.append)
        except product.Unavailable as error:
            raise AssertionError("native_context_refused:" + queue + ":" +
                                 (stages[-1] if stages else "unknown") + ":" + error.result)
    print("NATIVE_SENDMAIL_FIXTURE_PACKAGE_CONTEXT=verified", flush=True)


def fields(*args):
    reply = run([sys.executable, str(HELPER), "--scope", "sendmail", *args]).stdout
    require(len(reply) <= 16384 and "lmr365-queue-fixture" not in reply
            and "192.0.2.1" not in reply and "/var/spool/" not in reply,
            "private_output_or_size")
    result = {}
    for line in reply.splitlines():
        key, value = line.split("=", 1)
        require(key not in result, "duplicate_receipt")
        result[key] = value
    return result


def inventory(queue, count):
    nonce = secrets.token_hex(32)
    f = fields("--sendmail-inventory", queue, "--sendmail-reviewable",
               "--selection-nonce", nonce)
    require(f.get("SENDMAIL_ITEMS_RESULT") == "ok",
            "native_inventory_refused:" + queue + ":" + f.get("SENDMAIL_ITEMS_RESULT", "missing"))
    require(f.get("SENDMAIL_ITEMS_CONTEXT") == "verified", "native_context_unverified:" + queue)
    for key in ("TOTAL", "LISTED", "NATIVE_LISTED"):
        require(f.get("SENDMAIL_ITEMS_" + key) == str(count), "wrong_queue_count:" + queue)
    require(f.get("SENDMAIL_ITEMS_QUEUE") == queue
            and f.get("SENDMAIL_ITEMS_VERSION") == "2"
            and f.get("SENDMAIL_ITEMS_NATIVE_TRUNCATED") == "no"
            and f.get("SENDMAIL_ITEMS_CHANGES_APPLIED") == "no", "unexpected_inventory_receipt")
    if not count:
        require("SENDMAIL_ITEMS_ROW" not in f, "empty_queue_has_rows")
        return nonce, None, None
    row = f["SENDMAIL_ITEMS_ROW"].split("|")
    require(len(row) == 7 and row[0] == "1" and row[2] != "processing_mark"
            and SHA.fullmatch(row[6]) is not None, "native_selection_unverified:" + queue)
    return nonce, f["SENDMAIL_ITEMS_SAMPLED_AT"], row[6]


def snapshot():
    # Only synthetic files and native package statistics under isolated spools.
    return {queue: {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in Path(path).iterdir() if p.is_file() and not p.is_symlink()}
            for queue, (_, path) in QUEUES.items()}


def preview(queue, action, selection):
    nonce, sampled, token = selection
    args = ["--sendmail-action", action, "--sendmail-queue", queue, "--selection-nonce", nonce]
    if action == "retry":
        args += ["--sampled-at", sampled, "--target-fingerprint", token]
    return args, fields(*args)


def refusal(args, plan, action, digest):
    f = fields(*args, "--sendmail-apply", "--prepared-at", plan["SENDMAIL_ACTION_PREPARED_AT"],
               "--approve-sha256", digest, "--confirm", CONFIRM[action])
    require(f.get("SENDMAIL_ACTION_OUTCOME") == "not_requested"
            and f.get("SENDMAIL_ACTION_COMMAND_COUNT") == "0"
            and f.get("SENDMAIL_ACTION_DELIVERY_VERIFIED") == "no"
            and f.get("SENDMAIL_ACTION_CONFIG_CHANGED") == "no"
            and f.get("SENDMAIL_ACTION_SERVICE_CHANGED") == "no", "invalid_plan_dispatched")
    return f.get("SENDMAIL_ACTION_REASON")


def main():
    isolated_spools()
    print("NATIVE_SENDMAIL_FIXTURE_PHASE=empty_review", flush=True)
    for queue in QUEUES:
        _, f = preview(queue, "flush", inventory(queue, 0))
        require(f.get("SENDMAIL_ACTION_OUTCOME") == "not_requested"
                and f.get("SENDMAIL_ACTION_REASON") == "no_queued_messages"
                and f.get("SENDMAIL_ACTION_COMMAND_COUNT") == "0", "empty_queue_flush_accepted")

    print("NATIVE_SENDMAIL_FIXTURE_PHASE=synthetic_submission", flush=True)
    for queue, (mode, _) in QUEUES.items():
        run(["/usr/sbin/sendmail", mode, "-odq", "-i", "-f", "<>", RECIPIENT],
            "Subject: Isolated synthetic Sendmail queue fixture\n\nSynthetic test only.\n")
        inventory(queue, 1)
        inventory("msp" if queue == "mta" else "mta", 0 if queue == "mta" else 1)

    print("NATIVE_SENDMAIL_FIXTURE_PHASE=nonempty_review", flush=True)
    before = snapshot()
    require(all(any(name.startswith("qf") for name in files)
                for files in before.values()), "synthetic_queue_file_missing")
    for queue in QUEUES:
        other = "msp" if queue == "mta" else "mta"
        for action in ("retry", "flush"):
            args, plan = preview(queue, action, inventory(queue, 1))
            digest = plan.get("SENDMAIL_ACTION_PLAN_SHA256", "")
            require(plan.get("SENDMAIL_ACTION_OUTCOME") == "candidate"
                    and plan.get("SENDMAIL_ACTION_TARGET_COUNT") == "1"
                    and plan.get("SENDMAIL_ACTION_COMMAND_COUNT") == "0"
                    and SHA.fullmatch(digest) is not None,
                    "native_plan_refused:" + queue + ":" + action + ":" +
                    plan.get("SENDMAIL_ACTION_REASON", "missing"))
            bad_digest = ("0" if digest[0] != "0" else "1") + digest[1:]
            require(refusal(args, plan, action, bad_digest) == "plan_changed",
                    "tampered_plan_not_refused")
            other_args = args.copy()
            other_args[other_args.index("--sendmail-queue") + 1] = other
            require(refusal(other_args, plan, action, digest) in ("plan_changed", "sample_changed"),
                    "cross_queue_plan_not_refused")
            require(snapshot() == before, "synthetic_queue_changed_by_preview_or_refusal")
        print("NATIVE_SENDMAIL_" + queue.upper() + "_PREVIEW_AND_REFUSAL=verified")
    # Exercise confirmed product quarantine transitions ONLY on the two
    # isolated synthetic spools. No service or real delivery is involved.
    for queue, (mode, path) in QUEUES.items():
        other = "msp" if queue == "mta" else "mta"
        def held_count(expected):
            nonce = secrets.token_hex(32)
            f = fields("--sendmail-inventory", queue, "--sendmail-quarantine",
                       "--selection-nonce", nonce)
            require(f.get("SENDMAIL_ITEMS_VERSION") == "1" and
                    f.get("SENDMAIL_ITEMS_QUEUE_CLASS") == "quarantine" and
                    f.get("SENDMAIL_ITEMS_RESULT") == "ok" and
                    f.get("SENDMAIL_ITEMS_TOTAL") == str(expected) and
                    f.get("SENDMAIL_ITEMS_LISTED") == str(expected) and
                    "SENDMAIL_ITEMS_CONTEXT" not in f, "quarantine_inventory_mismatch:" + queue)
            require("LinuxMailRelay365 operator quarantine" not in str(f), "raw_quarantine_reason_disclosed")
        held_count(0)
        candidates = [p.name[2:] for p in Path(path).iterdir() if p.name.startswith("qf")]
        require(len(candidates) == 1 and re.fullmatch(r"[A-Za-z0-9]{8}[0-9]{5,56}", candidates[0]),
                "fixture_quarantine_id_invalid")
        ident = candidates[0]
        other_before = snapshot()[other]
        def transition(action, quarantine):
            nonce = secrets.token_hex(32)
            flags = ["--sendmail-inventory", queue, "--sendmail-reviewable",
                     "--selection-nonce", nonce]
            if quarantine:
                flags.append("--sendmail-quarantine")
            sample = fields(*flags)
            require(sample.get("SENDMAIL_ITEMS_CONTEXT") == "verified" and
                    sample.get("SENDMAIL_ITEMS_TOTAL") == "1", "transition_inventory_unverified")
            token = sample["SENDMAIL_ITEMS_ROW"].split("|")[6]
            args = ["--sendmail-action", action, "--sendmail-queue", queue,
                    "--selection-nonce", nonce, "--sampled-at", sample["SENDMAIL_ITEMS_SAMPLED_AT"],
                    "--target-fingerprint", token]
            plan = fields(*args)
            require(plan.get("SENDMAIL_ACTION_OUTCOME") == "candidate" and
                    plan.get("SENDMAIL_ACTION_TARGET_COUNT") == "1", "transition_plan_refused")
            receipt = fields(*args, "--sendmail-apply", "--prepared-at", plan["SENDMAIL_ACTION_PREPARED_AT"],
                "--approve-sha256", plan["SENDMAIL_ACTION_PLAN_SHA256"], "--confirm",
                ("QUARANTINE" if action == "quarantine" else "RELEASE") + "_SELECTED_SENDMAIL_MESSAGE")
            require(receipt.get("SENDMAIL_ACTION_OUTCOME") == "transition_verified" and
                    receipt.get("SENDMAIL_ACTION_EFFECT_VERIFIED") == "yes" and
                    receipt.get("SENDMAIL_ACTION_QUARANTINE_CHANGED") == "yes" and
                    receipt.get("SENDMAIL_ACTION_DELIVERY_VERIFIED") == "no",
                    "native_product_transition_unverified:" + action)
        transition("quarantine", False)
        held_count(1)
        inventory(queue, 0)
        require(snapshot()[other] == other_before, "quarantine_other_queue_changed")
        transition("release", True)
        held_count(0)
        inventory(queue, 1)
        require(snapshot()[other] == other_before, "release_other_queue_changed")
        print("NATIVE_SENDMAIL_" + queue.upper() + "_QUARANTINE_INVENTORY=verified_separate_classes")
    if os.environ.get("LMR365_CI_KVM_QUEUE_FIXTURE") == "1":
        verify_vm_message_labels()
        print("NATIVE_SENDMAIL_VM_QUEUE_TRANSITIONS=verified_under_enforcing", flush=True)
    print("NATIVE_SENDMAIL_QUEUE_ISOLATION=verified_private_spools_no_delivery")
    # Namespace teardown drops private mounts; container teardown discards
    # its writable overlay. Never delete host queue files.
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, AssertionError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print("NATIVE_SENDMAIL_QUEUE_PREVIEW=failed:" +
              (str(error) if isinstance(error, AssertionError) else
               type(error).__name__ + (":errno=" + str(error.errno)
                                      if isinstance(error, OSError) else "")), file=sys.stderr)
        sys.exit(2)
