#!/usr/bin/env python3
"""CI-only real Sendmail queue previews. No delivery or host spool writes."""
import hashlib
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys

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
                            stderr=subprocess.DEVNULL, text=True,
                            timeout=90, check=False,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    require(not check or result.returncode == 0,
            "native_command_failed:" + Path(args[0]).name)
    return result


def isolated_spools():
    require(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and bool(os.environ.get("RUNNER_TEMP")), "disposable_host_required")
    for ns in ("mnt", "net"):
        require(os.readlink("/proc/self/ns/" + ns) != os.readlink("/proc/1/ns/" + ns),
                "private_namespace_required:" + ns)
    require({name for _, name in socket.if_nameindex()} == {"lo"},
            "isolated_network_required")
    require(run(["systemctl", "is-active", "--quiet", "sendmail.service"],
                check=False).returncode != 0, "sendmail_service_active")
    require(run(["pgrep", "-x", "sendmail"], check=False).returncode == 1,
            "sendmail_process_present")
    run(["mount", "--make-rprivate", "/"])
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
              ":mode=" + format(stat.S_IMODE(meta.st_mode), "o"), flush=True)
    for _, path in QUEUES.values():
        meta = os.lstat(path)
        require(stat.S_ISDIR(meta.st_mode) and not meta.st_mode & 0o007,
                "unexpected_package_queue_directory")
        options = "size=16m,nosuid,nodev,noexec,mode={:o},uid={},gid={}".format(
            stat.S_IMODE(meta.st_mode), meta.st_uid, meta.st_gid)
        run(["mount", "-t", "tmpfs", "-o", options, "tmpfs", path])
        require(run(["findmnt", "-n", "-o", "FSTYPE", "--mountpoint", path]).stdout.strip()
                == "tmpfs", "fixture_spool_not_mounted")
        require(not list(Path(path).iterdir()), "fixture_spool_not_empty")
    print("NATIVE_SENDMAIL_FIXTURE_PRIVATE_MOUNTS=ready", flush=True)


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
    # Only synthetic files under the two private tmpfs mounts.
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
    print("NATIVE_SENDMAIL_QUEUE_ISOLATION=verified_private_spools_no_delivery")
    # Namespace teardown drops private mounts, never deletes host queue files.
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
