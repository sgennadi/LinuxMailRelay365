#!/usr/bin/env python3
"""Disposable stopped Exim: one queue-only synthetic message, no SMTP delivery."""
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

HELPER = str(Path(__file__).resolve().parents[1] / "linux/inspect-mail-queue.py")
ID = re.compile(r"[A-Za-z0-9]{6}-[A-Za-z0-9]{6,16}-[A-Za-z0-9]{2,8}")
SHA = re.compile(r"[a-f0-9]{64}")
RECIPIENT = "lmr365-fixture@example.invalid"


def run(args, data=None, check=True):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            universal_newlines=True, timeout=90, check=False)
    if check and result.returncode:
        raise AssertionError("native_exim_fixture_command_failed")
    return result


def stopped():
    for unit in ("exim4.service", "exim.service"):
        if run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0:
            raise AssertionError("native_exim_fixture_daemon_active")
    for proc in ("exim4", "exim"):
        if run(["pgrep", "-x", proc], check=False).returncode != 1:
            raise AssertionError("native_exim_fixture_process_present")


def fields(*args):
    output = run([sys.executable, HELPER, "--scope", "exim", *args]).stdout
    if len(output) > 16384 or RECIPIENT in output:
        raise AssertionError("native_exim_private_data_or_size")
    values = {}
    for line in output.splitlines():
        key, value = line.split("=", 1)
        if key in values:
            raise AssertionError("duplicate_exim_receipt")
        values[key] = value
    return values


def selection(state):
    nonce = secrets.token_hex(32)
    sample = fields("--exim-inventory", "--selection-nonce", nonce)
    if sample.get("EXIM_ITEMS_RESULT") != "ok" or sample.get("EXIM_ITEMS_TOTAL") != "1":
        raise AssertionError("native_exim_inventory_not_one")
    row = sample["EXIM_ITEMS_ROW"].split("|")
    if len(row) != 7 or row[1] != state or not SHA.fullmatch(row[6]):
        raise AssertionError("native_exim_selection_unverified")
    return nonce, sample["EXIM_ITEMS_SAMPLED_AT"], row[6]


def action(name, state):
    nonce, sampled, token = selection(state)
    args = ["--exim-action", name, "--selection-nonce", nonce,
            "--sampled-at", sampled, "--target-fingerprint", token]
    plan = fields(*args)
    if plan.get("EXIM_ACTION_OUTCOME") != "candidate" or not SHA.fullmatch(plan["EXIM_ACTION_PLAN_SHA256"]):
        raise AssertionError("native_exim_plan_refused")
    result = fields(*args, "--exim-apply", "--prepared-at", plan["EXIM_ACTION_PREPARED_AT"],
                    "--approve-sha256", plan["EXIM_ACTION_PLAN_SHA256"],
                    "--confirm", "PERMANENTLY_DELETE_SELECTED_FROZEN_EXIM_MESSAGE" if name == "delete"
                    else name.upper() + "_SELECTED_EXIM_MESSAGE")
    if (result.get("EXIM_ACTION_OUTCOME") != "command_completed" or
            result.get("EXIM_ACTION_EFFECT_VERIFIED") != "no" or
            result.get("EXIM_ACTION_COMMAND_COUNT") != "1" or
            result.get("EXIM_ACTION_DELETE_REQUESTED") != ("yes" if name == "delete" else "no")):
        raise AssertionError("native_exim_action_unconfirmed")


def main():
    if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true" or not os.environ.get("RUNNER_TEMP"):
        raise RuntimeError("disposable_root_runner_required")
    stopped()
    binary = "/usr/sbin/exim4"
    if run([binary, "-bpc"]).stdout.strip() != "0":
        raise AssertionError("fixture_requires_empty_queue")
    ident = None
    try:
        # -odq is queue-only; no daemon, network listener or queue run.
        run([binary, "-odq", "-i", "-f", "<>", RECIPIENT],
            "Subject: Synthetic Exim queue fixture\n\nSynthetic test only.\n")
        listing = run([binary, "-bp"]).stdout
        ids = run([binary, "-bpi"]).stdout.split()
        if len(ids) != 1 or not ID.fullmatch(ids[0]) or RECIPIENT not in listing:
            raise AssertionError("synthetic_exim_identity_unverified")
        ident = ids[0]
        action("freeze", "queued")
        selection("frozen")
        print("NATIVE_EXIM_FREEZE=verified_frozen")
        action("thaw", "frozen")
        selection("queued")
        print("NATIVE_EXIM_THAW=verified_queued")
        action("freeze", "queued")
        selection("frozen")
        action("delete", "frozen")
        if run([binary, "-bpc"]).stdout.strip() != "0":
            raise AssertionError("native_exim_delete_effect_unverified")
        ident = None
        print("NATIVE_EXIM_DELETE=verified_single_frozen_fixture_absent")
    finally:
        # Fixture cleanup only: never delete an unverified or non-fixture ID.
        if ident is not None:
            listing = run([binary, "-bp", ident]).stdout
            if RECIPIENT not in listing or ident not in listing:
                raise AssertionError("synthetic_cleanup_identity_unverified")
            run([binary, "-Mrm", ident])
        stopped()
    if run([binary, "-bpc"]).stdout.strip() != "0":
        raise AssertionError("native_exim_fixture_queue_not_empty")
    print("NATIVE_EXIM_QUEUE_MAINTENANCE=verified_no_delivery")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, AssertionError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print("NATIVE_EXIM_QUEUE_MAINTENANCE=failed:" +
              (str(error) if isinstance(error, AssertionError) else type(error).__name__), file=sys.stderr)
        sys.exit(2)
