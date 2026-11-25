#!/usr/bin/env python3
"""Disposable GitHub Actions sidecar only: real product queue maintenance.

Run inside smoke_local_postfix_delivery.sh's existing guarded temporary
loopback routing scope. One synthetic letter, 451 at DATA on every attempt.
No direct queue mutation outside the product helper; no external delivery.
"""
import json
import os
from pathlib import Path
import re
import secrets
import smtplib
import subprocess
import sys
import threading
import time
from email.message import EmailMessage

from smoke_local_postfix_sink import Sink, SENDER, RECIPIENT

CONF = "/etc/linuxmailrelay365/sidecar-postfix"
QUEUE = "/var/spool/linuxmailrelay365-sidecar"
HELPER = str(Path(__file__).resolve().parents[1] / "linux/inspect-mail-queue.py")
MARKER = "LMR365_SYNTHETIC_MAINTENANCE_TEST"
SHA = re.compile(r"[a-f0-9]{64}")
LONG = re.compile(r"[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]{10,100}z[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-y]{1,24}")


def native(*args):
    result = subprocess.run(["sudo", "-n"] + list(args), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, universal_newlines=True,
                            timeout=150, check=False)
    if result.returncode or len(result.stdout) > 1024 * 1024:
        raise AssertionError("native_fixture_command_failed")
    return result.stdout


def check_route(sinkport):
    expected = {
        "queue_directory": QUEUE, "inet_interfaces": "127.0.0.1",
        "relayhost": "[127.0.0.1]:" + str(sinkport),
        "default_transport": "smtp:[127.0.0.1]:" + str(sinkport),
        "relay_transport": "smtp:[127.0.0.1]:" + str(sinkport),
        "smtp_bind_address": "127.0.0.1", "smtp_fallback_relay": "",
        "smtp_tls_security_level": "none", "enable_long_queue_ids": "yes",
        "transport_maps": "", "sender_dependent_relayhost_maps": "",
        "sender_dependent_default_transport_maps": "", "content_filter": "",
        "mydestination": "", "minimal_backoff_time": "600s",
        "maximal_backoff_time": "600s", "queue_run_delay": "600s",
    }
    for key, value in expected.items():
        if native("postconf", "-c", CONF, "-h", key).strip() != value:
            raise AssertionError("loopback_fixture_route_unverified:" + key)
    if native("postconf", "-h", "queue_directory").strip() == QUEUE:
        raise AssertionError("primary_and_sidecar_not_isolated")
    native("systemctl", "is-active", "--quiet", "linuxmailrelay365-sidecar.service")


def rows():
    return [json.loads(line) for line in native("postqueue", "-c", CONF, "-j").splitlines()
            if line.strip()]


def wait_state(state, ident=None, timeout=45):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        sample = rows()
        if len(sample) > 1:
            raise AssertionError("unexpected_additional_mail")
        if not sample and state is None:
            return None
        if sample:
            item = sample[0]
            if (item.get("sender") != SENDER or
                    [r.get("address") for r in item.get("recipients", [])] != [RECIPIENT] or
                    not LONG.fullmatch(item.get("queue_id", "")) or
                    (ident is not None and item["queue_id"] != ident)):
                raise AssertionError("non_fixture_or_changed_message_identity")
            if item["queue_name"] == state:
                return item["queue_id"]
        time.sleep(.25)
    raise AssertionError("expected_queue_state_not_observed:" + str(state))


def fields(*args):
    raw = native("python3", HELPER, "--scope", "sidecar", *args)
    if len(raw) > 32768 or any(text in raw for text in (SENDER, RECIPIENT, MARKER)):
        raise AssertionError("private_or_excessive_product_output")
    result = {}
    for line in raw.splitlines():
        key, value = line.split("=", 1)
        if key in result:
            raise AssertionError("duplicate_product_field")
        result[key] = value
    return result


def require(report, expected):
    for key, value in expected.items():
        if report.get(key) != value:
            raise AssertionError("unexpected_product_receipt:" + key)


def selection(held=False):
    nonce = secrets.token_hex(32)
    report = fields("--messages", "--selection-nonce", nonce)
    require(report, {"MAIL_ITEMS_VERSION": "2", "MAIL_ITEMS_SCOPE": "sidecar",
                     "MAIL_ITEMS_RESULT": "ok", "MAIL_ITEMS_TOTAL": "1",
                     "MAIL_ITEMS_LISTED": "1", "MAIL_ITEMS_RETRY_STATE": "review_only"})
    row = report["MAIL_ITEMS_ROW"].split("|")
    if len(row) != 7 or row[0] != "1" or row[1] != ("held" if held else "deferred") or not SHA.fullmatch(row[-1]):
        raise AssertionError("selected_long_id_fingerprint_unverified")
    return nonce, report["MAIL_ITEMS_SAMPLED_AT"], row[-1]


def maintenance(action, held=False):
    if action == "flush":
        args = ["--maintenance", action, "--selection-nonce", secrets.token_hex(32)]
    else:
        nonce, sampled, token = selection(held)
        args = ["--maintenance", action, "--selection-nonce", nonce,
                "--sampled-at", sampled, "--target-fingerprint", token]
    plan = fields(*args)
    require(plan, {"MAIL_MAINT_ACTION": action, "MAIL_MAINT_SCOPE": "sidecar",
                   "MAIL_MAINT_PHASE": "prepare", "MAIL_MAINT_OUTCOME": "candidate",
                   "MAIL_MAINT_DELETE_REQUESTED": "no", "MAIL_MAINT_COMMAND_COUNT": "0"})
    if not SHA.fullmatch(plan["MAIL_MAINT_PLAN_SHA256"]):
        raise AssertionError("maintenance_plan_unverified")
    confirmation = {"hold": "HOLD_SELECTED_DEFERRED_MESSAGE",
                    "release": "RELEASE_SELECTED_HELD_MESSAGE",
                    "delete": "PERMANENTLY_DELETE_SELECTED_HELD_MESSAGE",
                    "flush": "FLUSH_SELECTED_POSTFIX_INSTANCE"}[action]
    result = fields(*args, "--maintenance-apply", "--prepared-at", plan["MAIL_MAINT_PREPARED_AT"],
                    "--approve-sha256", plan["MAIL_MAINT_PLAN_SHA256"], "--confirm", confirmation)
    require(result, {"MAIL_MAINT_ACTION": action, "MAIL_MAINT_SCOPE": "sidecar",
                     "MAIL_MAINT_PHASE": "apply", "MAIL_MAINT_OUTCOME": "command_completed",
                     "MAIL_MAINT_COMMAND_COUNT": "1", "MAIL_MAINT_EFFECT_VERIFIED": "no",
                     "MAIL_MAINT_DELIVERY_VERIFIED": "no",
                     "MAIL_MAINT_PLAN_SHA256": plan["MAIL_MAINT_PLAN_SHA256"],
                     "MAIL_MAINT_DELETE_REQUESTED": "yes" if action == "delete" else "no"})


def retry():
    nonce, sampled, token = selection()
    base = ["--selection-nonce", nonce, "--sampled-at", sampled]
    plan = fields(*base, "--retry-prepare", token)
    require(plan, {"MAIL_RETRY_RESULT": "candidate_review_only",
                   "MAIL_RETRY_SCOPE": "sidecar", "MAIL_RETRY_APPLY_AUTHORIZED": "no"})
    if not SHA.fullmatch(plan["MAIL_RETRY_PLAN_SHA256"]):
        raise AssertionError("retry_plan_unverified")
    result = fields(*base, "--retry-apply", token,
                    "--prepared-at", plan["MAIL_RETRY_PREPARED_AT"],
                    "--approve-sha256", plan["MAIL_RETRY_PLAN_SHA256"],
                    "--confirm", "RETRY_SELECTED_DEFERRED_MESSAGE")
    require(result, {"MAIL_RETRY_APPLY_OUTCOME": "request_accepted",
                     "MAIL_RETRY_APPLY_REQUEST_COUNT": "1",
                     "MAIL_RETRY_APPLY_DELIVERY_VERIFIED": "no",
                     "MAIL_RETRY_APPLY_PLAN_SHA256": plan["MAIL_RETRY_PLAN_SHA256"]})


def wait_attempt(receiver, previous):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if len(receiver.messages) > previous:
            if receiver.delivered.is_set():
                raise AssertionError("temporary_failure_sink_accepted_message")
            return
        time.sleep(.25)
    raise AssertionError("native_retry_attempt_not_observed")


def main(args):
    if os.environ.get("GITHUB_ACTIONS") != "true" or not os.environ.get("RUNNER_TEMP"):
        raise RuntimeError("disposable_runner_required")
    if len(args) != 2 or not all(x.isdigit() for x in args):
        raise ValueError("invalid_fixture_ports")
    inbound, sinkport = map(int, args)
    if sinkport != 46601 or not 1024 <= inbound <= 65535 or inbound == sinkport:
        raise ValueError("invalid_fixture_ports")
    check_route(sinkport)
    if rows():
        raise AssertionError("fixture_queue_must_be_empty")
    primary_config = native("sha256sum", "/etc/postfix/main.cf", "/etc/postfix/master.cf")
    primary_queue = native("postqueue", "-c", "/etc/postfix", "-j")
    message = EmailMessage()
    message["From"], message["To"] = SENDER, RECIPIENT
    message["Subject"] = "Synthetic queue maintenance fixture"
    message["Message-ID"] = "<maintenance-fixture@ci.invalid>"
    message.set_content(MARKER + "\n")
    with Sink(("127.0.0.1", sinkport), defer_delivery=True) as receiver:
        thread = threading.Thread(target=receiver.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
        thread.start()
        try:
            with smtplib.SMTP("127.0.0.1", inbound, timeout=15) as client:
                if client.sendmail(SENDER, [RECIPIENT], message.as_bytes()):
                    raise AssertionError("synthetic_submission_refused")
            wait_attempt(receiver, 0)
            ident = wait_state("deferred")
            maintenance("hold")
            wait_state("hold", ident)
            print("NATIVE_QUEUE_HOLD=verified_held")
            maintenance("release", held=True)
            wait_state("deferred", ident)
            print("NATIVE_QUEUE_RELEASE=verified_deferred")
            attempts = len(receiver.messages)
            retry()
            wait_attempt(receiver, attempts)
            wait_state("deferred", ident)
            print("NATIVE_QUEUE_RETRY=verified_loopback_attempt")
            attempts = len(receiver.messages)
            maintenance("flush")
            wait_attempt(receiver, attempts)
            wait_state("deferred", ident)
            print("NATIVE_QUEUE_FLUSH=verified_loopback_attempt")
            maintenance("hold")
            wait_state("hold", ident)
            maintenance("delete", held=True)
            wait_state(None, ident)
            if receiver.delivered.is_set():
                raise AssertionError("synthetic_mail_was_accepted")
            print("NATIVE_QUEUE_DELETE=verified_single_held_message_absent")
        finally:
            receiver.shutdown()
            thread.join(timeout=5)
    if native("sha256sum", "/etc/postfix/main.cf", "/etc/postfix/master.cf") != primary_config:
        raise AssertionError("primary_config_changed")
    if native("postqueue", "-c", "/etc/postfix", "-j") != primary_queue:
        raise AssertionError("primary_queue_changed")
    check_route(sinkport)
    print("NATIVE_QUEUE_MAINTENANCE_PRIMARY_UNCHANGED=yes")
    print("EXTERNAL_DELIVERY_VERIFIED=no")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, RuntimeError, AssertionError, KeyError,
            smtplib.SMTPException, subprocess.TimeoutExpired) as error:
        # Fixed assertion codes are safe; never print native command output.
        print("NATIVE_QUEUE_MAINTENANCE=failed:" +
              (str(error) if isinstance(error, AssertionError) else type(error).__name__), file=sys.stderr)
        sys.exit(2)
