#!/usr/bin/env python3
"""Disposable attested Rocky KVM acceptance of the actual Sendmail v2 Restore.

The normal CLI restores two real package files with SELinux Enforcing.
A separate child exercises the same implementation and exits abruptly
immediately after its first verified atomic replacement. A fresh process
reviews and rolls back that journal. No service or queue action is requested.
Failure aborts the outer fixture before Sendmail startup; never clear an
unverified journal or blindly repair unexpected files.
"""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
PRODUCT = HERE / "restore-foreign-mta-config.py"
EXIT_AFTER_FIRST_REPLACE = 91
CANDIDATE = "compiled_files_review_candidate_only"
RESTORE_CONFIRM = "RESTORE_STOPPED_SENDMAIL_V2_COMPILED_CONFIG"
ROLLBACK_CONFIRM = "ROLLBACK_INTERRUPTED_SENDMAIL_V2_CONFIG"
PREFIX = "LMR365_SENDMAIL_VM_PRODUCT_"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dual = load_module("lmr365_product_dual_fixture",
                   HERE / "rocky_vm_sendmail_stopped_dual_config_restore.py")
reboot = load_module("lmr365_product_reboot_fixture",
                     HERE / "rocky_vm_sendmail_post_reboot_check.py")


def require(condition, category):
    if not condition:
        raise RuntimeError(PREFIX + category)


def parse_fields(text):
    require(len(text) <= 8192 and "\0" not in text, "RECEIPT_SIZE")
    result = {}
    for row in text.splitlines():
        key, sep, value = row.partition("=")
        require(bool(sep and re.fullmatch(r"[A-Z0-9_]+", key) and value and
                     key not in result), "MALFORMED_RECEIPT")
        result[key] = value
    return result


def expect(fields, key, value):
    require(fields.get(key) == value, "UNEXPECTED_" + key)


def sha(fields, key):
    value = fields.get(key, "")
    require(bool(re.fullmatch(r"[a-f0-9]{64}", value)), "INVALID_" + key)
    return value


def native_command(*args, expected_code=0, child=False):
    dual.single.verify_disposable()
    script = Path(__file__).resolve() if child else PRODUCT
    argv = [sys.executable, str(script)] + ([] if child else ["--mta", "sendmail"])
    result = subprocess.run(argv + list(args), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, timeout=240, check=False)
    if result.returncode != expected_code:
        # Only bounded refusal categories are logged, never configuration or
        # raw native parser output.
        reason = re.search(r"(?m)^FOREIGN_RESTORE_STATUS=refused_or_failed:([a-z0-9_]+)$",
                           result.stderr[:8192])
        print(PREFIX + "CLI_REFUSAL=" + (reason.group(1) if reason else "unexpected_exit"),
              file=sys.stderr)
        require(False, "CLI_EXIT_" + str(result.returncode))
    if expected_code != 0:
        return result
    return parse_fields(result.stdout)


def review(snapshot_id, changed):
    fields = native_command("--sendmail-v2-plan", snapshot_id)
    expect(fields, "SENDMAIL_V2_PLAN_SNAPSHOT", snapshot_id)
    expect(fields, "SENDMAIL_V2_PLAN_STATUS", "review_only")
    expect(fields, "SENDMAIL_V2_PLAN_GATE", CANDIDATE)
    expect(fields, "SENDMAIL_V2_PLAN_COMPILED_TARGETS", "2")
    expect(fields, "SENDMAIL_V2_PLAN_COMPILED_CHANGED", str(changed))
    for key in ("OTHER_CHANGED", "MISSING", "EXTRA", "METADATA_CHANGED", "OBJECT_DRIFT"):
        expect(fields, "SENDMAIL_V2_PLAN_" + key, "0")
    for key, value in (("SERVICE", "stopped_declared"), ("PROCESSES", "none_observed"),
                       ("QUEUE", "empty_reported"), ("LISTENER", "none_observed"),
                       ("GATE", "offline_candidate_manual_recovery_only")):
        expect(fields, "SENDMAIL_V2_PLAN_OFFLINE_" + key, value)
    for key in ("CONFIG_CHANGED", "QUEUE_CHANGED", "SERVICE_CHANGED", "APPLY_AUTHORIZED"):
        expect(fields, "SENDMAIL_V2_PLAN_" + key, "no")
    sha(fields, "SENDMAIL_V2_PLAN_ARCHIVE_SHA256")
    sha(fields, "SENDMAIL_V2_PLAN_MANIFEST_SHA256")
    return sha(fields, "SENDMAIL_V2_PLAN_PLAN_SHA256")


def completed(fields, status, changed):
    expect(fields, "SENDMAIL_V2_RECOVERY_STATUS", status)
    expect(fields, "SENDMAIL_V2_RECOVERY_CHANGED_FILES", str(changed))
    expect(fields, "SENDMAIL_V2_RECOVERY_NATIVE_STATIC_CHECK", "passed_partial_parse_only")
    expect(fields, "SENDMAIL_V2_RECOVERY_MARKER_CLEARED", "yes")
    expect(fields, "SENDMAIL_V2_EVIDENCE_VERSION", "4")
    expect(fields, "SENDMAIL_V2_EVIDENCE_MTA", "sendmail")
    expect(fields, "SENDMAIL_V2_QUEUE_CHANGED", "no")
    expect(fields, "SENDMAIL_V2_SERVICE_CHANGED", "no")
    for name in ("TARGET_SHA256", "SAFETY_SHA256", "TARGET_MANIFEST_SHA256",
                 "SAFETY_MANIFEST_SHA256", "PLAN_SHA256"):
        sha(fields, "SENDMAIL_V2_EVIDENCE_" + name)
    clear = native_command("--pending-inspect")
    expect(clear, "FOREIGN_PENDING_INSPECT_STATUS", "clear")
    expect(clear, "FOREIGN_PENDING_INSPECT_RESUME_AUTHORIZED", "no")


def interrupt_child(snapshot_id, approved_sha):
    dual.single.verify_disposable()
    product = load_module("lmr365_product_interrupted_child", PRODUCT)
    require(bool(product.backup.ID.fullmatch(snapshot_id) and
                 product.backup.SHA.fullmatch(approved_sha)), "INVALID_CHILD_APPROVAL")
    replace = product.replace_one

    def interrupted(path, content, metadata, uid, **kwargs):
        dual.single.verify_disposable()
        require(path == Path("/etc/mail/sendmail.cf"), "UNEXPECTED_FIRST_WRITE")
        replace(path, content, metadata, uid, **kwargs)
        # A real separate process exits without unwinding finally blocks.
        # The product's fsynced marker and safety snapshot must survive.
        os._exit(EXIT_AFTER_FIRST_REPLACE)

    product.replace_one = interrupted
    product.apply_sendmail_v2(snapshot_id, approved_sha, RESTORE_CONFIRM)
    require(False, "MISSING_ABRUPT_EXIT")


def run(snapshot_id):
    dual.single.verify_disposable()
    product = load_module("lmr365_product_native_restore", PRODUCT)
    backup = product.backup
    require(bool(backup.ID.fullmatch(snapshot_id)), "INVALID_BASELINE_ID")
    require(product.read_pending(backup.BASE, 0) is None, "PREEXISTING_MARKER")
    records, archive_sha = dual.load_records(backup, snapshot_id)
    require(len(records) == 2, "INCOMPLETE_BASELINE")
    manifest, manifest_sha, _ = product.verified_sendmail_v2_manifest(snapshot_id, backup.BASE, 0)
    labels = reboot.fingerprint_package_selinux(manifest)
    baseline = product.sendmail_v2_current_inventory(backup.ROOT, 0)
    review(snapshot_id, 0)

    def check_baseline():
        dual.verify_recovered(backup, snapshot_id, records, archive_sha)
        current = product.sendmail_v2_current_inventory(backup.ROOT, 0)
        product.sendmail_v2_validate_live(current, baseline, manifest, 0)
        require(reboot.fingerprint_package_selinux(manifest) == labels, "FULL_PACKAGE_LABEL_DRIFT")
        require(product.native_static_config_check("sendmail") is True, "NATIVE_PARSER")
        require(product.read_pending(backup.BASE, 0) is None, "FINAL_MARKER_PRESENT")
        dual.single.verify_disposable()

    # Capture a known valid alternative differing only in harmless comments.
    # It is also the source state of the first normal Restore.
    for record in records:
        dual.change(record)
    alternate, _ = backup.backup("sendmail")
    require(alternate != snapshot_id, "ALTERNATE_SNAPSHOT_NOT_INDEPENDENT")
    require(backup.recovery_preview("sendmail", alternate)["current"] == "identical",
            "ALTERNATE_NOT_IDENTICAL")
    plan = review(snapshot_id, 2)
    restored = native_command("--sendmail-v2-apply", snapshot_id,
                              "--approve-sha256", plan, "--confirm", RESTORE_CONFIRM)
    completed(restored, "config_replaced_service_not_started", 2)
    expect(restored, "SENDMAIL_V2_EVIDENCE_TARGET", snapshot_id)
    expect(restored, "SENDMAIL_V2_EVIDENCE_TARGET_SHA256", archive_sha)
    expect(restored, "SENDMAIL_V2_EVIDENCE_TARGET_MANIFEST_SHA256", manifest_sha)
    expect(restored, "SENDMAIL_V2_EVIDENCE_PLAN_SHA256", plan)
    check_baseline()
    print(PREFIX + "RESTORE=verified_two_files_native_cli", flush=True)

    # Apply the alternative using the product, but end the child immediately
    # after the first actual atomic write. Then use only the real rollback.
    plan = review(alternate, 2)
    native_command("--interrupt", alternate, plan, expected_code=EXIT_AFTER_FIRST_REPLACE, child=True)
    dual.single.verify_disposable()
    require(dual.check_current(records[0]) == "controlled_edit" and
            dual.check_current(records[1]) == "restored", "PARTIAL_STATE_NOT_OBSERVED")
    marker = product.read_pending(backup.BASE, 0)
    require(marker is not None and marker["version"] == 4 and marker["target"] == alternate and
            marker["plan_sha256"] == plan, "DURABLE_MARKER_NOT_OBSERVED")
    pending = native_command("--pending-inspect")
    expect(pending, "FOREIGN_PENDING_INSPECT_STATUS", "manual_recovery_required")
    expect(pending, "FOREIGN_PENDING_INSPECT_COMPARISON", "verified_sampled_content_only")
    expect(pending, "FOREIGN_PENDING_INSPECT_TARGET_ONLY", "1")
    expect(pending, "FOREIGN_PENDING_INSPECT_ORIGINAL_ONLY", "1")
    expect(pending, "FOREIGN_PENDING_INSPECT_OTHER", "0")
    expect(pending, "FOREIGN_PENDING_INSPECT_MISSING", "0")
    expect(pending, "FOREIGN_PENDING_INSPECT_EXTRA", "0")
    expect(pending, "FOREIGN_PENDING_INSPECT_RESUME_AUTHORIZED", "no")
    refused = native_command("--sendmail-v2-plan", snapshot_id, expected_code=2)
    require("pending_restore_requires_manual_recovery" in refused.stderr, "REENTRY_NOT_BLOCKED")
    require(product.read_pending(backup.BASE, 0) == marker, "MARKER_CHANGED_DURING_REFUSAL")

    rollback = native_command("--sendmail-v2-rollback-plan")
    expect(rollback, "SENDMAIL_V2_ROLLBACK_STATUS", "review_only")
    expect(rollback, "SENDMAIL_V2_ROLLBACK_CHANGED_FILES", "1")
    expect(rollback, "SENDMAIL_V2_ROLLBACK_CONFIG_CHANGED", "no")
    expect(rollback, "SENDMAIL_V2_EVIDENCE_TARGET", alternate)
    expect(rollback, "SENDMAIL_V2_EVIDENCE_SAFETY", marker["safety"])
    rollback_sha = sha(rollback, "SENDMAIL_V2_ROLLBACK_PLAN_SHA256")
    result = native_command("--sendmail-v2-rollback-apply", "--approve-sha256",
                            rollback_sha, "--confirm", ROLLBACK_CONFIRM)
    completed(result, "original_verified_service_not_started", 1)
    expect(result, "SENDMAIL_V2_ROLLBACK_APPROVED_SHA256", rollback_sha)
    for key in ("TARGET", "SAFETY", "TARGET_SHA256", "SAFETY_SHA256",
                "TARGET_MANIFEST_SHA256", "SAFETY_MANIFEST_SHA256", "PLAN_SHA256"):
        expect(result, "SENDMAIL_V2_EVIDENCE_" + key, rollback["SENDMAIL_V2_EVIDENCE_" + key])
    check_baseline()
    print(PREFIX + "ABRUPT_ROLLBACK=verified_original_bytes", flush=True)
    print(PREFIX + "SELINUX=full_package_labels_unchanged", flush=True)
    print(PREFIX + "QUEUES_SERVICES=unchanged_stopped_empty", flush=True)
    print(PREFIX + "EXTERNAL_DELIVERY_TESTED=no", flush=True)
    print(PREFIX + "PRODUCTION_ACCEPTANCE=no", flush=True)


if __name__ == "__main__":
    dual.single.verify_disposable()
    if len(sys.argv) == 4 and sys.argv[1] == "--interrupt":
        interrupt_child(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 2:
        run(sys.argv[1])
    else:
        require(False, "INVALID_ARGUMENTS")
