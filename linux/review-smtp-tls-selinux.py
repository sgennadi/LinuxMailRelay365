#!/usr/bin/env python3
"""Reviewed SELinux label repair for one managed SMTP TLS generation.
No policy changes, no permissive mode, no recursive relabel, no service reload.
"""
import importlib.util
import json
import os
import re
import stat
import subprocess
from pathlib import Path

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
LABEL = re.compile(r"[A-Za-z0-9_.:-]+(?:,[A-Za-z0-9_.:-]+)*")
FILES = ("client-chain.pem", "fullchain.pem", "key.pem")


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def command(adapter, binary, *args):
    result = subprocess.run([adapter.trusted_binary(binary), *args], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=15, env=ENV)
    if result.returncode or len(result.stdout) > 4096:
        raise ValueError("SELinux tool failed")
    return result.stdout.decode("ascii").strip()


def safe_label(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or not LABEL.fullmatch(value) or value.count(":") < 2:
        raise ValueError("unknown context")
    return value


def label_row(path, adapter, repairable):
    st = path.lstat()
    if st.st_uid != 0 or (not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022):
        raise ValueError("unsafe label target")
    if stat.S_ISLNK(st.st_mode):
        kind = "symlink"
    elif stat.S_ISDIR(st.st_mode):
        kind = "directory"
    elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
        kind = "file"
    else:
        raise ValueError("unsupported label target")
    # matchpathcon uses the file type from lstat for existing paths.
    expected = safe_label(command(adapter, "/usr/sbin/matchpathcon", "-n", str(path)))
    actual = safe_label(os.getxattr(str(path), "security.selinux", follow_symlinks=False)
                        .rstrip(b"\x00").decode("ascii"))
    return {"path": str(path), "kind": kind, "actual": actual, "expected": expected,
            "matches": actual == expected, "repairable": repairable and kind != "symlink",
            "identity": [st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode, st.st_nlink]}


def journal_state(review):
    rows = {}
    for name in ("initial-deployment.json", "deployment.json"):
        state, sha = review.recovery_journal(name)
        rows[name] = {"phase": state["phase"] if state else "absent", "sha256": sha}
    return rows


def review_plan(candidate, review=None, adapter=None):
    review = review or load("review-smtp-tls-rotation")
    adapter = adapter or load("smtp-tls-postfix")
    if os.geteuid() != 0 or not review.GEN.fullmatch(candidate):
        raise ValueError("root and valid generation required")
    review.directory(review.ROOT, True)
    review.verify_files(candidate)
    active = review.active_generation()
    mode = command(adapter, "/usr/sbin/getenforce").lower()
    if mode not in ("enforcing", "permissive", "disabled"):
        raise ValueError("SELinux mode unknown")
    journals = journal_state(review)
    rows = []
    if mode != "disabled":
        # Observe the parent and active symlink, but never relabel those
        # outside the selected managed directory or replace any pointer.
        rows.append(label_row(review.ROOT.parent, adapter, False))
        if active is not None:
            rows.append(label_row(review.ROOT / "active", adapter, False))
        rows.append(label_row(review.ROOT, adapter, True))
        rows.append(label_row(review.ROOT / candidate, adapter, True))
        for name in FILES:
            rows.append(label_row(review.ROOT / candidate / name, adapter, True))
    pending = any(row["phase"] in review.PENDING_PHASES for row in journals.values())
    external_mismatch = any(not row["matches"] and not row["repairable"] for row in rows)
    changes = [row["path"] for row in rows if not row["matches"] and row["repairable"]]
    if pending:
        reason = "pending_transaction"
    elif mode == "disabled":
        reason = "selinux_disabled"
    elif external_mismatch:
        reason = "parent_or_pointer_context_requires_manual_review"
    elif changes:
        reason = "restore_default_contexts"
    else:
        reason = "contexts_match"
    material = {"candidate": candidate, "active": active, "mode": mode,
                "journals": journals, "paths": rows, "changes": changes, "reason": reason,
                "apply_supported": reason == "restore_default_contexts"}
    sha = review.digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode())
    return dict(material, status="selinux_review_ready", plan_sha256=sha,
                access_verified=False, policy_changed=False)


def execute(candidate, expected, review=None, adapter=None, tx=None, planner=review_plan):
    review = review or load("review-smtp-tls-rotation")
    adapter = adapter or load("smtp-tls-postfix")
    tx = tx or load("smtp-tls-transaction")
    review.directory(review.ROOT, True)
    with tx.deployment_lock(review.ROOT):
        plan = planner(candidate, review, adapter)
        if plan["plan_sha256"] != expected or not plan["apply_supported"]:
            raise ValueError("review changed or repair unsupported")
        allowed = {str(review.ROOT), str(review.ROOT / candidate)}
        allowed.update(str(review.ROOT / candidate / name) for name in FILES)
        if not plan["changes"] or not set(plan["changes"]).issubset(allowed):
            raise ValueError("unexpected relabel target")
        # No -R/-F, no policy modification. A partial failure stays visible.
        for path in plan["changes"]:
            command(adapter, "/usr/sbin/restorecon", str(path))
        after = planner(candidate, review, adapter)
        before_rows = {row["path"]: (row["identity"], row["expected"]) for row in plan["paths"]}
        after_rows = {row["path"]: (row["identity"], row["expected"]) for row in after["paths"]}
        if (after["mode"] != plan["mode"] or after["active"] != plan["active"]
                or after["journals"] != plan["journals"] or before_rows != after_rows
                or after["reason"] != "contexts_match"):
            raise ValueError("context repair incomplete or state changed")
        return {"status": "contexts_verified", "candidate": candidate, "mode": after["mode"],
                "plan_sha256": expected, "paths": after["paths"], "access_verified": False,
                "policy_changed": False}


