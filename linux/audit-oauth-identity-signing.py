#!/usr/bin/env python3
"""Read-only map-scoped PS256 proof for Microsoft 365 sender identities.

No Microsoft network calls, SMTP, mail queue writes, Postfix restart,
secrets in stdout, or automatic activation. Runs as root to inspect a
protected map, but the actual key-signing probe runs as m365mailer.
Python 3.6+; no third-party Python modules required.
"""
import argparse
import hashlib
import importlib.util
import os
import pwd
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
AUDITOR = HERE / "audit-oauth-sender-map.py"
TRANSPORT = HERE / "m365_xoauth2_transport.py"
MAX_IDENTITIES = 64
MAX_SECONDS = 55


class Refused(Exception):
    pass


def load_auditor():
    if not AUDITOR.is_file() or not TRANSPORT.is_file():
        raise Refused("missing_offline_audit_resources")
    spec = importlib.util.spec_from_file_location("lmr365_map", str(AUDITOR))
    if spec is None or spec.loader is None:
        raise Refused("missing_offline_audit_resources")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def probe_as_m365mailer(identity_path, runner=subprocess.run):
    """No shell, no proxy/environment secrets; no child stdout or stderr."""
    if not TRANSPORT.is_file():
        return False
    argv = ["/usr/sbin/runuser", "-u", "m365mailer", "--",
            "/usr/bin/python3", str(TRANSPORT),
            "--mapped-identity-config", identity_path, "--signing-check"]
    if not Path(argv[0]).is_file():
        # Some distributions place runuser under /usr/bin.
        argv[0] = "/usr/bin/runuser"
        if not Path(argv[0]).is_file():
            return False
    try:
        result = runner(argv, stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=MAX_SECONDS, check=False,
                        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                             "LC_ALL": "C"})
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def audit(path, auditor=None, runner=probe_as_m365mailer):
    auditor = auditor if auditor is not None else load_auditor()
    try:
        auditor.allowed_path(path)
        structural = auditor.audit(path)
        before = auditor.secure_read(path, auditor.MAX_MAP, 0o600, None)
        if hashlib.sha256(before).hexdigest() != structural["MAP_SHA256"]:
            raise Refused("sender_map_changed_during_review")
        rows = auditor.parse_map(before)
    except auditor.Refused:
        raise Refused("sender_map_invalid_or_inaccessible") from None
    unique = sorted(set(row[3] for row in rows))
    if not 1 <= len(unique) <= MAX_IDENTITIES:
        raise Refused("too_many_identities_for_signer_review")
    verified = 0
    for item in unique:
        try:
            # No paths, mailbox names, or credential contents are printed.
            if runner(item):
                verified += 1
        except Exception:
            # A signer subprocess failure cannot authorize delivery.
            pass
    try:
        after = auditor.secure_read(path, auditor.MAX_MAP, 0o600, None)
        if hashlib.sha256(after).hexdigest() != structural["MAP_SHA256"]:
            raise Refused("sender_map_changed_during_review")
    except auditor.Refused:
        raise Refused("sender_map_changed_during_review") from None
    return {
        "MAP_SHA256": structural["MAP_SHA256"],
        "IDENTITIES": len(unique),
        "VERIFIED": verified,
        "UNVERIFIED": len(unique) - verified,
        "ALL_SIGNERS_VALID": "yes" if verified == len(unique) else "no"
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline per-mailbox PS256 signer audit")
    ap.add_argument("--map-path", required=True)
    options = ap.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise Refused("root_required")
        if pwd.getpwnam("m365mailer").pw_uid < 1:
            raise Refused("service_identity_not_available")
        report = audit(options.map_path)
    except (Refused, KeyError, ValueError):
        print("OAUTH_SIGNING_REVIEW=refused", file=sys.stderr)
        print("OAUTH_SIGNING_ERROR=offline_review_failed", file=sys.stderr)
        print("OAUTH_SIGNING_MAIL_SENT=no", file=sys.stderr)
        return 2
    print("OAUTH_SIGNING_REVIEW=read_only_offline_only")
    for name in ("MAP_SHA256", "IDENTITIES", "VERIFIED", "UNVERIFIED",
                 "ALL_SIGNERS_VALID"):
        print("OAUTH_SIGNING_" + name + "=" + str(report[name]))
    print("OAUTH_SIGNING_HARDWARE_PROVENANCE=not_verified")
    print("OAUTH_SIGNING_EXCHANGE_SENDAS=not_verified")
    print("OAUTH_SIGNING_POSTFIX_CHANGED=no")
    print("OAUTH_SIGNING_ENROLLED_OR_ACTIVATED=no")
    print("OAUTH_SIGNING_MAIL_SENT=no")
    return 0 if report["ALL_SIGNERS_VALID"] == "yes" else 3


if __name__ == "__main__":
    sys.exit(main())
