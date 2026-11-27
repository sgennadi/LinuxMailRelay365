#!/usr/bin/env python3
"""Installed primary software-PEM runtime guard; no mail submission.

Use from a single-threaded trusted root CLI. Authentication is an observation,
not a delivery or SELinux execution-domain assertion. No persistent receipt.
"""
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import time
import uuid

HERE = Path(__file__).resolve().parent
LIBEXEC = Path("/usr/local/libexec")
TRANSPORT = "m365_xoauth2_transport.py"
SIGNER = "m365_hardware_signer.py"
ACTIVE = "/etc/postfix/m365-oauth/app.json"
CONFIRM = "VERIFY_PRIMARY_MAILBOX_SMTP_AUTH"
SUCCESS = b"Microsoft 365 STARTTLS and SMTP AUTH XOAUTH2 verified; no message submitted\n"
ENV = {"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C", "HOME":"/nonexistent"}
MAX_AGE = 90


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, str(HERE / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


R = load("runtime_primary_route", "preview-primary-mailbox-route.py")
C = load("runtime_primary_pem", "manage-primary-oauth-rotation.py")


class Refused(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(value):
    return hashlib.sha256(R.encode(value)).hexdigest()


def exact_guid(value):
    try:
        result = str(uuid.UUID(value))
        need(result == value and uuid.UUID(result).int != 0, "invalid_selected_guid")
        return result
    except (TypeError, ValueError, AttributeError):
        raise Refused("invalid_selected_guid") from None


def system_executable(path):
    # The OS package trust is a host prerequisite, not a package attestation.
    resolved = Path(path).resolve(strict=True)
    need(str(resolved).startswith(("/usr/bin/","/usr/sbin/","/bin/","/sbin/")),
         "unexpected_system_executable")
    R.E.trusted_directory(resolved.parent)
    meta = resolved.lstat()
    need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
         not meta.st_mode & 0o022 and bool(meta.st_mode & 0o111),
         "untrusted_system_executable")
    return [str(resolved),meta.st_dev,meta.st_ino,meta.st_size,
            meta.st_mtime_ns,meta.st_ctime_ns,meta.st_mode]


def reject_import_artifacts(directory):
    # The installed pipe imports this sibling module. Do not approve an
    # alternative package or precompiled module in place of pinned source.
    for name in os.listdir(str(directory)):
        if name == "m365_hardware_signer" or (
                name.startswith("m365_hardware_signer.") and name != SIGNER):
            raise Refused("ambiguous_installed_signer_import")
    cache = directory / "__pycache__"
    if os.path.lexists(str(cache)):
        R.E.trusted_directory(cache)
        if any(name.startswith("m365_hardware_signer.") for name in os.listdir(str(cache))):
            raise Refused("installed_signer_bytecode_requires_review")


def installed_snapshot(mailbox, tenant, client):
    try:
        need(os.geteuid() == 0, "root_required")
        R.parse(R.encode({"mailbox":mailbox,"nonce":"0"*64}))
        exact_guid(tenant)
        exact_guid(client)
        R.E.trusted_directory(HERE)
        R.E.trusted_directory(LIBEXEC)
        account = pwd.getpwnam("m365mailer")
        group = grp.getgrnam("m365mailer")
        groups = sorted(set(os.getgrouplist("m365mailer",account.pw_gid)))
        need(account.pw_name == "m365mailer" and account.pw_uid > 0 and
             account.pw_gid == group.gr_gid > 0 and groups == [group.gr_gid],
             "unsupported_service_account_or_groups")
        active = C.current(group.gr_gid)
        identity = active["identity"]
        need(identity["tenant_id"] == tenant and identity["client_id"] == client and
             identity["mailbox"].lower() == mailbox,
             "selected_primary_identity_mismatch")
        inventory = R.E.active_inventory("primary")
        need(inventory["tenant"] == tenant and inventory["client"] == client and
             inventory["mailbox"] == mailbox and
             inventory["identity_sha"] == C.sha(active["raw"]),
             "active_identity_inventory_mismatch")
        sources = {}
        for name in (TRANSPORT,SIGNER):
            bundled = R.E.secure_read(HERE/name,1048576,modes=(0o600,0o640,0o644,0o755))
            installed = R.E.secure_read(LIBEXEC/name,1048576,modes=(0o644,0o755))
            need(bundled == installed,"installed_runtime_version_mismatch")
            sources[name] = hashlib.sha256(installed).hexdigest()
        reject_import_artifacts(LIBEXEC)
        return {"version":1,"mailbox":mailbox,"tenant":tenant,"client":client,
                "uid":account.pw_uid,"gid":group.gr_gid,"groups":groups,
                "identity_sha256":inventory["identity_sha"],
                "certificate_sha256":inventory["certificate_sha"],
                "certificate_file_sha256":active["cert_sha"],
                "key_sha256":active["key_sha"],"sources":sources,
                "python":system_executable("/usr/bin/python3"),
                "openssl":system_executable("/usr/bin/openssl")}
    except Refused:
        raise
    except (R.E.Refused,C.Refused,OSError,KeyError,ValueError,TypeError,
            subprocess.SubprocessError):
        raise Refused("primary_pem_runtime_not_verified") from None


def run_auth(state, runner=subprocess.run):
    uid,gid = state["uid"],state["gid"]
    need(os.geteuid() == 0 and type(uid) is int and type(gid) is int and uid>0 and gid>0
         and state["groups"] == [gid], "invalid_diagnostic_service_identity")
    def drop():
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        if os.getresuid() != (uid,uid,uid) or os.getresgid() != (gid,gid,gid) or os.getgroups():
            raise RuntimeError("incomplete_privilege_drop")
    # Same installed interpreter and transport as the proposed pipe.
    # Ignore inherited Python settings, disable user site and bytecode writes.
    args = ["/usr/bin/python3","-E","-s","-B",str(LIBEXEC/TRANSPORT),
            "--smtp-auth-check","--config",ACTIVE]
    try:
        result = runner(args,input=b"",stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                        timeout=120,check=False,env=dict(ENV),cwd="/",preexec_fn=drop)
    except (OSError,subprocess.SubprocessError):
        raise Refused("primary_smtp_auth_unavailable") from None
    need(result.returncode == 0 and result.stdout == SUCCESS and not result.stderr,
         "primary_smtp_auth_not_verified")


class RuntimeGuard:
    """Stable SHA plus a recent in-memory AUTH observation.

    Callers must hold the maintenance and rotation locks throughout.
    Any dependency drift poisons this instance; require a fresh review.
    """
    def __init__(self, tenant, client, confirmation, snapshot=installed_snapshot,
                 auth=run_auth, clock=time.monotonic):
        need(confirmation == CONFIRM, "explicit_smtp_auth_confirmation_required")
        self.tenant = exact_guid(tenant)
        self.client = exact_guid(client)
        self.snapshot = snapshot
        self.auth = auth
        self.clock = clock
        self.bound = None
        self.checked_at = None
        self.failed = False

    def __call__(self, mailbox):
        need(not self.failed, "runtime_guard_requires_fresh_review")
        try:
            state = self.snapshot(mailbox,self.tenant,self.client)
            fingerprint = digest(state)
            if self.bound is not None:
                need(fingerprint == self.bound, "installed_runtime_changed")
            now = self.clock()
            if self.checked_at is not None:
                need(now >= self.checked_at, "invalid_auth_observation_clock")
            if self.checked_at is None or now-self.checked_at >= MAX_AGE:
                self.auth(state)
                need(digest(self.snapshot(mailbox,self.tenant,self.client)) == fingerprint,
                     "runtime_changed_during_smtp_auth")
                end = self.clock()
                need(end >= now, "invalid_auth_observation_clock")
                self.checked_at = end
            self.bound = fingerprint
            return fingerprint
        except Exception:
            self.failed = True
            raise


if __name__ == "__main__":
    raise SystemExit("Runtime guard library; use the separately approved offline review.")
