#!/usr/bin/env python3
"""Prepare one new, unbound software OAuth identity; never change mail routing.

Python 3.6+. Key material stays on Linux. No token requests, SMTP, cloud
writes, existing identity replacement, TPM operations or service changes.
"""
import base64
import fcntl
import grp
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile

_spec = importlib.util.spec_from_file_location(
    "prepare_identity_inventory", str(Path(__file__).with_name("inspect-multi-mailbox-identities.py")))
I = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(I)
A, E = I.A, I.E
BASE, IDENTITIES, SOURCE, RUNTIME = I.BASE, I.IDENTITIES, I.SOURCE, I.RUNTIME
LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")
SELINUX = Path("/sys/fs/selinux/enforce")
LABEL_ATTR = "security.selinux"
CONFIRM = "CREATE_UNBOUND_OAUTH_IDENTITY"
Refused, need = I.Refused, I.need
ENV = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent"}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def request(raw):
    need(1 <= len(raw) <= 4096, "request_size")
    obj = I.decode(raw)
    need(isinstance(obj, dict) and set(obj) == {
        "tenant", "client", "mailbox", "days", "source_sha", "nonce", "approval", "confirm"},
        "request_fields")
    need(all(isinstance(v, str) for k, v in obj.items() if k != "days") and
         type(obj["days"]) is int and 1 <= obj["days"] <= 365,
         "request_types")
    I.guid(obj["tenant"])
    I.guid(obj["client"])
    need(I.valid_mailbox(obj["mailbox"]) and A.EMAIL.fullmatch(obj["mailbox"]) and
         I.SHA.fullmatch(obj["nonce"]) and
         (obj["source_sha"] == "" or I.SHA.fullmatch(obj["source_sha"])),
         "identity_context")
    need((obj["approval"] == "" and obj["confirm"] == "") or
         (I.SHA.fullmatch(obj["approval"]) and obj["confirm"] == CONFIRM),
         "approval_context")
    return obj


def execute(command, data=None, timeout=30):
    try:
        result = subprocess.run(command, input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout,
                                env=ENV, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("local_crypto_unavailable") from None
    need(result.returncode == 0, "local_crypto_or_service_access_failed")
    return result.stdout


def openssl(args, data=None, timeout=30):
    return execute(["/usr/bin/openssl"] + args, data, timeout)


def missing(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def sync_dir(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def selinux_mode():
    try:
        raw = SELINUX.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return "inactive"
    except (OSError, UnicodeError):
        raise Refused("selinux_mode_unverified") from None
    need(raw in ("0", "1"), "selinux_mode_unverified")
    return "enforcing" if raw == "1" else "permissive"


def checked_context(raw):
    need(isinstance(raw, bytes) and 1 <= len(raw) <= 256, "selinux_context_invalid")
    if raw.endswith(b"\0"):
        raw = raw[:-1]
    need(re.fullmatch(rb"[A-Za-z0-9_]+:object_r:[A-Za-z0-9_]+:s[0-9][A-Za-z0-9_:.,-]*", raw),
         "selinux_context_invalid")
    # etc_t is legitimate for configuration files under /etc. This is a
    # policy/metadata check, not proof that a confined service may use them.
    need(raw.split(b":")[2] not in (b"default_t", b"unlabeled_t", b"file_t",
         b"tmp_t", b"user_tmp_t", b"unconfined_t"), "selinux_unsafe_context_type")
    return raw.decode("ascii")


def query_label(path, mode):
    need(mode in ("dir", "file"), "selinux_invalid_policy_query")
    tool = None
    for candidate in (Path("/usr/sbin/matchpathcon"), Path("/usr/bin/matchpathcon")):
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError:
            continue
        E.trusted_directory(resolved.parent)
        info = resolved.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and
             bool(info.st_mode & 0o111), "selinux_untrusted_matchpathcon")
        tool = str(resolved)
        break
    need(tool is not None, "selinux_matchpathcon_required")
    try:
        out = execute([tool, "-N", "-n", "-m", mode, str(path)], timeout=15)
    except Refused:
        raise Refused("selinux_policy_lookup_failed") from None
    lines = out.splitlines()
    need(len(lines) == 1 and lines[0] == lines[0].strip(), "selinux_policy_lookup_unverified")
    return checked_context(lines[0])


def label_fd(fd):
    need(set(os.listxattr(fd)) == {LABEL_ATTR}, "selinux_missing_label_or_foreign_xattrs")
    return checked_context(os.getxattr(fd, LABEL_ATTR))


def verify_label(path, expected, directory=False):
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 (os.O_DIRECTORY if directory else os.O_NONBLOCK))
    try:
        info = os.fstat(fd)
        need((stat.S_ISDIR(info.st_mode) if directory else
              stat.S_ISREG(info.st_mode) and info.st_nlink == 1) and
             info.st_uid == 0 and not info.st_mode & 0o022,
             "selinux_untrusted_labeled_path")
        need(label_fd(fd) == expected, "selinux_existing_context_mismatch")
        live = path.lstat()
        need((live.st_dev, live.st_ino) == (info.st_dev, info.st_ino), "selinux_path_changed")
    finally:
        os.close(fd)


def policy_snapshot(targets):
    mode = selinux_mode()
    if mode == "inactive":
        return dict(mode=mode, labels={})
    E.trusted_directory(BASE)
    labels = {}
    for path in (BASE, IDENTITIES):
        context = query_label(path, "dir")
        if not missing(path):
            E.trusted_directory(path)
            verify_label(path, context, directory=True)
        else:
            need(path == IDENTITIES, "selinux_base_directory_missing")
        labels[str(path)] = context
    need(len(targets) == 3 and len(set(targets)) == 3 and
         all(p.parent == IDENTITIES and re.fullmatch(r"mbx-[a-f0-9]{32}\.(key|crt|json)", p.name)
             for p in targets) and {p.suffix for p in targets} == {".key", ".crt", ".json"} and
         len({p.stem for p in targets}) == 1, "selinux_unapproved_identity_paths")
    for path in targets:
        context = query_label(path, "file")
        if not missing(path):
            verify_label(path, context)
        labels[str(path)] = context
    need(selinux_mode() == mode, "selinux_mode_changed")
    return dict(mode=mode, labels=labels)


def require_policy(policy):
    targets = [Path(name) for name in policy["labels"] if name not in (str(BASE), str(IDENTITIES))]
    need(selinux_mode() == policy["mode"], "selinux_mode_changed")
    if policy["mode"] != "inactive":
        need(policy_snapshot(targets) == policy, "selinux_policy_changed")


def set_new_label(fd, context):
    # Only our exclusively created directory or private scratch inode is
    # relabeled. Never use a recursive relabel or modify an existing target.
    need(set(os.listxattr(fd)) <= {LABEL_ATTR}, "selinux_foreign_xattrs")
    os.setxattr(fd, LABEL_ATTR, context.encode("ascii") + b"\0")
    need(label_fd(fd) == context, "selinux_new_context_not_verified")


def ensure_identity_directory(gid, policy):
    require_policy(policy)
    if missing(IDENTITIES):
        IDENTITIES.mkdir(mode=0o700)
        fd = os.open(str(IDENTITIES), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            live = IDENTITIES.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
                 stat.S_IMODE(info.st_mode) == 0o700 and
                 (info.st_dev, info.st_ino) == (live.st_dev, live.st_ino),
                 "new_identity_directory_changed")
            if policy["mode"] != "inactive":
                set_new_label(fd, policy["labels"][str(IDENTITIES)])
            os.fchown(fd, 0, gid)
            os.fchmod(fd, 0o750)
            os.fsync(fd)
        finally:
            os.close(fd)
        sync_dir(BASE)
    require_policy(policy)
    return directory_state(gid, policy)


def directory_state(gid, policy=None):
    E.trusted_directory(BASE)
    if missing(IDENTITIES):
        return "absent"
    E.trusted_directory(IDENTITIES)
    info = IDENTITIES.lstat()
    need(stat.S_IMODE(info.st_mode) == 0o750 and info.st_gid == gid,
         "identity_directory_requires_root_service_group_0750")
    state = [info.st_dev, info.st_ino, info.st_gid, stat.S_IMODE(info.st_mode)]
    if policy is not None and policy["mode"] != "inactive":
        need(selinux_mode() == policy["mode"], "selinux_mode_changed")
        expected = policy["labels"][str(IDENTITIES)]
        verify_label(IDENTITIES, expected, directory=True)
        state.extend([policy["mode"], expected])
    else:
        need(selinux_mode() == "inactive" and not os.listxattr(str(IDENTITIES), follow_symlinks=False),
             "identity_directory_extended_attributes_require_review")
    return state


def route_state(req, gid):
    source = I.read_optional(SOURCE, A.MAX_MAP, (0o600,))
    runtime = I.read_optional(RUNTIME, A.MAX_MAP, (0o640,), gid)
    hashes = [I.digest(raw) if raw is not None else "" for raw in (source, runtime)]
    need(hashes[0] == req["source_sha"], "source_changed_since_inventory")
    for raw in (source, runtime):
        if raw is not None:
            rows = A.parse_map(raw)
            need(not any(row[2] == req["mailbox"] for row in rows),
                 "mailbox_already_bound_use_separate_rotation")
    return hashes


def paths(req):
    stem = "mbx-" + req["nonce"][:32]
    return [IDENTITIES / (stem + suffix) for suffix in (".key", ".crt", ".json")]


def plan(req, gid, policy=None):
    if policy is None:
        policy = policy_snapshot(paths(req))
    require_policy(policy)
    state = directory_state(gid, policy)
    hashes = route_state(req, gid)
    need(all(missing(p) for p in paths(req)), "identity_destination_already_exists")
    runuser = shutil.which("runuser", path=ENV["PATH"])
    need(bool(runuser), "runuser_required")
    version = openssl(["version"]).decode("ascii").strip()
    need(version.startswith("OpenSSL ") and len(version) <= 160,
         "unsupported_openssl")
    review = dict(request={k:v for k,v in req.items() if k not in ("approval", "confirm")},
                  directory=state, group=gid, runtime_sha=hashes[1],
                  name=paths(req)[2].name, openssl=version)
    if policy["mode"] != "inactive":
        review["selinux_policy"] = policy
    result = dict(version=1, status="preview", plan_sha=I.digest(encode(review)),
                source_sha=hashes[0], runtime_sha=hashes[1], nonce=req["nonce"],
                tenant=req["tenant"], client=req["client"], mailbox=req["mailbox"],
                days=req["days"], identity_file=review["name"], changes=False,
                runtime_changed=False, cloud_changed=False, mail_sent=False,
                certificate_sha256="", certificate_der="")
    if policy["mode"] != "inactive":
        result.update(selinux_mode=policy["mode"], selinux_policy_sha=I.digest(encode(policy)))
    require_policy(policy)
    return result


def publish(stage, target, gid, mode, policy=None):
    if policy is None:
        # Other workflows retain their existing inactive-SELinux gate until
        # their own private-marker and recovery policies are integrated.
        need(selinux_mode() == "inactive", "selinux_reviewed_policy_required")
        policy = dict(mode="inactive", labels={})
    require_policy(policy)
    need(missing(target), "identity_destination_already_exists")
    fd = os.open(str(stage), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
             not info.st_mode & 0o022, "unsafe_staged_identity_file")
        os.fchown(fd, 0, gid)
        os.fchmod(fd, mode)
        if policy["mode"] != "inactive":
            need(str(target) in policy["labels"], "selinux_unreviewed_publication_target")
            set_new_label(fd, policy["labels"][str(target)])
        os.fsync(fd)
        require_policy(policy)
        live = stage.lstat()
        need((live.st_dev, live.st_ino) == (info.st_dev, info.st_ino), "staged_identity_changed")
        # Atomic no-clobber, including dangling symlinks.
        os.link(str(stage), str(target), follow_symlinks=False)
        linked = target.lstat()
        need((linked.st_dev, linked.st_ino) == (info.st_dev, info.st_ino), "published_identity_changed")
        stage.unlink()
        final = os.fstat(fd)
        need(final.st_nlink == 1 and final.st_uid == 0 and final.st_gid == gid and
             stat.S_IMODE(final.st_mode) == mode, "published_identity_metadata_changed")
        if policy["mode"] != "inactive":
            need(label_fd(fd) == policy["labels"][str(target)], "selinux_published_context_changed")
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_dir(IDENTITIES)
    require_policy(policy)


def service_proof(service, key, cert, work):
    public = openssl(["x509", "-in", str(cert), "-pubkey", "-noout"])
    need(public == openssl(["pkey", "-in", str(key), "-pubout"]),
         "certificate_key_mismatch")
    openssl(["x509", "-in", str(cert), "-checkend", "3600", "-noout"])
    payload = b"LinuxMailRelay365 unbound OAuth PS256 local acceptance"
    runuser = shutil.which("runuser", path=ENV["PATH"])
    need(bool(runuser), "runuser_required")
    signature = execute([runuser, "-u", service, "--", "/usr/bin/openssl",
                         "dgst", "-sha256", "-sign", str(key),
                         "-sigopt", "rsa_padding_mode:pss",
                         "-sigopt", "rsa_pss_saltlen:32"], payload)
    need(128 <= len(signature) <= 1024, "local_signature_invalid")
    pubfile, sigfile = work / "public.pem", work / "signature.bin"
    pubfile.write_bytes(public)
    sigfile.write_bytes(signature)
    result = openssl(["dgst", "-sha256", "-verify", str(pubfile),
                      "-signature", str(sigfile), "-sigopt", "rsa_padding_mode:pss",
                      "-sigopt", "rsa_pss_saltlen:32"], payload)
    need(b"Verified OK" in result, "local_signature_invalid")
    return openssl(["x509", "-in", str(cert), "-outform", "DER"])


def apply(req, gid, service="m365mailer"):
    E.trusted_directory(LOCK.parent)
    fd = os.open(str(LOCK), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    started = False
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600, "unsafe_shared_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        policy = policy_snapshot(paths(req))
        preview = plan(req, gid, policy)
        need(preview["plan_sha"] == req["approval"] and req["confirm"] == CONFIRM,
             "plan_changed_since_approval")
        need(pwd.getpwnam(service).pw_gid == gid, "service_group_changed")
        key, cert, identity = paths(req)
        started = missing(IDENTITIES)
        state = ensure_identity_directory(gid, policy)
        with tempfile.TemporaryDirectory(prefix=".prepare-", dir=str(IDENTITIES)) as folder:
            work = Path(folder)
            os.chmod(folder, 0o700)
            staged_key, staged_cert = work / "key", work / "cert"
            openssl(["req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256",
                     "-days", str(req["days"]), "-subj", "/CN=LinuxMailRelay365-MultiMailbox",
                     "-keyout", str(staged_key), "-out", str(staged_cert)], timeout=60)
            require_policy(policy)
            need(directory_state(gid, policy) == state and route_state(req, gid) ==
                 [preview["source_sha"], preview["runtime_sha"]] and
                 all(missing(p) for p in (key, cert, identity)),
                 "configuration_changed_before_publish")
            started = True
            # If interrupted, retain exact unique partial files for review.
            # Never delete a key or retry a partially published identity.
            publish(staged_key, key, gid, 0o640, policy)
            publish(staged_cert, cert, gid, 0o640, policy)
            E.secure_read(key, 65536, gid, modes=(0o640,))
            E.secure_read(cert, E.MAX_PEM, gid, modes=(0o640,))
            der = service_proof(service, key, cert, work)
            need(1 <= len(der) <= 8192 and I.public_certificate_sha(str(cert)) == I.digest(der),
                 "certificate_digest_mismatch")
            # Publish the identity pointer LAST, only after the real local
            # service-account PS256 check and a second route snapshot.
            require_policy(policy)
            need(directory_state(gid, policy) == state and route_state(req, gid) ==
                 [preview["source_sha"], preview["runtime_sha"]],
                 "route_changed_before_identity_publish")
            data = encode(dict(tenant_id=req["tenant"], client_id=req["client"],
                               mailbox=req["mailbox"], certificate=str(cert), private_key=str(key)))
            A.validate_identity(data, req["mailbox"])
            staged_identity = work / "identity"
            staged_identity.write_bytes(data)
            publish(staged_identity, identity, gid, 0o640, policy)
            need(E.secure_read(identity, A.MAX_IDENTITY, gid, modes=(0o640,)) == data,
                 "identity_readback_mismatch")
            row = I.identity_row("proof", req["mailbox"], req["mailbox"], str(identity), gid)
            need(row["status"] == "public_certificate_read" and
                 row["certificate_sha256"] == I.digest(der), "identity_inventory_unverified")
            # Also require actual service-account read access to the JSON.
            runuser = shutil.which("runuser", path=ENV["PATH"])
            need(bool(runuser), "runuser_required")
            need(execute([runuser, "-u", service, "--", "/usr/bin/test", "-r", str(identity)]) == b"",
                 "service_identity_unreadable")
            require_policy(policy)
            need(directory_state(gid, policy) == state and
                 route_state(req, gid) == [preview["source_sha"], preview["runtime_sha"]],
                 "route_changed_after_identity_publish")
            return dict(preview, status="prepared", changes=True,
                        certificate_sha256=I.digest(der),
                        certificate_der=base64.b64encode(der).decode("ascii"))
    except BaseException:
        if started:
            print("IDENTITY_PREPARATION_OUTCOME=review_partial_files", file=sys.stderr, flush=True)
        raise
    finally:
        os.close(fd)


def main():
    try:
        need(os.geteuid() == 0, "root_required")
        os.umask(0o077)
        req = request(sys.stdin.buffer.read(4097))
        gid = grp.getgrnam("m365mailer").gr_gid
        if req["approval"]:
            result = apply(req, gid)
        else:
            result = plan(req, gid)
            need(plan(req, gid) == result, "configuration_changed_during_preview")
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (Refused, A.Refused, E.Refused, OSError, KeyError, ValueError, TypeError, UnicodeError):
        print("IDENTITY_PREPARATION=refused_or_review_required")
        return 2


if __name__ == "__main__":
    sys.exit(main())
