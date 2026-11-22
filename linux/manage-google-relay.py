#!/usr/bin/env python3
"""Guarded in-place Postfix outbound relay change for Google mail.

Never changes incoming SMTP, master.cf, mydestination, mynetworks, local
delivery or the queue. An exact SHA-256 preview is mandatory. A verified
root-only snapshot of /etc/postfix is created via the existing recovery tool
before Apply and automatically restored on failure after a mutation.

The operator's one-off Gmail App Password is received only through encrypted
SSH stdin and is stored only on the Linux server in a root-only Postfix hash
map database when explicitly approved. The map database is not encrypted:
a root administrator can recover its contents. Never print the credential,
its encoding or provider SMTP replies.
"""
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile

# LMR365_CONFIG_MARKER
# LMR365_RECOVERY_MARKER

MAIN = pathlib.Path("/etc/postfix/main.cf")
MASTER = pathlib.Path("/etc/postfix/master.cf")
MAP = pathlib.Path("/etc/postfix/lmr365-google-sasl.db")
BACKUP_ID = re.compile(r"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\Z")
HEX = re.compile(r"\A[a-f0-9]{64}\Z")
EXPECTED = {
    "gmail": ("smtp.gmail.com", (465, 587)),
    "workspace": ("smtp-relay.gmail.com", (25, 465, 587)),
}


def config(data):
    if type(data) is not dict or data.get("profile") not in EXPECTED:
        raise ValueError("Unknown Google SMTP profile")
    profile = data["profile"]
    port = data.get("port")
    if type(port) is not int or port not in EXPECTED[profile][1]:
        raise ValueError("Unsupported Google outbound SMTP port")
    if data.get("operation") not in ("preview", "apply"):
        raise ValueError("Unsupported Google SMTP operation")
    is_apply = data["operation"] == "apply"
    sha = data.get("expected_sha", "")
    if is_apply and (type(sha) is not str or not HEX.fullmatch(sha)):
        raise ValueError("Missing exact reviewed fingerprint")
    if not is_apply and sha not in ("", None):
        raise ValueError("Unexpected preview fingerprint")
    sender = data.get("user", "")
    secret = data.get("secret", "")
    if profile == "gmail" and is_apply:
        if (not isinstance(sender, str) or not re.fullmatch(
                r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{2,190}", sender) or
                not isinstance(secret, str) or not 1 <= len(secret) <= 256 or
                any(ord(ch) < 32 or ord(ch) == 127 for ch in secret)):
            raise ValueError("Invalid one-use Gmail App Password request")
    elif sender or secret:
        raise ValueError("No credentials allowed for this operation")
    return data


def run(args, *, input=None):
    return subprocess.run(args, input=input, capture_output=True,
                          check=False, timeout=75)


def postconf(key):
    done = run(["postconf", "-h", key])
    if done.returncode:
        raise RuntimeError("Postfix configuration unavailable")
    data = done.stdout.decode("utf-8", "replace").strip()
    if len(data) > 1024 or any(ord(c) < 32 for c in data):
        raise RuntimeError("Unexpected Postfix configuration value")
    return data


def fingerprint():
    digest = hashlib.sha256()
    for file in (MAIN, MASTER):
        if file.is_symlink() or not file.is_file():
            raise RuntimeError("Postfix configuration not a regular file")
        metadata = file.stat()
        if metadata.st_uid != 0 or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("Postfix config must be root-owned")
        content = file.read_bytes()
        if len(content) > 2 * 1024 * 1024:
            raise RuntimeError("Excessive Postfix config size")
        digest.update(file.name.encode() + b"\0" + content + b"\0")
    return digest.hexdigest()


def route_conflicts():
    # An existing transport map or per-sender relay can bypass relayhost.
    # Do not claim to migrate all outgoing mail when these are present.
    for name in (
        "transport_maps", "sender_dependent_relayhost_maps",
        "sender_dependent_default_transport_maps"
    ):
        if postconf(name):
            return True
    return postconf("default_transport") not in ("", "smtp")


def queue_state():
    result = run(["postqueue", "-j"])
    if result.returncode:
        return "unverified"
    # Do not parse or log message content. This is only a nonempty check.
    return "empty" if not result.stdout.strip() else "nonempty"


def prerequisites():
    if os.geteuid() != 0:
        raise RuntimeError("Root required")
    if not pathlib.Path("/etc/postfix").is_dir() or pathlib.Path("/etc/postfix").is_symlink():
        raise RuntimeError("Postfix base directory invalid")
    for tool in ("postconf", "postfix", "postqueue", "postmap", "systemctl"):
        if shutil.which(tool) is None:
            raise RuntimeError("Required Postfix/systemd tool missing")
    active = run(["systemctl", "is-active", "--quiet", "postfix"])
    if active.returncode:
        raise RuntimeError("Existing primary Postfix not active")
    # All operations remain on the primary Postfix. Never install packages.
    return fingerprint()


def preview(request):
    sha = prerequisites()
    conflict = route_conflicts()
    queue = queue_state()
    blocked = conflict or queue != "empty"
    print("GOOGLE_ROUTE_VERSION=1")
    print("GOOGLE_ROUTE_PROFILE=" + request["profile"])
    print("GOOGLE_ROUTE_PORT=" + str(request["port"]))
    print("GOOGLE_ROUTE_PREVIEW_SHA256=" + sha)
    print("GOOGLE_ROUTE_CONFLICTING_MAPS=" + ("yes" if conflict else "no"))
    print("GOOGLE_ROUTE_QUEUE=" + queue)
    print("GOOGLE_ROUTE_APPLY_ALLOWED=" + ("no" if blocked else "yes"))
    print("GOOGLE_ROUTE_INBOUND_CHANGED=no")
    print("GOOGLE_ROUTE_MAIL_SENT=no")
    print("GOOGLE_ROUTE_CONFIG_CHANGED=no")


def verified_backup():
    # Execute the EXISTING recovery utility from an in-memory stdin script:
    # no secret material is passed to it, and no scripts are left on disk.
    script = base64.b64decode(RECOVERY_B64, validate=True)
    r = run(["bash", "-s", "--", "--backup"], input=script)
    if r.returncode:
        raise RuntimeError("Verified primary Postfix backup creation failed")
    ids = re.findall(rb"(?m)^BACKUP_ID=([0-9]{8}T[0-9]{6}Z-[a-f0-9]{12})$", r.stdout)
    if len(ids) != 1:
        raise RuntimeError("Primary Postfix backup ID not confirmed")
    backup_id = ids[0].decode("ascii")
    proof = run(["bash", "-s", "--", "--verify", backup_id], input=script)
    if proof.returncode or b"BACKUP_STATUS=verified" not in proof.stdout:
        raise RuntimeError("Primary Postfix backup verification failed")
    return backup_id


def restore_backup(backup_id):
    recovery = base64.b64decode(RECOVERY_B64, validate=True)
    result = run(["bash", "-s", "--", "--restore", backup_id,
                  "--confirm", "AUTO_ROLLBACK_AFTER_FAILED_INSTALL"], input=recovery)
    return result.returncode == 0


def update_postconf(field, value):
    if re.search(r"[\r\n\0]", field + value):
        raise ValueError("Invalid Postfix parameter")
    result = run(["postconf", "-e", field + " = " + value])
    if result.returncode:
        raise RuntimeError("Unable to update a Postfix setting")


def prepare_gmail_map(request):
    if MAP.is_symlink():
        raise RuntimeError("Refusing symlinked Google credential map")
    host = "[smtp.gmail.com]:" + str(request["port"])
    # As standard Postfix does not offer a passwordless OAuth2 transport by
    # default, an explicitly approved Gmail App Password is required here.
    # The temporary plaintext is removed; the final .db remains reversible.
    with tempfile.TemporaryDirectory(prefix=".lmr365-google-", dir="/etc/postfix") as temp:
        plain = pathlib.Path(temp) / "auth"
        plain.touch(mode=0o600, exist_ok=False)
        plain.chmod(0o600)
        with plain.open("w", encoding="utf-8", newline="\n") as out:
            out.write(host + " " + request["user"] + ":" + request["secret"] + "\n")
        result = run(["postmap", "hash:" + str(plain)])
        if result.returncode:
            raise RuntimeError("Postfix password hash DB failed")
        database = pathlib.Path(str(plain) + ".db")
        if not database.is_file() or database.is_symlink():
            raise RuntimeError("Postfix DB not created")
        database.chmod(0o600)
        os.chown(database, 0, 0)
        os.replace(database, MAP)
        MAP.chmod(0o600)
        if shutil.which("restorecon"):
            # On RHEL-like SELinux hosts, maintain the normal /etc/postfix
            # file context for a new map database.
            checked = run(["restorecon", "-F", str(MAP)])
            if checked.returncode:
                raise RuntimeError("SELinux map context could not be restored")


def apply(request):
    sha = prerequisites()
    if sha != request["expected_sha"]:
        raise RuntimeError("Postfix changed since the reviewed preview")
    if route_conflicts() or queue_state() != "empty":
        raise RuntimeError("Mail queue or sender-specific routing requires review")
    profile = request["profile"]
    host = EXPECTED[profile][0]
    port = request["port"]
    if not pathlib.Path("/etc/ssl/certs/ca-certificates.crt").is_file():
        trust = pathlib.Path("/etc/pki/tls/certs/ca-bundle.crt")
        if not trust.is_file():
            raise RuntimeError("No trusted CA certificate bundle")
    else:
        trust = pathlib.Path("/etc/ssl/certs/ca-certificates.crt")
    backup_id = verified_backup()
    if fingerprint() != sha:
        raise RuntimeError("Postfix modified while backup was running")
    changed = False
    try:
        # The exact newly chosen destination, never a hard-coded 2525 listener.
        if profile == "gmail":
            prepare_gmail_map(request)
            changed = True
            update_postconf("smtp_sasl_password_maps",
                            "hash:/etc/postfix/lmr365-google-sasl")
            update_postconf("smtp_sasl_auth_enable", "yes")
            update_postconf("smtp_sasl_security_options", "noanonymous")
            update_postconf("smtp_sasl_tls_security_options", "noanonymous")
        else:
            # Workspace profile intentionally uses the IP-authorized relay
            # path. It does not invent a Google credential, tenant allowlist
            # or sender policy. The operator must approve Google Admin rules.
            changed = True
            update_postconf("smtp_sasl_auth_enable", "no")
        update_postconf("relayhost", "[" + host + "]:" + str(port))
        update_postconf("smtp_tls_CAfile", str(trust))
        update_postconf("smtp_tls_security_level", "secure")
        update_postconf("smtp_tls_wrappermode", "yes" if port == 465 else "no")
        if run(["postfix", "check"]).returncode:
            raise RuntimeError("Postfix syntax validation failed")
        if run(["postfix", "reload"]).returncode:
            raise RuntimeError("Postfix reload failed")
        if postconf("relayhost") != "[" + host + "]:" + str(port) or (
            run(["systemctl", "is-active", "--quiet", "postfix"]).returncode):
            raise RuntimeError("Google relay activation not verified")
        print("GOOGLE_ROUTE_VERSION=1")
        print("GOOGLE_ROUTE_PROFILE=" + profile)
        print("GOOGLE_ROUTE_PORT=" + str(port))
        print("GOOGLE_ROUTE_BACKUP_ID=" + backup_id)
        print("GOOGLE_ROUTE_APPLIED=yes")
        print("GOOGLE_ROUTE_ROLLBACK=not_required")
        print("GOOGLE_ROUTE_INBOUND_CHANGED=no")
        print("GOOGLE_ROUTE_MAIL_SENT=no")
        print("GOOGLE_ROUTE_SECRET_STORED_ON_LINUX=" + ("yes" if profile == "gmail" else "no"))
    except Exception:
        print("GOOGLE_ROUTE_VERSION=1")
        print("GOOGLE_ROUTE_BACKUP_ID=" + backup_id)
        print("GOOGLE_ROUTE_APPLIED=no")
        print("GOOGLE_ROUTE_ROLLBACK=" + ("ok" if not changed or restore_backup(backup_id) else "failed"))
        print("GOOGLE_ROUTE_MAIL_SENT=no")
        raise


def self_test():
    base = {"profile": "gmail", "port": 587, "operation": "preview",
            "expected_sha": "", "user": "", "secret": ""}
    config(base)
    config(dict(base, operation="apply", expected_sha="a" * 64,
                user="relay@example.org", secret="temporary-app-password"))
    config(dict(base, profile="workspace", port=25))
    for invalid in (
        dict(base, profile="unknown"),
        dict(base, port=2525),
        dict(base, operation="apply", expected_sha="x" * 64),
        dict(base, operation="apply", expected_sha="a" * 64,
             user="user@example.org", secret="bad\nsecret"),
        dict(base, profile="workspace", operation="apply",
             expected_sha="a" * 64, user="a@example.org", secret="password"),
    ):
        try:
            config(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid route input accepted")
    assert EXPECTED["gmail"][0] == "smtp.gmail.com"
    assert EXPECTED["workspace"][0] == "smtp-relay.gmail.com"
    print("Google Postfix route manager self-test OK")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        try:
            # The GUI injects both constants into protected SSH standard input.
            request = config(json.loads(base64.b64decode(CONFIG_B64, validate=True)))
            if request["operation"] == "preview":
                preview(request)
            else:
                apply(request)
        except Exception:
            # Never print password, encoded input, original command arguments
            # or server exception content. Failure requires explicit review.
            print("GOOGLE_ROUTE_ERROR=preflight_or_apply_failed")
            sys.exit(2)
