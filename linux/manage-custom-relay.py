#!/usr/bin/env python3
"""Guarded in-place Postfix migration to an operator-chosen outbound SMTP relay.

Never changes listening ports, local delivery, master.cf or queued messages.
An exact SHA-256 Preview, empty queue, no conflicting maps, verified root-only
backup and post-reload invariants are required. On failure, restore the backup.
Password-mode stores a root-recoverable credential DB ONLY on Linux after
explicit approval; never log its contents or upstream SMTP responses.
"""
import base64
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile

# LMR365_CONFIG_MARKER
# LMR365_RECOVERY_MARKER

MAIN = pathlib.Path("/etc/postfix/main.cf")
MASTER = pathlib.Path("/etc/postfix/master.cf")
MAP = pathlib.Path("/etc/postfix/lmr365-custom-sasl.db")
BACKUP_ID = re.compile(r"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\Z")
HEX = re.compile(r"\A[a-f0-9]{64}\Z")
HOST = re.compile(
    r"\A(?=.{1,253}\Z)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\Z")
MANAGED_MAP = "hash:/etc/postfix/lmr365-custom-sasl"


def host_name(value):
    if type(value) is not str or not HOST.fullmatch(value):
        raise ValueError("Invalid SMTP destination")
    if re.fullmatch(r"[0-9.]+", value):
        import ipaddress
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            raise ValueError("Invalid SMTP IPv4")
    return value.lower()


def config(data):
    keys = {"host", "port", "tls", "auth_mode", "operation",
            "expected_sha", "expected_resolution_sha",
            "username", "secret", "plaintext_approval"}
    if type(data) is not dict or set(data) != keys:
        raise ValueError("Invalid outbound SMTP request")
    data["host"] = host_name(data["host"])
    if type(data["port"]) is not int or not 1 <= data["port"] <= 65535:
        raise ValueError("Invalid outbound SMTP TCP port")
    if data["tls"] not in ("starttls", "implicit", "plain"):
        raise ValueError("Invalid outgoing TLS mode")
    if data["auth_mode"] not in ("none", "password"):
        raise ValueError("Invalid SMTP AUTH mode")
    applying = data["operation"] == "apply"
    if data["operation"] not in ("preview", "apply"):
        raise ValueError("Invalid routing operation")
    sha = data["expected_sha"]
    if type(sha) is not str or (applying and not HEX.fullmatch(sha)) or (
            not applying and sha):
        raise ValueError("Exact reviewed SHA required for Apply")
    resolved_sha = data["expected_resolution_sha"]
    if (type(resolved_sha) is not str or
            (applying and not HEX.fullmatch(resolved_sha)) or
            (not applying and resolved_sha)):
        raise ValueError("Exact reviewed destination DNS SHA required for Apply")
    user, secret = data["username"], data["secret"]
    if type(user) is not str or type(secret) is not str:
        raise ValueError("Invalid SMTP credentials")
    if data["auth_mode"] == "password":
        if data["tls"] == "plain":
            raise ValueError("Password authentication over plaintext forbidden")
        if applying:
            if (not 1 <= len(user) <= 254 or not 1 <= len(secret) <= 256 or
                    any(ord(x) < 33 or ord(x) > 126 or x == ":" for x in user) or
                    any(ord(x) < 32 or ord(x) == 127 for x in secret)):
                raise ValueError("Invalid one-time SMTP credential")
        elif user or secret:
            raise ValueError("Preview may not carry SMTP credentials")
    elif user or secret:
        raise ValueError("Credential supplied for no-auth SMTP mode")
    approval = data["plaintext_approval"]
    if type(approval) is not str or (
            applying and data["tls"] == "plain" and
            approval != "I_ACCEPT_UNENCRYPTED_OUTBOUND_SMTP") or (
            (not applying or data["tls"] != "plain") and approval):
        raise ValueError("Explicit approval required for unencrypted outbound SMTP")
    return data


def run(args, *, input=None):
    # stdout/stderr PIPE instead of capture_output keeps Python 3.6
    # compatibility on RHEL/Rocky/Alma 8, without leaking SMTP credentials.
    return subprocess.run(args, input=input, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False, timeout=75)


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
            raise RuntimeError("Postfix config not a regular file")
        meta = file.stat()
        if meta.st_uid != 0 or not stat.S_ISREG(meta.st_mode):
            raise RuntimeError("Postfix config not root-owned")
        payload = file.read_bytes()
        if len(payload) > 2 * 1024 * 1024:
            raise RuntimeError("Oversized Postfix config")
        digest.update(file.name.encode() + b"\0" + payload + b"\0")
    # Binding an existing managed password map prevents unnoticed credential
    # changes between Preview and Apply. Only its digest is returned.
    if MAP.is_symlink():
        raise RuntimeError("Symlinked SMTP credential map")
    if MAP.exists():
        meta = MAP.stat()
        if (not MAP.is_file() or meta.st_uid != 0 or
                meta.st_mode & 0o077 or meta.st_size > 8 * 1024 * 1024):
            raise RuntimeError("Unsafe SMTP credential map")
        digest.update(b"custom-map\0" + MAP.read_bytes())
    else:
        digest.update(b"custom-map-absent\0")
    return digest.hexdigest()


def outbound_master_overrides():
    """Flag outgoing smtp/relay service overrides that may defeat this route.

    Postfix postconf -P returns effective master.cf -o assignments in the form
    service/type/parameter=value. Unlike text scanning, it handles multi-line
    master.cf services. No values are exposed to the Windows GUI.
    """
    result = run(["postconf", "-P"])
    if result.returncode or len(result.stdout) > 131072:
        return True
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        key, separator, _ = line.partition("=")
        parts = key.strip().lower().split("/")
        if not separator or len(parts) != 3:
            return True
        service, protocol, parameter = parts
        if service in ("smtp", "relay") and protocol == "unix":
            if (parameter.startswith("smtp_tls_") or
                    parameter.startswith("smtp_sasl_") or
                    parameter in ("relayhost", "smtp_use_tls", "smtp_enforce_tls")):
                return True
    return False


def route_conflicts():
    # Never overwrite special routes, destination TLS maps or someone else's
    # credential map. An owned map is eligible only after exact SHA review.
    for name in ("transport_maps", "sender_dependent_relayhost_maps",
                 "sender_dependent_default_transport_maps", "smtp_tls_policy_maps",
                 "smtp_tls_per_site", "smtp_fallback_relay"):
        if postconf(name):
            return True
    if postconf("default_transport") not in ("", "smtp"):
        return True
    if postconf("smtp_sasl_password_maps") not in ("", MANAGED_MAP):
        return True
    if postconf("smtp_sender_dependent_authentication").lower() != "no":
        return True
    matches = set(filter(None, re.split(
        r"[\s,:]+", postconf("smtp_tls_secure_cert_match").lower())))
    if not matches or not matches.issubset({"nexthop", "dot-nexthop"}):
        return True
    return outbound_master_overrides()


def scope_status():
    """Never change a secondary or relocated Postfix configuration by accident."""
    try:
        directory = postconf("config_directory")
        instances = postconf("multi_instance_enable").lower()
        other_directories = postconf("multi_instance_directories")
    except (RuntimeError, OSError, TimeoutError):
        return "unverified"
    return "verified" if (directory == "/etc/postfix" and
                          instances == "no" and
                          not other_directories) else "unverified"


def client_sasl_status():
    """Check whether THIS Postfix client can use Google PLAIN/LOGIN over TLS.

    SMTP AUTH on a remote Google connection is not a substitute for checking
    local Postfix client SASL implementation and installed client mechanisms.
    Status is deliberately conservative and never prints plugin details.
    """
    try:
        configured = postconf("smtp_sasl_type").strip()
        supported = run(["postconf", "-A"])
    except (RuntimeError, OSError, TimeoutError):
        return "unverified"
    if supported.returncode != 0:
        return "unverified"
    available = supported.stdout.decode("utf-8", "replace").split()
    if configured not in available:
        return "missing"
    # Cyrus SASL is the only supported credential-map route for this manager.
    # Other Postfix implementations are not silently rewritten or replaced.
    if configured != "cyrus":
        return "unverified"
    filter_value = postconf("smtp_sasl_mechanism_filter").upper()
    viewer = shutil.which("saslpluginviewer")
    if viewer is None:
        return "unverified"
    result = run([viewer, "-c"])
    if result.returncode != 0:
        return "unverified"
    # Inspect only mechanism names; never expose SASL plugin output.
    mechanisms = set(re.findall(
        r"\b(?:PLAIN|LOGIN)\b", result.stdout.decode("utf-8", "replace").upper()))
    if not mechanisms:
        return "missing"
    if filter_value:
        # Negative filters (!login) and static:rest must be respected. Merely
        # finding the word LOGIN inside "!login" is a false positive.
        tokens = [item for item in re.split(r"[\s,]+", filter_value) if item]
        known = {"PLAIN", "LOGIN", "GSSAPI", "XOAUTH2", "OAUTHBEARER",
                 "CRAM-MD5", "DIGEST-MD5", "NTLM", "ANONYMOUS"}
        if any(token not in known and
               token not in {"STATIC:ALL", "STATIC:REST"} and
               not (token.startswith("!") and token[1:] in known)
               for token in tokens):
            # Dynamic lookup tables, file patterns, or unfamiliar filters
            # cannot be evaluated by a static preflight. Fail closed.
            return "unverified"
        included = set(token for token in tokens if token in mechanisms)
        if "STATIC:ALL" in tokens or "STATIC:REST" in tokens:
            included.update(mechanisms)
        excluded = set(token[1:] for token in tokens if token.startswith("!"))
        mechanisms = included - excluded
    return "ready" if mechanisms else "missing"


# Values which must survive an outbound-only upstream migration unchanged.
# SMTP AUTH here is the *inbound* server flag, distinct from smtp_sasl_*.
INBOUND_SETTINGS = (
    "inet_interfaces", "inet_protocols", "mydestination", "myorigin",
    "mynetworks", "smtpd_sasl_auth_enable", "smtpd_relay_restrictions",
    "smtpd_recipient_restrictions", "local_transport", "mailbox_transport",
    "virtual_transport", "virtual_alias_maps", "virtual_mailbox_maps",
    "alias_maps", "alias_database",
)


def inbound_snapshot():
    """Capture local delivery and inbound policy without printing values."""
    if not MASTER.is_file() or MASTER.is_symlink():
        raise RuntimeError("Postfix master.cf changed or is not a regular file")
    contents = MASTER.read_bytes()
    if len(contents) > 2 * 1024 * 1024:
        raise RuntimeError("Postfix master.cf exceeds expected size")
    return (hashlib.sha256(contents).digest(),
            tuple(postconf(key) for key in INBOUND_SETTINGS))


def require_password_map(host, port):
    if not MAP.is_file() or MAP.is_symlink():
        raise RuntimeError("Managed SMTP credential DB missing")
    meta = MAP.stat()
    if meta.st_uid != 0 or not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077:
        raise RuntimeError("Managed SMTP credential DB unsafe")
    result = run(["postmap", "-q", "[" + host + "]:" + str(port), MANAGED_MAP])
    if result.returncode or not result.stdout.strip():
        raise RuntimeError("Managed SMTP credential lookup failed")


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


def outbound_destination_evidence(host):
    """Fail closed when destination DNS resolves to this host.

    Only emit a status and a SHA256 of sorted resolved IPs, never raw network
    inventory. The ip -j address show command reports Linux interface IPs.
    Missing utility, ambiguous JSON or DNS errors block automatic Apply.
    """
    unknown = ("unverified", "0" * 64)
    if host == "localhost" or host.endswith(".localhost"):
        return ("yes", "0" * 64)
    try:
        records = socket.getaddrinfo(host, 0, type=socket.SOCK_STREAM)
        resolved = set()
        for record in records:
            addr = ipaddress.ip_address(record[4][0].split("%", 1)[0])
            if addr.version == 6 and addr.ipv4_mapped:
                addr = addr.ipv4_mapped
            resolved.add(addr)
        if not resolved or len(resolved) > 128:
            return unknown
        serialized = "\n".join(sorted(str(a) for a in resolved)).encode("ascii")
        proof = hashlib.sha256(serialized).hexdigest()
        if any(a.is_loopback or a.is_unspecified or a.is_multicast or
               a.is_link_local for a in resolved):
            return ("yes", proof)
        if shutil.which("ip") is None:
            return unknown
        result = run(["ip", "-j", "address", "show"])
        if result.returncode or len(result.stdout) > 131072:
            return unknown
        interfaces = json.loads(result.stdout.decode("utf-8"))
        if type(interfaces) is not list or not 1 <= len(interfaces) <= 256:
            return unknown
        local = set()
        for iface in interfaces:
            if type(iface) is not dict or type(iface.get("addr_info")) is not list:
                return unknown
            for entry in iface["addr_info"]:
                if type(entry) is not dict:
                    return unknown
                address = entry.get("local")
                if type(address) is str:
                    local.add(ipaddress.ip_address(address.split("%", 1)[0]))
        if not local:
            return unknown
        return ("yes" if resolved & local else "no", proof)
    except (ValueError, KeyError, IndexError, TypeError, OSError,
            socket.gaierror, UnicodeError, json.JSONDecodeError):
        return unknown


def preview(request):
    sha = prerequisites()
    conflict = route_conflicts()
    queue = queue_state()
    scope = scope_status()
    sasl = client_sasl_status() if request["auth_mode"] == "password" else "not_required"
    enabled = postconf("smtp_sasl_auth_enable").lower()
    outbound_auth = "enabled" if enabled == "yes" else (
        "disabled" if enabled == "no" else "unverified")
    tls_level = postconf("smtp_tls_security_level").lower()
    if tls_level not in ("none", "may", "encrypt", "dane", "dane-only",
                         "fingerprint", "verify", "secure"):
        tls_level = "unverified"
    loop, resolved_sha = outbound_destination_evidence(request["host"])
    allowed = (not conflict and queue == "empty" and scope == "verified" and
               loop == "no" and (request["auth_mode"] != "password" or sasl == "ready"))
    fields = {
        "VERSION": "1", "HOST": request["host"],
        "PORT": str(request["port"]), "TLS": request["tls"],
        "AUTH_MODE": request["auth_mode"], "PREVIEW_SHA256": sha,
        "CONFLICTING_MAPS": "yes" if conflict else "no",
        "QUEUE": queue, "OUTBOUND_SASL": outbound_auth,
        "PASSWORD_MAP": ("configured" if postconf("smtp_sasl_password_maps") else "not_configured"),
        "TLS_LEVEL": tls_level, "POSTFIX_SCOPE": scope,
        "CLIENT_SASL": sasl, "SELF_LOOP_RISK": loop,
        "RESOLUTION_SHA256": resolved_sha,
        "APPLY_ALLOWED": "yes" if allowed else "no",
        "INBOUND_CHANGED": "no", "MAIL_SENT": "no", "CONFIG_CHANGED": "no"
    }
    for key, value in fields.items():
        print("CUSTOM_ROUTE_" + key + "=" + value)


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


def prepare_password_map(request):
    if MAP.is_symlink():
        raise RuntimeError("Symlinked SMTP credential DB")
    destination = "[" + request["host"] + "]:" + str(request["port"])
    # .db is not encrypted. Root can recover its contents.
    with tempfile.TemporaryDirectory(prefix=".lmr365-custom-", dir="/etc/postfix") as temp:
        plain = pathlib.Path(temp) / "auth"
        plain.touch(mode=0o600, exist_ok=False)
        plain.chmod(0o600)
        with plain.open("w", encoding="utf-8", newline="\n") as out:
            out.write(destination + " " + request["username"] + ":" + request["secret"] + "\n")
        result = run(["postmap", "hash:" + str(plain)])
        if result.returncode:
            raise RuntimeError("Postfix password hash database failed")
        database = pathlib.Path(str(plain) + ".db")
        if not database.is_file() or database.is_symlink():
            raise RuntimeError("Postfix credential map not created")
        database.chmod(0o600)
        os.chown(database, 0, 0)
        os.replace(database, MAP)
        MAP.chmod(0o600)
        if shutil.which("restorecon"):
            if run(["restorecon", "-F", str(MAP)]).returncode:
                raise RuntimeError("SELinux credential map context could not be restored")


def apply(request):
    sha = prerequisites()
    if sha != request["expected_sha"]:
        raise RuntimeError("Postfix configuration drifted since Preview")
    route_risk, resolution_sha = outbound_destination_evidence(request["host"])
    if (route_risk != "no" or resolution_sha != request["expected_resolution_sha"] or
            route_conflicts() or queue_state() != "empty" or
            scope_status() != "verified" or
            (request["auth_mode"] == "password" and client_sasl_status() != "ready")):
        raise RuntimeError("Destination DNS or Postfix configuration changed since Preview")
    trust = pathlib.Path("/etc/ssl/certs/ca-certificates.crt")
    if not trust.is_file():
        trust = pathlib.Path("/etc/pki/tls/certs/ca-bundle.crt")
    if request["tls"] != "plain" and not trust.is_file():
        raise RuntimeError("No trusted certificate bundle")
    inbound = inbound_snapshot()
    backup_id = verified_backup()
    renewed_risk, renewed_resolution_sha = outbound_destination_evidence(request["host"])
    if (fingerprint() != sha or renewed_risk != "no" or
            renewed_resolution_sha != resolution_sha or route_conflicts() or
            queue_state() != "empty" or scope_status() != "verified" or
            (request["auth_mode"] == "password" and client_sasl_status() != "ready")):
        raise RuntimeError("Postfix configuration drifted during backup")
    modified = False
    try:
        if request["auth_mode"] == "password":
            modified = True
            prepare_password_map(request)
            update_postconf("smtp_sasl_password_maps", MANAGED_MAP)
            update_postconf("smtp_sasl_auth_enable", "yes")
            update_postconf("smtp_sasl_security_options", "noanonymous")
            update_postconf("smtp_sasl_tls_security_options", "noanonymous")
            require_password_map(request["host"], request["port"])
        else:
            modified = True
            update_postconf("smtp_sasl_auth_enable", "no")
        route = "[" + request["host"] + "]:" + str(request["port"])
        update_postconf("relayhost", route)
        if request["tls"] != "plain":
            update_postconf("smtp_tls_CAfile", str(trust))
            update_postconf("smtp_tls_security_level", "secure")
        else:
            update_postconf("smtp_tls_security_level", "none")
        update_postconf("smtp_tls_wrappermode", "yes" if request["tls"] == "implicit" else "no")
        if run(["postfix", "check"]).returncode:
            raise RuntimeError("Postfix configuration syntax invalid")
        if run(["postfix", "reload"]).returncode:
            raise RuntimeError("Postfix reload failed")
        if (postconf("relayhost") != route or
                run(["systemctl", "is-active", "--quiet", "postfix"]).returncode or
                postconf("smtp_sasl_auth_enable") !=
                    ("yes" if request["auth_mode"] == "password" else "no") or
                postconf("smtp_tls_wrappermode") !=
                    ("yes" if request["tls"] == "implicit" else "no") or
                postconf("smtp_tls_security_level") !=
                    ("none" if request["tls"] == "plain" else "secure")):
            raise RuntimeError("Postfix outgoing SMTP policy mismatch")
        if request["auth_mode"] == "password":
            if postconf("smtp_sasl_password_maps") != MANAGED_MAP:
                raise RuntimeError("Activated SMTP credential map mismatch")
            require_password_map(request["host"], request["port"])
        if inbound_snapshot() != inbound:
            raise RuntimeError("Local or inbound SMTP settings drifted")
        result = {
            "VERSION": "1", "HOST": request["host"],
            "PORT": str(request["port"]), "TLS": request["tls"],
            "AUTH_MODE": request["auth_mode"], "BACKUP_ID": backup_id,
            "APPLIED": "yes", "ROLLBACK": "not_required",
            "INBOUND_CHANGED": "no", "MAIL_SENT": "no",
            "SECRET_STORED_ON_LINUX": (
                "yes" if request["auth_mode"] == "password" else "no")
        }
        for key, value in result.items():
            print("CUSTOM_ROUTE_" + key + "=" + value)
    except Exception:
        print("CUSTOM_ROUTE_VERSION=1")
        print("CUSTOM_ROUTE_BACKUP_ID=" + backup_id)
        print("CUSTOM_ROUTE_APPLIED=no")
        print("CUSTOM_ROUTE_ROLLBACK=" +
              ("ok" if not modified or restore_backup(backup_id) else "failed"))
        print("CUSTOM_ROUTE_MAIL_SENT=no")
        raise



def write_lock():
    """Exclusive shared write lock across Google and generic Postfix managers.

    Held from the first reviewed Apply recheck through backup, mutation and
    any rollback. Unknown owner/mode, symlink or concurrent migration fails.
    No lock is acquired for the read-only Preview path.
    """
    path = "/run/linuxmailrelay365-postfix-route.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or
                meta.st_mode & 0o077):
            raise RuntimeError("Unsafe shared Postfix route lock")
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception:
        os.close(fd)
        raise
    return fd


def release_lock(fd):
    # Closing releases the advisory kernel lock even after a failed rollback.
    os.close(fd)


def self_test():
    base = dict(host="mail.example.org", port=587, tls="starttls",
                auth_mode="password", operation="preview", expected_sha="",
                expected_resolution_sha="", username="", secret="",
                plaintext_approval="")
    config(dict(base))
    config(dict(base, port=2525))
    config(dict(base, port=25, tls="plain", auth_mode="none"))
    config(dict(base, operation="apply", expected_sha="a"*64,
                expected_resolution_sha="b"*64,
                username="user@example.org", secret="one-use-only"))
    config(dict(base, port=25, auth_mode="none", tls="plain",
                operation="apply", expected_sha="a"*64,
                expected_resolution_sha="b"*64,
                plaintext_approval="I_ACCEPT_UNENCRYPTED_OUTBOUND_SMTP"))
    for invalid in (
            dict(base, host="host;rm"), dict(base, host="300.300.1.1"),
            dict(base, port=0), dict(base, port=65536),
            dict(base, auth_mode="password", tls="plain"),
            dict(base, operation="apply", expected_sha="x"*64),
            dict(base, operation="apply", expected_sha="a"*64,
                 username="user", secret="bad\nsecret"),
            dict(base, auth_mode="none", secret="oops"),
            dict(base, auth_mode="none", tls="plain",
                 operation="apply", expected_sha="a"*64)):
        try:
            config(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Unsafe custom SMTP request accepted")
    print("Custom SMTP route manager self-test OK")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        try:
            request = config(json.loads(base64.b64decode(CONFIG_B64, validate=True)))
            if request["operation"] == "preview":
                preview(request)
            else:
                lock_fd = write_lock()
                try:
                    apply(request)
                finally:
                    release_lock(lock_fd)
        except Exception:
            # Never print credentials, encoded SSH input or SMTP server replies.
            print("CUSTOM_ROUTE_ERROR=preflight_or_apply_failed")
            sys.exit(2)
