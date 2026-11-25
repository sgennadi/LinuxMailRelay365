#!/usr/bin/env python3
"""Read-only OAuth X.509 public export and ephemeral Entra addKey PoP signing.

Never exports PEM private keys, modifies active or staged identities, sends
mail, installs modules or contacts Microsoft Graph. The separate --proof
operation signs a short-lived RS256 JWT using ONLY the installed active
software PEM key, which stays on Linux. Python 3.6+.
"""
import argparse
import base64
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import time

VERSION = "1"
ROOTS = {
    "sidecar": Path("/etc/linuxmailrelay365/sidecar-identity"),
    "primary": Path("/etc/postfix/m365-oauth"),
    "primary-rotation": Path("/etc/postfix/m365-oauth")
}
GUID = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SHA = re.compile(r"\A[a-f0-9]{64}\Z")
MAX_IDENTITY = 32768
MAX_PEM = 24576
POP_AUDIENCE = "00000002-0000-0000-c000-000000000000"


class Refused(Exception):
    pass


def emit(k, v):
    print("ENTRA_OAUTH_{}={}".format(k, v))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def trusted_directory(directory):
    p = Path(directory)
    while True:
        try:
            info = p.lstat()
        except OSError:
            raise Refused("trusted_identity_directory_missing")
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused("untrusted_identity_directory")
        if p == p.parent:
            break
        p = p.parent


def secure_read(path, max_size, gid=None, modes=(0o640,)):
    path = Path(path)
    try:
        first = path.lstat()
    except OSError:
        raise Refused("required_root_identity_file_missing")
    if (not stat.S_ISREG(first.st_mode) or first.st_uid != 0 or
            first.st_nlink != 1 or stat.S_IMODE(first.st_mode) not in modes or
            (gid is not None and first.st_gid != gid) or
            first.st_size < 1 or first.st_size > max_size):
        raise Refused("unsafe_root_identity_file")
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as reader:
            now = os.fstat(reader.fileno())
            if (first.st_ino != now.st_ino or first.st_dev != now.st_dev or
                    first.st_mode != now.st_mode or first.st_uid != now.st_uid or
                    first.st_gid != now.st_gid or first.st_nlink != now.st_nlink or
                    first.st_size != now.st_size):
                raise Refused("identity_file_changed_during_read")
            raw = reader.read(max_size + 1)
    except OSError:
        raise Refused("identity_file_read_failed")
    if len(raw) != first.st_size:
        raise Refused("identity_file_changed_during_read")
    return raw


def der_from_pem(pem):
    try:
        text = pem.decode("ascii").strip()
        if text.count("-----BEGIN CERTIFICATE-----") != 1 or \
                text.count("-----END CERTIFICATE-----") != 1 or \
                "PRIVATE KEY" in text:
            raise Refused("certificate_not_public_x509_pem")
        der = ssl.PEM_cert_to_DER_cert(text)
    except (ValueError, UnicodeError):
        raise Refused("certificate_not_public_x509_pem")
    if not 250 <= len(der) <= MAX_PEM:
        raise Refused("candidate_certificate_der_invalid")
    return der


def read_identity(path, root, group):
    raw = secure_read(path, MAX_IDENTITY, group)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise Refused("invalid_oauth_identity_json")
    if not isinstance(obj, dict):
        raise Refused("invalid_oauth_identity_json")
    for k in ("tenant_id", "client_id", "mailbox", "certificate"):
        if not isinstance(obj.get(k), str) or not obj[k]:
            raise Refused("invalid_oauth_identity_fields")
    if not GUID.fullmatch(obj["tenant_id"]) or not GUID.fullmatch(obj["client_id"]):
        raise Refused("invalid_tenant_or_app_client_guid")
    if Path(obj["certificate"]).parent != root:
        raise Refused("certificate_outside_fixed_identity")
    return raw, obj


def active_inventory(target):
    """Public certificate referenced by app.json; no staged key or signing."""
    if os.geteuid() != 0 or target not in ("primary", "sidecar"):
        raise Refused("active_inventory_scope_invalid")
    root = ROOTS[target]
    trusted_directory(root)
    try:
        group = grp.getgrnam("m365mailer").gr_gid
    except KeyError:
        raise Refused("m365mailer_group_missing")
    def sample():
        # Use the existing fixed-root ownership and no-symlink checks.
        raw, identity = read_identity(root / "app.json", root, group)
        # Reject duplicate JSON properties: the running transport and the
        # audit must not interpret ambiguous identity records differently.
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise Refused("duplicate_identity_property")
                result[key] = value
            return result
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        if parsed != identity:
            raise Refused("identity_parse_mismatch")
        mailbox = identity["mailbox"].lower()
        if (len(mailbox) > 254 or ".." in mailbox or not re.fullmatch(
                r"[a-z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", mailbox)):
            raise Refused("active_mailbox_invalid")
        der = der_from_pem(secure_read(identity["certificate"], MAX_PEM,
                                      modes=(0o640, 0o644)))
        return {"target": target, "tenant": identity["tenant_id"],
                "client": identity["client_id"], "mailbox": mailbox,
                "identity_sha": digest(raw), "certificate_sha": digest(der),
                "certificate_der": base64.b64encode(der).decode("ascii")}
    first = sample()
    if sample() != first:
        raise Refused("active_identity_changed_during_review")
    return first


POSTFIX_CONFIGS = {
    "primary": Path("/etc/postfix"),
    "sidecar": Path("/etc/linuxmailrelay365/sidecar-postfix"),
}
ROUTE_SETTINGS = ("default_transport", "relay_transport", "transport_maps",
                  "sender_dependent_default_transport_maps",
                  "sender_dependent_relayhost_maps", "relayhost",
                  "m365xoauth2_destination_recipient_limit")
ROUTE_FIELDS = ("DEFAULT_TRANSPORT", "RELAY_TRANSPORT", "ROUTING_OVERRIDES",
                "MASTER_PIPE", "SERVICE_OVERRIDES", "RECIPIENT_LIMIT")


def classify_postfix_route(target, values, master, overrides):
    """Configuration only. Never resolve an address class or evaluate a map."""
    if target not in POSTFIX_CONFIGS:
        raise Refused("unsupported_postfix_route_scope")
    def expected(key, value):
        return "expected" if values[key] == value else "different"
    command = ("m365xoauth2 unix - n n - 2 pipe flags=q user=m365mailer "
               "argv=/usr/bin/python3 ")
    if target == "primary":
        command += "/usr/local/libexec/m365_xoauth2_transport.py"
    else:
        command += ("/usr/local/libexec/linuxmailrelay365-sidecar-transport.py "
                    "--config /etc/linuxmailrelay365/sidecar-identity/app.json")
    command += " --recipient $"+ "{recipient}"
    return {
        "DEFAULT_TRANSPORT": expected("default_transport", "m365xoauth2:"),
        "RELAY_TRANSPORT": expected("relay_transport", "m365xoauth2:"),
        "ROUTING_OVERRIDES": "declared" if any(values[k] for k in
            ("transport_maps", "sender_dependent_default_transport_maps",
             "sender_dependent_relayhost_maps", "relayhost")) else "absent",
        "MASTER_PIPE": "expected" if master.split() == command.split() else "different",
        "SERVICE_OVERRIDES": "declared" if overrides.strip() else "absent",
        "RECIPIENT_LIMIT": expected("m365xoauth2_destination_recipient_limit", "1"),
    }


def postfix_route_snapshot(target):
    root = POSTFIX_CONFIGS[target]
    trusted_directory(root)
    binary = "/usr/sbin/postconf"
    # Do not discover commands via a caller-controlled PATH.
    resolved = Path(binary).resolve(strict=True)
    trusted_directory(resolved.parent)
    metadata = resolved.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or
            metadata.st_mode & 0o022 or not metadata.st_mode & 0o111):
        raise Refused("untrusted_postconf")
    def config_digest():
        return tuple(digest(secure_read(root / name, 524288,
                      modes=(0o600, 0o640, 0o644))) for name in ("main.cf", "master.cf"))
    before = config_digest()

    def run(*args):
        p = subprocess.run([binary, "-c", str(root)] + list(args),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=5, check=False,
                           env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        if p.returncode or p.stderr.strip() or len(p.stdout) > 65536:
            raise Refused("postconf_readback_unverified")
        result = p.stdout.decode("utf-8").strip()
        if "\0" in result or "\r" in result:
            raise Refused("postconf_readback_unverified")
        return result

    values = {key: run("-h", key) for key in ROUTE_SETTINGS}
    master = run("-M", "m365xoauth2/unix")
    overrides = run("-P")
    if config_digest() != before:
        raise Refused("postfix_config_changed_during_read")
    # Retain hashes and raw values only in memory for the second sample.
    return before, values, master, overrides


def sample_configured_oauth(target):
    # An unavailable Postfix inspection must not suppress a valid public
    # certificate review, and must never become a positive route finding.
    try:
        before = postfix_route_snapshot(target)
    except (Refused, OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        before = None
    identity = active_inventory(target)
    route = dict((key, "unverified") for key in ROUTE_FIELDS)
    if before is not None:
        try:
            after = postfix_route_snapshot(target)
            if before == after:
                route = classify_postfix_route(target, before[1], before[2], before[3])
        except (Refused, OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
            pass
    return identity, route


def print_active_inventory(value, route=None):
    for name, key in (("TARGET", "target"), ("TENANT_ID", "tenant"),
                      ("CLIENT_ID", "client"), ("MAILBOX", "mailbox"),
                      ("IDENTITY_SHA256", "identity_sha"),
                      ("CERT_SHA256", "certificate_sha"),
                      ("CERT_DER_BASE64", "certificate_der")):
        print("ACTIVE_OAUTH_{}={}".format(name, value[key]))
    print("ACTIVE_OAUTH_VERSION=2")
    for key in ROUTE_FIELDS:
        print("ACTIVE_OAUTH_{}={}".format(key, (route or {}).get(key, "unverified")))
    print("ACTIVE_OAUTH_PRIVATE_KEY_EXPORTED=no")
    print("ACTIVE_OAUTH_SIGNING_TESTED=no")
    print("ACTIVE_OAUTH_MAIL_SENT=no")
    print("ACTIVE_OAUTH_CONFIG_CHANGED=no")


def inventory(target):
    if os.geteuid() != 0:
        raise Refused("root_required")
    if target not in ROOTS:
        raise Refused("unsupported_identity_target")
    root = ROOTS[target]
    trusted_directory(root)
    try:
        group = grp.getgrnam("m365mailer").gr_gid
    except KeyError:
        raise Refused("m365mailer_group_missing")
    active_raw, active = read_identity(root / "app.json", root, group)
    if target == "primary-rotation":
        # This path is intentionally software PEM only, never TPM/HSM.
        # Keep the existing app identity untouched until Graph registration
        # and candidate SMTP AUTH both pass.
        pattern = re.compile(r"\Aapp\.rotation\.[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\Z")
        active_key = active.get("private_key")
        if "signer" in active or not isinstance(active_key, str) or \
                Path(active_key).parent != root or \
                not ((Path(active_key).name == "app.key" and
                      Path(active["certificate"]).name == "app.crt") or
                     (pattern.fullmatch(Path(active["certificate"]).stem) and
                      Path(active_key).name ==
                      Path(active["certificate"]).stem + ".key")):
            raise Refused("software_pem_active_identity_required")
        stage_raw, stage = read_identity(root / "pem-rotation-staged.json", root, group)
        if set(stage) != {"tenant_id", "client_id", "mailbox",
                          "certificate", "private_key"} or \
                not isinstance(stage["private_key"], str) or \
                Path(stage["private_key"]).parent != root or \
                not pattern.fullmatch(Path(stage["certificate"]).stem) or \
                Path(stage["private_key"]).name != Path(stage["certificate"]).stem + ".key":
            raise Refused("invalid_primary_pem_candidate")
        secure_read(active_key, MAX_PEM, group)
        secure_read(stage["private_key"], MAX_PEM, group)
        def public_key(*args):
            try:
                p = subprocess.run(["/usr/bin/openssl"] + list(args),
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=25, check=False)
            except (OSError, subprocess.TimeoutExpired):
                raise Refused("staged_software_key_check_unavailable")
            if p.returncode or not 200 <= len(p.stdout) <= 4096:
                raise Refused("staged_software_key_check_failed")
            return p.stdout.strip()
        if public_key("pkey", "-in", stage["private_key"], "-pubout") != \
                public_key("x509", "-in", stage["certificate"], "-pubkey", "-noout"):
            raise Refused("staged_software_key_certificate_mismatch")
    else:
        stage_raw, stage = read_identity(root / "hardware-staged.json", root, group)
        if "signer" not in stage or "private_key" in stage or \
                not isinstance(stage["signer"], dict) or \
                stage["signer"].get("provider") not in ("tpm2", "pkcs11"):
            raise Refused("staged_identity_must_be_hardware_only")
        if Path(stage["certificate"]).name != "hardware-app.crt":
            raise Refused("unexpected_hardware_certificate_name")
    if any(active[x] != stage[x] for x in ("tenant_id", "client_id", "mailbox")):
        raise Refused("active_staged_tenant_client_sender_mismatch")
    active_der = der_from_pem(secure_read(active["certificate"], MAX_PEM,
                                          modes=(0o640, 0o644)))
    candidate_der = der_from_pem(secure_read(stage["certificate"], MAX_PEM,
                                             modes=(0o640, 0o644)))
    if active_der == candidate_der:
        raise Refused("candidate_must_use_different_certificate")
    return {"target": target, "root": root, "group": group,
            "active": active, "stage": stage,
            "active_sha": digest(active_raw), "stage_sha": digest(stage_raw),
            "active_der": active_der, "candidate_der": candidate_der,
            "active_cert_sha": digest(active_der),
            "candidate_cert_sha": digest(candidate_der)}


def print_inventory(x):
    emit("VERSION", VERSION)
    emit("TARGET", x["target"])
    emit("TENANT_ID", x["active"]["tenant_id"])
    emit("CLIENT_ID", x["active"]["client_id"])
    emit("ACTIVE_SHA256", x["active_sha"])
    emit("STAGED_SHA256", x["stage_sha"])
    emit("ACTIVE_CERT_SHA256", x["active_cert_sha"])
    emit("ACTIVE_CERT_DER_BASE64", base64.b64encode(x["active_der"]).decode("ascii"))
    emit("CANDIDATE_CERT_SHA256", x["candidate_cert_sha"])
    emit("CANDIDATE_CERT_DER_BASE64", base64.b64encode(x["candidate_der"]).decode("ascii"))
    emit("ACTIVE_SIGNER", "software_pem" if "private_key" in x["active"] else "hardware_other")
    emit("ROUTING_IDENTITY_UNCHANGED", "yes")
    emit("PRIVATE_KEY_EXPORTED", "no")
    emit("ENTRA_CONTACTED", "no")
    emit("MAIL_SENT", "no")
    emit("ACTIVE_OAUTH_CHANGED", "no")


def make_proof(x, object_id, expected_active, expected_stage,
               expected_active_cert, expected_candidate_cert,
               command_runner=subprocess.run, now=None):
    """Generate ephemeral RS256 PoP; key is never exported or printed.

    Graph addKey requires an existing valid cert's PoP. Refuse a hardware
    current signer until a separate hardware-aware Graph PoP path is verified.
    """
    if not GUID.fullmatch(object_id) or any(not SHA.fullmatch(z) for z in (
            expected_active, expected_stage, expected_active_cert,
            expected_candidate_cert)):
        raise Refused("invalid_reviewed_proof_arguments")
    if (expected_active != x["active_sha"] or expected_stage != x["stage_sha"] or
            expected_active_cert != x["active_cert_sha"] or
            expected_candidate_cert != x["candidate_cert_sha"]):
        raise Refused("linux_identity_or_cert_changed_repreview")
    old = x["active"]
    if "signer" in old or not isinstance(old.get("private_key"), str) or \
            Path(old["private_key"]).parent != x["root"]:
        raise Refused("existing_software_private_key_required_for_graph_pop")
    secure_read(old["private_key"], MAX_PEM, x["group"])
    current = int(time.time()) if now is None else int(now)
    header = {"typ": "JWT", "alg": "RS256",
              "x5t": b64url(hashlib.sha1(x["active_der"]).digest())}
    payload = {"aud": POP_AUDIENCE, "iss": object_id,
               "nbf": current - 30, "exp": current + 570}
    signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode("ascii")) +
                     "." + b64url(json.dumps(payload, separators=(",", ":")).encode("ascii")))
    try:
        outcome = command_runner(
            ["/usr/bin/openssl", "dgst", "-sha256", "-sign", old["private_key"]],
            input=signing_input.encode("ascii"), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=25, check=False,
            env={"LC_ALL": "C", "HOME": "/nonexistent", "PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("existing_signer_pop_failed")
    if outcome.returncode or not 128 <= len(outcome.stdout) <= 1024:
        raise Refused("existing_signer_pop_failed")
    # The Graph-side script independently verifies RS256 against the exact
    # existing Entra key credential matching active_cert_sha.
    return signing_input + "." + b64url(outcome.stdout)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", choices=sorted(ROOTS), required=True)
    ap.add_argument("--inventory", action="store_true")
    ap.add_argument("--active-inventory", action="store_true")
    ap.add_argument("--proof", action="store_true")
    ap.add_argument("--object-id")
    ap.add_argument("--expected-active-sha")
    ap.add_argument("--expected-stage-sha")
    ap.add_argument("--expected-active-cert-sha")
    ap.add_argument("--expected-candidate-cert-sha")
    args = ap.parse_args(argv)
    try:
        if sum((args.inventory, args.active_inventory, args.proof)) != 1:
            raise Refused("select_one_certificate_operation")
        proofs = (args.object_id, args.expected_active_sha,
                  args.expected_stage_sha, args.expected_active_cert_sha,
                  args.expected_candidate_cert_sha)
        if (args.inventory or args.active_inventory) and any(x is not None for x in proofs):
            raise Refused("proof_arguments_not_allowed_in_inventory")
        if args.active_inventory:
            identity, route = sample_configured_oauth(args.target)
            print_active_inventory(identity, route)
            return 0
        x = inventory(args.target)
        if args.inventory:
            print_inventory(x)
        else:
            if any(x is None for x in proofs):
                raise Refused("complete_reviewed_proof_arguments_required")
            emit("PROOF_VERSION", VERSION)
            emit("PROOF_JWT", make_proof(x, *proofs))
            emit("PRIVATE_KEY_EXPORTED", "no")
            emit("ENTRA_CONTACTED", "no")
            emit("MAIL_SENT", "no")
        return 0
    except Refused as error:
        emit("ERROR", str(error))
        return 2
    except (OSError, UnicodeError, ValueError, TypeError):
        emit("ERROR", "oauth_certificate_operation_failed")
        return 2


if __name__ == "__main__":
    sys.exit(main())
