#!/usr/bin/env python3
"""Explicit OpenSSL 3 TPM2/PKCS#11 PS256 signer for M365 XOAUTH2.

Non-exportable hardware key operations only; no fallback to a PEM private
key. TPM2 provider uses persistent handle or a TSS2 private-key *blob*
usable only on its originating TPM. PKCS#11 uses a PIN-free key URI; any
PIN must be configured through an approved root-managed OpenSSL config.
This module does not create TPM objects, install providers or modify Entra.
Python 3.6+ (RHEL/Oracle/Rocky/Alma and Ubuntu).
"""
import grp
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

PROVIDERS = ("tpm2", "pkcs11")
IDENTITIES = (Path("/etc/linuxmailrelay365/sidecar-identity"),
              Path("/etc/postfix/m365-oauth"),
              Path("/etc/linuxmailrelay365/oauth-identities"))
PKCS11_URI = re.compile(r"\Apkcs11:[A-Za-z0-9%._+;=:@-]{5,230}\Z")
TPM_HANDLE = re.compile(r"\Ahandle:0x81[a-fA-F0-9]{6}\Z")
MAX_CONFIG_BYTES = 32768


class HardwareSignerError(Exception):
    pass


def check_root_file(file, base, mode=0o640):
    target = Path(file)
    if target.parent != base or not target.is_absolute():
        raise HardwareSignerError("hardware_reference_outside_identity")
    try:
        meta = target.lstat()
        group = grp.getgrnam("m365mailer").gr_gid
    except (OSError, KeyError):
        raise HardwareSignerError("hardware_reference_unavailable")
    if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or
            meta.st_uid != 0 or meta.st_gid != group or
            stat.S_IMODE(meta.st_mode) != mode):
        raise HardwareSignerError("unsafe_hardware_reference_permissions")
    return target


def validate_spec(config, identity_path):
    """Validate explicit hardware selection and all local filesystem gates."""
    spec = config.get("signer")
    if not isinstance(spec, dict) or set(spec) != {
            "type", "provider", "key_ref", "provider_config"}:
        raise HardwareSignerError("invalid_hardware_signer_config")
    if spec["type"] != "openssl-provider" or spec["provider"] not in PROVIDERS:
        raise HardwareSignerError("unsupported_hardware_provider")
    base = Path(identity_path).parent
    if base not in IDENTITIES:
        raise HardwareSignerError("unsupported_hardware_identity_path")
    if config.get("private_key"):
        raise HardwareSignerError("pem_fallback_forbidden_in_hardware_mode")
    provider_file = check_root_file(spec["provider_config"], base)
    if provider_file.stat().st_size > MAX_CONFIG_BYTES:
        raise HardwareSignerError("hardware_provider_config_too_large")
    reference = spec["key_ref"]
    if not isinstance(reference, str) or "\x00" in reference or "\n" in reference:
        raise HardwareSignerError("invalid_hardware_private_key_reference")
    if spec["provider"] == "pkcs11":
        if (not PKCS11_URI.fullmatch(reference) or
                re.search("pin|module-path|module-name", reference, re.I) or
                not ("object=" in reference or "id=" in reference) or
                "type=private" not in reference):
            raise HardwareSignerError("hardware_pkcs11_uri_must_not_embed_secrets")
    else:
        tpm_file = base / "tpm2-app.key"
        if reference != str(tpm_file) and not TPM_HANDLE.fullmatch(reference):
            raise HardwareSignerError("unsupported_tpm2_key_reference")
        if reference == str(tpm_file):
            check_root_file(tpm_file, base)
            with tpm_file.open("rb") as stream:
                sample = stream.read(96)
            if b"-----BEGIN TSS2 PRIVATE KEY-----" not in sample:
                raise HardwareSignerError("not_a_tpm2_wrapped_private_key")
    return spec


def _public_key(cert):
    result = subprocess.run(
        ["/usr/bin/openssl", "x509", "-in", cert, "-pubkey", "-noout"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=False, timeout=15)
    if result.returncode or b"BEGIN PUBLIC KEY" not in result.stdout:
        raise HardwareSignerError("hardware_signer_certificate_invalid")
    return result.stdout


def sign_ps256(config, unsigned):
    """Sign with the selected provider and verify against Entra public cert."""
    if not isinstance(unsigned, bytes) or not 1 <= len(unsigned) <= 4096:
        raise HardwareSignerError("invalid_assertion_payload")
    spec = validate_spec(config, config["_identity_path"])
    provider = spec["provider"]
    # Environment deliberately excludes OPENSSL_MODULES, PKCS11_* and
    # inherited OPENSSL_CONF. Only a root-managed provider config may load
    # a PKCS11 driver and a protected PIN file, if needed by the device.
    env = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
           "OPENSSL_CONF": spec["provider_config"]}
    proc = subprocess.run(
        ["/usr/bin/openssl", "pkeyutl",
         "-provider", "default" if provider == "pkcs11" else "base",
         "-provider", provider, "-sign", "-inkey", spec["key_ref"],
         "-rawin", "-digest", "sha256",
         "-pkeyopt", "rsa_padding_mode:pss",
         "-pkeyopt", "rsa_pss_saltlen:32"],
        input=unsigned, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=False, timeout=40, env=env)
    signature = proc.stdout
    if proc.returncode != 0 or not 128 <= len(signature) <= 1024:
        raise HardwareSignerError("hardware_signature_unavailable_no_pem_fallback")
    public_key = _public_key(config["certificate"])
    # Temporary public key and signed assertion signature only, never
    # private material, access tokens, PIN values or mail content.
    with tempfile.TemporaryDirectory(prefix="lmr365-signcheck-") as folder:
        pub = Path(folder) / "public.pem"
        sig = Path(folder) / "signature.bin"
        pub.write_bytes(public_key)
        sig.write_bytes(signature)
        pub.chmod(0o600)
        sig.chmod(0o600)
        checked = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(pub),
             "-signature", str(sig),
             "-sigopt", "rsa_padding_mode:pss",
             "-sigopt", "rsa_pss_saltlen:32"],
            input=unsigned, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, timeout=15)
    if checked.returncode or b"Verified OK" not in checked.stdout:
        raise HardwareSignerError("hardware_key_does_not_match_entra_certificate")
    return signature


def signing_probe(config):
    """Offline smoke; no Entra token or SMTP is requested."""
    from importlib import import_module
    transport = import_module("m365_xoauth2_transport")
    endpoint, assertion = transport.make_client_assertion(config)
    # make_client_assertion already performs signature verification.
    if not endpoint.startswith("https://login.microsoftonline.com/") or \
            len(assertion.split(".")) != 3:
        raise HardwareSignerError("invalid_hardware_assertion")
    return True
