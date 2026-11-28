"""Candidate primary TPM broker message contract (not an installed service).

The request selects ONE fixed primary OAuth assertion operation. The caller
cannot submit bytes to sign, choose an identity, key, tenant, audience, or
supply a path. A future daemon must first authenticate the Unix peer and load
its own protected active identity. No socket listener, network, token exchange,
production installer, or fallback to software signing is implemented here.
Compatible with Python 3.6+.
"""
import base64
import binascii
import hashlib
import json
import re
import subprocess
import time
import uuid
from pathlib import Path

import m365_xoauth2_transport as transport
from m365_hardware_signer import HardwareSignerError, TPM_HANDLE

REQUEST_LIMIT = 256
RESPONSE_LIMIT = 8192
VERSION = 1
OPERATION = "primary_assertion"
NONCE = re.compile(r"\A[0-9a-f]{32}\Z")
SEGMENT = re.compile(r"\A[A-Za-z0-9_-]+\Z")
IDENTITY = Path("/etc/postfix/m365-oauth/app.json")
CERTIFICATE = IDENTITY.parent / "hardware-app.crt"
PROVIDER_CONFIG = IDENTITY.parent / "tpm2.cnf"


class BrokerProtocolError(ValueError):
    """Fixed diagnostic codes only; never include an assertion or wire data."""


def need(condition, code):
    if not condition:
        raise BrokerProtocolError(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "broker_duplicate_json_field")
        result[key] = value
    return result


def reject_constant(value):
    raise BrokerProtocolError("broker_invalid_json_constant")


def json_object(raw, limit):
    need(type(raw) is bytes and 0 < len(raw) <= limit, "broker_json_size")
    try:
        obj = json.loads(raw.decode("ascii"), object_pairs_hook=unique_object,
                         parse_constant=reject_constant)
    except BrokerProtocolError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise BrokerProtocolError("broker_invalid_json") from None
    need(type(obj) is dict, "broker_json_object_required")
    return obj


def frame(obj, limit):
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    need(len(raw) <= limit, "broker_frame_size")
    return raw


def parse_frame(raw, limit):
    need(type(raw) is bytes and 0 < len(raw) <= limit and
         raw.endswith(b"\n") and raw.count(b"\n") == 1 and b"\r" not in raw,
         "broker_frame_invalid")
    obj = json_object(raw[:-1], limit - 1)
    # Canonical framing excludes alternate representations and extra bytes.
    try:
        need(frame(obj, limit) == raw, "broker_noncanonical_frame")
    except (ValueError, TypeError, RecursionError):
        raise BrokerProtocolError("broker_noncanonical_frame") from None
    return obj


def valid_nonce(nonce):
    need(type(nonce) is str and NONCE.fullmatch(nonce), "broker_nonce_invalid")
    return nonce


def encode_request(nonce):
    return frame({"v": VERSION, "op": OPERATION, "nonce": valid_nonce(nonce)},
                 REQUEST_LIMIT)


def decode_request(raw):
    obj = parse_frame(raw, REQUEST_LIMIT)
    need(set(obj) == {"v", "op", "nonce"} and type(obj["v"]) is int and
         obj["v"] == VERSION and obj["op"] == OPERATION, "broker_request_schema")
    return valid_nonce(obj["nonce"])


def require_primary_identity(config):
    # The trusted caller must load the root-managed primary identity; this
    # checks the supported subset, not filesystem ownership or service access.
    need(type(config) is dict and set(config) == {
        "tenant_id", "client_id", "mailbox", "certificate", "signer", "_identity_path"
    }, "broker_primary_identity_schema")
    need(config["_identity_path"] == str(IDENTITY) and
         config["certificate"] == str(CERTIFICATE), "broker_primary_identity_path")
    spec = config["signer"]
    need(type(spec) is dict and set(spec) == {
        "type", "provider", "key_ref", "provider_config"
    } and spec["type"] == "openssl-provider" and spec["provider"] == "tpm2" and
         spec["provider_config"] == str(PROVIDER_CONFIG) and
         type(spec["key_ref"]) is str and TPM_HANDLE.fullmatch(spec["key_ref"]),
         "broker_persistent_tpm_required")
    for key in ("tenant_id", "client_id"):
        value = config[key]
        try:
            need(type(value) is str and str(uuid.UUID(value)) == value,
                 "broker_identity_guid")
        except (ValueError, AttributeError, TypeError):
            raise BrokerProtocolError("broker_identity_guid") from None
    need(type(config["mailbox"]) is str and
         transport.EMAIL_RE.fullmatch(config["mailbox"]), "broker_identity_mailbox")
    return "https://login.microsoftonline.com/" + config["tenant_id"] + "/oauth2/v2.0/token"


def b64_segment(segment, limit):
    need(type(segment) is str and 0 < len(segment) <= limit * 2 and
         SEGMENT.fullmatch(segment), "broker_jwt_segment")
    try:
        raw = base64.b64decode(segment + "=" * (-len(segment) % 4),
                               altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise BrokerProtocolError("broker_jwt_segment") from None
    need(0 < len(raw) <= limit and transport.base64url(raw) == segment,
         "broker_jwt_segment")
    return raw


def split_assertion(assertion):
    need(type(assertion) is str and 0 < len(assertion) <= 6144, "broker_jwt_size")
    pieces = assertion.split(".")
    need(len(pieces) == 3 and len(pieces[0]) + len(pieces[1]) + 1 <= 4096,
         "broker_jwt_shape")
    header = json_object(b64_segment(pieces[0], 1024), 1024)
    claims = json_object(b64_segment(pieces[1], 3072), 3072)
    signature = b64_segment(pieces[2], 1024)
    need(128 <= len(signature) <= 1024, "broker_jwt_signature_size")
    return header, claims


def encode_response(nonce, assertion):
    split_assertion(assertion)
    return frame({"v": VERSION, "nonce": valid_nonce(nonce), "assertion": assertion},
                 RESPONSE_LIMIT)


def decode_response(raw, nonce):
    obj = parse_frame(raw, RESPONSE_LIMIT)
    need(set(obj) == {"v", "nonce", "assertion"} and type(obj["v"]) is int and
         obj["v"] == VERSION and obj["nonce"] == valid_nonce(nonce),
         "broker_response_schema_or_nonce")
    split_assertion(obj["assertion"])
    return obj["assertion"]


def validate_claims(config, assertion, now):
    endpoint = require_primary_identity(config)
    need(type(now) is int and now > 0, "broker_clock_invalid")
    header, claims = split_assertion(assertion)
    try:
        der = transport.run_openssl("x509", "-in", config["certificate"],
                                    "-outform", "DER")
    except (OSError, subprocess.SubprocessError, transport.TransientError):
        raise BrokerProtocolError("broker_certificate_unavailable") from None
    need(type(der) is bytes and bool(der), "broker_certificate_unavailable")
    thumbprint = transport.base64url(hashlib.sha256(der).digest())
    need(header == {"alg": "PS256", "typ": "JWT", "x5t#S256": thumbprint},
         "broker_jwt_header")
    need(set(claims) == {"aud", "iss", "sub", "jti", "nbf", "iat", "exp"} and
         claims["aud"] == endpoint and claims["iss"] == config["client_id"] and
         claims["sub"] == config["client_id"], "broker_jwt_claims")
    try:
        jti = uuid.UUID(claims["jti"])
        need(type(claims["jti"]) is str and jti.version == 4 and
             str(jti) == claims["jti"], "broker_jwt_jti")
    except (ValueError, AttributeError, TypeError):
        raise BrokerProtocolError("broker_jwt_jti") from None
    need(all(type(claims[key]) is int for key in ("nbf", "iat", "exp")) and
         now - 60 <= claims["iat"] <= now + 5 and
         claims["nbf"] == claims["iat"] - 60 and
         claims["exp"] == claims["iat"] + 600 and
         claims["nbf"] <= now < claims["exp"], "broker_jwt_time")
    return endpoint


def issue_primary_assertion(raw, config, now=None):
    """Server-side pure contract, called ONLY after peer and identity checks."""
    nonce = decode_request(raw)
    endpoint = require_primary_identity(config)
    stamp = int(time.time()) if now is None else now
    need(type(stamp) is int and stamp > 0, "broker_clock_invalid")
    try:
        actual_endpoint, assertion = transport.make_client_assertion(config, now=stamp)
    except (ValueError, OSError, subprocess.SubprocessError, HardwareSignerError,
            transport.TransientError):
        raise BrokerProtocolError("broker_hardware_assertion_failed") from None
    need(actual_endpoint == endpoint, "broker_endpoint_mismatch")
    validate_claims(config, assertion, stamp)
    return encode_response(nonce, assertion)


def verify_primary_response(raw, nonce, config, now=None):
    """Client-side verification: exact identity, freshness and real PS256."""
    assertion = decode_response(raw, nonce)
    stamp = int(time.time()) if now is None else now
    endpoint = validate_claims(config, assertion, stamp)
    try:
        transport.verify_assertion_signature(config, assertion)
    except (ValueError, OSError, subprocess.SubprocessError, transport.TransientError):
        raise BrokerProtocolError("broker_response_signature_invalid") from None
    return endpoint, assertion
