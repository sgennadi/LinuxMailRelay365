#!/usr/bin/env python3
"""Explicit selected-mailbox live AUTH-only diagnostic, Python 3.6+.

Root resolves the reviewed map row; m365mailer performs the local signature,
HTTPS token request and SMTP STARTTLS/XOAUTH2 check. No delivery, queue,
service, runtime or cloud configuration mutation. Never relay raw output.
"""
import grp
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import smtplib
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location("mailbox_auth_inventory", str(HERE/"inspect-multi-mailbox-identities.py"))
I = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(I)
A, E, need, Refused = I.A, I.E, I.need, I.Refused
CONFIRM = "CHECK_SELECTED_MAILBOX_SMTP_AUTH_ONLY"
ENV = {"LC_ALL":"C", "PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "HOME":"/nonexistent"}
NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,90}\.json\Z")
RESULT = re.compile(r"\A(?:authenticated|config_failed|signing_failed|token_failed|token_http_[1-5][0-9]{2}|starttls_unavailable|xoauth2_unavailable|smtp_failed|smtp_rejected_[1-5][0-9]{2}|identity_changed|worker_failed)\Z")


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")


def request(raw):
    need(1 <= len(raw) <= 4096, "request_size")
    obj = I.decode(raw)
    need(isinstance(obj, dict) and set(obj) == {
        "scope","map_sha","login","mailbox","tenant","client","identity_sha","certificate_sha",
        "signer","nonce","confirm"} and all(isinstance(x,str) for x in obj.values()), "request_fields")
    need(obj["scope"] in ("source","runtime") and I.LOGIN.fullmatch(obj["login"]) and
         I.valid_mailbox(obj["mailbox"]) and A.EMAIL.fullmatch(obj["mailbox"]) and
         obj["signer"] in ("software","hardware") and
         all(I.SHA.fullmatch(obj[k]) for k in ("map_sha","identity_sha","certificate_sha","nonce")) and
         obj["confirm"] == CONFIRM, "request_context")
    I.guid(obj["tenant"])
    I.guid(obj["client"])
    return obj


def selected(req, gid):
    path = I.SOURCE if req["scope"] == "source" else I.RUNTIME
    runtime = req["scope"] == "runtime"
    raw = I.read_optional(path, A.MAX_MAP, (0o640,) if runtime else (0o600,), gid if runtime else None)
    need(raw is not None and I.digest(raw) == req["map_sha"], "reviewed_map_changed")
    rows = A.parse_map(raw)
    need(1 <= len(rows) <= 64, "map_row_limit")
    matches = [r for r in rows if r[:3] == (req["login"], req["mailbox"], req["mailbox"])]
    need(len(matches) == 1, "selected_mailbox_missing")
    config = Path(matches[0][3])
    need(config.parent == I.IDENTITIES and NAME.fullmatch(config.name) and str(config) == matches[0][3],
         "unsafe_identity_filename")
    row = I.identity_row(*matches[0], gid)
    need(row["status"] == "public_certificate_read" and row["tenant"] == req["tenant"] and
         row["client"] == req["client"] and row["identity_sha256"] == req["identity_sha"] and
         row["certificate_sha256"] == req["certificate_sha"] and row["signer"] == req["signer"],
         "selected_identity_changed")
    return str(config)


def checked_config(req, path, gid, transport):
    target = Path(path)
    need(target.parent == I.IDENTITIES and NAME.fullmatch(target.name) and str(target) == path,
         "unsafe_identity_filename")
    E.trusted_directory(target.parent)
    raw = E.secure_read(target, A.MAX_IDENTITY, gid, modes=(0o640,))
    need(I.digest(raw) == req["identity_sha"], "identity_changed")
    item = I.decode(raw)
    A.validate_identity(raw, req["mailbox"])
    config = transport.load_config(path)
    need(config["tenant_id"] == req["tenant"] and config["client_id"] == req["client"] and
         config["mailbox"] == req["mailbox"] and
         ("hardware" if "signer" in config else "software") == req["signer"] and
         I.public_certificate_sha(item["certificate"]) == req["certificate_sha"] and
         E.secure_read(target, A.MAX_IDENTITY, gid, modes=(0o640,)) == raw,
         "identity_changed")
    return config


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def token_for_assertion(config, endpoint, assertion):
    expected = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(config["tenant_id"])
    need(endpoint == expected, "unexpected_token_endpoint")
    data = urllib.parse.urlencode({
        "client_id":config["client_id"], "grant_type":"client_credentials",
        "scope":"https://outlook.office365.com/.default",
        "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":assertion}).encode("ascii")
    req = urllib.request.Request(expected, data=data,
        headers={"Content-Type":"application/x-www-form-urlencoded"}, method="POST")
    # No credential-bearing redirects or ambient proxy settings. Bound the
    # response and do not print any token, assertion or HTTP error body.
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(req, timeout=30) as response:
        raw = response.read(131073)
    need(len(raw) <= 131072, "token_response_limit")
    obj = I.decode(raw)
    token = obj.get("access_token") if isinstance(obj, dict) else None
    need(isinstance(token, str) and 1 <= len(token) <= 32768 and
         re.fullmatch(r"[A-Za-z0-9._~+/-]+={0,2}", token), "invalid_token_response")
    return token


def worker(req, path, gid, transport, token_reader=token_for_assertion):
    try:
        config = checked_config(req, path, gid, transport)
    except Exception:
        return "config_failed"
    try:
        endpoint, assertion = transport.make_client_assertion(config)
        transport.verify_assertion_signature(config, assertion)
    except Exception:
        return "signing_failed"
    try:
        if checked_config(req, path, gid, transport) != config:
            return "identity_changed"
    except Exception:
        return "identity_changed"
    try:
        token = token_reader(config, endpoint, assertion)
    except urllib.error.HTTPError as exc:
        return "token_http_{}".format(exc.code) if isinstance(exc.code, int) and 100 <= exc.code <= 599 else "token_failed"
    except Exception:
        return "token_failed"
    finally:
        del assertion
    try:
        if checked_config(req, path, gid, transport) != config:
            return "identity_changed"
    except Exception:
        return "identity_changed"
    try:
        transport.check_smtp_auth(config, token)
    except smtplib.SMTPResponseException as exc:
        return "smtp_rejected_{}".format(exc.smtp_code) if isinstance(exc.smtp_code,int) and 100 <= exc.smtp_code <= 599 else "smtp_failed"
    except Exception as exc:
        # Match only known transport messages and emit fixed categories.
        msg = str(exc)
        if msg == "Microsoft 365 did not offer STARTTLS":
            return "starttls_unavailable"
        if msg == "Microsoft 365 did not advertise AUTH XOAUTH2":
            return "xoauth2_unavailable"
        if msg == "Microsoft 365 rejected staged XOAUTH2 token (334)":
            return "smtp_rejected_334"
        match = re.fullmatch(r"Microsoft 365 staged XOAUTH2 authentication failed \(SMTP ([1-5][0-9]{2})\)", msg)
        return "smtp_rejected_" + match.group(1) if match else "smtp_failed"
    finally:
        del token
    try:
        if checked_config(req, path, gid, transport) != config:
            return "identity_changed"
    except Exception:
        return "identity_changed"
    return "authenticated"


def service_account():
    user = pwd.getpwnam("m365mailer")
    gid = grp.getgrnam("m365mailer").gr_gid
    need(user.pw_uid > 0 and gid > 0 and user.pw_gid == gid, "unsafe_service_identity")
    return user, gid


def dispatch(req, gid, runner=subprocess.run):
    path = selected(req, gid)
    E.trusted_directory(HERE)
    # Files come from this build's ephemeral, root-owned code directory.
    for name in ("check-multi-mailbox-smtp-auth.py","inspect-multi-mailbox-identities.py",
                 "audit-oauth-sender-map.py","export-hardware-oauth-cert.py",
                 "m365_xoauth2_transport.py","m365_hardware_signer.py"):
        E.secure_read(HERE/name, 1048576, modes=(0o644,))
    runuser = shutil.which("runuser", path=ENV["PATH"])
    need(bool(runuser), "runuser_required")
    try:
        reply = runner([runuser,"-u","m365mailer","--","/usr/bin/python3","-I","-B",
                        str(HERE/"check-multi-mailbox-smtp-auth.py"),"--worker"],
                       input=encode({"request":req,"path":path}), stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, timeout=210, env=ENV, check=False)
        status = reply.stdout.decode("ascii").strip() if reply.returncode == 0 and len(reply.stdout) <= 64 else "worker_failed"
        if not RESULT.fullmatch(status):
            status = "worker_failed"
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        status = "worker_failed"
    need(selected(req,gid) == path, "selection_changed_after_auth")
    return dict(version=1, nonce=req["nonce"], scope=req["scope"], map_sha=req["map_sha"],
                login=req["login"], mailbox=req["mailbox"], tenant=req["tenant"], client=req["client"],
                identity_sha=req["identity_sha"], certificate_sha=req["certificate_sha"], signer=req["signer"],
                status=status, authenticated=status=="authenticated", service_account="m365mailer",
                endpoint="smtp.office365.com:587", mail_sent=False, changes=False, runtime_changed=False,
                cloud_changed=False, token_exported=False, delivery_verified=False)


def main():
    try:
        user,gid = service_account()
        os.umask(0o077)
        if sys.argv[1:] == ["--worker"]:
            need(os.geteuid() == user.pw_uid and os.getegid() == gid, "service_identity_required")
            raw = sys.stdin.buffer.read(8193)
            need(1 <= len(raw) <= 8192, "worker_request_size")
            job = I.decode(raw)
            need(isinstance(job,dict) and set(job)=={"request","path"}, "worker_request_fields")
            req = request(encode(job["request"]))
            import m365_xoauth2_transport as transport
            print(worker(req,job["path"],gid,transport))
            return 0
        need(not sys.argv[1:] and os.geteuid()==0, "root_required")
        req = request(sys.stdin.buffer.read(4097))
        print(encode(dispatch(req,gid)).decode("ascii"))
        return 0
    except (Refused,A.Refused,E.Refused,OSError,KeyError,ValueError,TypeError,UnicodeError):
        print("MAILBOX_SMTP_AUTH=refused_or_review_required")
        return 2


if __name__ == "__main__":
    sys.exit(main())
