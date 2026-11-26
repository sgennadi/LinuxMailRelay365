#!/usr/bin/env python3
"""Read-only preview of one M365 sender for the primary Postfix.

No migration approval, SMTP connection, credential access/export, package
installation, queue mutation, service operation or Postfix configuration write.
Inspect effective settings, rather than assume every message uses one route.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("primary_route_evidence", str(HERE/"export-hardware-oauth-cert.py"))
E = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(E)
ROOT = Path("/etc/postfix")
ENV = {"LC_ALL":"C", "PATH":"/usr/sbin:/usr/bin:/sbin:/bin"}
MAIL = re.compile(r"\A[a-z0-9][a-z0-9._+%-]{0,62}@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z0-9]{2,63}\Z")
SHA = re.compile(r"\A[a-f0-9]{64}\Z")
MAPS = ("transport_maps","sender_dependent_default_transport_maps",
        "sender_dependent_relayhost_maps","content_filter")
SETTINGS = ("config_directory","multi_instance_enable","multi_instance_directories",
            "default_transport","relay_transport","relayhost",
            "mydestination","virtual_alias_domains","virtual_mailbox_domains",
            "relay_domains") + MAPS


def need(ok, code):
    if not ok:
        raise E.Refused(code)


def encode(value):
    return json.dumps(value,sort_keys=True,separators=(",",":")).encode("ascii")


def parse(raw):
    need(0 < len(raw) <= 2048,"request_size")
    def unique(pairs):
        result={}
        for k,v in pairs:
            need(k not in result,"duplicate_request_key")
            result[k]=v
        return result
    obj=json.loads(raw.decode("utf-8"),object_pairs_hook=unique)
    need(isinstance(obj,dict) and set(obj)=={"mailbox","nonce"} and
         all(isinstance(v,str) for v in obj.values()) and
         MAIL.fullmatch(obj["mailbox"]) and ".." not in obj["mailbox"] and
         SHA.fullmatch(obj["nonce"]),"invalid_request")
    return obj


def command(name,args):
    need(name in ("postconf","postqueue","systemctl"),"unexpected_command")
    for directory in ("/usr/sbin","/usr/bin","/sbin","/bin"):
        try:
            binary=(Path(directory)/name).resolve(strict=True)
        except FileNotFoundError:
            continue
        E.trusted_directory(binary.parent)
        st=binary.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022 and
             bool(st.st_mode&0o111),"untrusted_tool")
        result=subprocess.run([str(binary)]+list(args),stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=15,env=ENV,check=False)
        # Never return arbitrary diagnostic text to the GUI.
        need(len(result.stdout)<=2097152,"command_output_limit")
        return result
    raise E.Refused("required_tool_missing")


def config_hash():
    E.trusted_directory(ROOT)
    return E.digest(b"\0".join(E.secure_read(ROOT/name,524288,
        modes=(0o600,0o640,0o644)) for name in ("main.cf","master.cf")))


def sample():
    digest=config_hash()
    def read(*args):
        result=command("postconf",("-c",str(ROOT))+args)
        need(result.returncode==0 and not result.stderr.strip() and len(result.stdout)<=131072,
             "postconf_unverified")
        value=result.stdout.decode("utf-8").strip()
        need("\0" not in value and "\r" not in value,"invalid_postconf_output")
        return value
    values={key:read("-h",key) for key in SETTINGS}
    # The custom recipient-limit parameter is not present on a stock
    # installation. Query it only if the pipe already exists.
    master=read("-M")
    values["m365xoauth2_destination_recipient_limit"] = (
        read("-h","m365xoauth2_destination_recipient_limit")
        if re.search(r"(?m)^m365xoauth2\s+unix(?:\s|$)",master) else "")
    overrides=read("-P")
    need(config_hash()==digest,"configuration_changed")
    return digest,values,master,overrides


def identity_status(mailbox):
    path=ROOT/"m365-oauth"/"app.json"
    if not os.path.lexists(str(path)):
        return "absent"
    try:
        item=E.active_inventory("primary")
    except (E.Refused,OSError,KeyError,ValueError,TypeError,UnicodeError):
        return "unverified"
    return "mailbox_matches" if item["mailbox"]==mailbox else "different_mailbox"


def classify(sampled):
    _,values,master,overrides=sampled
    scope="primary_only" if (values["config_directory"]==str(ROOT) and
        values["multi_instance_enable"]=="no" and not values["multi_instance_directories"]) else "review_required"
    service_lines=[line for line in master.splitlines()
                   if re.match(r"^m365xoauth2\s+unix(?:\s|$)",line)]
    pipe=E.classify_postfix_route("primary",values,
        service_lines[0] if len(service_lines)==1 else "",overrides)
    maps=any(values[k] for k in MAPS)
    expected=(pipe["DEFAULT_TRANSPORT"]=="expected" and pipe["RELAY_TRANSPORT"]=="expected" and
              pipe["MASTER_PIPE"]=="expected" and pipe["RECIPIENT_LIMIT"]=="expected" and
              not maps and not values["relayhost"] and not overrides)
    conflicts=(maps or bool(overrides) or
        values["default_transport"] not in ("smtp","smtp:","m365xoauth2:") or
        values["relay_transport"] not in ("relay","relay:","smtp","smtp:","m365xoauth2:") or
        (bool(service_lines) and pipe["MASTER_PIPE"]!="expected"))
    return dict(scope=scope,route="configured" if expected else "review_required" if conflicts else "migration_candidate",
                override_status="present" if conflicts else "absent",
                local_classes="configured" if any(values[k] for k in
                    ("mydestination","virtual_alias_domains","virtual_mailbox_domains")) else "not_declared")


def inspect(req):
    first=sample()
    route=classify(first)
    ident=identity_status(req["mailbox"])
    active=command("systemctl",("is-active","--quiet","postfix"))
    try:
        queue=command("postqueue",("-c",str(ROOT),"-j"))
        queue_status="unverified" if queue.returncode else "nonempty" if queue.stdout.strip() else "empty"
    except (E.Refused,OSError,subprocess.TimeoutExpired):
        queue_status="unverified"
    need(sample()==first and identity_status(req["mailbox"])==ident,"configuration_changed")
    return dict(version=1,nonce=req["nonce"],mailbox=req["mailbox"],config_sha256=first[0],
        identity=ident,service="active" if active.returncode==0 else "unverified",
        queue=queue_status,changes=False,mail_sent=False,apply_supported=False,
        local_delivery_changed=False,listener_changed=False,**route)


def main():
    try:
        need(os.geteuid()==0,"root_required")
        req=parse(sys.stdin.buffer.read(2049))
        print(encode(inspect(req)).decode("ascii"))
        return 0
    except (E.Refused,OSError,KeyError,ValueError,TypeError,UnicodeError,subprocess.TimeoutExpired):
        print("PRIMARY_MAILBOX_ROUTE=review_required")
        return 2


if __name__=="__main__":
    sys.exit(main())
