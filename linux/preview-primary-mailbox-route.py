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
import tempfile

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
         len(obj["mailbox"])<=254 and MAIL.fullmatch(obj["mailbox"]) and ".." not in obj["mailbox"] and
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


def config_bytes():
    E.trusted_directory(ROOT)
    return tuple(E.secure_read(ROOT/name,524288,
        modes=(0o600,0o640,0o644)) for name in ("main.cf","master.cf"))


def config_hash():
    return E.digest(b"\0".join(config_bytes()))


# Only these settings may be changed by the proposed in-place migration.
# In particular, do not rewrite inet_interfaces, mynetworks, mydestination,
# local/virtual transports, smtpd restrictions, message_size_limit or ports.
ROUTE_CHANGES = (
    ("default_transport","m365xoauth2:"),
    ("relay_transport","m365xoauth2:"),
    ("relayhost",""),
    ("m365xoauth2_destination_recipient_limit","1"),
    ("m365xoauth2_destination_concurrency_limit","2"),
)
PIPE = (b"m365xoauth2 unix - n n - 2 pipe\n"
        b"  flags=q user=m365mailer argv=/usr/bin/python3 "
        b"/usr/local/libexec/m365_xoauth2_transport.py --recipient ${recipient}\n")


def candidate_configs(raw, sampled):
    """Compile exact candidate bytes; never write a live or staged file."""
    main, master = raw
    _, values, services, _ = sampled
    need(classify(sampled)["route"] != "review_required","route_conflict")
    for blob in raw:
        need(len(blob)<=524288 and b"\0" not in blob and b"\r" not in blob,
             "unsupported_config_format")
        blob.decode("utf-8")
    targets=dict(ROUTE_CHANGES)
    seen=set()
    changed=set()
    out=[]
    last=None
    # Preserve all unrelated lines byte for byte, including continuations.
    # Reject targeted multi-line/duplicate definitions and macros that could
    # make unrelated effective settings change when a target is replaced.
    refs=re.compile(rb"\$(?:\{\s*)?(?:"+
                    b"|".join(k.encode("ascii") for k in targets)+rb")(?![A-Za-z0-9_])")
    for line in main.splitlines(keepends=True):
        stripped=line.strip()
        if not stripped or stripped.startswith(b"#"):
            out.append(line)
            continue
        if line[:1] in (b" ",b"\t"):
            need(last is not None and last not in targets,"target_continuation_or_orphan")
            need(not refs.search(line),"dependent_config_macro")
            out.append(line)
            continue
        match=re.match(rb"^([a-zA-Z][a-zA-Z0-9_]*)[ \t]*=",line)
        need(match is not None,"unrecognized_main_cf_line")
        last=match.group(1).decode("ascii")
        if last not in targets:
            need(not refs.search(line),"dependent_config_macro")
            out.append(line)
            continue
        need(last not in seen,"duplicate_route_parameter")
        seen.add(last)
        value=targets[last].encode("ascii")
        if line.split(b"=",1)[1].strip()==value:
            out.append(line)
        else:
            out.append(last.encode("ascii")+b" = "+value+b"\n")
            changed.add(last)
    new_main=b"".join(out)
    for name,value in ROUTE_CHANGES:
        if name not in seen:
            # Avoid creating an unnecessary empty relayhost override.
            if name=="relayhost" and not values["relayhost"]:
                continue
            if new_main and not new_main.endswith(b"\n"):
                new_main+=b"\n"
            new_main+=name.encode("ascii")+b" = "+value.encode("ascii")+b"\n"
            changed.add(name)
    need(not refs.search(b"\n".join(line for line in master.splitlines()
                                   if not line.lstrip().startswith(b"#"))),
         "dependent_master_macro")
    raw_services=[line for line in master.splitlines()
                  if re.match(rb"^m365xoauth2(?:[ \t]|$)",line)]
    effective_services=[line for line in services.splitlines()
                        if re.match(r"^m365xoauth2(?:\s|$)",line)]
    need(len(raw_services)==len(effective_services) and len(raw_services)<=1,
         "ambiguous_existing_pipe")
    if raw_services:
        pipe=E.classify_postfix_route("primary",values,effective_services[0],
                                     sampled[3])
        need(pipe["MASTER_PIPE"]=="expected","unexpected_existing_pipe")
        new_master=master
    else:
        new_master=master+(b"" if not master or master.endswith(b"\n") else b"\n")+PIPE
        changed.add("master.cf:m365xoauth2")
    ordered=[name for name,_ in ROUTE_CHANGES if name in changed]
    if "master.cf:m365xoauth2" in changed:
        ordered.append("master.cf:m365xoauth2")
    return (new_main,new_master),ordered


def candidate_evidence(raw,sampled,mailbox,identity):
    empty=dict(candidate_status="review_required",candidate_sha256="",
               plan_sha256="",change_set=[])
    need(E.digest(b"\0".join(raw))==sampled[0],"configuration_changed")
    try:
        candidate,changes=candidate_configs(raw,sampled)
    except (E.Refused,UnicodeError):
        return empty
    sha=E.digest(b"\0".join(candidate))
    plan=E.digest(encode(dict(version=2,config_sha256=sampled[0],
        candidate_sha256=sha,mailbox=mailbox,identity=identity,change_set=changes)))
    return dict(candidate_status="ready" if changes else "already_configured",
                candidate_sha256=sha,plan_sha256=plan,change_set=changes)


# In addition to every explicit main.cf assignment, sample expanded
# values for the address classes, listeners and policies that must remain
# unchanged. This is a native parser check, not a daemon or delivery test.
PRESERVED_KEYS = (
    "config_directory","queue_directory","data_directory",
    "multi_instance_enable","multi_instance_directories",
    "myhostname","mydomain","myorigin","mydestination","relay_domains",
    "virtual_alias_domains","virtual_mailbox_domains","local_transport",
    "virtual_transport","alias_maps","local_recipient_maps",
    "virtual_alias_maps","virtual_mailbox_maps","relay_recipient_maps",
    "transport_maps","sender_dependent_default_transport_maps",
    "sender_dependent_relayhost_maps","content_filter","inet_interfaces",
    "inet_protocols","mynetworks","smtpd_relay_restrictions",
    "smtpd_recipient_restrictions","smtpd_sasl_auth_enable",
    "smtpd_tls_security_level","smtp_sasl_auth_enable","smtp_tls_security_level",
    "smtp_tls_policy_maps","default_transport","relay_transport","relayhost",
)


def parameter_map(raw):
    result={}
    for line in raw.splitlines():
        name,sep,value=line.partition(" = ")
        need(sep and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*",name)
             and name not in result,"ambiguous_native_parameter")
        result[name]=value
    return result


def native_snapshot(directory,runner=command):
    directory=Path(directory)
    def read(*args):
        r=runner("postconf",("-c",str(directory))+args)
        need(r.returncode==0 and not r.stderr.strip() and len(r.stdout)<=524288,
             "native_candidate_postconf_unverified")
        value=r.stdout.decode("utf-8","strict")
        need("\0" not in value and "\r" not in value,"invalid_native_output")
        return value
    explicit=parameter_map(read("-n"))
    expanded=parameter_map(read("-x",*PRESERVED_KEYS))
    need(set(expanded)==set(PRESERVED_KEYS) and
         expanded["config_directory"]==str(directory),"native_directory_or_fields_unverified")
    services={}
    for line in read("-M").splitlines():
        tokens=line.split()
        need(len(tokens)>=8,"invalid_native_master_service")
        key=tokens[0]+"/"+tokens[1]
        need(key not in services,"duplicate_native_master_service")
        services[key]=tokens
    need(not read("-P").strip(),"native_service_overrides_require_review")
    # A temporary config root can affect derived path defaults. Normalize
    # only that exact generated path, then compare against the live sample.
    def normalize(value):
        return value.replace(str(directory),str(ROOT)) if directory!=ROOT else value
    return {"explicit":{k:normalize(v) for k,v in explicit.items()},
            "expanded":{k:normalize(v) for k,v in expanded.items()},
            "services":{k:[normalize(v) for v in row] for k,row in services.items()}}


def compare_native_candidate(before,after):
    targets=dict(ROUTE_CHANGES)
    need(set(before)==set(after)=={"explicit","expanded","services"},
         "native_snapshot_shape")
    old,new=before["explicit"],after["explicit"]
    need({k:v for k,v in old.items() if k not in targets}==
         {k:v for k,v in new.items() if k not in targets},
         "unexpected_explicit_parameter_change")
    for key,value in targets.items():
        if key=="relayhost" and key not in new:
            need(not after["expanded"]["relayhost"],"native_relayhost_not_cleared")
        else:
            need(new.get(key)==value,"native_candidate_parameter_mismatch")
    previous,current=before["expanded"],after["expanded"]
    need(set(previous)==set(current)==set(PRESERVED_KEYS),"native_expanded_fields_changed")
    for key,value in current.items():
        need(value==(targets[key] if key in targets else previous[key]),
             "unexpected_effective_parameter_change")
    pipe="m365xoauth2/unix"
    old_services,new_services=before["services"],after["services"]
    need({k:v for k,v in old_services.items() if k!=pipe}==
         {k:v for k,v in new_services.items() if k!=pipe},
         "native_unrelated_service_changed")
    expected=PIPE.decode("ascii").split()
    need(new_services.get(pipe)==expected and
         (pipe not in old_services or old_services[pipe]==expected),
         "native_pipe_not_exact")


def native_candidate_validation(raw,candidate,snapshot=native_snapshot):
    """Private alternate-config postconf only; never call postfix check/start."""
    try:
        E.trusted_directory(Path("/run"))
        live=snapshot(ROOT)
        need(config_bytes()==raw,"live_configuration_changed")
        with tempfile.TemporaryDirectory(prefix="lmr365-primary-native-",dir="/run") as work:
            directory=Path(work)
            E.trusted_directory(directory)
            need(stat.S_IMODE(directory.stat().st_mode)==0o700,"native_stage_not_private")
            for index,blob in enumerate((raw,candidate)):
                for name,data in zip(("main.cf","master.cf"),blob):
                    if index==0:
                        fd=os.open(str(directory/name),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                        with os.fdopen(fd,"wb") as stream:
                            stream.write(data)
                    else:
                        # Only overwrite the two files in our private scratch directory.
                        with (directory/name).open("wb") as stream:
                            stream.write(data)
                sampled=snapshot(directory)
                if index==0:
                    baseline=sampled
                    need(baseline==live,"alternate_config_baseline_differs")
                else:
                    compare_native_candidate(baseline,sampled)
                    checked=sampled
            need(config_bytes()==raw and snapshot(ROOT)==live and config_bytes()==raw,
                 "live_configuration_changed_during_native_review")
            return "verified",E.digest(encode({"before":live,"after":checked}))
    except (E.Refused,OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired):
        # Never emit native output: main.cf may contain sensitive values.
        return "review_required",""


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


def identity_snapshot(mailbox):
    path=ROOT/"m365-oauth"/"app.json"
    if not os.path.lexists(str(path)):
        return ("absent","","")
    try:
        item=E.active_inventory("primary")
        need(SHA.fullmatch(item["identity_sha"]) and SHA.fullmatch(item["certificate_sha"]),
             "invalid_identity_digest")
    except (E.Refused,OSError,KeyError,ValueError,TypeError,UnicodeError):
        return ("unverified","","")
    return ("mailbox_matches" if item["mailbox"]==mailbox else "different_mailbox",
            item["identity_sha"],item["certificate_sha"])


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
    return dict(scope=scope,route="review_required" if scope!="primary_only" or conflicts else "configured" if expected else "migration_candidate",
                override_status="present" if conflicts else "absent",
                local_classes="configured" if any(values[k] for k in
                    ("mydestination","virtual_alias_domains","virtual_mailbox_domains")) else "not_declared")


def inspect(req):
    first=sample()
    route=classify(first)
    ident=identity_snapshot(req["mailbox"])
    raw=config_bytes()
    candidate=candidate_evidence(raw,first,req["mailbox"],ident)
    native_status,native_sha="not_attempted",""
    if candidate["candidate_status"]!="review_required":
        proposed,_=candidate_configs(raw,first)
        native_status,native_sha=native_candidate_validation(raw,proposed)
        if native_status=="verified":
            candidate["plan_sha256"]=E.digest(encode({
                "structural_plan":candidate["plan_sha256"],"native_sha256":native_sha}))
    active=command("systemctl",("is-active","--quiet","postfix"))
    try:
        queue=command("postqueue",("-c",str(ROOT),"-j"))
        queue_status="unverified" if queue.returncode else "nonempty" if queue.stdout.strip() else "empty"
    except (E.Refused,OSError,subprocess.TimeoutExpired):
        queue_status="unverified"
    need(sample()==first and identity_snapshot(req["mailbox"])==ident,"configuration_changed")
    return dict(version=3,nonce=req["nonce"],mailbox=req["mailbox"],config_sha256=first[0],
        native_validation=native_status,native_sha256=native_sha,
        identity=ident[0],service="active" if active.returncode==0 else "unverified",
        queue=queue_status,changes=False,mail_sent=False,apply_supported=False,
        local_delivery_changed=False,listener_changed=False,**route,**candidate)


def validate_apply_preconditions(report, expected_plan):
    """Read-only gate for a future transaction; not authorization to write."""
    need(isinstance(expected_plan,str) and SHA.fullmatch(expected_plan),
         "invalid_reviewed_plan")
    need(report["plan_sha256"]==expected_plan,"stale_reviewed_plan")
    need(report["scope"]=="primary_only" and report["route"]!="review_required" and
         report["candidate_status"]=="ready","migration_not_ready")
    need(report.get("native_validation")=="verified" and
         SHA.fullmatch(report.get("native_sha256","")),"native_candidate_not_verified")
    need(report["identity"]=="mailbox_matches","identity_not_ready")
    need(report["service"]=="active","service_not_ready")
    need(report["queue"]=="empty","queue_not_empty_or_unverified")


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
