#!/usr/bin/env python3
"""Bounded read-only lookup of an installed Postfix configuration, Python 3.6+.

Queries private copies of allowlisted local indexed routing maps only.
No arbitrary dictionary backends, credential maps, SMTP, reload or Apply.
The result is a configuration candidate, not proof of a real delivery.
"""
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

_spec = importlib.util.spec_from_file_location(
    "public_oauth_support", str(Path(__file__).with_name("export-hardware-oauth-cert.py")))
E = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(E)
ROOTS = E.POSTFIX_CONFIGS
Refused = E.Refused
MAPS = ("transport_maps", "sender_dependent_default_transport_maps",
        "sender_dependent_relayhost_maps")
CLASSES = (("mydestination", "local"), ("virtual_alias_domains", "virtual_alias"),
           ("virtual_mailbox_domains", "virtual_mailbox"), ("relay_domains", "relay"))
REWRITES = ("canonical_maps", "sender_canonical_maps", "recipient_canonical_maps",
            "virtual_alias_maps", "masquerade_domains", "relocated_maps",
            "content_filter", "header_checks", "body_checks", "mime_header_checks",
            "nested_header_checks", "smtp_generic_maps", "smtpd_milters",
            "non_smtpd_milters", "multi_instance_directories")
KEYS = tuple(sorted(set(MAPS + tuple(k for k, _ in CLASSES) + REWRITES + (
    "default_transport", "relay_transport", "local_transport", "virtual_transport",
    "relayhost", "recipient_delimiter", "parent_domain_matches_subdomains"))))
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN = re.compile(LABEL + r"(?:\." + LABEL + r")*\Z")
ADDRESS = re.compile(r"[a-z0-9][a-z0-9._+%-]{0,62}@"+LABEL+r"(?:\."+LABEL+r")+\Z")
MAP_NAME = {
    MAPS[0]: re.compile(r"(?:transport|lmr365-[a-f0-9]{64}-recipient-transport)\Z"),
    MAPS[1]: re.compile(r"(?:sender_transport|sender_dependent_default_transport|lmr365-[a-f0-9]{64}-sender-transport)\Z"),
    MAPS[2]: re.compile(r"(?:sender_relay|sender_relayhost|sender_dependent_relayhost|lmr365-conditional-[a-f0-9]{64}-sender)\Z"),
}
SUFFIX = {"hash": ".db", "lmdb": ".lmdb"}
MAX_DB = 4 * 1024 * 1024
ENV = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


def need(ok, code):
    if not ok:
        raise Refused(code)


def address(value):
    need(isinstance(value, str) and len(value) <= 254 and value == value.lower()
         and ADDRESS.fullmatch(value) and ".." not in value, "invalid_address")
    return value


def unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate_request_property")
        out[key] = value
    return out


def request(raw):
    need(1 <= len(raw) <= 4096, "invalid_request_size")
    obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    need(isinstance(obj, dict) and set(obj) == {"target", "sender", "recipient", "nonce"},
         "invalid_request_fields")
    need(obj["target"] in ROOTS and isinstance(obj["nonce"], str)
         and E.SHA.fullmatch(obj["nonce"]), "invalid_request_context")
    address(obj["sender"])
    address(obj["recipient"])
    return obj


def native(name, args):
    need(name in ("postconf", "postmap"), "invalid_tool")
    binary = Path("/usr/sbin") / name
    resolved = binary.resolve(strict=True)
    E.trusted_directory(resolved.parent)
    st = resolved.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
         and st.st_mode & 0o111, "untrusted_native_tool")
    p = subprocess.run([str(resolved)] + list(args), input=b"", stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=5, check=False, env=ENV)
    need(not p.stderr.strip() and len(p.stdout) <= 131072, "native_readback_failed")
    return p.returncode, p.stdout


def config(root):
    E.trusted_directory(root)
    def stamp():
        return tuple(E.digest(E.secure_read(root / name, 524288,
                     modes=(0o600, 0o640, 0o644))) for name in ("main.cf", "master.cf"))
    before = stamp()
    rc, raw = native("postconf", ["-c", str(root), "-x"] + list(KEYS))
    need(rc == 0, "postconf_failed")
    values = {}
    for line in raw.decode("utf-8", "strict").splitlines():
        key, sep, value = line.partition("=")
        key = key.strip()
        need(sep and key in KEYS and key not in values and len(value) <= 8192
             and not any(ord(c) < 32 and c != "\t" for c in value), "invalid_postconf")
        values[key] = value.strip()
    need(set(values) == set(KEYS), "incomplete_postconf")
    rc, overrides = native("postconf", ["-c", str(root), "-P"])
    need(rc == 0 and stamp() == before, "config_changed")
    return before, values, overrides


def map_spec(root, key, value):
    # Deliberately do not evaluate SQL, LDAP, regexp, proxymap, sockets,
    # lists, macros or arbitrary files (including any SASL credential map).
    if not value:
        return None
    backend, sep, pathname = value.partition(":")
    path = Path(pathname)
    need(sep and backend in SUFFIX and pathname == str(path) and path.parent == root
         and MAP_NAME[key].fullmatch(path.name), "unsupported_map")
    return backend, root / (path.name + SUFFIX[backend])


def snapshot(root, key, value):
    try:
        spec = map_spec(root, key, value)
    except Refused:
        return "unsupported", None, None
    if spec is None:
        return "not_declared", None, None
    backend, path = spec
    try:
        data = E.secure_read(path, MAX_DB, modes=(0o600, 0o640, 0o644))
        return "ready", backend, data
    except (Refused, OSError):
        return "unverified", None, None


def transport_keys(recipient, delimiter, parents):
    user, domain = recipient.rsplit("@", 1)
    keys = [(recipient, "exact")]
    if delimiter:
        positions = [i for i, ch in enumerate(user) if ch in delimiter]
        if positions and min(positions) > 0:
            keys.append((user[:min(positions)] + "@" + domain, "extension"))
    keys.append((domain, "domain"))
    labels = domain.split(".")
    for i in range(1, len(labels)):
        keys.append((("" if parents else ".") + ".".join(labels[i:]), "parent"))
    keys.append(("*", "wildcard"))
    need(len(keys) <= 12, "too_many_lookup_keys")
    return keys


def sender_keys(sender):
    return [(sender, "exact"), ("@" + sender.rsplit("@", 1)[1], "domain")]


def query_copy(work, index, backend, data, keys, runner=native):
    # Never query the original database. LMDB lock files, if any, are
    # confined to our temporary directory, not the live Postfix tree.
    base = work / ("route-" + str(index))
    (work / (base.name + SUFFIX[backend])).write_bytes(data)
    for key, shape in keys:
        rc, raw = runner("postmap", ["-c", str(work), "-q", key, backend + ":" + str(base)])
        if rc == 1 and raw == b"":
            continue
        need(rc == 0 and 0 < len(raw) <= 4096, "invalid_lookup_result")
        value = raw.decode("ascii", "strict").rstrip("\n")
        need(bool(value) and not any(ord(ch) < 32 or ord(ch) > 126 for ch in value),
             "invalid_lookup_value")
        return "matched_" + shape, value
    return "no_match", None


def literal_class(domain, values):
    parent_features = set(re.split(r"[\s,]+", values["parent_domain_matches_subdomains"]))
    matches = []
    for key, cls in CLASSES:
        tokens = [s.lower() for s in re.split(r"[\s,]+", values[key]) if s]
        for token in tokens:
            base = token.lstrip(".")
            if not DOMAIN.fullmatch(base) or token not in (base, "." + base):
                return "unknown"
            if domain == token or (domain.endswith("." + base)
                and (token.startswith(".") or key in parent_features)):
                matches.append(cls)
    return matches[0] if len(set(matches)) == 1 else "default" if not matches else "unknown"


def endpoint(value):
    # Only a single literal DNS name/IPv4 with optional numeric port.
    # Never return an arbitrary map value, URI, username or credentials.
    m = re.fullmatch(r"(\[([a-z0-9.-]+)\]|([a-z0-9.-]+))(?::([0-9]{1,5}))?", value.lower())
    if not m:
        return None
    host = m.group(2) or m.group(3)
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if not DOMAIN.fullmatch(host) or "." not in host or len(host) > 253:
            return None
    port = int(m.group(4) or 25)
    if not 1 <= port <= 65535:
        return None
    shown = ("[" + host + "]" if m.group(2) else host) + ":" + str(port)
    kind = ("smtp_m365_eop" if host.endswith(".mail.protection.outlook.com") and port == 25
            else "smtp_m365_submission" if host == "smtp.office365.com" and port == 587
            else "smtp_other")
    return kind, shown


def classify(values, cls, evidence, overrides):
    unknown = ("unknown", "unknown", "")
    if cls == "unknown" or any(v[0] in ("unsupported", "unverified", "ready") for v in evidence):
        return unknown
    if overrides.strip() or any(values[k] for k in REWRITES):
        return unknown
    transport, sender_transport, sender_relay = [v[1] for v in evidence]
    if transport is not None:
        # Null transport/nexthop has special semantics; refuse incomplete
        # matches rather than guess at the destination.
        source = "transport_maps"
        selected = transport
        if ":" not in selected or selected.startswith(":"):
            return unknown
    elif cls == "virtual_alias":
        return unknown
    elif cls in ("local", "virtual_mailbox", "relay"):
        source = {"local": "local_transport", "virtual_mailbox": "virtual_transport",
                  "relay": "relay_transport"}[cls]
        selected = values[source]
    elif sender_transport is not None and sender_transport.upper() != "DUNNO":
        source, selected = "sender_transport_map", sender_transport
    else:
        source, selected = "default_transport", values["default_transport"]
    service, colon, hop = selected.partition(":")
    if service == "m365xoauth2" and not hop:
        return source, "oauth_pipe", ""
    if service in ("local", "virtual", "error", "discard"):
        return source, service, ""
    if service not in ("smtp", "relay"):
        return (source, "custom_transport", "") if re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", service) else unknown
    if source == "transport_maps" and not hop:
        return unknown
    if not hop:
        if cls in ("local", "virtual_mailbox"):
            return unknown
        if sender_relay is not None and sender_relay.upper() != "DUNNO":
            hop = sender_relay
            source = "sender_relay_map"
        elif values["relayhost"]:
            hop = values["relayhost"]
            source = "relayhost"
        else:
            return source, "smtp_dns", ""
    parsed = endpoint(hop)
    return (source, parsed[0], parsed[1]) if parsed else unknown


def inspect(req):
    root = ROOTS[req["target"]]
    first = config(root)
    _, values, overrides = first
    snapshots = [snapshot(root, k, values[k]) for k in MAPS]
    evidence = [(state, None) for state, _, _ in snapshots]
    with tempfile.TemporaryDirectory(prefix="lmr365-route-read-") as folder:
        work = Path(folder)
        (work / "main.cf").write_text("myhostname = route-audit.example.invalid\n"
                                     "mydomain = example.invalid\n", encoding="ascii")
        (work / "master.cf").write_text("# read-only native map queries\n", encoding="ascii")
        parents = "transport_maps" in re.split(r"[\s,]+", values["parent_domain_matches_subdomains"])
        delimiter = values["recipient_delimiter"]
        need(len(delimiter) <= 16 and not any(ch.isspace() for ch in delimiter), "delimiter_unknown")
        keys = [transport_keys(req["recipient"], delimiter, parents),
                sender_keys(req["sender"]), sender_keys(req["sender"])]
        for i, (state, backend, data) in enumerate(snapshots):
            if state != "ready":
                continue
            try:
                evidence[i] = query_copy(work, i, backend, data, keys[i])
            except (Refused, OSError, UnicodeError, subprocess.TimeoutExpired):
                evidence[i] = ("unverified", None)
    # Drift includes DB bytes, main.cf/master.cf and expanded settings.
    need(config(root) == first and
         [snapshot(root, k, values[k]) for k in MAPS] == snapshots, "configuration_drift")
    cls = literal_class(req["recipient"].rsplit("@", 1)[1], values)
    source, route, hop = classify(values, cls, evidence, overrides)
    return dict(address_class=cls, transport_lookup=evidence[0][0],
                sender_transport_lookup=evidence[1][0], sender_relay_lookup=evidence[2][0],
                source=source, route=route, endpoint=hop,
                rewriting_or_overrides="declared" if overrides.strip() or any(values[k] for k in REWRITES) else "absent",
                status="candidate" if route != "unknown" else "review")


def main():
    raw = sys.stdin.buffer.read(4097)
    try:
        need(os.geteuid() == 0, "root_required")
        req = request(raw)
    except (Refused, ValueError, TypeError, UnicodeError):
        print("POSTFIX_ROUTE_ERROR=invalid_request")
        return 2
    try:
        result = inspect(req)
    except (Refused, OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        result = dict(address_class="unknown", transport_lookup="unverified",
            sender_transport_lookup="unverified", sender_relay_lookup="unverified",
            source="unknown", route="unknown", endpoint="", rewriting_or_overrides="unverified",
            status="unverified")
    result.update(version=1, target=req["target"], nonce=req["nonce"],
                  request_sha256=hashlib.sha256(raw).hexdigest(), changes=False, mail_sent=False)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
