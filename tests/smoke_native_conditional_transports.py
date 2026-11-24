#!/usr/bin/env python3
"""Native compilation of dedicated transport services using synthetic accounts."""
import hashlib
import importlib.util
import os
import pathlib

if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("Disposable root CI only")
ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "transport_compiler", str(ROOT / "linux/compile-conditional-transports.py"))
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
os.umask(0o077)
protected = [pathlib.Path("/etc/postfix") / x for x in ("main.cf", "master.cf")]
before = [hashlib.sha256(x.read_bytes()).hexdigest() for x in protected]
rules = [
    dict(selector="exact-envelope-sender", pattern="first@example.org",
         host="relay.example.net", port=587, tls="starttls", auth="password"),
    dict(selector="exact-envelope-sender", pattern="second@example.org",
         host="relay.example.net", port=587, tls="starttls", auth="password"),
    dict(selector="envelope-sender-domain", pattern="other.example.org",
         host="relay.example.net", port=465, tls="implicit", auth="password"),
    dict(selector="exact-envelope-sender", pattern="fourth@example.org",
         host="custom.example.net", port=46500, tls="starttls", auth="none"),
]
request = {"rules": rules, "credentials": [
    {"username": "fixture-a", "password": "synthetic-A"},
    {"username": "fixture-b", "password": "synthetic-B"},
    {"username": "fixture-c", "password": "synthetic-C"}, None]}
_, sha = T.plan(rules)
result = T.compile_profiles(request, sha, T.CONFIRM, 0,
                            T.tmpfs_parent(), T.installed_ca())
assert result[0] == sha and result[1] in ("hash", "lmdb") and result[2:] == (4, 3)
assert before == [hashlib.sha256(x.read_bytes()).hexdigest() for x in protected]
print("NATIVE_DEDICATED_TRANSPORTS_AND_PRIVATE_AUTH_MAPS=PASS")
print("NATIVE_DEDICATED_TRANSPORTS_PRIMARY_CONFIG_UNCHANGED=PASS")
