#!/usr/bin/env python3
"""Real packaged Postfix dictionary compilation, no active map installation."""
import hashlib
import importlib.util
import os
import pathlib
import tempfile

if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("Disposable root CI only")
ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "conditional_maps", str(ROOT / "linux/stage-conditional-postfix-maps.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
os.umask(0o077)
protected = [pathlib.Path("/etc/postfix/main.cf"), pathlib.Path("/etc/postfix/master.cf")]
before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in protected]

with tempfile.TemporaryDirectory(prefix="lmr365-native-map-smoke-", dir="/var/lib") as temp:
    fd = os.open(temp, m.DIR_FLAGS)
    try:
        for kind, keys in (
            ("exact-envelope-sender", ["alpha@example.org", "beta@example.org"]),
            ("envelope-sender-domain", ["example.org", "other.example.org"]),
            ("recipient-domain", ["example.org", "other.example.net"]),
        ):
            rules = [dict(selector=kind, pattern=key, host="relay.example.net",
                          port=port, tls="starttls", auth="none")
                     for key, port in zip(keys, (25, 46500))]
            sha, _ = m.build(rules)
            _, stage_sha = m.stage(fd, rules, sha, "STAGE_CONDITIONAL_MAPS_ONLY", 0)
            receipt = m.compile_stage(fd, sha, stage_sha,
                                      "COMPILE_CONDITIONAL_MAPS_ONLY", 0, temp)
            assert receipt[2] in ("hash", "lmdb") and receipt[3] == 2
            assert m.verify_compiled(fd, sha, 0, temp) == receipt
            print("NATIVE_CONDITIONAL_MAP=" + kind + "; backend=" + receipt[2] + "; PASS")
    finally:
        os.close(fd)

assert before == [hashlib.sha256(path.read_bytes()).hexdigest() for path in protected]
print("NATIVE_CONDITIONAL_MAP_COMPILE_AND_QUERY=PASS_NO_ACTIVE_CONFIG_CHANGE")
