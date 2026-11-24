#!/usr/bin/env python3
"""Real packaged Postfix dictionary compilation, no active map installation."""
import hashlib
import importlib.util
import os
import pathlib
import subprocess
import tempfile

if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("Disposable root CI only")
ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "conditional_maps", str(ROOT / "linux/stage-conditional-postfix-maps.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
os.umask(0o077)


def ci_native(tool, args, data=None):
    # Real tool output can contain only generated fixture keys/paths here.
    # Never add this verbose runner to production.
    result = subprocess.run([m.trusted_postfix_tool(tool)] + args,
                            input=data if data is not None else b"",
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                 "LC_ALL": "C"}, timeout=15, check=False)
    if result.returncode and not (tool == "postmap" and
            "-q" in args and m.NEGATIVE_KEY in args and result.returncode == 1):
        print("CI_NATIVE_MAP_TOOL_FAILURE=" + tool, flush=True)
        print(result.stderr.decode("utf-8", "replace")[:4000], flush=True)
    return result.returncode, result.stdout


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
                                      "COMPILE_CONDITIONAL_MAPS_ONLY", 0, temp, ci_native)
            assert receipt[2] in ("hash", "lmdb") and receipt[3] == 2
            assert m.verify_compiled(fd, sha, 0, temp, ci_native) == receipt
            print("NATIVE_CONDITIONAL_MAP=" + kind + "; backend=" + receipt[2] + "; PASS")
    finally:
        os.close(fd)

assert before == [hashlib.sha256(path.read_bytes()).hexdigest() for path in protected]
print("NATIVE_CONDITIONAL_MAP_COMPILE_AND_QUERY=PASS_NO_ACTIVE_CONFIG_CHANGE")
