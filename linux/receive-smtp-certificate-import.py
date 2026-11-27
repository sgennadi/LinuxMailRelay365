#!/usr/bin/env python3
"""Receive a bounded certificate package over stdin; never activate Postfix."""
import base64
import json
import os
import sys
import tempfile
import stat
import argparse
import importlib.util
from pathlib import Path

def receive(stream, root, validate, stage=None):
    if os.geteuid() != 0:
        raise ValueError("root required")
    root = Path(root)
    for parent in reversed(list(root.parents)):
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("unsafe import directory")
    root.mkdir(mode=0o700, exist_ok=True)
    st = root.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise ValueError("private directory required")
    raw = stream.read(6 * 1024 * 1024 + 1)
    if len(raw) > 6 * 1024 * 1024:
        raise ValueError("package too large")
    data = json.loads(raw)
    if set(data) != {"certificate", "chain", "key"}:
        raise ValueError("invalid package")
    files = {}
    for name in ("certificate", "chain", "key"):
        value = base64.b64decode(data[name], validate=True)
        if not value or len(value) > 1024 * 1024:
            raise ValueError("invalid file size")
        files[name] = value
    directory = Path(tempfile.mkdtemp(prefix="import-", dir=str(root)))
    try:
        for name, value in files.items():
            path = directory / (name + ".pem")
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
        report = validate(directory)
        if report.get("status") != "local_checks_passed":
            raise ValueError("certificate validation refused")
        if stage is not None:
            generation = stage(directory)
            for path in directory.iterdir():
                path.unlink()
            directory.rmdir()
            return {"status": "staged_locally_validated", "generation": generation,
                    "exchange_acceptance": "unverified", "apply_supported": False}
        return {"status": "received_locally_validated", "directory": str(directory),
                "exchange_acceptance": "unverified",
                "apply_supported": False}
    except BaseException:
        if directory.exists():
            for path in directory.iterdir():
                path.unlink()
            directory.rmdir()
        raise

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--domain", required=True)
        args = parser.parse_args()
        spec = importlib.util.spec_from_file_location("smtp_cert_check",
            str(Path(__file__).resolve().with_name("check-smtp-relay-certificate.py")))
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        def validate(directory):
            return checker.inspect(str(directory / "certificate.pem"),
                str(directory / "chain.pem"), args.domain, "auto",
                str(directory / "key.pem"))
        stage_spec = importlib.util.spec_from_file_location("smtp_cert_stage",
            str(Path(__file__).resolve().with_name("stage-smtp-relay-certificate.py")))
        stager = importlib.util.module_from_spec(stage_spec)
        stage_spec.loader.exec_module(stager)
        def stage(directory):
            return stager.stage(str(directory / "certificate.pem"),
                str(directory / "chain.pem"), str(directory / "key.pem"),
                args.domain, "auto")
        print(json.dumps(receive(sys.stdin.buffer, "/etc/postfix/lmr365-smtp-tls", validate, stage)))
    except Exception:
        print(json.dumps({"status": "refused", "apply_supported": False}))
        sys.exit(1)
