#!/usr/bin/env python3
"""Receive a bounded certificate package over stdin; never activate Postfix."""
import base64
import json
import os
import sys
import tempfile
import stat
from pathlib import Path

def receive(stream, root):
    if os.geteuid() != 0:
        raise ValueError("root required")
    root = Path(root)
    for parent in [root] + list(root.parents):
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("unsafe import directory")
    if root.stat().st_mode & 0o077:
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
        return {"status": "received_unverified", "directory": str(directory),
                "apply_supported": False}
    except BaseException:
        for path in directory.iterdir():
            path.unlink()
        directory.rmdir()
        raise

if __name__ == "__main__":
    try:
        print(json.dumps(receive(sys.stdin.buffer, "/etc/postfix/lmr365-smtp-tls")))
    except Exception:
        print(json.dumps({"status": "refused", "apply_supported": False}))
        sys.exit(1)
