#!/usr/bin/env python3
"""Run the shipped certificate importer without installing privileged helpers.

Only public Python source arrives in argv. The certificate package is received
by the existing importer on stdin, unchanged.
"""
import base64
import json
import os
import re
import runpy
import stat
import sys
import tempfile
from pathlib import Path

FILES = ("check-smtp-relay-certificate.py",
         "stage-smtp-relay-certificate.py",
         "receive-smtp-certificate-import.py")


def run_bundle(args, parent):
    if len(args) != 4 or not re.fullmatch(r"--domain=[A-Za-z0-9.-]{1,253}", args[0]):
        raise ValueError("invalid import arguments")
    if any(not item or len(item) > 65536 for item in args[1:]):
        raise ValueError("invalid helper size")
    sources = [base64.b64decode(item, validate=True) for item in args[1:]]
    if any(not source for source in sources):
        raise ValueError("empty helper")
    # Only helper sources, not the secret package, are written here.
    with tempfile.TemporaryDirectory(prefix="lmr365-cert-import-", dir=parent) as directory:
        for name, source in zip(FILES, sources):
            path = Path(directory) / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(source)
        old_argv = sys.argv
        try:
            receiver = str(Path(directory) / FILES[-1])
            sys.argv = [receiver, args[0]]
            runpy.run_path(receiver, run_name="__main__")
        finally:
            sys.argv = old_argv


def main():
    try:
        if os.geteuid() != 0:
            raise ValueError("root required")
        parent = Path("/run")
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("unsafe runtime directory")
        os.umask(0o077)
        run_bundle(sys.argv[1:], parent)
    except Exception:
        print(json.dumps({"status": "refused", "apply_supported": False}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
