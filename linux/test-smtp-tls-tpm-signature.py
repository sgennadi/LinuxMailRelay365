#!/usr/bin/env python3
"""Explicit transient TPM provider signing test, not Postfix qualification."""
import argparse
import importlib.util
import json
import os
import subprocess
import tempfile
from pathlib import Path

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--confirm",required=True)
    a=p.parse_args()
    if os.geteuid()!=0 or a.confirm!="TEST_TRANSIENT_TPM_KEY":
        p.error("root and explicit confirmation required")
    report=dict(version=1,status="failed",signature_verified=False,postfix_tpm_verified=False)
    try:
        spec=importlib.util.spec_from_file_location("postfix",str(Path(__file__).resolve().with_name("smtp-tls-postfix.py")))
        m=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        binary=m.trusted_binary("/usr/bin/openssl")
        if not Path("/dev/tpmrm0").exists():
            raise ValueError("TPM resource manager required")
        env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","TPM2OPENSSL_TCTI":"device:/dev/tpmrm0"}
        os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix="lmr365-tpm-",dir="/var/tmp") as tmp:
            root=Path(tmp)
            def run(*args):
                subprocess.check_call([binary]+list(args),cwd=tmp,env=env,timeout=60,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            providers=("-provider","default","-provider","tpm2")
            (root/"message").write_bytes(os.urandom(32))
            run("genpkey",*providers,"-propquery","provider=tpm2","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:2048","-out","key.pem")
            run("pkey",*providers,"-in","key.pem","-pubout","-out","public.pem")
            run("dgst",*providers,"-sha256","-sign","key.pem","-out","signature","message")
            run("dgst","-provider","default","-sha256","-verify","public.pem","-signature","signature","message")
            report.update(status="passed",signature_verified=True)
    except Exception:
        pass
    print(json.dumps(report,sort_keys=True))
    return 0 if report["signature_verified"] else 1
if __name__=="__main__":
    raise SystemExit(main())
