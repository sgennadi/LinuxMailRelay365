#!/usr/bin/env python3
"""Read-only TPM capability discovery; never provision keys."""
import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path

def main():
    spec=importlib.util.spec_from_file_location("postfix",str(Path(__file__).resolve().with_name("smtp-tls-postfix.py")))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    report=dict(version=1,devices=[],tools={},tpm2_verified=False,postfix_tpm_verified=False,protection_available=False)
    for path in ("/dev/tpmrm0","/dev/tpm0"):
        try:
            if stat.S_ISCHR(os.stat(path).st_mode):
                report["devices"].append(path)
        except OSError:
            pass
    env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"}
    for name in ("tpm2_getcap","openssl"):
        try:
            binary=m.trusted_binary("/usr/bin/"+name)
            report["tools"][name]=True
            if name=="tpm2_getcap" and "/dev/tpmrm0" in report["devices"]:
                r=subprocess.run([binary,"-T","device:/dev/tpmrm0","properties-fixed"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,env=env)
                report["tpm2_verified"]=r.returncode==0 and b"TPM2_PT_FAMILY_INDICATOR" in r.stdout
            if name=="openssl":
                r=subprocess.run([binary,"list","-providers"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,env=env)
                report["openssl_provider_listing_available"]=r.returncode==0
        except Exception:
            report["tools"].setdefault(name,False)
    print(json.dumps(report,sort_keys=True))
if __name__=="__main__":
    main()
