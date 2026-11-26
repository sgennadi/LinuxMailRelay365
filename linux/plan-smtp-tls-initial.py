#!/usr/bin/env python3
"""Read-only initial managed SMTP TLS configuration preflight."""
import importlib.util
import json
from pathlib import Path

def plan(read, overrides):
    if read("config_directory")!="/etc/postfix":
        raise ValueError("unsupported configuration directory")
    if read("multi_instance_directories"):
        raise ValueError("multi-instance configuration")
    if any("/smtp_tls_" in line or "/smtp_use_tls" in line or "/smtp_enforce_tls" in line
           for line in overrides.splitlines()):
        raise ValueError("service-specific TLS settings")
    expected="/etc/postfix/lmr365-smtp-tls/active/client-chain.pem"
    current=read("smtp_tls_chain_files")
    if current and current!=expected:
        raise ValueError("existing TLS chain requires manual review")
    for key in ("smtp_tls_cert_file","smtp_tls_key_file","smtp_tls_dcert_file",
                "smtp_tls_dkey_file","smtp_tls_eccert_file","smtp_tls_eckey_file"):
        if read(key):
            raise ValueError("existing SMTP client TLS identity requires manual review")
    return {"status":"candidate","postfix_version":read("mail_version"),
            "changes":{} if current==expected else {"smtp_tls_chain_files":expected},
            "tls_security_level":read("smtp_tls_security_level"),
            "apply_supported":False}

def main():
    spec=importlib.util.spec_from_file_location("adapter",str(Path(__file__).with_name("smtp-tls-postfix.py")))
    adapter=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    try:
        postfix=adapter.Postfix()
        def read(key):
            return postfix.run(postfix.postconf,"-h",key)
        print(json.dumps(plan(read,postfix.run(postfix.postconf,"-P"))))
        return 0
    except (ValueError,RuntimeError,OSError) as exc:
        print(json.dumps({"status":"refused","reason":str(exc),"apply_supported":False}))
        return 1

if __name__=="__main__":
    raise SystemExit(main())
