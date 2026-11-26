"""Build isolated DNS challenge test commands without activating TLS."""
from pathlib import Path
import importlib.util

def command(provider,name,domain,server,email,credentials,test_root):
    if server!="https://acme-staging-v02.api.letsencrypt.org/directory":
        raise ValueError("unapproved staging endpoint")
    suffix={"dns-azure":"azure","dns-cloudflare":"cloudflare","dns-google":"google","dns-route53":"route53","dns-rfc2136":"rfc2136"}[provider]
    spec=importlib.util.spec_from_file_location("adapter",str(Path(__file__).resolve().with_name("issue-smtp-acme-"+suffix+".py")))
    adapter=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    args=adapter.command(name,domain,server,email,credentials)
    root=Path(test_root)
    if not root.is_absolute():
        raise ValueError("absolute test directory required")
    for flag,folder in (("--config-dir","config"),("--work-dir","work"),("--logs-dir","logs")):
        args[args.index(flag)+1]=str(root/folder)
    args.remove("--keep-until-expiring")
    args.append("--dry-run")
    return args
