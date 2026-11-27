"""Local credential-file preflight; does not claim DNS API authorization."""
import os
import stat
import json
import configparser
from pathlib import Path

def inspect(provider,path):
    path=Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute path required")
    for parent in path.parents:
        st=parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise ValueError("unsafe credential directory")
    fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o7077:
            raise ValueError("unsafe credential file")
        raw=f.read(65537)
    if not raw or len(raw)>65536:
        raise ValueError("invalid credential size")
    data=raw.decode("utf-8")
    if provider=="dns-google":
        obj=json.loads(data)
        if not isinstance(obj,dict) or obj.get("type")!="service_account" or not all(isinstance(obj.get(k),str) and obj[k].strip() for k in ("client_email","private_key","project_id")):
            raise ValueError("invalid service account structure")
    elif provider in ("dns-cloudflare","dns-rfc2136","dns-azure","dns-route53"):
        cfg=configparser.ConfigParser(interpolation=None)
        cfg.read_string(data if provider=="dns-route53" else "[credentials]\n"+data)
        section=cfg["default" if provider=="dns-route53" else "credentials"]
        required={"dns-route53":("aws_access_key_id","aws_secret_access_key"),"dns-rfc2136":("dns_rfc2136_server","dns_rfc2136_name","dns_rfc2136_secret","dns_rfc2136_algorithm")}.get(provider,())
        if any(not section.get(k,"").strip() for k in required):
            raise ValueError("required credential fields missing")
        if provider=="dns-cloudflare" and not (section.get("dns_cloudflare_api_token") or (section.get("dns_cloudflare_email") and section.get("dns_cloudflare_api_key"))):
            raise ValueError("Cloudflare credentials missing")
        if provider=="dns-azure" and not any(k.startswith("dns_azure_") for k in section):
            raise ValueError("Azure configuration missing")
    else:
        raise ValueError("unsupported provider")
    return dict(file_preflight_passed=True,api_permissions_verified=False)
