"""Read-only systemd installation preview for managed SMTP TLS."""
import hashlib
import os
import stat
from pathlib import Path

UNITS=("linuxmailrelay365-smtp-acme-renew.service",
       "linuxmailrelay365-smtp-acme-renew.timer",
       "linuxmailrelay365-smtp-tls-initial-recovery.service",
       "linuxmailrelay365-smtp-tls-prestart.service",
       "linuxmailrelay365-smtp-tls-recovery.service")

def preview(source,target=Path("/etc/systemd/system")):
    source,target=Path(source),Path(target)
    result=[]
    for name in UNITS:
        src=source/name
        st=src.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_size>65536:
            raise ValueError("invalid packaged unit: "+name)
        data=src.read_bytes()
        dst=target/name
        status="create"
        if os.path.lexists(str(dst)):
            st=dst.lstat()
            status="conflict"
            if stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022 and st.st_size<=65536:
                if dst.read_bytes()==data:
                    status="unchanged"
        result.append(dict(name=name,status=status,sha256=hashlib.sha256(data).hexdigest()))
    return dict(units=result,conflict=any(x["status"]=="conflict" for x in result),
                apply_supported=False)
