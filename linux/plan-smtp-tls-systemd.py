"""Read-only systemd installation preview for managed SMTP TLS."""
import hashlib
import os
import stat
from pathlib import Path

UNITS=("linuxmailrelay365-smtp-acme-renew.service",
       "linuxmailrelay365-smtp-acme-renew.timer",
       "linuxmailrelay365-smtp-tls-initial-recovery.service",
       "linuxmailrelay365-smtp-tls-prestart.service",
       "linuxmailrelay365-smtp-tls-recovery.service",
       "linuxmailrelay365-smtp-tls-health.service",
       "linuxmailrelay365-smtp-tls-health.timer")

def preview(source,target=Path("/etc/systemd/system"),allow_missing_health=False):
    source,target=Path(source),Path(target)
    result=[]
    for name in UNITS:
        src=source/name
        if allow_missing_health and "-health." in name and not os.path.lexists(str(src)):
            result.append(dict(name=name,status="absent",sha256=None))
            continue
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


def preview_uninstall(source,target=Path("/etc/systemd/system")):
    installed=preview(source,target)
    states={"create":"absent","unchanged":"remove","conflict":"preserve"}
    units=[dict(name=u["name"],status=states[u["status"]],sha256=u["sha256"]) for u in installed["units"]]
    return dict(units=units,conflict=installed["conflict"],apply_supported=False,
                requires_disabled_timer=True,requires_inactive_renewal=True,
                preserves_certificates=True,preserves_postfix_configuration=True)


def preview_update(source,previous,target=Path("/etc/systemd/system")):
    new=preview(source,target)
    old=preview(previous,target,allow_missing_health=True)
    prior={u["name"]:u for u in old["units"]}
    units=[]
    for u in new["units"]:
        before=prior[u["name"]]
        status=u["status"]
        if status=="conflict" and before["status"]=="unchanged":
            status="update"
        units.append(dict(name=u["name"],status=status,sha256=u["sha256"],previous_sha256=before["sha256"]))
    return dict(units=units,conflict=any(u["status"]=="conflict" for u in units),apply_supported=False)
