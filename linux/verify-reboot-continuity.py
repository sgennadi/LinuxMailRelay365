#!/usr/bin/env python3
"""Local service continuity across a REAL Linux reboot; no mail is sent.

Record a root-only baseline before shutdown, then verify *after* reboot.
Always checks the kernel boot ID changed; a systemctl restart alone cannot
pass. The baseline contains ONLY SHA-256 of Postfix configs and service
presence, not credentials, addresses, mail contents, or TLS private keys.
Python 3.6+ (RHEL/Oracle Linux 8). Does not reboot or modify an MTA.
"""
import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

DIR=Path("/var/lib/linuxmailrelay365-reboot-check")
BASE=DIR/"baseline.json"
POSTFIX=Path("/etc/postfix")
SIDE=Path("/etc/linuxmailrelay365/sidecar-postfix")
AUTH=Path("/etc/linuxmailrelay365/smtp-auth")
BOOTID=Path("/proc/sys/kernel/random/boot_id")
SOCKET=Path("/var/spool/linuxmailrelay365-sidecar/private/auth")


def digest(path):
    item=path.lstat()
    if not stat.S_ISREG(item.st_mode) or item.st_size>2*1024*1024:
        raise ValueError("unsafe_config_file")
    val=hashlib.sha256()
    with path.open("rb") as fd:
        for chunk in iter(lambda:fd.read(32768),b""):
            val.update(chunk)
    return val.hexdigest()


def status(unit):
    try:
        p=subprocess.run(["systemctl","is-active","--quiet",unit],
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
        return p.returncode==0
    except (OSError,subprocess.TimeoutExpired):
        return False


def snapshot(port):
    if os.geteuid()!=0:
        raise ValueError("root_required")
    if (SIDE/"smtp-port").read_text(encoding="ascii").strip()!=str(port):
        raise ValueError("installed_custom_port_mismatch")
    boot=BOOTID.read_text(encoding="ascii").strip()
    if len(boot)!=36 or boot.count("-")!=4:
        raise ValueError("unrecognized_kernel_boot_id")
    if not status("linuxmailrelay365-sidecar.service"):
        raise ValueError("isolated_postfix_not_active")
    auth=AUTH.is_dir()
    if auth and (not status("linuxmailrelay365-smtp-auth.service") or not SOCKET.is_socket()):
        raise ValueError("isolated_smtp_auth_not_ready")
    return {
        "version":1,
        "port":port,
        "boot_id":boot,
        "auth":auth,
        "primary_main_sha256":digest(POSTFIX/"main.cf"),
        "primary_master_sha256":digest(POSTFIX/"master.cf"),
        "sidecar_main_sha256":digest(SIDE/"main.cf"),
        "sidecar_master_sha256":digest(SIDE/"master.cf")
    }


def compare(before,after):
    if before.get("version")!=1 or before.get("port")!=after.get("port"):
        return "invalid_or_mismatched_baseline"
    if before.get("boot_id")==after.get("boot_id"):
        return "no_actual_reboot_detected"
    for name in ("primary_main_sha256","primary_master_sha256",
                 "sidecar_main_sha256","sidecar_master_sha256","auth"):
        if before.get(name)!=after.get(name):
            return "configuration_or_service_mode_changed"
    return "local_services_continuity_verified"


def main():
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument("--record-baseline",action="store_true")
    group.add_argument("--verify-after-reboot",action="store_true")
    p.add_argument("--smtp-port",type=int,required=True)
    args=p.parse_args()
    if not 1024<=args.smtp_port<=65535:
        p.error("custom SMTP port must be 1024-65535")
    try:
        if args.record_baseline:
            state=snapshot(args.smtp_port)
            if DIR.is_symlink() or BASE.exists() or BASE.is_symlink():
                raise ValueError("baseline_already_exists_or_directory_symlink")
            DIR.mkdir(mode=0o700,parents=True,exist_ok=True)
            info=DIR.lstat()
            if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
                raise ValueError("baseline_directory_must_be_root_0700")
            fd,name=tempfile.mkstemp(prefix=".pending.",dir=str(DIR))
            try:
                with os.fdopen(fd,"w",encoding="ascii") as target:
                    json.dump(state,target,sort_keys=True)
                    target.flush()
                    os.fsync(target.fileno())
                os.chmod(name,0o600)
                if BASE.exists():
                    raise ValueError("baseline_exists")
                os.rename(name,str(BASE))
            finally:
                if os.path.exists(name):
                    os.unlink(name)
            result="baseline_recorded_requires_real_reboot"
        else:
            info=BASE.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
                raise ValueError("untrusted_baseline")
            before=json.loads(BASE.read_text(encoding="ascii"))
            after=snapshot(args.smtp_port)
            result=compare(before,after)
        print("REBOOT_CONTINUITY_REPORT_VERSION=1")
        print("CUSTOM_SMTP_PORT={}".format(args.smtp_port))
        print("REBOOT_CONTINUITY_RESULT={}".format(result))
        print("REBOOT_MICROSOFT365_DELIVERY_VERIFIED=no")
        print("REBOOT_EXTERNAL_TLS_CLIENTS_VERIFIED=no")
        print("REBOOT_CONFIG_CHANGED=no" if result=="local_services_continuity_verified" else
              "REBOOT_CONFIG_CHANGED=not_verified")
        return 0 if result in ("baseline_recorded_requires_real_reboot",
                               "local_services_continuity_verified") else 2
    except (OSError,ValueError,TypeError) as error:
        print("REBOOT_CONTINUITY_REPORT_VERSION=1")
        print("REBOOT_CONTINUITY_RESULT=manual_review_required")
        print("REBOOT_CONTINUITY_ERROR={}".format(str(error)[:75]))
        return 2


if __name__=="__main__":
    sys.exit(main())
