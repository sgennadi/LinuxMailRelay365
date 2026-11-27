#!/usr/bin/env python3
"""Read-only Certbot readiness; no hooks, renewal, or DNS credential-file reads."""
import json
import os
import re
import stat
import subprocess
from pathlib import Path

ROOT = Path("/etc/letsencrypt/renewal")
MANAGED_ROOT = Path("/var/lib/linuxmailrelay365/smtp-acme/config/renewal")
PROFILE = Path("/etc/postfix/lmr365-smtp-tls/renewal-profile.json")
SAFE_DNS = {"dns-azure", "dns-cloudflare", "dns-route53", "dns-google", "dns-rfc2136"}
UNITS = ("certbot.timer", "certbot-renew.timer", "snap.certbot.renew.timer",
         "linuxmailrelay365-smtp-acme-renew.timer", "linuxmailrelay365-smtp-acme-renew.service")
PROPERTIES = {"LoadState", "ActiveState", "UnitFileState", "Result"}


def inspect_config(text):
    section = False
    seen_section = False
    values = {}
    hooks = False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line == "[renewalparams]"
            if section and seen_section:
                return "ambiguous", None
            seen_section |= section
            continue
        if "=" not in line:
            continue
        key, value = map(str.strip, line.split("=", 1))
        if "hook" in key.lower():
            hooks = True
        if section:
            if key in values:
                return "ambiguous", None
            values[key] = value if key == "authenticator" else ""
    auth = values.get("authenticator", "")
    if auth == "manual":
        mode = "manual_hook_unverified" if hooks else "manual"
    elif auth in SAFE_DNS:
        mode = "dns_plugin_configured"
    elif auth in ("webroot", "standalone", "nginx", "apache"):
        mode = "http_validation_configured"
    else:
        mode = "unknown"
    return mode, hooks


def classify(text):
    return inspect_config(text)[0]


def trusted_directory(path):
    if not path.is_absolute():
        raise ValueError("absolute path required")
    for parent in reversed([path, *path.parents]):
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("untrusted directory")


def read_config(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or st.st_size > 65536:
            raise ValueError("untrusted config")
        raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("config too large")
        return raw.decode("utf-8")


def inventory_scope(root, scope):
    rows = []
    try:
        trusted_directory(root)
        truncated = False
        with os.scandir(root) as entries:
            for index, entry in enumerate(entries):
                if index >= 4096 or len(rows) >= 128:
                    truncated = True
                    break
                if not entry.name.endswith(".conf"):
                    continue
                name = entry.name[:-5]
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", name) or ".." in name:
                    continue
                try:
                    mode, hooks = inspect_config(read_config(root / entry.name))
                except (OSError, ValueError):
                    mode, hooks = "unverified", None
                rows.append({"lineage": name, "scope": scope, "renewal_method": mode,
                             "configured_hooks_detected": hooks, "renewal_test": "not_run"})
        return ("truncated" if truncated else "present"), sorted(rows, key=lambda row: row["lineage"])
    except FileNotFoundError:
        return "absent", []
    except (OSError, ValueError):
        return "unverified", []


def profile_state(path):
    try:
        trusted_directory(path.parent)
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077 or st.st_size > 16384:
            return "unverified"
        return "protected_file_present_unvalidated"
    except FileNotFoundError:
        return "absent"
    except (OSError, ValueError):
        return "unverified"


def timer_state():
    result = {}
    for unit in UNITS:
        try:
            p = subprocess.run(["/usr/bin/systemctl", "show", unit,
                "--property=LoadState,ActiveState,UnitFileState,Result"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            fields = {}
            if p.returncode == 0 and len(p.stdout) <= 4096:
                for line in p.stdout.decode("ascii", "replace").splitlines():
                    key, sep, value = line.partition("=")
                    if sep and key in PROPERTIES and re.fullmatch(r"[a-z0-9-]{1,40}", value):
                        fields[key] = value
            result[unit] = fields
        except (OSError, ValueError, subprocess.SubprocessError):
            result[unit] = {}
    return result


def inventory():
    standard, rows = inventory_scope(ROOT, "system")
    managed, managed_rows = inventory_scope(MANAGED_ROOT, "managed")
    return {"version": 2, "status": "read_only_inventory",
            "lineages": rows + managed_rows, "timers": timer_state(),
            "system_config": standard, "managed_config": managed,
            "managed_profile": profile_state(PROFILE),
            "automatic_renewal_verified": False, "activation_supported_by_inspector": False}


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("root required")
    print(json.dumps(inventory()))
