#!/usr/bin/env python3
"""Explicit staging-CA DNS renewal test for one managed SMTP TLS profile.
No production renewal, Postfix activation, hook invocation or reload path.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
from pathlib import Path

STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
PROVIDERS = {"dns-azure": "dns_azure_config",
             "dns-cloudflare": "dns_cloudflare_credentials",
             "dns-google": "dns_google_credentials",
             "dns-rfc2136": "dns_rfc2136_credentials",
             "dns-route53": None}
BASE_KEYS = {"version", "archive_dir", "cert", "privkey", "chain", "fullchain",
             "renew_before_expiry"}
PARAM_KEYS = {"account", "authenticator", "server", "key_type", "rsa_key_size",
              "elliptic_curve", "installer", "pref_challs", "preferred_chain",
              "reuse_key", "renew_before_expiry"}


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_private(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or st.st_mode & 0o077 or st.st_size > limit):
            raise ValueError("unsafe private file")
        data = stream.read(limit + 1)
        if not data or len(data) > limit:
            raise ValueError("invalid file size")
        return data


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def parse_config(text):
    top, params = {}, {}
    current = top
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line == "[renewalparams]" and current is top:
            current = params
            continue
        if line.startswith("["):
            raise ValueError("unsupported config section")
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not key or key in current or "hook" in key.lower():
            raise ValueError("ambiguous config or hooks")
        current[key] = value
    provider = params.get("authenticator")
    if provider not in PROVIDERS or params.get("server") not in (PRODUCTION, STAGING):
        raise ValueError("unsupported DNS plugin or CA")
    credential_key = PROVIDERS[provider]
    allowed = PARAM_KEYS | {provider.replace("-", "_") + "_propagation_seconds"}
    if credential_key:
        allowed.add(credential_key)
        if not params.get(credential_key):
            raise ValueError("credential file required")
    if set(top) - BASE_KEYS or set(params) - allowed:
        raise ValueError("unsupported configuration option")
    if params.get("installer", "None") not in ("None", "none", ""):
        raise ValueError("installer not permitted")
    return top, params, provider


def private_directory(path):
    for item in [path, *path.parents]:
        st = item.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("unsafe directory")
    if path.stat().st_mode & 0o077:
        raise ValueError("private directory required")


def prepare():
    profile = load("smtp-tls-renewal-profile")
    private_directory(profile.PROFILE.parent)
    profile_path = profile.trusted(profile.PROFILE, True)
    raw_profile = read_private(profile_path, 16384)
    meta = json.loads(raw_profile, object_pairs_hook=no_duplicates)
    files = profile.load()
    name, domain = meta["lineage"], meta["domain"]
    if name != domain or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,252}", domain):
        raise ValueError("single managed DNS identity required")
    base = profile.BASE
    for directory in (base, base / "renewal", base.parent / "work", base.parent / "logs"):
        private_directory(directory)
    if os.path.lexists(base / "cli.ini"):
        raise ValueError("custom global config refused")
    config_path = profile.trusted(base / "renewal" / (name + ".conf"), True)
    raw_config = read_private(config_path, 65536)
    top, params, provider = parse_config(raw_config.decode("utf-8"))
    expected = {"archive_dir": str(base / "archive" / name)}
    expected.update({key: str(base / "live" / name / (key + ".pem"))
                     for key in ("cert", "privkey", "chain", "fullchain")})
    if any(top.get(k) != v for k, v in expected.items()):
        raise ValueError("unexpected lineage paths")
    trusted_binary = load("smtp-tls-postfix").trusted_binary
    certbot = trusted_binary("/usr/bin/certbot")
    openssl = trusted_binary("/usr/bin/openssl")
    san = subprocess.run([openssl, "x509", "-in", files["cert"], "-noout", "-ext", "subjectAltName"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    lines = san.stdout.decode("ascii").strip().splitlines()
    if len(lines) < 2 or ",".join(line.strip() for line in lines[1:]) != "DNS:" + domain:
        raise ValueError("single matching DNS SAN required")
    credential_key = PROVIDERS[provider]
    credential = Path(params[credential_key]) if credential_key else profile.PROFILE.parent / "aws-credentials"
    if not credential.is_absolute():
        raise ValueError("absolute credentials required")
    load("check-smtp-acme-credentials").inspect(provider, credential)
    st = credential.lstat()
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/root"}
    if provider == "dns-route53":
        env.update(AWS_SHARED_CREDENTIALS_FILE=str(credential), AWS_CONFIG_FILE="/dev/null",
                   AWS_PROFILE="default", AWS_EC2_METADATA_DISABLED="true")
    args = [certbot, "renew", "--dry-run", "--server", STAGING, "--non-interactive",
            "--no-directory-hooks", "--config", "/dev/null", "--cert-name", name,
            "--config-dir", str(base), "--work-dir", str(base.parent / "work"),
            "--logs-dir", str(base.parent / "logs")]
    material = {"profile": hashlib.sha256(raw_profile).hexdigest(),
                "config": hashlib.sha256(raw_config).hexdigest(),
                "credential_stat": [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns],
                "certificate_path": files["cert"], "command": args}
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    report = {"status": "ready_for_review", "lineage": name, "domain": domain,
              "provider": provider, "staging_ca": STAGING, "plan_sha256": digest,
              "dry_run": True, "activation_requested": False,
              "dns_challenge_writes_possible": True, "exchange_acceptance": "unverified"}
    return report, args, env


def execute(expected, prepare_fn=prepare):
    report, args, env = prepare_fn()
    if report["plan_sha256"] != expected:
        raise ValueError("reviewed plan changed")
    try:
        result = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=600, env=env)
    except subprocess.TimeoutExpired:
        return dict(report, status="outcome_unverified", renewal_exit=None)
    return dict(report, status="dry_run_passed" if result.returncode == 0 else "dry_run_failed",
                renewal_exit=result.returncode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preview", "run"))
    parser.add_argument("--expected-sha")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError("root required")
        os.umask(0o077)
        if args.action == "preview":
            if args.expected_sha is not None:
                raise ValueError("unexpected approval")
            result, _, _ = prepare()
        else:
            if not re.fullmatch(r"[a-f0-9]{64}", args.expected_sha or ""):
                raise ValueError("review required")
            lock = load("smtp-tls-renewal-profile").PROFILE.parent / "acme-renewal.lock"
            private_directory(lock.parent)
            fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
                    raise ValueError("unsafe lock")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = execute(args.expected_sha)
            finally:
                os.close(fd)
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({"status": "refused", "dry_run": True, "activation_requested": False,
                          "exchange_acceptance": "unverified"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
