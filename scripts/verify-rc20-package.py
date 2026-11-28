#!/usr/bin/env python3
"""Read-only verification of same-run unsigned RC20 package artifacts.

RC19 rehearsal is never RC20 transition evidence. No signing or publishing.
The caller must obtain artifacts from the same trusted workflow run.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
from zipfile import ZipFile

SHA = re.compile(r"\A[a-f0-9]{64}\Z")
COMMIT = re.compile(r"\A[a-f0-9]{40}\Z")
SOURCE_SHA = "6d59f380ac5686a5847b0babb02c0f3858ba2eed289912d990c9654d41610dba"
STATUS = "STATUS=preview_unsigned_not_for_production"
NAME = "LinuxMailRelay365.exe"
MACHINES = {"x64": 0x8664, "arm64": 0xaa64}
MAX_ARTIFACT = 512 * 1024 * 1024


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def unique(pairs):
    data = {}
    for key, value in pairs:
        need(key not in data, "duplicate_receipt_field")
        data[key] = value
    return data


def bounded(path, limit):
    need(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= limit,
         "invalid_artifact_file")
    return path


def sha_file(path):
    digest = hashlib.sha256()
    with bounded(path, MAX_ARTIFACT).open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def receipt(path, commit, version):
    need(COMMIT.fullmatch(commit) is not None, "invalid_commit")
    need(version in ("0.1.1-rc.19", "0.1.1-rc.20"), "unsupported_candidate_version")
    row = json.loads(bounded(path, 8192).read_text(encoding="utf-8-sig"),
                     object_pairs_hook=unique)
    expected = {
        "schema": 1, "commit": commit, "candidate_version": version,
        "source_tag": "v0.1.1-rc.19", "source_zip_sha256": SOURCE_SHA,
        "transition": "0.1.1-rc.19->0.1.1-rc.20" if version == "0.1.1-rc.20"
                      else "equal_version_file_replacement_rehearsal_only",
        "replacement": "PASS", "rollback": "PASS", "interactive_helper": "NOT_TESTED"
    }
    need(type(row) is dict and set(row) == set(expected) | {"candidate_sha256"} and
         type(row["schema"]) is int and all(row[k] == v for k, v in expected.items()) and
         type(row["candidate_sha256"]) is str and SHA.fullmatch(row["candidate_sha256"]),
         "invalid_upgrade_receipt")
    return row["candidate_sha256"]


def verify(root, proof, commit, version):
    candidate = receipt(proof, commit, version)
    lines = bounded(root / "preview-artifact-digests.txt", 8192).read_text(
        encoding="utf-8-sig").splitlines()
    need(len(lines) == 5 and lines.count(STATUS) == 1, "invalid_manifest_status")
    expected = {}
    for line in lines:
        if line == STATUS:
            continue
        items = line.split()
        need(len(items) == 3, "invalid_manifest_row")
        arch, name, digest = items
        need(digest.startswith("sha256:") and SHA.fullmatch(digest[7:]) is not None and
             (arch, name) not in expected, "invalid_manifest_digest")
        expected[(arch, name)] = digest[7:]
    keys = {("win-" + arch, name) for arch in MACHINES
            for name in (NAME, "LinuxMailRelay365-win-" + arch + ".zip")}
    need(set(expected) == keys, "invalid_manifest_inventory")
    for arch, machine in MACHINES.items():
        suffix = "win-" + arch
        exe = bounded(root / suffix / NAME, MAX_ARTIFACT)
        archive = bounded(root / "release-candidates" / ("LinuxMailRelay365-" + suffix + ".zip"),
                          MAX_ARTIFACT)
        digest = sha_file(exe)
        need(digest == expected[(suffix, NAME)] and
             sha_file(archive) == expected[(suffix, archive.name)], "package_hash_mismatch")
        if arch == "x64":
            need(digest == candidate, "updater_tested_binary_mismatch")
        with exe.open("rb") as stream:
            head = stream.read(64)
            need(len(head) == 64 and head[:2] == b"MZ", "invalid_mz")
            pe = struct.unpack_from("<I", head, 0x3c)[0]
            need(64 <= pe <= exe.stat().st_size - 6, "invalid_pe_offset")
            stream.seek(pe)
            marker = stream.read(6)
            need(marker[:4] == b"PE\0\0" and len(marker) == 6 and
                 struct.unpack_from("<H", marker, 4)[0] == machine, "invalid_pe_architecture")
        with ZipFile(archive) as zipped:
            members = zipped.infolist()
            need(len(members) == 1 and members[0].filename == NAME and
                 members[0].file_size == exe.stat().st_size, "invalid_zip_layout")
            payload = hashlib.sha256()
            with zipped.open(members[0]) as stream:
                for part in iter(lambda: stream.read(1024 * 1024), b""):
                    payload.update(part)
            need(payload.hexdigest() == digest, "zip_payload_mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", choices=("0.1.1-rc.19", "0.1.1-rc.20"), required=True)
    args = parser.parse_args()
    verify(args.root, args.receipt, args.commit, args.version)
    print("RC20_PACKAGE_SHA256_AND_ZIP=PASS")
    print("RC20_PACKAGE_UPGRADE=" + ("verified_version_transition" if args.version.endswith(".20")
                                    else "equal_version_rehearsal_only"))
    print("RC20_PACKAGE_STABLE_AUTHORIZED=no")


if __name__ == "__main__":
    main()
