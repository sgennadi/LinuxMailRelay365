"""Offline tamper tests for same-run RC20 package and upgrade evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("rc20_package", ROOT / "scripts/verify-rc20-package.py")
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proof = self.root / "receipt.json"
        self.commit = "a" * 40
        self.version = "0.1.1-rc.20"
        self.lines = []
        (self.root / "release-candidates").mkdir()
        for arch, machine in V.MACHINES.items():
            folder = self.root / ("win-" + arch)
            folder.mkdir()
            exe = folder / V.NAME
            head = bytearray(70)
            head[:2] = b"MZ"
            struct.pack_into("<I", head, 0x3c, 64)
            head[64:68] = b"PE\0\0"
            struct.pack_into("<H", head, 68, machine)
            exe.write_bytes(head)
            archive = self.root / "release-candidates" / ("LinuxMailRelay365-win-" + arch + ".zip")
            with ZipFile(archive, "w") as z:
                z.write(exe, V.NAME)
            for path in (exe, archive):
                self.lines.append("win-" + arch + " " + path.name + " sha256:" + V.sha_file(path))
        self.manifest = self.root / "preview-artifact-digests.txt"
        self.manifest.write_text("\n".join(self.lines + [V.STATUS]) + "\n")
        self.row = dict(schema=1, commit=self.commit, candidate_version=self.version,
                        candidate_sha256=V.sha_file(self.root / "win-x64" / V.NAME),
                        source_tag="v0.1.1-rc.19", source_zip_sha256=V.SOURCE_SHA,
                        transition="0.1.1-rc.19->0.1.1-rc.20", replacement="PASS",
                        rollback="PASS", interactive_helper="NOT_TESTED")

    def check(self):
        self.proof.write_text(json.dumps(self.row))
        V.verify(self.root, self.proof, self.commit, self.version)

    def test_actual_transition_and_rehearsal_are_distinct(self):
        self.check()
        self.row["transition"] = "equal_version_file_replacement_rehearsal_only"
        with self.assertRaisesRegex(ValueError, "invalid_upgrade_receipt"):
            self.check()
        self.version = self.row["candidate_version"] = "0.1.1-rc.19"
        self.check()

    def test_receipt_tampering_refuses(self):
        for key, bad in (("commit", "b" * 40), ("schema", True),
                         ("source_zip_sha256", "b" * 64), ("rollback", "FAIL"),
                         ("interactive_helper", "PASS"), ("candidate_version", "0.1.1-rc.19"),
                         ("candidate_sha256", "b" * 64)):
            with self.subTest(key=key):
                original = self.row[key]
                self.row[key] = bad
                with self.assertRaises(ValueError):
                    self.check()
                self.row[key] = original
        self.proof.write_text(json.dumps(self.row)[:-1] + ', "commit": "' + self.commit + '"}')
        with self.assertRaisesRegex(ValueError, "duplicate_receipt_field"):
            V.verify(self.root, self.proof, self.commit, self.version)

    def test_changed_exe_and_invalid_manifest_refuse(self):
        self.check()
        self.manifest.write_text("\n".join(self.lines + [V.STATUS, V.STATUS]))
        with self.assertRaisesRegex(ValueError, "invalid_manifest_status"):
            self.check()
        self.manifest.write_text("\n".join(self.lines + [V.STATUS]))
        exe = self.root / "win-arm64" / V.NAME
        exe.write_bytes(exe.read_bytes() + b"x")
        with self.assertRaisesRegex(ValueError, "package_hash_mismatch"):
            self.check()

    def test_wrong_architecture_with_updated_hashes_refuses(self):
        exe = self.root / "win-arm64" / V.NAME
        data = bytearray(exe.read_bytes())
        struct.pack_into("<H", data, 68, V.MACHINES["x64"])
        exe.write_bytes(data)
        archive = self.root / "release-candidates/LinuxMailRelay365-win-arm64.zip"
        with ZipFile(archive, "w") as z:
            z.write(exe, V.NAME)
        lines = [line for line in self.lines if not line.startswith("win-arm64 ")]
        lines += ["win-arm64 " + p.name + " sha256:" + V.sha_file(p) for p in (exe, archive)]
        self.manifest.write_text("\n".join(lines + [V.STATUS]))
        with self.assertRaisesRegex(ValueError, "invalid_pe_architecture"):
            self.check()


if __name__ == "__main__":
    unittest.main()
