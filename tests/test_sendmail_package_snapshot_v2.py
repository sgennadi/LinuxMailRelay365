"""Offline compatibility and mutation-refusal tests for Sendmail snapshot v2.

Synthetic fixtures run as an ordinary CI user and never touch /etc.
"""
import hashlib
import importlib.util
import io
import json
from contextlib import redirect_stdout
from unittest.mock import patch
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "lmr365_sendmail_package_v2",
    str(ROOT / "linux" / "foreign-mta-config-backup.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class V2SnapshotTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "machine"
        self.base = Path(tmp.name) / "backups"
        (self.root / "etc" / "mail" / "smrsh").mkdir(parents=True)
        (self.root / "etc" / "mail" / "sendmail.cf").write_text(
            "O DaemonPortOptions=Addr=127.0.0.1\n", encoding="utf-8")
        (self.root / "etc" / "mail" / "smrsh" / "procmail").symlink_to(
            "/usr/bin/procmail")
        (self.root / "etc" / "aliases").write_text("postmaster: root\n")
        self.uid = os.getuid()
        self.folder = self.base / "sendmail" / "20261121T000000Z-abcdefabcdef"
        self.folder.mkdir(parents=True, mode=0o700)
        self.archive = self.folder / "config.tar.gz"
        self.manifest_path = self.folder / "manifest.json"
        self.objects = {}
        self.files = m.selected_files("sendmail", self.root, self.uid, self.objects)
        self.assertEqual(self.objects["etc/mail/smrsh/procmail"]["kind"], "symlink")
        self.manifest = {"version": 2, "mta": "sendmail",
                         "files": {}, "objects": self.objects}
        with self.archive.open("wb") as stream:
            os.chmod(str(self.archive), 0o600)
            with tarfile.open(fileobj=stream, mode="w:gz") as tar:
                for name, path in sorted(self.files.items()):
                    data = path.read_bytes()
                    info = path.stat()
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    entry.uid, entry.gid = info.st_uid, info.st_gid
                    entry.mode = stat.S_IMODE(info.st_mode)
                    tar.addfile(entry, io.BytesIO(data))
                    self.manifest["files"][name] = {
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "size": len(data), "uid": info.st_uid, "gid": info.st_gid,
                        "mode": stat.S_IMODE(info.st_mode)}
        self.manifest["sha256"] = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.save()

    def save(self):
        self.manifest_path.write_text(json.dumps(
            self.manifest, sort_keys=True), encoding="utf-8")
        os.chmod(str(self.manifest_path), 0o600)

    def test_cli_verify_identifies_v2_metadata_only(self):
        # The actual v2 archive and its owner permissions are checked above
        # as the nonroot CI user. Root CLI output is tested separately with
        # that same pre-verified result, not by bypassing on-disk ACLs.
        preverified = m.verify(self.folder, "sendmail", self.uid)
        output = io.StringIO()
        with patch.object(m, "BASE", self.base), \
             patch.object(m, "verify", return_value=preverified), \
             patch.object(m.os, "geteuid", return_value=0), \
             redirect_stdout(output):
            result = m.main(["--mta", "sendmail", "--verify", self.folder.name])
        self.assertEqual(result, 0)
        self.assertIn("FOREIGN_BACKUP_FORMAT=v2_package_metadata\n",
                      output.getvalue())
        self.assertIn("FOREIGN_BACKUP_STATUS=verified\n",
                      output.getvalue())

    def test_cli_preview_identifies_v2_metadata_only(self):
        review = m.recovery_preview(
            "sendmail", self.folder.name, self.root, self.base, self.uid)
        output = io.StringIO()
        with patch.object(m, "recovery_preview", return_value=review), \
             patch.object(m.os, "geteuid", return_value=0), \
             redirect_stdout(output):
            result = m.main(["--mta", "sendmail",
                             "--preview-recovery", self.folder.name])
        self.assertEqual(result, 0)
        self.assertIn("FOREIGN_BACKUP_FORMAT=v2_package_metadata\n",
                      output.getvalue())
        self.assertIn("FOREIGN_BACKUP_CURRENT_CONFIG_MATCH=identical\n",
                      output.getvalue())

    def test_v2_verifies_file_contents_and_untouched_symlink_metadata(self):
        result = m.verify(self.folder, "sendmail", self.uid)
        self.assertEqual(result["files"], len(self.files))
        self.assertEqual(result["mta"], "sendmail")
        self.assertEqual(m.recovery_preview(
            "sendmail", self.folder.name, self.root, self.base, self.uid)["current"],
            "identical")
        self.assertTrue((self.root / "etc" / "mail" / "smrsh" / "procmail").is_symlink())

    def test_modified_link_target_is_detected_in_preview(self):
        link = self.root / "etc" / "mail" / "smrsh" / "procmail"
        link.unlink()
        link.symlink_to("/tmp/untrusted")
        self.assertEqual(m.recovery_preview(
            "sendmail", self.folder.name, self.root, self.base, self.uid)["current"],
            "different")

    def test_corrupted_archive_is_refused(self):
        with self.archive.open("ab") as writer:
            writer.write(b"tampered")
        with self.assertRaises(m.Refused):
            m.verify(self.folder, "sendmail", self.uid)

    def test_unlisted_package_link_is_refused(self):
        link = self.root / "etc" / "mail" / "smrsh" / "unexpected"
        link.symlink_to("/tmp")
        with self.assertRaisesRegex(m.Refused, "unrecognized_sendmail_package_symlink"):
            m.selected_files("sendmail", self.root, self.uid, {})

    def test_unlisted_manifest_symlink_is_refused(self):
        self.manifest["objects"]["etc/mail/unlisted"] = {
            "kind": "symlink", "uid": self.uid,
            "gid": os.getgid(), "target": "/etc/passwd"}
        self.save()
        with self.assertRaisesRegex(m.Refused, "invalid_package_symlink_metadata"):
            m.verify(self.folder, "sendmail", self.uid)

    def test_file_metadata_mismatch_refused(self):
        name = "etc/mail/sendmail.cf"
        self.manifest["files"][name]["uid"] += 1
        self.save()
        with self.assertRaisesRegex(m.Refused, "package_file_metadata_mismatch"):
            m.verify(self.folder, "sendmail", self.uid)

    def test_package_export_explicitly_blocked(self):
        with self.assertRaisesRegex(m.Refused, "metadata_aware_export"):
            m.extract_offline("sendmail", self.folder.name, self.base, self.uid)

    def test_package_restore_never_applies(self):
        spec = importlib.util.spec_from_file_location(
            "lmr365_sendmail_v2_restore",
            str(ROOT / "linux" / "restore-foreign-mta-config.py"))
        restore = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(restore)
        with self.assertRaisesRegex(
                restore.Refused, "package_snapshot_restore_requires_manual_metadata_review"):
            restore.content_from_snapshot(
                "sendmail", self.folder.name, self.base, self.uid)

    def test_malformed_object_root_refused(self):
        self.manifest["objects"]["etc/mail"] = "not_an_object"
        self.save()
        with self.assertRaisesRegex(m.Refused, "root_directory_unrecorded"):
            m.verify(self.folder, "sendmail", self.uid)


if __name__ == "__main__":
    unittest.main()
