"""RC14 staged candidate map transactions; no real MTA or /var/lib touched."""
import hashlib
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "conditional_stage", str(ROOT / "linux" / "stage-conditional-postfix-maps.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def rule(selector="exact-envelope-sender", pattern="user@example.org",
         host="relay.example.net", port=587, tls="starttls", auth="none"):
    return dict(selector=selector, pattern=pattern, host=host, port=port,
                tls=tls, auth=auth)


class StageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = pathlib.Path(self.tmp.name)
        self.fd = os.open(str(self.path), M.DIR_FLAGS)
        self.addCleanup(os.close, self.fd)
        self.uid = os.getuid()
        self.request = [rule(), rule(pattern="other@another.example", port=46500)]
        self.sha, self.expected = M.build(self.request)
        self.base = self.path / M.BASE_NAME

    def stage(self):
        return M.stage(self.fd, self.request, self.sha,
                       "STAGE_CONDITIONAL_MAPS_ONLY", self.uid)

    def test_exact_sender_map_and_custom_port(self):
        self.assertIn(b"user@example.org\t[relay.example.net]:587\n",
                      self.expected["sender-candidates.txt"])
        self.assertIn(b"other@another.example\t[relay.example.net]:46500\n",
                      self.expected["sender-candidates.txt"])
        self.assertNotIn(b"smtp:", self.expected["recipient-candidates.txt"])
        self.assertFalse(M.decode(self.expected[M.MANIFEST])["active"])
        self.assertNotEqual(self.sha, M.build(self.request[::-1])[0])
        self.assertEqual(len(self.sha), 64)
        expected = "LMR365-COND-ROUTES-V1\n"
        for item in self.request:
            for field in M.FIELDS:
                v = str(item[field])
                expected += "{}:{}\n".format(len(v), v)
        self.assertEqual(self.sha, hashlib.sha256(expected.encode("ascii")).hexdigest())

    def test_sender_domain_and_recipient_formats(self):
        _, sender = M.build([rule("envelope-sender-domain", "example.org", port=25)])
        self.assertIn(b"@example.org\t[relay.example.net]:25\n",
                      sender["sender-candidates.txt"])
        _, receiver = M.build([rule("recipient-domain", "example.org")])
        self.assertIn(b"example.org\tsmtp:[relay.example.net]:587\n",
                      receiver["recipient-candidates.txt"])

    def test_refuse_unsupported_and_overlapping_rules(self):
        for proposal in (
            [rule(port=True)], [rule(port=0)], [rule(tls="implicit")],
            [rule(auth="password")], [rule(host="127.0.0.1")],
            [rule(host="bad\nhost")], [rule(pattern="x@example.org\nfoo")],
            [dict(rule(), secret="must_not_accept")],
            [rule(), rule()],
            [rule(), rule("envelope-sender-domain", "example.org")],
            [rule(), rule("recipient-domain", "example.org")],
            [rule("recipient-domain", "example.org"),
             rule("recipient-domain", "sub.example.org")],
        ):
            with self.subTest(proposal=proposal):
                with self.assertRaises(M.Refused):
                    M.build(proposal)
        self.assertFalse(self.base.exists())
        with self.assertRaises(M.Refused):
            M.decode(b'{"x":1,"x":2}')

    def test_review_required_before_any_directory_creation(self):
        for sha, confirmation in (("0" * 64, "STAGE_CONDITIONAL_MAPS_ONLY"),
                                  (self.sha, "wrong")):
            with self.assertRaises(M.Refused):
                M.stage(self.fd, self.request, sha, confirmation, self.uid)
        self.assertFalse(self.base.exists())

    def test_stage_verify_and_never_overwrite(self):
        sha, receipt = self.stage()
        self.assertEqual(sha, self.sha)
        self.assertEqual(receipt, M.verify(self.fd, sha, self.uid))
        folder = self.base / sha
        self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
        for name, data in self.expected.items():
            self.assertEqual((folder / name).read_bytes(), data)
            self.assertEqual((folder / name).stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual(M.verify(self.fd, sha, self.uid), receipt)

    def test_reject_tampered_manifest_and_source(self):
        self.stage()
        folder = self.base / self.sha
        for name in (M.MANIFEST, "sender-candidates.txt", "plan.json"):
            path = folder / name
            saved = path.read_bytes()
            path.write_bytes(saved + b"x")
            with self.assertRaises(M.Refused):
                M.verify(self.fd, self.sha, self.uid)
            path.write_bytes(saved)
        (folder / "extra").write_text("unexpected")
        with self.assertRaises(M.Refused):
            M.verify(self.fd, self.sha, self.uid)

    def test_reject_unsafe_base_and_file_links(self):
        target = self.path / "elsewhere"
        target.mkdir(mode=0o700)
        self.base.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            self.stage()
        self.assertEqual(list(target.iterdir()), [])
        self.base.unlink()
        self.stage()
        folder = self.base / self.sha
        path = folder / "sender-candidates.txt"
        path.unlink()
        path.symlink_to(folder / "plan.json")
        with self.assertRaises(OSError):
            M.verify(self.fd, self.sha, self.uid)
        path.unlink()
        os.link(str(folder / "plan.json"), str(path))
        with self.assertRaises(M.Refused):
            M.verify(self.fd, self.sha, self.uid)

    def test_incomplete_stage_cannot_be_verified_or_resumed(self):
        original = M.write_file
        def fail_manifest(fd, name, data):
            if name == M.MANIFEST:
                raise OSError("simulated interrupted write")
            return original(fd, name, data)
        with patch.object(M, "write_file", side_effect=fail_manifest):
            with self.assertRaises(OSError):
                self.stage()
        with self.assertRaises(M.Refused):
            M.verify(self.fd, self.sha, self.uid)
        with self.assertRaises(FileExistsError):
            self.stage()

    def test_verify_missing_stage_does_not_create_base(self):
        with self.assertRaises(FileNotFoundError):
            M.verify(self.fd, self.sha, self.uid)
        self.assertFalse(self.base.exists())


if __name__ == "__main__":
    unittest.main()
