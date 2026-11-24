"""Scoped Sendmail v2 Apply/rollback with isolated paths and no actual mail."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "sendmail_v2_transaction", str(ROOT / "linux/restore-foreign-mta-config.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class SendmailV2Transaction(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "machine"
        self.base = Path(tmp.name) / "backup"
        self.uid = os.getuid()
        self.mail = self.root / "etc/mail"
        (self.mail / "smrsh").mkdir(parents=True)
        self.a = self.mail / "sendmail.cf"
        self.b = self.mail / "submit.cf"
        self.db = self.mail / "access.db"
        self.link = self.mail / "smrsh/procmail"
        self.a.write_bytes(b"target a\n")
        self.b.write_bytes(b"target b\n")
        self.db.write_bytes(b"database")
        self.link.symlink_to("/usr/bin/procmail")
        self.target, _ = r.backup.backup("sendmail", self.root, self.base, self.uid, package_v2=True)
        self.a.write_bytes(b"original a\n")
        self.b.write_bytes(b"original b\n")
        self.options = dict(root=self.root, base=self.base, uid=self.uid,
                            lock_path=Path(tmp.name) / "lock", preflight_check=self.preflight)
        self.write_options = dict(self.options, offline_check=lambda _: True,
                                  static_check=lambda *_: True)

    def preflight(self, mta, sid, root, base, uid):
        info = r.backup.verify(base / mta / sid, mta, uid)
        return dict(mta=mta, snapshot_id=sid, archive_sha256=info["sha256"],
                    current="different", service="stopped_declared", processes="none_observed",
                    queue="empty_reported", listener="none_observed",
                    gate="offline_candidate_manual_recovery_only")

    def review(self):
        return r.preview_sendmail_v2(self.target, **self.options)

    def apply(self, plan=None, **options):
        return r.apply_sendmail_v2(self.target, (plan or self.review())["plan_sha256"],
                                   r.SENDMAIL_V2_APPROVAL, **dict(self.write_options, **options))

    def rollback_plan(self):
        return r.preview_sendmail_v2_rollback(**dict(self.options, offline_check=lambda _: True))

    def rollback(self, plan=None, **options):
        return r.rollback_sendmail_v2((plan or self.rollback_plan())["sha"],
                                      r.SENDMAIL_V2_ROLLBACK_APPROVAL,
                                      **dict(self.write_options, **options))

    def assert_unrelated(self):
        self.assertEqual(self.db.read_bytes(), b"database")
        self.assertTrue(self.link.is_symlink())
        self.assertEqual(os.readlink(str(self.link)), "/usr/bin/procmail")

    def test_success_two_existing_files_and_independent_safety(self):
        db_identity = self.db.stat().st_ino
        result = self.apply()
        self.assertEqual(result["changed"], 2)
        self.assertEqual(self.a.read_bytes(), b"target a\n")
        self.assertEqual(self.b.read_bytes(), b"target b\n")
        self.assertEqual(self.db.stat().st_ino, db_identity)
        self.assert_unrelated()
        self.assertIsNone(r.read_pending(self.base, self.uid))
        record = result["record"]
        self.assertEqual(record["version"], 4)
        self.assertNotEqual(record["target"], record["safety"])
        self.assertTrue(r.read_saved_review(self.base, self.uid, record))
        r.sendmail_v2_bound_archives(self.base, self.uid, record)

    def interrupt(self):
        replace = r.replace_one
        def abrupt(*args, **kwargs):
            replace(*args, **kwargs)
            raise KeyboardInterrupt()
        with patch.object(r, "replace_one", side_effect=abrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.apply()
        self.assertEqual(self.a.read_bytes(), b"target a\n")
        self.assertEqual(self.b.read_bytes(), b"original b\n")
        return r.read_pending(self.base, self.uid)

    def test_interrupted_apply_review_and_rollback(self):
        marker = self.interrupt()
        self.assertEqual(marker["version"], 4)
        with self.assertRaisesRegex(r.Refused, "pending_restore"):
            self.review()
        report = r.inspect_pending(**{k: self.options[k] for k in ("root", "base", "uid", "lock_path")})
        self.assertEqual(report["counts"]["target_only"], 1)
        self.assertEqual(report["counts"]["original_only"], 1)
        result = self.rollback()
        self.assertEqual(result["changed"], 1)
        self.assertEqual(self.a.read_bytes(), b"original a\n")
        self.assertEqual(self.b.read_bytes(), b"original b\n")
        self.assert_unrelated()
        self.assertIsNone(r.read_pending(self.base, self.uid))

    def test_stale_approval_and_inventory_drift_refuse_before_writes(self):
        review = self.review()
        self.a.write_bytes(b"later edit")
        with self.assertRaisesRegex(r.Refused, "plan_changed"):
            self.apply(review)
        self.db.write_bytes(b"unrelated change")
        with self.assertRaisesRegex(r.Refused, "not_eligible"):
            self.apply()
        self.assertEqual(self.a.read_bytes(), b"later edit")
        self.assertEqual(r.backup.listed("sendmail", self.base, self.uid), [self.target])

    def test_parser_failure_keeps_marker_and_rollback_requires_parser(self):
        with self.assertRaisesRegex(r.Refused, "native_static"):
            self.apply(static_check=lambda *_: False)
        self.assertIsNotNone(r.read_pending(self.base, self.uid))
        with self.assertRaisesRegex(r.Refused, "native_static"):
            self.rollback(static_check=lambda *_: False)
        self.assertEqual(self.a.read_bytes(), b"original a\n")
        self.assertIsNotNone(r.read_pending(self.base, self.uid))
        self.assertEqual(self.rollback()["changed"], 0)
        self.assertIsNone(r.read_pending(self.base, self.uid))

    def test_rollback_refuses_unrelated_drift(self):
        marker = self.interrupt()
        self.db.write_bytes(b"other")
        with self.assertRaisesRegex(r.Refused, "unrelated_file_drift"):
            self.rollback_plan()
        self.assertEqual(r.read_pending(self.base, self.uid), marker)

    def test_rollback_refuses_tampered_manifest_without_tar_change(self):
        marker = self.interrupt()
        path = self.base / "sendmail" / marker["safety"] / "manifest.json"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(r.Refused, "bound_archive_changed"):
            self.rollback_plan()
        self.assertEqual(r.read_pending(self.base, self.uid), marker)

    def test_rollback_refuses_stale_approval_even_same_content(self):
        marker = self.interrupt()
        plan = self.rollback_plan()
        self.b.write_bytes(b"original b\n")
        with self.assertRaisesRegex(r.Refused, "plan_changed"):
            self.rollback(plan)
        self.assertEqual(r.read_pending(self.base, self.uid), marker)

    def test_running_or_wrong_confirmation_never_mutates(self):
        plan = self.review()
        with self.assertRaisesRegex(r.Refused, "confirmation"):
            r.apply_sendmail_v2(self.target, plan["plan_sha256"], "WRONG", **self.write_options)
        with self.assertRaisesRegex(r.Refused, "not_stopped"):
            self.apply(plan, offline_check=lambda _: False)
        self.assertEqual(self.a.read_bytes(), b"original a\n")
        self.assertIsNone(r.read_pending(self.base, self.uid))


if __name__ == "__main__":
    unittest.main()
