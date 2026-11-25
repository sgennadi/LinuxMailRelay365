"""Sendmail normal queue actions: unit tests never run a real delivery."""
import importlib.util
from pathlib import Path
import subprocess
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sm_action_product", str(ROOT / "linux/inspect-mail-queue.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
HEADER = "-----Q-ID----- --Size-- -----Q-Time----- ------------Sender/Recipient-----------\n"
ID = "3AP123AB45678"


def message(ident=ID, marker="", size=123):
    return ident + marker + "   " + str(size) + " Wed Nov 25 06:00 <sender@example.invalid>\n" + \
        "                                    <recipient@example.invalid>\n"


class SendmailActions(unittest.TestCase):
    def setUp(self):
        self.nonce = "a" * 64
        self.raw = "Mail Queue (1 request)\n" + HEADER + message()
        self.runner = Mock(side_effect=lambda *_: self.raw)
        self.context = Mock(side_effect=lambda queue: ("scope", queue, "config", "boot"))
        self.execute = Mock(return_value="command_completed")

    def inventory(self, queue="msp"):
        return q.sendmail_review_inventory(queue, self.nonce, self.runner, self.context, now=1000)

    def plan(self, action, token="-", sampled=0, queue="msp"):
        return q.sm_prepare(queue, action, self.nonce, sampled, token, self.runner, self.context, clock=lambda: 1060)

    def apply(self, action, prepared, digest, token="-", sampled=0, queue="msp", **extra):
        opts = dict(runner=self.runner, context_check=self.context, executor=self.execute,
                    clock=lambda: 1070, monotonic=lambda: 1)
        opts.update(extra)
        return q.sm_apply(queue, action, self.nonce, sampled, token, prepared, digest, q.SM_ACTIONS[action], **opts)

    def test_private_selection_bound_to_explicit_mode_and_full_id(self):
        report = self.inventory()
        self.assertEqual(report[:5], ("ok", 1, 1, 1, "no"))
        token = report[5][0][-1]
        self.assertRegex(token, r"^[a-f0-9]{64}$")
        self.assertEqual(report[-2:], (1000, "verified"))
        receipt = "\n".join(q.sendmail_inventory_lines("msp", self.nonce, *report))
        self.assertNotIn(ID, receipt)
        self.assertNotIn("example.invalid", receipt)
        self.assertIn("SENDMAIL_ITEMS_VERSION=2", receipt)
        self.assertEqual(self.runner.call_args[0], ("sendmail", ["-Ac", "-bp"]))
        self.assertNotEqual(self.inventory("mta")[5][0][-1], token)
        self.assertEqual(self.runner.call_args[0], ("sendmail", ["-Am", "-bp"]))
        result, prepared, digest, count = self.plan("retry", token, 1000)
        self.assertEqual((result, count), ("candidate", 1))
        self.assertEqual(self.apply("retry", prepared, digest, token, 1000, queue="mta"),
                         ("not_requested", "sample_changed"))
        self.assertEqual(self.apply("retry", prepared, digest, token, 1000), ("command_completed", "none"))
        self.execute.assert_called_once_with("msp", "retry", ID)

    def test_substring_collision_processing_and_truncation_refused(self):
        self.raw = "Mail Queue (2 requests)\n" + HEADER + message() + message(ID + "9")
        self.assertEqual(self.inventory()[5][0][-1], "-")
        self.raw = "Mail Queue (1 request)\n" + HEADER + message(marker="*")
        self.assertEqual(self.inventory()[5][0][-1], "-")
        self.raw = "Mail Queue (2 requests, only 1 printed)\n" + HEADER + message()
        report = self.inventory()
        self.assertEqual((report[-1], report[5][0][-1]), ("unverified", "-"))
        self.assertEqual(self.plan("flush")[0], "scope_unverified")
        self.execute.assert_not_called()

    def test_flush_full_sample_expiration_and_mode_change(self):
        result, prepared, digest, count = self.plan("flush", queue="mta")
        self.assertEqual((result, count), ("candidate", 1))
        self.assertEqual(self.apply("flush", prepared, digest, queue="msp"), ("not_requested", "plan_changed"))
        self.assertEqual(self.apply("flush", prepared, digest, queue="mta", clock=lambda: 1121),
                         ("not_requested", "expired"))
        self.raw = self.raw.replace("123 Wed", "124 Wed")
        self.assertEqual(self.apply("flush", prepared, digest, queue="mta"), ("not_requested", "plan_changed"))
        self.execute.assert_not_called()
        self.raw = self.raw.replace("124 Wed", "123 Wed")
        self.assertEqual(self.apply("flush", prepared, digest, queue="mta"), ("command_completed", "none"))
        self.execute.assert_called_once_with("mta", "flush", None)

    def test_config_refusal_and_unknown_result(self):
        self.context.side_effect = q.Unavailable("scope_unverified")
        self.assertEqual(self.inventory()[-1], "unverified")
        self.assertEqual(self.plan("flush")[0], "scope_unverified")
        self.context.side_effect = lambda queue: ("scope", queue)
        _, prepared, digest, _ = self.plan("flush")
        self.execute.return_value = "outcome_unknown"
        self.assertEqual(self.apply("flush", prepared, digest), ("outcome_unknown", "native_result_unconfirmed"))
        self.execute.assert_called_once()
        q.sm_config_queue("O QueueDirectory=/var/spool/mqueue\n", "/var/spool/mqueue")
        for config in ("O QueueDirectory=/var/spool/mqueue/*", "O QueueDirectory=/tmp/queue",
                       "O QueueDirectory=/var/spool/mqueue\nQextra, P=/tmp/queue",
                       "O QueueDirectory=/var/spool/mqueue\nOQ/tmp/queue"):
            with self.assertRaises(q.Unavailable):
                q.sm_config_queue(config, "/var/spool/mqueue")

    def test_package_queue_path_is_config_selected_and_scope_bound(self):
        allowed = q.SM_ALLOWED_QUEUE_PATHS
        for path in allowed["msp"]:
            for spelling in (path, path + "/"):
                self.assertEqual(q.sm_config_queue("O QueueDirectory=" + spelling, allowed["msp"]), path)
                with self.assertRaises(q.Unavailable):
                    q.sm_config_queue("O QueueDirectory=" + spelling, allowed["mta"])
        for value in ("/var/spool/mqueue", "/var/spool/mqueue-client/*",
                      "/var/spool/mqueue-client//", "/var/spool/../spool/mqueue-client",
                      "/var/spool/mqueue-client\nO QueueDirectory=/var/spool/clientmqueue"):
            with self.assertRaises(q.Unavailable):
                q.sm_config_queue("O QueueDirectory=" + value, allowed["msp"])
        self.assertEqual(q.sm_config_queue("O QueueDirectory=/var/spool/mqueue", allowed["mta"]),
                         "/var/spool/mqueue")

    def test_trusted_package_spool_ownership_and_modes(self):
        deb = "/var/spool/mqueue-client"
        rhel = "/var/spool/clientmqueue"
        mta = "/var/spool/mqueue"
        def metadata(uid, gid, mode, kind=stat.S_IFDIR):
            return SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=kind | mode)
        users = {"smmta": SimpleNamespace(pw_uid=112, pw_gid=117),
                 "smmsp": SimpleNamespace(pw_uid=113, pw_gid=118)}
        with patch.object(q.pwd, "getpwnam", side_effect=users.__getitem__), \
                patch.object(q.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=118)):
            q.sm_queue_directory("mta", mta, metadata(112, 118, 0o2750), deb)
            q.sm_queue_directory("msp", deb, metadata(113, 118, 0o2770), deb)
            q.sm_queue_directory("mta", mta, metadata(0, 0, 0o700), rhel)
            q.sm_queue_directory("msp", rhel, metadata(113, 118, 0o770), rhel)
            for queue, path, info, msp in (
                    ("mta", mta, metadata(112, 118, 0o2750), rhel),
                    ("mta", mta, metadata(112, 118, 0o2770), deb),
                    ("mta", mta, metadata(112, 117, 0o2750), deb),
                    ("mta", mta, metadata(113, 118, 0o2750), deb),
                    ("mta", mta, metadata(0, 0, 0o720), rhel),
                    ("msp", deb, metadata(113, 117, 0o2770), deb),
                    ("msp", deb, metadata(113, 118, 0o2777), deb),
                    ("msp", deb, metadata(0, 118, 0o2770), deb),
                    ("msp", deb, metadata(113, 118, 0o2770, stat.S_IFLNK), deb),
                    ("msp", deb, metadata(113, 118, 0o2770), rhel)):
                with self.subTest(queue=queue, path=path, mode=info.st_mode), self.assertRaises(q.Unavailable):
                    q.sm_queue_directory(queue, path, info, msp)

    def test_selected_quarantine_release_requires_both_classes_and_observed_effect(self):
        empty = "Mail queue is empty\n"
        normal = self.raw
        held = normal.replace("                                    <recipient",
                              " QUARANTINE: private reason\n                                    <recipient")
        state = {"normal": normal, "held": empty}
        self.runner.side_effect = lambda tool, args: state["held" if "-qQ" in args else "normal"]
        token = self.inventory()[5][0][-1]
        result, prepared, digest, count = self.plan("quarantine", token, 1000)
        self.assertEqual((result, count), ("candidate", 1))
        # A valid command exit without a visible transition is not success.
        self.assertEqual(self.apply("quarantine", prepared, digest, token, 1000),
                         ("outcome_unknown", "native_result_unconfirmed"))
        def move(queue, action, ident):
            self.assertEqual((queue, ident), ("msp", ID))
            state.update(normal=empty, held=held) if action == "quarantine" else state.update(normal=normal, held=empty)
            return "command_completed"
        self.execute.side_effect = move
        self.assertEqual(self.apply("quarantine", prepared, digest, token, 1000),
                         ("transition_verified", "none"))
        report = q.sendmail_review_inventory("msp", self.nonce, self.runner, self.context,
                                            now=1000, quarantine=True)
        held_token = report[5][0][-1]
        self.assertNotEqual(held_token, token)
        result, prepared, digest, count = self.plan("release", held_token, 1000)
        self.assertEqual((result, count), ("candidate", 1))
        state["normal"] = normal
        self.assertEqual(self.apply("release", prepared, digest, held_token, 1000),
                         ("not_requested", "sample_changed"))
        state["normal"] = empty
        self.assertEqual(self.apply("release", prepared, digest, held_token, 1000),
                         ("transition_verified", "none"))
        receipt = "\n".join(q.sm_action_lines("msp", "release", self.nonce, 1000, held_token,
                            "apply", prepared, digest, "transition_verified", "none"))
        self.assertIn("SENDMAIL_ACTION_EFFECT_VERIFIED=yes", receipt)
        self.assertIn("SENDMAIL_ACTION_QUARANTINE_CHANGED=yes", receipt)
        self.assertNotIn(ID, receipt)

    def test_fixed_native_modes_and_no_quarantine_or_periodic_command(self):
        with patch.object(q, "native_binary", return_value="/usr/sbin/sendmail"), \
                patch.object(q.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            for queue, mode in (("mta", "-Am"), ("msp", "-Ac")):
                self.assertEqual(q.sm_execute(queue, "retry", ID), "command_completed")
                self.assertEqual(run.call_args[0][0], ["/usr/sbin/sendmail", mode, "-qf", "-qI" + ID])
                self.assertEqual(q.sm_execute(queue, "flush", None), "command_completed")
                self.assertEqual(run.call_args[0][0], ["/usr/sbin/sendmail", mode, "-qf"])
            for queue, action, ident in (("both", "flush", None), ("mta", "retry", "ALL"),
                                         ("mta", "flush", ID), ("msp", "delete", ID)):
                with self.assertRaises(ValueError):
                    q.sm_execute(queue, action, ident)
            self.assertEqual(run.call_count, 4)
            self.assertEqual(q.sm_execute("msp", "quarantine", ID), "command_completed")
            self.assertEqual(run.call_args[0][0], ["/usr/sbin/sendmail", "-Ac", "-Q" + q.SM_QUARANTINE_REASON, "-qI" + ID])
            self.assertEqual(q.sm_execute("msp", "release", ID), "command_completed")
            self.assertEqual(run.call_args[0][0], ["/usr/sbin/sendmail", "-Ac", "-qQ", "-Q", "-qI" + ID])
            self.assertFalse(q.allowed_args("sendmail", ["-Am", "-qf"]))


if __name__ == "__main__":
    unittest.main()
