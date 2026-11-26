"""Offline-only Postfix multi-OAuth route installer static and failure tests."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "linux" / "manage-multi-mailbox-postfix.py"
spec = importlib.util.spec_from_file_location("multi_mail_postfix", str(SOURCE))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class MultiPostfixInstallerTests(unittest.TestCase):
    def test_managed_settings_only_change_expected_keys(self):
        base = (b"# preserve this comment\n"
                b"myhostname = smtp.example.org\n"
                b"default_transport = smtp:[test.mail.protection.outlook.com]:25\n"
                b"relay_transport = smtp:[test.mail.protection.outlook.com]:25\n")
        output = mod.replace_settings(base)
        self.assertIn(b"myhostname = smtp.example.org\n", output)
        self.assertEqual(output.count(b"default_transport = m365multi:"), 1)
        self.assertEqual(output.count(b"relay_transport = m365multi:"), 1)
        self.assertEqual(output.count(b"m365multi_destination_recipient_limit = 1"), 1)
        self.assertEqual(output.count(b"m365multi_destination_concurrency_limit = 2"), 1)
        self.assertNotIn(b"postconf -e", output)
        self.assertEqual(mod.replace_settings(output), output)

    def test_main_disallows_duplicate_or_multiline_ambiguity(self):
        for source in (b"default_transport = old:\ndefault_transport = new:\n",
                       b"some = yes\n continued stuff\n",
                       b"some = yes\r\n", b"a = yes\x00unsafe",
                       b"\xff\xfe"):
            with self.subTest(source=source), self.assertRaises(mod.Refused):
                mod.replace_settings(source)

    def test_postfix_pipe_requires_both_verified_sasl_attributes(self):
        service = mod.master_service(b"# custom port\n", "d" * 64)
        expected = (
            b"m365multi unix - n n - 2 pipe",
            b"flags=q user=m365mailer argv=/usr/bin/python3 ",
            b"--recipient ${recipient}",
            b"--envelope-sender ${sender}",
            b"--sasl-login ${sasl_username}",
            b"--sasl-method ${sasl_method}",
            b"--expected-map-sha256 " + b"d" * 64,
        )
        for fragment in expected:
            self.assertIn(fragment, service)
        self.assertIn(b"# custom port\n", service)
        self.assertEqual(service.count(b"m365multi unix"), 1)

    def test_master_refuses_existing_service_or_invalid_sha(self):
        for old, digest in ((b"m365multi unix - n n - 2 pipe\n", "a" * 64),
                            (b"# not a valid token\n", "A" * 64),
                            (b"# null\x00\n", "b" * 64),
                            (b"# CRLF\r\n", "b" * 64)):
            with self.subTest(old=old[:20]), self.assertRaises(mod.Refused):
                mod.master_service(old, digest)

    def test_offline_refuses_active_service_and_nonempty_queue(self):
        with mock.patch.object(mod, "run", side_effect=[
                "LoadState=loaded\nActiveState=active"]):
            with self.assertRaisesRegex(mod.Refused, "not_proven_stopped"):
                mod.offline()
        with mock.patch.object(mod, "run", side_effect=[
                "LoadState=loaded\nActiveState=inactive",
                '{"queue_id":"not-empty"}']):
            with self.assertRaisesRegex(mod.Refused, "queue_not_empty"):
                mod.offline()
        with mock.patch.object(mod, "run", side_effect=[
                "LoadState=loaded\nActiveState=inactive", "", ""]), \
             mock.patch.object(mod, "read", return_value=(None, b"2525\n")):
            self.assertTrue(mod.offline())
        with mock.patch.object(mod, "run", side_effect=[
                "LoadState=loaded\nActiveState=inactive", "",
                "LISTEN 0 128 127.0.0.1:2525 0.0.0.0:*"]), \
             mock.patch.object(mod, "read", return_value=(None, b"2525\n")):
            with self.assertRaisesRegex(mod.Refused, "still_listening"):
                mod.offline()

    def test_offline_never_fakes_success_when_loadstate_missing(self):
        for result in ("ActiveState=inactive", "LoadState=not-found\nActiveState=inactive",
                       "LoadState=loaded\nActiveState=failed"):
            with mock.patch.object(mod, "run", return_value=result):
                with self.assertRaises(mod.Refused):
                    mod.offline()

    def test_apply_requires_root_and_reviewed_sha_before_any_host_read(self):
        for digest, phrase in (("", mod.CONFIRM), ("a" * 64, ""),
                               ("A" * 64, mod.CONFIRM)):
            with mock.patch.object(mod, "plan") as planned:
                with self.assertRaises(mod.Refused):
                    mod.apply_offline(digest, phrase)
                planned.assert_not_called()
        with mock.patch.object(mod.os, "geteuid", return_value=1000), \
             mock.patch.object(mod, "plan") as planned:
            with self.assertRaises(mod.Refused):
                mod.apply_offline("a" * 64, mod.CONFIRM)
            planned.assert_not_called()

    def test_plan_does_not_access_host_as_unprivileged_user(self):
        with mock.patch.object(mod.os, "geteuid", return_value=1001), \
             mock.patch.object(mod, "read") as read:
            with self.assertRaisesRegex(mod.Refused, "root_required"):
                mod.plan()
            read.assert_not_called()

    def test_selinux_context_parser(self):
        self.assertEqual(mod.checked_context(b"system_u:object_r:etc_t:s0\0"),"system_u:object_r:etc_t:s0")
        for raw in (b"",b"system_u:object_r:tmp_t:s0",b"system_u:object_r:unlabeled_t:s0"):
            with self.assertRaises(mod.Refused):
                mod.checked_context(raw)

    @unittest.skipUnless(os.geteuid()==0 and os.environ.get("GITHUB_ACTIONS")=="true"
                         and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted",
                         "disposable root CI only")
    def test_active_policy_staged_runtime_and_config_publication(self):
        # Real file ownership, xattrs and fsync with synthetic labels.
        with tempfile.TemporaryDirectory(prefix="lmr365-route-policy-",dir="/var/lib") as folder:
            base=Path(folder)
            modefile=base/"enforce"
            modefile.write_text("1")
            label="system_u:object_r:etc_t:s0"
            code="system_u:object_r:bin_t:s0"
            attr="user.lmr365_test_context"
            config=base/"main.cf"
            config.write_bytes(b"before\n")
            config.chmod(0o640)
            os.setxattr(str(config),attr,label.encode()+b"\0")
            target=base/"runtime"
            stage=base/"stage"
            stage.mkdir(mode=0o700)
            overrides={}
            def expected(path,directory=False):
                return overrides.get(path,code if path==target or path.parent==target else label)
            with mock.patch.multiple(mod,SELINUX=modefile,LABEL_ATTR=attr), \
                 mock.patch.object(mod,"expected_label",side_effect=expected):
                policy=mod.policy_snapshot([(config,False),(target,True),(target/"module.py",False)])
                self.assertEqual(policy["mode"],"enforcing")
                mod.label_new_directory(stage,target,"enforcing")
                mod.write_new(stage/"module.py",b"code\n","enforcing",0o644,destination=target/"module.py")
                mod.require_policy(policy)
                stage.rename(target)
                mod.require_policy(policy)
                mod.verify_label(target/"module.py",code)
                before=mod.read(config,1024)
                mod.replace_file(config,b"after\n",before)
                self.assertEqual(config.read_bytes(),b"after\n")
                mod.require_policy(policy)
                overrides[config]=code
                with self.assertRaises(mod.Refused):
                    mod.require_policy(policy)
                with self.assertRaises(mod.Refused):
                    mod.replace_file(config,b"should not write\n",mod.read(config,1024))
                self.assertEqual(config.read_bytes(),b"after\n")
                overrides.clear()
                modefile.write_text("0")
                with self.assertRaisesRegex(mod.Refused,"policy_changed"):
                    mod.require_policy(policy)

    def test_no_background_start_network_calls_or_primary_mta_writes(self):
        text = SOURCE.read_text(encoding="utf-8")
        for value in ("systemctl start", "systemctl restart",
                      "systemctl reload", "postfix reload", "postfix start",
                      "ufw allow", "firewall-cmd --add-port",
                      "smtp.office365.com", "New-InboundConnector"):
            self.assertNotIn(value, text)
        self.assertIn("INSTALL_MULTI_MAILBOX_OFFLINE", text)
        self.assertIn("MULTI_OAUTH_MESSAGES_SENT=no", text)
        self.assertIn("MULTI_OAUTH_PRIMARY_POSTFIX_CHANGED=no", text)


if __name__ == "__main__":
    unittest.main()
