import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location("candidate",str(pathlib.Path(__file__).resolve().parents[1]/"linux/smtp-tls-initial-candidate.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class CandidateTests(unittest.TestCase):
    def test_preserves(self):
        original=b"# comment\nrelayhost = [example.org]:25\n"
        self.assertTrue(m.build(original).startswith(original))
        self.assertEqual(m.build(m.build(original)),m.build(original))
    def test_refuses(self):
        for data in (b"smtp_tls_chain_files = /other\n",b"smtp_tls_chain_files =\n continuation\n",b"smtp_tls_chain_files =\nsmtp_tls_chain_files =\n"):
            with self.assertRaises(ValueError):
                m.build(data)


class EffectivePreflightTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import Mock
        source=pathlib.Path(__file__).resolve().parents[1]/"linux/plan-smtp-tls-initial.py"
        spec=importlib.util.spec_from_file_location("planner",str(source))
        self.planner=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.planner)
        self.pf=Mock()
        self.pf.postconf="/usr/sbin/postconf"
        self.settings={"config_directory":"/etc/postfix","mail_version":"3.5.25",
                       "smtp_tls_security_level":"encrypt"}
        def run(binary,*args):
            self.assertEqual(binary,self.pf.postconf)
            if args==("-P",):
                return ""
            # Raw defaults would return a nonempty parameter reference.
            if args==("-h","smtp_tls_key_file"):
                return "$smtp_tls_cert_file"
            self.assertEqual(args[:2],("-h","-x"))
            return self.settings.get(args[2],"")
        self.pf.run.side_effect=run

    def test_expanded_empty_default_is_not_an_existing_identity(self):
        plan=self.planner.plan_postfix(self.pf)
        self.assertIn("smtp_tls_chain_files",plan["changes"])

    def test_expanded_nonempty_identity_still_refused(self):
        self.settings["smtp_tls_key_file"]="/existing/private.pem"
        with self.assertRaises(ValueError):
            self.planner.plan_postfix(self.pf)

    def test_all_initial_entry_points_use_effective_settings(self):
        root=pathlib.Path(__file__).resolve().parents[1]/"linux"
        for name in ("manage-smtp-tls-initial.py","review-smtp-tls-rotation.py"):
            self.assertIn("planner.plan_postfix(pf)",(root/name).read_text())
