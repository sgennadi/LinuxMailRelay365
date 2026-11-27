import importlib.util
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("avc", ROOT / "linux/check-smtp-tls-avc.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


def row(event="123.456:7", source="postfix_smtp_t", mode="0", extra=""):
    return ('type=AVC msg=audit(' + event + '): avc:  denied  { read } for pid=5 '
            'comm="smtp" name="client-chain.pem" scontext=system_u:system_r:' + source +
            ':s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=' + mode + extra + '\n').encode()


class SmtpTlsAvcTests(unittest.TestCase):
    def test_deduplicate_and_separate_modes(self):
        result = M.summarize(row() + row() + row("123.456:8", mode="1"))
        self.assertEqual(result["matching_denials"], 2)
        self.assertEqual(result["enforcing_denials"], 1)
        self.assertEqual(result["permissive_denials"], 1)
        self.assertEqual(result["parsed_records"], 3)

    def test_conflicting_mode_is_unknown(self):
        result = M.summarize(row() + row(mode="1"))
        self.assertEqual(result["unknown_mode_denials"], 1)
        self.assertEqual(result["matching_denials"], 1)

    def test_unknown_record_is_not_silently_clean(self):
        result = M.summarize(row() + b"type=USER_AVC msg=audit(123.456:9): opaque\n")
        self.assertEqual(result["unparsed_records"], 1)

    def test_unrelated_event_not_counted(self):
        result = M.summarize(row(source="other_t").replace(b'comm="smtp"', b'comm="other"'))
        self.assertEqual(result["matching_denials"], 0)

    def test_audit_health_is_not_no_denial_proof(self):
        def query(args, *limits):
            if args[0].endswith("auditctl"):
                return 0, b"enabled 1\npid 123\nlost 2\n"
            return 1, b""
        with patch.object(M.os, "geteuid", return_value=0):
            result = M.inspect("recent", lambda path: path, query)
        self.assertEqual(result["audit_health"], "active")
        self.assertEqual(result["audit_lost_total"], 2)
        self.assertEqual(result["status"], "no_matches_or_audit_unavailable")
        self.assertFalse(result["access_verified"])
        self.assertFalse(result["raw_records_exported"])

    def test_truncated_output_refused(self):
        with self.assertRaises(ValueError):
            M.summarize(row().rstrip(b"\n"))

    def test_read_only_gui_wiring(self):
        src = ROOT / "src/LinuxMailRelay365"
        self.assertIn('remote("avc-preview", null, null, null)', (src / "SmtpTlsRotationDialog.cs").read_text())
        self.assertIn("check-smtp-tls-avc.py", (src / "LinuxMailRelay365.csproj").read_text())
        self.assertIn("BuildSmtpTlsAvcDiagnosis", (src / "MainForm.DeliveryMiniWizard.cs").read_text())
