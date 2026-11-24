"""Read-only outbound policy report, no real system mutations or mail."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("route_readiness", str(
    ROOT / "linux/inspect-conditional-transport-selinux-readiness.py"))
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)
RULES = [
    dict(selector="exact-envelope-sender", pattern="one@example.org",
         host="smtp.example.net", port=2526, tls="starttls", auth="password"),
    dict(selector="exact-envelope-sender", pattern="two@example.org",
         host="smtp.example.net", port=465, tls="implicit", auth="none"),
]
POLICY = ("SELinux Port Type              Proto    Port Number\n\n"
          "smtp_port_t tcp 25, 465, 587\n"
          "reserved_port_t tcp 1-1023\n"
          "unreserved_port_t tcp 1024-65535\n"
          "other_port_t tcp 2525-2527\n"
          "other_port_t udp 465\n")


class ReadinessTests(unittest.TestCase):
    def runner(self, tool, args, data=None):
        self.assertEqual(tool, "postconf")
        return 0, b"hash\nlmdb\n" if args == ["-m"] else b"cyrus\n"

    def command(self, tool, args):
        self.assertEqual((tool, args), ("semanage", ["port", "-l"]))
        return POLICY

    def report(self, mode="enforcing", requested="auto", installed=False, command=None):
        return D.report(-1, RULES, requested, installed, 0, 123,
                        lambda: None, mode, command or self.command, self.runner)

    def test_ports_and_conflicting_types(self):
        self.assertEqual(D.port_types([25, 465, 2526, 4444], POLICY),
                         {25: "smtp_port_t", 465: "smtp_port_t", 2526: "other_type",
                          4444: "no_specific_type"})
        self.assertEqual(D.port_types([465], POLICY + "other_port_t tcp 465\n"),
                         {465: "other_type"})

    def test_malformed_or_incomplete_policy_refused(self):
        for raw in ("", "smtp_port_t tcp 25\n", POLICY + "garbage\n",
                    POLICY.replace("2525-2527", "2527-2525"),
                    POLICY.replace("smtp_port_t tcp", "foreign_t tcp")):
            with self.assertRaises(D.L.Refused):
                D.port_types([25, 2526], raw)

    def test_readiness_never_authorizes_mutation(self):
        with patch.object(D.L, "observe") as observe:
            result = self.report()
        self.assertEqual(result["BACKEND"], "hash")
        self.assertEqual(result["SASL"], "cyrus_available")
        self.assertEqual(result["PORTS"], "465:smtp_port_t,2526:other_type")
        self.assertEqual(result["LABELS"], "policy_match_read_only")
        self.assertEqual(observe.call_count, 1)
        for key in ("WRITE_ALLOWED", "RUNTIME_VERIFIED", "MAIL_SENT", "CHANGES_APPLIED"):
            self.assertEqual(result[key], "no")

    def test_inactive_mode_does_not_query_policy(self):
        with patch.object(D.L, "observe", side_effect=AssertionError("label read")) as observe:
            result = self.report("inactive_or_unavailable",
                                 command=lambda *args: self.fail("policy queried"))
        observe.assert_not_called()
        self.assertEqual(result["LABELS"], "not_checked")
        self.assertEqual(result["PORTS"], "465:not_checked,2526:not_checked")

    def test_missing_tool_and_label_drift_are_unverified(self):
        with patch.object(D.L, "observe", side_effect=OSError("fixture")):
            result = self.report(command=lambda *args: None)
        self.assertEqual(result["LABELS"], "unverified")
        self.assertEqual(result["PORTS"], "465:unverified,2526:unverified")

    def test_policy_change_during_read_is_unverified(self):
        with patch.object(D.L, "observe"):
            values = iter([POLICY, POLICY + "other_port_t tcp 465\n"])
            result = self.report(command=lambda *args: next(values))
        self.assertEqual(result["PORTS"], "465:unverified,2526:unverified")

    def test_native_backend_and_sasl_do_not_guess(self):
        def runner(tool, args, data=None):
            return 0, b"lmdb\n" if args == ["-m"] else b""
        self.assertEqual(D.native_options(RULES, "auto", runner), ("lmdb", "unavailable"))
        self.assertEqual(D.native_options(RULES, "hash", runner), ("unavailable", "unavailable"))
        with self.assertRaises(D.L.Refused):
            self.report(installed=True)

    def test_gui_embedded_and_read_only(self):
        cs = ROOT / "src/LinuxMailRelay365"
        assets = {item.attrib.get("Include") for item in
                  ET.parse(cs / "LinuxMailRelay365.csproj").iter("EmbeddedResource")}
        for name in ("inspect-conditional-transport-selinux.py",
                     "inspect-conditional-transport-selinux-readiness.py"):
            self.assertIn("../../linux/" + name, assets)
        ui = (cs / "MainForm.TransportSelinux.cs").read_text(encoding="utf-8")
        self.assertIn("TransportSelinuxContext() != context", ui)
        self.assertIn("TransportSelinuxClient.Parse", ui)
        self.assertNotIn("result.StdErr", ui)
        panel = (cs / "MainForm.MultiTransport.cs").read_text(encoding="utf-8")
        self.assertLess(panel.index("ShowTransportSelinuxReadiness(page, width, l)"),
                        panel.index("if (OfflineHostContext() is null)"))
        self.assertIn("TransportSelinuxClient.SelfTest", (cs / "Program.cs").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
