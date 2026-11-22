"""Explicit SMTP/25 must never replace an installed primary MTA.
This is a test-only input/contract suite; no Linux service or mail is changed.
"""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_CASES = (
    ("linux/install-preserve-postfix-sidecar.sh", [
        "--check-only", "--tenant-id", "11111111-1111-4111-8111-111111111111",
        "--client-id", "22222222-2222-4222-8222-222222222222",
        "--mailbox", "alerts@example.org"]),
    ("linux/install-direct-send-sidecar.sh", [
        "--check-only", "--mx-host", "example-org.mail.protection.outlook.com",
        "--accepted-domain", "example.org", "--fixed-sender", "alerts@example.org"]),
    ("linux/install-connector-sidecar.sh", [
        "--check-only", "--mx-host", "example-org.mail.protection.outlook.com",
        "--accepted-domain", "example.org", "--fixed-sender", "alerts@example.org",
        "--public-ip", "8.8.8.8"]),
)

class StandardSMTP25ChoiceTests(unittest.TestCase):
    def test_all_new_sidecars_accept_explicit_25_but_not_other_privileged_ports(self):
        for script, args in SCRIPT_CASES:
            for port in ("25", "2525", "46500", "587", "465", "22"):
                with self.subTest(script=script, port=port):
                    result = subprocess.run(
                        ["bash", str(ROOT / script)] + args + ["--smtp-port", port],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        universal_newlines=True, timeout=10)
                    if port in ("25", "2525", "46500"):
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn("CHANGES_APPLIED=no" if "preserve" not in script
                                      else "SIDECAR_APPLIED=no", result.stdout)
                    else:
                        self.assertNotEqual(result.returncode, 0)

    def test_port25_checks_occupied_socket_and_primary_reboot_state(self):
        for script, _ in SCRIPT_CASES:
            content = (ROOT / script).read_text(encoding="utf-8")
            self.assertIn("smtp_socket_scan_failed", content)
            self.assertIn("port_already_bound", content)
            self.assertIn("primary_mta_may_claim_port25" if "preserve" not in script
                          else "primary_mta_may_claim_port25", content)
            self.assertIn("postfix.service exim.service exim4.service sendmail.service", content)
            self.assertLess(content.index("primary_mta_may_claim_port25"),
                            content.index("systemctl enable --now linuxmailrelay365-sidecar.service"))

    def test_gui_offers_25_separately_and_outbound_m365_port_is_unchanged(self):
        main = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        plan = (ROOT / "src/LinuxMailRelay365/MailRoutingPlan.cs").read_text(encoding="utf-8")
        self.assertIn('isolatedSmtpPort.Text = "25";', main)
        self.assertIn("StandardPort25Observation()", main)
        self.assertIn("port == 25 || port is >= 1024 and <= 65535", plan)
        self.assertIn("SidecarPort { get; set; } = 2525", plan)
        self.assertIn("SMTP/25 selected as a plan only", main)
        self.assertIn('relayhost = [$MX]:25', (ROOT /
            "linux/install-connector-sidecar.sh").read_text(encoding="utf-8"))

    def test_hostname_probe_never_silently_uses_2525(self):
        main = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        assets = (ROOT / "src/LinuxMailRelay365/EmbeddedAssets.cs").read_text(encoding="utf-8")
        section = main.split("private async Task InspectMailRoutingAsync()", 1)[1]
        section = section.split("private string? TryCurrentIdentity()", 1)[0]
        self.assertIn("int? checkPort = null;", section)
        self.assertIn("int.TryParse(isolatedSmtpPort.Text.Trim(), out int candidatePort)", section)
        self.assertIn("SmtpIngressPort.Supported(candidatePort)", section)
        self.assertIn("No implicit TCP 2525 fallback.", section)
        self.assertIn("EmbeddedAssets.BuildMailHostInspectionBundle(checkPort, inventory.Mta)", section)
        self.assertIn("Configured inbound SMTP ports: ", section)
        self.assertNotIn("? checkPort : 2525", section)
        self.assertNotIn("BuildMailHostInspectionBundle(2525", section)
        self.assertIn("BuildMailHostInspectionBundle(int? selectedPort = null,", assets)
        self.assertIn("--configured-ports", assets)
        self.assertIn("selectedPort.HasValue ? \"--smtp-port \"", assets)


if __name__ == "__main__":
    unittest.main()
