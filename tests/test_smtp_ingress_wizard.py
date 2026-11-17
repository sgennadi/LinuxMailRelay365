from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]

class ReadOnlyIngressUiContract(unittest.TestCase):
    def test_ui_wires_installer_listener_and_subnets(self):
        source=(ROOT/'src/LinuxMailRelay365/MainForm.cs').read_text(encoding='utf-8')
        for text in ['--listen-ip', '--trusted-network', 'smtpListenIp',
                     'smtpTrustedCidrs', 'MailRoutingPlanStore.Validate(routingPlan)']:
            self.assertIn(text, source)
        bundle=(ROOT/'src/LinuxMailRelay365/EmbeddedAssets.cs').read_text(encoding='utf-8')
        self.assertIn("or '/'",bundle)
    def test_local_default_is_loopback_and_mta_preserved(self):
        plan=(ROOT/'src/LinuxMailRelay365/MailRoutingPlan.cs').read_text(encoding='utf-8')
        self.assertIn('public string ListenIpv4 { get; set; } = "";',plan)
        self.assertIn('public string TrustedCidrs { get; set; } = "";',plan)
        self.assertIn('PreserveExistingMail { get; set; } = true',plan)
if __name__=='__main__': unittest.main()
