from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]

class MailRoutingSafetyContracts(unittest.TestCase):
    def test_safe_defaults_and_separate_server_persistence(self):
        text=(ROOT/'src/LinuxMailRelay365/MailRoutingPlan.cs').read_text(encoding='utf8')
        self.assertIn('Transport { get; set; } = "oauth2"',text)
        self.assertIn('SenderPolicy { get; set; } = "fixed-mailbox"',text)
        self.assertIn('PreserveExistingMail { get; set; } = true',text)
        self.assertIn('routing-plan-',text)
        self.assertIn('Identity("linux-b.example"',text)
        self.assertNotIn('password { get; set; }',text.lower())

    def test_existing_mta_never_modified_by_default(self):
        ui=(ROOT/'src/LinuxMailRelay365/MainForm.cs').read_text(encoding='utf8')
        self.assertIn('var inventory = MailRoutingInventory.Parse(observed.StdOut)',ui)
        self.assertIn('inventory.Mta == "postfix" && preserveExistingMail.Checked',ui)
        self.assertIn('inventory.Mta is "sendmail" or "exim"',ui)
        self.assertIn('chosenTransport != "oauth2" || chosenSender != 0',ui)
        self.assertIn('No Postfix changes were applied',ui)

    def test_domain_masquerade_never_enabled_silently(self):
        linux=(ROOT/'linux/install-postfix-m365-xoauth2.sh').read_text(encoding='utf8')
        self.assertNotIn("postconf -e 'masquerade_domains =",linux)
        self.assertNotIn("postconf -e 'sender_canonical_maps =",linux)
        ui=(ROOT/'src/LinuxMailRelay365/MainForm.cs').read_text(encoding='utf8')
        # Sender rewriting is allowed only in an independent Connector sidecar.
        self.assertIn('Connector sender handling is available under the isolated EOP route',ui)
        self.assertIn('Connector и политики сохранения/маскарада отправителя можно применить',ui)
        self.assertNotIn('Маскарад и Connector пока доступны только как план',ui)
        self.assertIn('chosenTransport != "oauth2" || chosenSender != 0',ui)
        self.assertIn('ApplyEopRouteAsync',ui)
        self.assertIn('RestoreEopRouteAsync',ui)
        self.assertIn('MailRoutingPlanStore.Save',ui)

if __name__=='__main__': unittest.main()
