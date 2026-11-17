from pathlib import Path
import hashlib
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "windows" / "Initialize-LinuxMailRelay365.ps1"

class SharedAppMailboxScopeTests(unittest.TestCase):
    def test_second_mailbox_has_distinct_scope(self):
        app = "123456781234123412341234567890ab"
        def scope(mailbox):
            digest = hashlib.sha256(mailbox.lower().encode("utf-8")).hexdigest().upper()[:16]
            return "LMR365-" + app[:16] + "-" + digest
        self.assertEqual(scope("one@example.org"), scope("ONE@example.org"))
        self.assertNotEqual(scope("one@example.org"), scope("two@example.org"))
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("GetBytes($Mailbox)", source)
        self.assertIn("$prefix = $appPrefix + '-' + $mailboxKey", source)
        self.assertIn("Get-ManagementScope -Identity $prefix", source)
        self.assertIn("New-ManagementRoleAssignment -Name $assignmentName", source)
        self.assertIn("Test-ServicePrincipalAuthorization", source)

    def test_legacy_and_existing_attributes_are_preserved(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("if ($existingTag -eq $appPrefix)", source)
        self.assertIn("$prefix = $appPrefix", source)
        self.assertIn("CustomAttribute15 is already used", source)
        self.assertIn("refusing to broaden access", source)
        self.assertIn("Set-CASMailbox -Identity $Mailbox", source)
        self.assertNotIn("Set-TransportConfig", source)
        self.assertNotIn("Set-ConditionalAccessPolicy", source)

if __name__ == "__main__":
    unittest.main()
