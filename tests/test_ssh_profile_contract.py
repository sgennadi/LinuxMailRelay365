from pathlib import Path
import unittest

CS = Path(__file__).resolve().parents[1] / "src/LinuxMailRelay365"


class SshProfileContract(unittest.TestCase):
    def test_default_and_verified_save(self):
        form = (CS / "MainForm.cs").read_text(encoding="utf-8")
        self.assertIn('sshUser = Field("root")', form)
        self.assertIn("InitializeSshProfiles();", form)
        self.assertIn("ShowSshProfiles(form, availableWidth);", form)
        self.assertIn("await CheckSshAsync();\n        RememberVerifiedSshProfile();", form)

    def test_profiles_never_store_credentials_or_trust(self):
        store = (CS / "SshProfileStore.cs").read_text(encoding="utf-8")
        self.assertIn("record SshProfile(string Host, int Port, string Username, bool PasswordMode)", store)
        self.assertIn("JsonUnmappedMemberHandling.Disallow", store)
        self.assertIn("File.Move(temporary, path, overwrite: true)", store)
        ui = (CS / "MainForm.SshProfiles.cs").read_text(encoding="utf-8")
        for field in ("sshPassword", "sudoPassword", "sshKey", "sshFingerprint"):
            self.assertIn(field + ".Clear();", ui)
        self.assertIn("approvedSshIdentity = null;", ui)
        self.assertIn('profile?.Username ?? "root"', ui)
        self.assertIn("SshProfileStore.SelfTest", (CS / "Program.cs").read_text(encoding="utf-8"))
