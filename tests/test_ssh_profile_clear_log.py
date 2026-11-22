"""Windows SSH login-profile diagnostics and clear-visible-log regression contracts."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/LinuxMailRelay365"


class SshProfileAndActivityTests(unittest.TestCase):
    def test_login_profile_is_explicitly_opt_in_not_auto_sourced(self):
        ssh = (SOURCE / "SshRemote.cs").read_text(encoding="utf-8")
        gui = (SOURCE / "MainForm.cs").read_text(encoding="utf-8")
        program = (SOURCE / "Program.cs").read_text(encoding="utf-8")
        self.assertIn('private const string LoginProfileProbeCommand =', ssh)
        self.assertIn('bash -lc', ssh)
        self.assertIn('ProbeLoginProfileAsync', ssh)
        self.assertIn('SummarizeLoginProfileProbe(RemoteResult report)', ssh)
        self.assertIn('LoginProfileProbeSelfTest', program)
        self.assertIn('InspectSshLoginProfileAsync, false, "check", "ssh-login-profile"', gui)
        section = gui.split("private async Task InspectSshLoginProfileAsync()", 1)[1].split(
            "private async Task CheckSshAsync()", 1)[0]
        self.assertIn("MessageBoxButtons.YesNo", section)
        self.assertIn("if (answer != DialogResult.Yes) return;", section)
        self.assertIn("SshRemote.ProbeLoginProfileAsync(Endpoint())", section)
        self.assertIn("SshRemote.SummarizeLoginProfileProbe(result)", section)
        self.assertNotIn("result.StdOut", section)
        self.assertNotIn("result.StdErr", section)
        normal_ssh = ssh.split("internal static async Task<RemoteResult> ExecuteAsync(", 1)[1].split(
            "internal static Task<RemoteResult> RunRootScriptAsync(", 1)[0]
        self.assertNotIn("bash -lc", normal_ssh)
        self.assertNotIn("/etc/profile", normal_ssh)

    def test_non_login_checks_have_system_path(self):
        ssh = (SOURCE / "SshRemote.cs").read_text(encoding="utf-8")
        assets = (SOURCE / "EmbeddedAssets.cs").read_text(encoding="utf-8")
        self.assertIn("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", ssh)
        self.assertGreaterEqual(assets.count(
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"), 2)
        for method in ("BuildMailHostInspectionBundle", "BuildExistingSmtpAuditBundle"):
            section = assets.split("internal static string " + method, 1)[1].split(
                "\n    internal static ", 1)[0]
            self.assertIn("export PATH", section)
            self.assertNotIn("source /etc/profile", section)
            self.assertNotIn("bash -lc", section)

    def test_clear_affects_only_visible_text_not_diagnostics_history(self):
        gui = (SOURCE / "MainForm.cs").read_text(encoding="utf-8")
        program = (SOURCE / "Program.cs").read_text(encoding="utf-8")
        icons = (SOURCE / "UiIcons.cs").read_text(encoding="utf-8")
        self.assertIn('UiTheme.Action("Clear log", glyph: "trash")', gui)
        self.assertIn('clearActivityButton.Click += (_, _) => ClearActivityWindow();', gui)
        self.assertIn('clearActivityButton.Text = T("Очистить лог", "Clear log"', gui)
        self.assertIn('activityPanel.Controls.Add(activityLayout);', gui)
        self.assertIn('case "trash":', icons)
        section = gui.split("private void ClearActivityWindow()", 1)[1].split(
            "private void WriteLine(", 1)[0]
        self.assertIn("ClearVisibleActivityText(activity);", section)
        self.assertIn("textbox.Clear()", section)
        self.assertNotIn("journal.", section)
        self.assertNotIn("File.", section)
        self.assertNotIn("Directory.", section)
        self.assertIn("ClearActivityWindowSelfTest", program)


if __name__ == "__main__":
    unittest.main()
