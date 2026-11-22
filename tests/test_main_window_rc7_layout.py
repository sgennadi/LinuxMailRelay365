"""RC7 real WinForms main-window layout and update entry contracts.

No installation, SSH, profile execution, or network calls are performed.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")


class MainWindowLayoutRC7Contracts(unittest.TestCase):
    def test_clear_update_toolbar_is_outside_ssh_card(self):
        self.assertIn('UiTheme.Action("Проверить обновления", glyph: "refresh")', MAIN)
        self.assertIn('headerUpdateButton.Text = T("Проверить обновления', MAIN)
        self.assertIn('headerUpdateButton.Click += (_, _) => ShowHeaderUpdateMenu();', MAIN)
        self.assertIn('top.Controls.Add(updateToolbar, 0, 1);', MAIN)
        self.assertIn('top.SetColumnSpan(updateToolbar, 3);', MAIN)
        self.assertIn('ColumnCount = 3, RowCount = 2', MAIN)
        self.assertIn('headerUpdateMenu.Items.Add(stable);', MAIN)
        self.assertIn('headerUpdateMenu.Items.Add(preview);', MAIN)
        self.assertIn('previewUpdates.Checked = false;', MAIN)
        self.assertIn('previewUpdates.Checked = true;', MAIN)
        self.assertIn('RunBusyAsync("update", CheckUpdatesAsync)', MAIN)
        self.assertIn('ExpandActivityForUpdates();', MAIN)
        page0 = MAIN.split('case 0:\n                RenderConnectionStep(page);', 1)
        self.assertEqual(len(page0), 2)
        self.assertEqual(MAIN.count('AddUpdateAccess(page);'), 1)

    def test_full_width_credentials_and_collapsible_advanced_section(self):
        section = MAIN.split('private void RenderConnectionStep(TableLayoutPanel page)', 1)[1].split(
            'private async Task CheckSshAndContinueAsync()', 1)[0]
        self.assertIn('ColumnCount = 1, RowCount = 0', section)
        self.assertIn('form.MaximumSize = new Size(availableWidth, 0)', section)
        self.assertIn('AddConnectionPair(form,', section)
        self.assertIn('sshAuthMode.SelectedIndex == 1', section)
        self.assertIn('specifyHostKeyManually.Checked', section)
        self.assertIn('sshHelpExpanded = !sshHelpExpanded;', section)
        self.assertIn('if (sshHelpExpanded)', section)
        self.assertIn('InspectSshLoginProfileAsync', section)
        self.assertIn('AddLine(cards, helpToggle);', section)
        self.assertNotIn('ColumnCount = connectionWideLayout ? 2 : 1', section)
        self.assertNotIn('availableWidth * 63 / 100', section)
        self.assertNotIn('AddUpdateAccess(page)', section)
        # At 200% DPI inputs stack without changing SSH auth semantics.
        self.assertIn('bool pairFields = connectionWideLayout;', section)
        self.assertIn('UseWideConnectionLayout(pageHost.ClientSize.Width, DeviceDpi)', section)

    def test_login_checks_and_safe_update_workflow_are_unchanged(self):
        self.assertIn('RunBusyAsync("ssh", CheckSshAndContinueAsync)', MAIN)
        self.assertIn('SshRemote.ProbeLoginProfileAsync(Endpoint())', MAIN)
        self.assertIn('SignedPortableUpdater.StageAndLaunchAsync(', MAIN)
        self.assertIn('SignedPortableUpdater.CanInstallPreview(out _)', MAIN)
        self.assertIn('SignedPortableUpdater.CanInstall(out string publisher', MAIN)
        self.assertIn('MessageBoxButtons.YesNoCancel', MAIN)
        self.assertIn('ClearVisibleActivityText(activity)', MAIN)

    def test_actual_screen_captures_cover_advanced_panel(self):
        for image in ('01-linux-help-expanded.png', '01-linux-help-expanded-bottom.png',
                      '01-linux-help-compact.png'):
            self.assertIn(image, MAIN)


if __name__ == "__main__":
    unittest.main()
