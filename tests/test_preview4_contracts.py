from pathlib import Path
import unittest
import re

ROOT = Path(__file__).resolve().parents[1]

class Preview4Contracts(unittest.TestCase):
    def test_app_icon_and_version_synchronized(self):
        proj = (ROOT/'src/LinuxMailRelay365/LinuxMailRelay365.csproj').read_text()
        app = (ROOT/'src/LinuxMailRelay365/MainForm.cs').read_text()
        fallback = (ROOT/'src/LinuxMailRelay365/UpdateCheck.Fallback.cs').read_text()
        version = re.search(r'<Version>(\d+\.\d+\.\d+(?:-preview\.\d+)?)</Version>', proj)
        assert version is not None
        current = version.group(1)
        shared = (ROOT/'src/LinuxMailRelay365/UpdateCheck.cs').read_text()
        readme = (ROOT/'README.md').read_text()
        assert current in fallback and current in shared and current in readme
        assert '<ApplicationIcon>Assets/LinuxMailRelay365.ico</ApplicationIcon>' in proj
        assert 'GetManifestResourceStream("LinuxMailRelay365.BrandIcon")' in app
        assert (ROOT/'src/LinuxMailRelay365/Assets/LinuxMailRelay365.ico').stat().st_size > 1024

    def test_diagnostics_privacy_and_visible_export(self):
        app = (ROOT/'src/LinuxMailRelay365/MainForm.cs').read_text()
        journal = (ROOT/'src/LinuxMailRelay365/DiagnosticJournal.cs').read_text()
        for method in ('CopySafeReportAsync', 'SaveSafeReportAsync'):
            assert method in app
        assert 'DiagnosticJournal.SanitizeLocalActivity' in app
        assert 'journal.Record(category, "failed")' in app
        assert 'private_key' not in journal.split('new\n        {',1)[-1].split('};',1)[0]
        assert 'secretMaterialIncluded = false' in journal

    def test_optional_shared_updater_with_standalone_ci(self):
        proj = (ROOT/'src/LinuxMailRelay365/LinuxMailRelay365.csproj').read_text()
        workflow = (ROOT/'.github/workflows/ci.yml').read_text()
        assert 'UseSharedUpdater' in proj and 'USE_UNIVERSAL_UPDATER' in proj
        assert "-p:UseSharedUpdater=false" in workflow
        assert 'win-arm64' in workflow and 'win-x64' in workflow
        # Upload action v6 is native Node.js 24; v4 was deprecated Node 20.
        assert 'actions/upload-artifact@v6' in workflow
        assert 'actions/upload-artifact@v4' not in workflow
        assert 'MODULES_READ_TOKEN' not in workflow

if __name__ == '__main__':
    unittest.main()
