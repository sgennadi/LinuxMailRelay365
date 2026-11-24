using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    private IReadOnlyList<SshProfile> sshProfiles = Array.Empty<SshProfile>();
    private bool loadingSshProfile;
    private SshProfile? selectedSshProfile;
    private bool SshProfilesEnabled => Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true";

    private void InitializeSshProfiles()
    {
        if (!SshProfilesEnabled) return;
        try
        {
            sshProfiles = SshProfileStore.Load(dataDirectory);
            if (sshProfiles.FirstOrDefault() is { } recent) LoadSshProfile(recent);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   System.Text.Json.JsonException or ArgumentException or InvalidDataException)
        {
            WriteLine("WARNING: Saved SSH profiles could not be loaded (" + ex.GetType().Name + ").");
        }
    }

    private void LoadSshProfile(SshProfile? profile)
    {
        if (busy) return;
        loadingSshProfile = true;
        try
        {
            // Do not carry credentials, key paths or trust from the previous
            // server, even when two profiles have the same hostname.
            sshPassword.Clear();
            sudoPassword.Clear();
            sshKey.Clear();
            sshFingerprint.Clear();
            approvedSshIdentity = null;
            automaticallyPinnedSshFingerprint = null;
            specifyHostKeyManually.Checked = false;
            host.Text = profile?.Host ?? "";
            sshPort.Text = (profile?.Port ?? 22).ToString(System.Globalization.CultureInfo.InvariantCulture);
            sshUser.Text = profile?.Username ?? "root";
            sshAuthMode.SelectedIndex = profile?.PasswordMode == true ? 1 : 0;
            selectedSshProfile = profile;
        }
        finally { loadingSshProfile = false; }
    }

    private void RememberVerifiedSshProfile()
    {
        if (!SshProfilesEnabled) return;
        try
        {
            // Called only after CheckSshAsync succeeds. Metadata only.
            var profile = new SshProfile(host.Text.Trim(), int.Parse(sshPort.Text,
                System.Globalization.CultureInfo.InvariantCulture), sshUser.Text.Trim(),
                sshAuthMode.SelectedIndex == 1);
            sshProfiles = SshProfileStore.Remember(dataDirectory, profile);
            selectedSshProfile = profile;
            WriteLine("SSH connection profile saved (server, port, username and authentication method only).");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   System.Text.Json.JsonException or ArgumentException or InvalidDataException or FormatException)
        {
            WriteLine("WARNING: SSH profile was not saved (" + ex.GetType().Name + ").");
        }
    }

    private void ShowSshProfiles(TableLayoutPanel card, int width)
    {
        var picker = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Enabled = !busy };
        picker.Items.Add(T("Новое подключение", "New connection", "חיבור חדש"));
        foreach (var profile in sshProfiles) picker.Items.Add(profile);
        int index = selectedSshProfile is null ? -1 :
            Array.FindIndex(sshProfiles.ToArray(), p => p.SameEndpoint(selectedSshProfile));
        picker.SelectedIndex = index + 1;
        AddConnectionField(card, T("Сохранённые подключения", "Saved SSH connections", "חיבורי SSH שמורים"), picker);
        picker.SelectionChangeCommitted += (_, _) =>
        {
            if (busy) return;
            LoadSshProfile(picker.SelectedItem as SshProfile);
            RenderPage();
        };
        if (selectedSshProfile is { } saved)
        {
            var remove = UiTheme.Action(T("Удалить выбранный профиль", "Forget selected profile", "שכח פרופיל נבחר"), glyph: "trash");
            remove.Enabled = !busy;
            remove.Click += (_, _) =>
            {
                if (busy || MessageBox.Show(this, T("Удалить только локальный профиль подключения?",
                    "Remove only this local connection profile?", "למחוק רק את פרופיל החיבור המקומי?"),
                    Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                try
                {
                    sshProfiles = SshProfileStore.Remove(dataDirectory, saved);
                    selectedSshProfile = null;
                    RenderPage();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                           System.Text.Json.JsonException or ArgumentException or InvalidDataException)
                {
                    WriteLine("WARNING: SSH profile was not removed (" + ex.GetType().Name + ").");
                }
            };
            AddLine(card, remove);
        }
        AddConnectionHelp(card, T(
            "Успешные подключения сохраняются автоматически. Пароли, закрытые ключи и доверие SSH host key не сохраняются.",
            "Successful connections are remembered automatically. Passwords, private keys and SSH host-key trust are not saved.",
            "חיבורים מוצלחים נשמרים אוטומטית. סיסמאות, מפתחות פרטיים ואמון במפתח השרת אינם נשמרים."),
            width - 64);
    }
}
