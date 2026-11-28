using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    // CI-only real queue windows with synthetic metadata. The capture callback
    // disables every remote action in the production dialogs, including Refresh.
    internal int CaptureQueueScreens(string? directory)
    {
        if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
            string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("RUNNER_TEMP")) ||
            !Visible || InvokeRequired)
            throw new InvalidOperationException("Queue capture requires the disposable Windows UI runner.");

        string? target = directory is null ? null : Path.GetFullPath(directory);
        if (target is not null) Directory.CreateDirectory(target);
        var endpoint = new SshEndpoint("queue-fixture.invalid", 22, "root", "");
        string nonce = new('a', 64);
        long sampled = 1760000000;
        int captured = 0;
        var manifest = new List<string>();
        int originalLanguage = language.SelectedIndex;
        string variant = "";
        string locale = "";

        void Capture(Form dialog, Panel viewport, DataGridView grid, FlowLayoutPanel footer)
        {
            dialog.Show(this);
            try
            {
                Application.DoEvents();
                var desktop = Screen.FromControl(dialog).WorkingArea;
                void SetSize(int width, int height)
                {
                    viewport.AutoScrollPosition = Point.Empty;
                    dialog.Size = new Size(Math.Min(width, desktop.Width - 32),
                        Math.Min(height, desktop.Height - 32));
                    dialog.PerformLayout();
                    Application.DoEvents();
                    if (dialog.Width > desktop.Width || dialog.Height > desktop.Height)
                        throw new InvalidOperationException("Queue dialog exceeds working desktop.");
                }
                void Reach(Control control)
                {
                    int logicalTop = viewport.PointToClient(control.PointToScreen(Point.Empty)).Y -
                        viewport.AutoScrollPosition.Y;
                    viewport.AutoScrollPosition = new Point(0, Math.Max(0, logicalTop - 4));
                    Application.DoEvents();
                    var bounds = new Rectangle(viewport.PointToClient(control.PointToScreen(Point.Empty)), control.Size);
                    var intersection = Rectangle.Intersect(viewport.ClientRectangle, bounds);
                    if (!control.Visible || intersection.Width <= 0 || intersection.Height <= 0 ||
                        bounds.Left < -2 || bounds.Right > viewport.ClientSize.Width + 2)
                        throw new InvalidOperationException("Queue control unreachable: " + control.GetType().Name);
                    if (control is Button && intersection.Height + 2 < bounds.Height)
                        throw new InvalidOperationException("Queue action clipped vertically.");
                }
                void Validate()
                {
                    if (grid.Rows.Count == 0 || grid.Height < QueueDialogLayout.Scale(150, dialog.DeviceDpi))
                        throw new InvalidOperationException("Queue table collapsed or empty.");
                    Reach(grid);
                    var buttons = footer.Controls.OfType<Button>().ToArray();
                    if (buttons.Length < 3 || buttons.Count(button => button.Enabled) != 1 ||
                        dialog.CancelButton is not Button close || !close.Enabled)
                        throw new InvalidOperationException("Synthetic queue action isolation failed.");
                    foreach (var button in buttons) Reach(button);
                }
                void Save(string region)
                {
                    dialog.Refresh();
                    Application.DoEvents();
                    // Ordinary CI verifies control geometry without
                    // capturing or retaining any rendered pixels.
                    if (target is not null)
                    {
                        using var bitmap = new Bitmap(dialog.Width, dialog.Height);
                        dialog.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size));
                        string name = locale + "-" + variant + "-" + region + ".png";
                        bitmap.Save(Path.Combine(target, name), ImageFormat.Png);
                        manifest.Add(name + " | actual DPI=" + dialog.DeviceDpi +
                            " | client=" + dialog.ClientSize.Width + "x" + dialog.ClientSize.Height);
                    }
                    Reach(region == "compact-table" ? grid : (Control)dialog.CancelButton!);
                    captured++;
                }

                SetSize(1050, 800);
                Validate();
                SetSize(760, 600);
                Validate();
                Reach(grid);
                Save("compact-table");
                if (dialog.CancelButton is not Button closeButton)
                    throw new InvalidOperationException("Queue close action unavailable.");
                Reach(closeButton);
                Save("compact-actions");
            }
            finally { dialog.Close(); }
        }

        try
        {
            for (int lang = 0; lang < 3; lang++)
            {
                language.SelectedIndex = lang;
                locale = new[] { "ru", "en", "he" }[lang];
                foreach (string scope in new[] { "postfix", "sidecar" })
                {
                    variant = scope;
                    var sample = new QueueMessageInventory(scope, "ok", 4, false,
                    [
                        new(1, "deferred", 240, 18294, 1, "auth"),
                        new(2, "held", 125, 4321, 2, "not_applicable"),
                        new(3, "active", 20, 877, 1, "not_applicable"),
                        new(4, "deferred", 7, 1400, 1, "temporary")
                    ], sampled, "unverified");
                    ShowQueueMessages(endpoint, sample, nonce, Capture);
                }
                variant = "exim";
                ShowEximQueue(endpoint, nonce, new EximQueueInventory("ok", sampled, 2, false, false,
                    [new(1, "frozen", 90, "12K", 1, 0, "-"),
                     new(2, "queued", 4, "3K", 2, 0, "-")]), Capture);
                foreach (string queue in new[] { "mta", "msp" })
                foreach (bool quarantine in new[] { false, true })
                {
                    variant = "sendmail-" + queue + (quarantine ? "-quarantine" : "-normal");
                    ShowSendmailQueue(endpoint, new SendmailQueueInventory(queue, "ok", 3, 1, 3,
                        false, false,
                        [new(1, 1, "queued", 1200, "Wed Nov 25 09:00", "auth"),
                         new(2, 1, "load_limited", 2100, "Wed Nov 25 09:01", "temporary"),
                         new(3, 1, "too_young", 500, "Wed Nov 25 09:02", "no_reason")],
                         sampled, false, quarantine), nonce, Capture);
                }
            }
        }
        finally { language.SelectedIndex = originalLanguage; }
        if (target is not null) File.WriteAllLines(Path.Combine(target, "README.txt"),
            new[] { "Real WinForms queue dialogs with synthetic metadata only.",
                "Normal and compact geometry checked; SSH, SMTP and mutation disabled.",
                "These screenshots record the actual runner DPI, not simulated 200% monitor DPI." }.Concat(manifest));
        return captured;
    }
}
