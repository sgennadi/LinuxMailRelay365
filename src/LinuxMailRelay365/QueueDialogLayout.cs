using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

// Keep the message table usable even when translations, warnings, or action
// buttons wrap. The entire content remains reachable in a vertical viewport;
// a long help label must not consume the table's available height.
internal static class QueueDialogLayout
{
    internal static int Scale(int logical, int dpi) =>
        (int)Math.Ceiling(logical * Math.Max(96, dpi) / 96.0);

    internal static int ContentWidth(int clientWidth, int dpi, int scrollbarWidth) =>
        Math.Max(1, clientWidth - Math.Max(Scale(20, dpi), scrollbarWidth) - 2);

    internal static int GridHeight(int clientHeight, int dpi) =>
        Math.Max(Scale(180, dpi), (int)Math.Round(clientHeight * 0.43));

    internal static Panel Attach(Form dialog, TableLayoutPanel root, params Label[] wrappingLabels)
    {
        var viewport = new Panel
        {
            Dock = DockStyle.Fill, AutoScroll = true, BackColor = UiTheme.Canvas,
            TabStop = false
        };
        root.Dock = DockStyle.None;
        root.Anchor = AnchorStyles.Top | AnchorStyles.Left;
        root.Location = Point.Empty;
        root.AutoSize = true;
        root.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        root.RowStyles[2].SizeType = SizeType.Absolute;
        viewport.Controls.Add(root);
        dialog.Controls.Add(viewport);
        bool fitting = false;
        void Fit()
        {
            if (fitting || dialog.IsDisposed) return;
            fitting = true;
            root.SuspendLayout();
            try
            {
                int dpi = Math.Max(96, dialog.DeviceDpi);
                // Reserve the vertical scrollbar before measuring labels.
                // Use form width, not changing scrollbar-dependent width,
                // to avoid a resize/reflow feedback loop.
                int width = ContentWidth(dialog.ClientSize.Width, dpi, SystemInformation.VerticalScrollBarWidth);
                root.MaximumSize = new Size(width, 0);
                root.MinimumSize = new Size(width, 0);
                root.Width = width;
                root.RowStyles[2].Height = GridHeight(dialog.ClientSize.Height, dpi);
                int labelWidth = Math.Max(1, width - root.Padding.Horizontal - Scale(18, dpi));
                foreach (var label in wrappingLabels)
                    label.MaximumSize = new Size(labelWidth, 0);
            }
            finally
            {
                root.ResumeLayout(true);
                fitting = false;
            }
        }
        dialog.ClientSizeChanged += (_, _) => Fit();
        dialog.Shown += (_, _) => Fit();
        dialog.DpiChanged += (_, _) =>
        {
            if (!dialog.IsDisposed && dialog.IsHandleCreated)
                dialog.BeginInvoke(new Action(Fit));
        };
        Fit();
        return viewport;
    }

    internal static bool SelfTest() =>
        ContentWidth(760, 96, 17) == 738 &&
        ContentWidth(760, 192, 17) == 718 &&
        ContentWidth(10, 192, 17) == 1 &&
        GridHeight(200, 96) == 180 &&
        GridHeight(200, 192) == 360 &&
        GridHeight(900, 192) == 387 &&
        Scale(180, 144) == 270;
}
