using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace LinuxMailRelay365;

// Shared visual language: compact native Windows controls, green only for the primary
// action/success, navy for navigation, restrained neutral surfaces and DPI-safe text.
internal static class UiTheme
{
    internal static readonly Color Canvas = Color.FromArgb(246, 248, 251);
    internal static readonly Color Navy = Color.FromArgb(20, 46, 82);
    internal static readonly Color Muted = Color.FromArgb(80, 94, 112);
    internal static readonly Color Accent = Color.FromArgb(15, 118, 92);
    internal static readonly Color Border = Color.FromArgb(214, 221, 230);
    internal static readonly Color InfoSurface = Color.FromArgb(230, 241, 255);
    internal static readonly Color WarningSurface = Color.FromArgb(255, 244, 216);
    internal static readonly Color WarningInk = Color.FromArgb(121, 67, 11);
    internal static readonly Color SuccessSurface = Color.FromArgb(224, 247, 235);

    // Color supplements words; never convey state with color alone.
    internal static Label Emphasis(string caption, int width, bool warning = false, bool success = false)
    {
        var label = Text(caption, heading: true);
        label.MaximumSize = new Size(Math.Max(240, width), 0);
        label.Padding = new Padding(10, 8, 10, 8);
        label.BackColor = SystemInformation.HighContrast ? SystemColors.Window :
            warning ? WarningSurface : success ? SuccessSurface : InfoSurface;
        label.ForeColor = SystemInformation.HighContrast ? SystemColors.WindowText :
            warning ? WarningInk : success ? Accent : Navy;
        return label;
    }

    internal static void HighlightInput(Control input)
    {
        if (SystemInformation.HighContrast || input is not (TextBox or ComboBox)) return;
        input.BackColor = InfoSurface;
        input.ForeColor = Navy;
    }

    internal static Button Action(string label, bool primary = false, string glyph = "") =>
        new ModernActionButton(label, primary, glyph);

    internal static Label Text(string caption, bool heading = false) => new()
    {
        Text = caption,
        AutoSize = true,
        ForeColor = heading ? Navy : Muted,
        Font = new Font(heading ? "Segoe UI Semibold" : "Segoe UI", heading ? 14f : 10f,
                        heading ? FontStyle.Bold : FontStyle.Regular),
        Margin = new Padding(0, 5, 0, 5),
        MaximumSize = new Size(930, 0)
    };
}

internal sealed class ModernActionButton : Button
{
    private readonly bool primary;
    private readonly string glyph;
    private bool hovered;
    private bool pressed;

    internal ModernActionButton(string title, bool primary, string glyph)
    {
        this.primary = primary;
        this.glyph = glyph;
        Text = title;
        AccessibleName = title;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        UseMnemonic = false;
        MinimumSize = new Size(122, 42);
        Margin = new Padding(0, 5, 8, 5);
        Padding = new Padding(14, 7, 14, 7);
        Font = new Font("Segoe UI Semibold", 10f, FontStyle.Bold);
        Cursor = Cursors.Hand;
        TabStop = true;
        FlatStyle = FlatStyle.Flat;
        FlatAppearance.BorderSize = 0;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
    }

    public override Size GetPreferredSize(Size proposedSize)
    {
        float scale = IsHandleCreated ? DeviceDpi / 96f : 1f;
        int parentWidth = Parent?.ClientSize.Width ?? (int)(720 * scale);
        int availableTextWidth = Math.Max((int)(170 * scale),
            Math.Min((int)(570 * scale), parentWidth - (int)(100 * scale)));
        var measured = TextRenderer.MeasureText(Text, Font,
            new Size(availableTextWidth, (int)(360 * scale)),
            TextFormatFlags.NoPrefix | TextFormatFlags.WordBreak);
        int iconWidth = glyph.Length > 0 ? (int)(23 * scale) : 0;
        return new Size(Math.Max((int)(122 * scale),
                            Math.Min(availableTextWidth, measured.Width) + iconWidth + (int)(37 * scale)),
                        Math.Max((int)(42 * scale), measured.Height + (int)(19 * scale)));
    }

    protected override void OnMouseEnter(EventArgs e) { base.OnMouseEnter(e); hovered = true; Invalidate(); }
    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); hovered = false; pressed = false; Invalidate(); }
    protected override void OnMouseDown(MouseEventArgs e) { base.OnMouseDown(e); pressed = true; Invalidate(); }
    protected override void OnMouseUp(MouseEventArgs e) { base.OnMouseUp(e); pressed = false; Invalidate(); }
    protected override void OnEnabledChanged(EventArgs e) { base.OnEnabledChanged(e); Invalidate(); }
    protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
    protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }

    protected override void OnPaint(PaintEventArgs e)
    {
        if (SystemInformation.HighContrast) { base.OnPaint(e); return; }
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Parent?.BackColor ?? UiTheme.Canvas);
        if (Width <= 4 || Height <= 4) return;
        float scale = DeviceDpi / 96f;
        var outer = new Rectangle(1, 1, Width - 3, Height - 3);
        using var shape = Rounded(outer, Math.Max(4, (int)(7 * scale)));
        var bg = primary ? UiTheme.Accent : Color.White;
        if (hovered && Enabled) bg = primary ? Color.FromArgb(10, 103, 80) : Color.FromArgb(233, 239, 245);
        if (pressed && Enabled) bg = primary ? Color.FromArgb(5, 92, 72) : Color.FromArgb(225, 233, 240);
        if (!Enabled) bg = Color.FromArgb(236, 239, 241);
        using var bgBrush = new SolidBrush(bg);
        g.FillPath(bgBrush, shape);
        using var pen = new Pen(primary && Enabled ? bg : UiTheme.Border, 1);
        g.DrawPath(pen, shape);
        Color ink = !Enabled ? Color.FromArgb(126, 136, 145) : primary ? Color.White : UiTheme.Navy;
        var textBounds = new Rectangle(12, 2, Math.Max(1, Width - 24), Math.Max(1, Height - 4));
        if (glyph.Length > 0)
        {
            int iconSize = (int)Math.Max(16, 19 * scale);
            int x = Math.Max(12, (Width - TextRenderer.MeasureText(Text, Font).Width - iconSize - (int)(10 * scale)) / 2);
            using var image = UiIcons.Draw(glyph, ink, iconSize);
            g.DrawImage(image, x, (Height - iconSize) / 2, iconSize, iconSize);
            textBounds = new Rectangle(x + iconSize + (int)(7 * scale), 2,
                Math.Max(1, Width - x - iconSize - (int)(14 * scale)), Math.Max(1, Height - 4));
        }
        TextRenderer.DrawText(g, Text, Font, textBounds, ink,
            TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak |
            TextFormatFlags.NoPrefix | (glyph.Length == 0 ? TextFormatFlags.HorizontalCenter : TextFormatFlags.Left));
        if (Focused && ShowFocusCues)
            ControlPaint.DrawFocusRectangle(g, Rectangle.Inflate(outer, -4, -4), ink, bg);
    }

    private static GraphicsPath Rounded(Rectangle r, int radius)
    {
        int diameter = Math.Min(Math.Min(r.Width, r.Height), 2 * radius);
        var path = new GraphicsPath();
        if (diameter < 2) { path.AddRectangle(r); return path; }
        path.AddArc(r.Left, r.Top, diameter, diameter, 180, 90);
        path.AddArc(r.Right - diameter, r.Top, diameter, diameter, 270, 90);
        path.AddArc(r.Right - diameter, r.Bottom - diameter, diameter, diameter, 0, 90);
        path.AddArc(r.Left, r.Bottom - diameter, diameter, diameter, 90, 90);
        path.CloseFigure();
        return path;
    }
}
