using System.Drawing;
using System.Drawing.Drawing2D;

namespace LinuxMailRelay365;

// Resource-free vector glyphs: consistent on 100-300% DPI, no icon-font dependency.
internal static class UiIcons
{
    internal static Bitmap Draw(string name, Color color, int pixels = 24)
    {
        var b = new Bitmap(Math.Max(16, pixels), Math.Max(16, pixels));
        using var g = Graphics.FromImage(b);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        float scale = b.Width / 24f;
        g.ScaleTransform(scale, scale);
        using var p = new Pen(color, 1.8f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
        switch (name)
        {
            case "ssh":
                g.DrawRectangle(p, 3, 5, 18, 14); g.DrawLines(p, [new Point(6, 9), new Point(9, 12), new Point(6, 15)]);
                g.DrawLine(p, 12, 15, 17, 15); break;
            case "cloud":
                g.DrawArc(p, 4, 8, 12, 12, 135, 205); g.DrawArc(p, 9, 4, 11, 12, 180, 220);
                g.DrawLine(p, 6, 19, 19, 19); break;
            case "shield":
                g.DrawLines(p, [new Point(12, 2), new Point(20, 5), new Point(19, 14), new Point(12, 21), new Point(5, 14), new Point(4, 5), new Point(12, 2)]);
                g.DrawLines(p, [new Point(8, 12), new Point(11, 15), new Point(16, 9)]); break;
            case "send":
                g.DrawLines(p, [new Point(3, 4), new Point(21, 12), new Point(3, 20), new Point(6, 13), new Point(21, 12), new Point(6, 11), new Point(3, 4)]); break;
            case "check":
                g.DrawEllipse(p, 3, 3, 18, 18); g.DrawLines(p, [new Point(7, 12), new Point(11, 16), new Point(17, 8)]); break;
            case "refresh":
                g.DrawArc(p, 3, 3, 18, 18, 210, 270); g.DrawLines(p, [new Point(20, 4), new Point(20, 10), new Point(14, 9)]); break;
            case "download":
                g.DrawLine(p, 12, 3, 12, 15); g.DrawLines(p, [new Point(7, 10), new Point(12, 15), new Point(17, 10)]);
                g.DrawLine(p, 5, 20, 19, 20); break;
            case "copy":
                g.DrawRectangle(p, 7, 7, 13, 14); g.DrawLine(p, 4, 17, 4, 4); g.DrawLine(p, 4, 4, 17, 4); break;
            case "gear":
                g.DrawEllipse(p, 8, 8, 8, 8); g.DrawEllipse(p, 3, 3, 18, 18); break;
            case "back":
                g.DrawLines(p, [new Point(13, 5), new Point(6, 12), new Point(13, 19)]); g.DrawLine(p, 6, 12, 20, 12); break;
            case "next":
                g.DrawLines(p, [new Point(11, 5), new Point(18, 12), new Point(11, 19)]); g.DrawLine(p, 18, 12, 4, 12); break;
            default:
                g.DrawEllipse(p, 4, 4, 16, 16); g.DrawLine(p, 12, 10, 12, 17); g.DrawEllipse(p, 11, 7, 2, 2); break;
        }
        return b;
    }
}
