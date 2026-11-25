using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

// Visual emphasis is descriptive only, never proof of delivery, nor permission
// to change a queue. Keep the native Windows selection and accessibility colors.
internal static class QueueVisuals
{
    internal enum Tone { Neutral, Info, Waiting, Warning, Held, Error }

    internal static Tone State(string state, bool quarantine = false) => state switch
    {
        "active" or "incoming" or "processing_mark" => Tone.Info,
        "deferred" or "load_limited" => Tone.Warning,
        "held" or "frozen" => Tone.Held,
        "too_young" => Tone.Waiting,
        _ => quarantine ? Tone.Held : Tone.Neutral
    };

    internal static Tone Reason(string reason) => reason switch
    {
        "auth" or "tls" or "permanent" or "mixed" => Tone.Error,
        "dns" or "network" or "temporary" or "other_reason" => Tone.Warning,
        _ => Tone.Neutral
    };

    internal static Tone Heading(bool warning, bool outcomeUnknown, bool quarantine = false) =>
        outcomeUnknown ? Tone.Error : warning ? Tone.Warning : quarantine ? Tone.Held : Tone.Info;

    private static (Color Ink, Color Surface) Palette(Tone tone) => tone switch
    {
        Tone.Info => (UiTheme.Navy, UiTheme.InfoSurface),
        Tone.Waiting => (Color.FromArgb(51, 65, 85), Color.FromArgb(241, 245, 249)),
        Tone.Warning => (UiTheme.WarningInk, UiTheme.WarningSurface),
        Tone.Held => (Color.FromArgb(91, 33, 137), Color.FromArgb(245, 237, 255)),
        Tone.Error => (Color.FromArgb(139, 28, 28), Color.FromArgb(255, 235, 235)),
        _ => (Color.Empty, Color.Empty)
    };

    internal static void ApplyHeading(Label label, bool warning, bool outcomeUnknown, bool quarantine = false)
    {
        var (ink, surface) = Palette(Heading(warning, outcomeUnknown, quarantine));
        label.BackColor = SystemInformation.HighContrast ? SystemColors.Window : surface;
        label.ForeColor = SystemInformation.HighContrast ? SystemColors.WindowText : ink;
    }

    internal static void ApplyState(DataGridViewCell cell, string state, bool quarantine = false) =>
        ApplyCell(cell, State(state, quarantine));

    internal static void ApplyReason(DataGridViewCell cell, string reason) =>
        ApplyCell(cell, Reason(reason));

    private static void ApplyCell(DataGridViewCell cell, Tone tone)
    {
        var (ink, surface) = Palette(tone);
        var style = cell.Style;
        // Empty colors inherit the grid theme for normal rows and high contrast.
        style.BackColor = SystemInformation.HighContrast ? Color.Empty : surface;
        style.ForeColor = SystemInformation.HighContrast ? Color.Empty : ink;
        style.SelectionBackColor = SystemColors.Highlight;
        style.SelectionForeColor = SystemColors.HighlightText;
    }

    internal static bool SelfTest()
    {
        if (State("active") != Tone.Info || State("processing_mark") != Tone.Info ||
            State("deferred") != Tone.Warning || State("load_limited") != Tone.Warning ||
            State("held") != Tone.Held || State("frozen") != Tone.Held ||
            State("queued", quarantine: true) != Tone.Held || State("queued") != Tone.Neutral ||
            State("too_young") != Tone.Waiting || State("other") != Tone.Neutral ||
            Reason("auth") != Tone.Error || Reason("tls") != Tone.Error ||
            Reason("permanent") != Tone.Error || Reason("mixed") != Tone.Error ||
            Reason("temporary") != Tone.Warning || Reason("dns") != Tone.Warning ||
            Reason("network") != Tone.Warning || Reason("no_reason") != Tone.Neutral ||
            Reason("not_applicable") != Tone.Neutral ||
            Heading(true, true, true) != Tone.Error || Heading(true, false, true) != Tone.Warning ||
            Heading(false, false, true) != Tone.Held || Heading(false, false) != Tone.Info)
            return false;

        // Test every non-neutral foreground/background pair at >= 4.5:1,
        // including the shared UiTheme values. OS-provided high-contrast and
        // selection colors remain the responsibility of Windows.
        static double Linear(byte component)
        {
            double v = component / 255.0;
            return v <= 0.04045 ? v / 12.92 : Math.Pow((v + 0.055) / 1.055, 2.4);
        }
        static double Luminance(Color c) =>
            0.2126 * Linear(c.R) + 0.7152 * Linear(c.G) + 0.0722 * Linear(c.B);
        foreach (Tone tone in Enum.GetValues<Tone>())
        {
            var (ink, surface) = Palette(tone);
            if (tone == Tone.Neutral)
            {
                if (!ink.IsEmpty || !surface.IsEmpty) return false;
                continue;
            }
            double a = Luminance(ink), b = Luminance(surface);
            if (ink.IsEmpty || surface.IsEmpty ||
                (Math.Max(a, b) + 0.05) / (Math.Min(a, b) + 0.05) < 4.5)
                return false;
        }
        return true;
    }
}
