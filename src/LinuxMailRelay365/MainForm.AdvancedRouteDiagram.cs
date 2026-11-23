using System.Drawing;
using System.Windows.Forms;

namespace LinuxMailRelay365;

internal sealed partial class MainForm
{
    // Native WinForms flow visualization: no generated picture, no shell,
    // SMTP connection, remote commands, DNS claim or MTA configuration change.
    private Control BuildConditionalRoutingDiagram(int width, int languageIndex)
    {
        int scale = Math.Clamp((int)Math.Round(DeviceDpi / 96.0 * 100), 100, 250);
        bool narrow = (long)width * 96L < 820L * Math.Max(96, DeviceDpi);
        int available = Math.Max(270, width - 40);
        var diagram = new TableLayoutPanel
        {
            ColumnCount = 1, RowCount = 0, AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Width = available,
            BackColor = Color.FromArgb(241, 246, 253),
            Padding = new Padding(11, 12, 11, 12),
            Margin = new Padding(0, 6, 0, 14)
        };
        diagram.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        AddLine(diagram, UiTheme.Text(TranslateMailFlow(languageIndex,
            "Условный путь сообщения — только модель",
            "Conditional message flow — PROPOSAL, not active routing",
            "זרימת דואר מדומה בלבד"), true));
        AddLine(diagram, MailFlowText(
            (inspectedMail?.Mta ?? "Linux MTA") + "  ·  " +
            TranslateMailFlow(languageIndex,
                "Источник: envelope MAIL FROM + RCPT TO. Реальная политика не подтверждена.",
                "Source: SMTP envelope MAIL FROM + RCPT TO. Actual MTA precedence is unverified.",
                "מקור: MAIL FROM ו-RCPT TO; קדימות הנתיבים אינה מאומתת."),
            available - 24, warning: true));

        var potentiallyOverlapping = AdvancedRoutePlanner.PossibleOverlaps(
            advancedRoutingRules)
            .SelectMany(x => new[] { x.FirstRule, x.SecondRule })
            .ToHashSet();
        for (int n = 0; n < advancedRoutingRules.Count; n++)
        {
            int index = n;
            var rule = advancedRoutingRules[n];
            var flow = new FlowLayoutPanel
            {
                Width = Math.Max(246, available - 20),
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                FlowDirection = narrow ? FlowDirection.TopDown : FlowDirection.LeftToRight,
                WrapContents = false,
                BackColor = potentiallyOverlapping.Contains(n)
                    ? Color.FromArgb(255, 244, 228) : Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Padding = new Padding(6),
                Margin = new Padding(0, 5, 0, 7)
            };

            Button InteractiveNode(string caption, string glyph)
            {
                var button = UiTheme.Action(caption, false, glyph);
                button.MaximumSize = new Size(narrow
                    ? Math.Max(205, available - 56)
                    : Math.Max(170, (available - 85) / 2), 0);
                button.MinimumSize = new Size(154, (int)Math.Round(48.0 * scale / 100));
                button.Click += (_, _) =>
                {
                    BeginAdvancedRouteEdit(index);
                    RenderPage();
                };
                button.AccessibleName = "Edit proposed conditional route " +
                    (index + 1) + ": " + caption;
                return button;
            }

            flow.Controls.Add(InteractiveNode(
                "#" + (n + 1) + " · " +
                AdvancedRouteSelector(rule.Kind, languageIndex) +
                Environment.NewLine + rule.Pattern, "filter"));
            var arrow = new Label
            {
                Text = narrow ? "↓" : "→",
                Width = narrow ? Math.Max(202, available - 50) : 27,
                Height = (int)Math.Round((narrow ? 26 : 64) * scale / 100.0),
                TextAlign = ContentAlignment.MiddleCenter,
                ForeColor = UiTheme.Accent,
                Font = new Font("Segoe UI", 16f, FontStyle.Bold),
                Margin = new Padding(2),
                AccessibleName = "Hypothetical outbound routing connection"
            };
            flow.Controls.Add(arrow);
            flow.Controls.Add(InteractiveNode(
                "SMTP " + rule.Endpoint + Environment.NewLine +
                rule.TlsMode.ToUpperInvariant() + " · AUTH=" + rule.AuthMode,
                "mail"));
            AddLine(diagram, flow);
        }
        AddLine(diagram, MailFlowText(TranslateMailFlow(languageIndex,
            "Нажмите на любой узел, чтобы редактировать соответствующее правило. Стрелки показывают лишь предложенные связи. Реальную доставку они не подтверждают.",
            "Click a node to edit the corresponding condition. Arrows show proposed connections ONLY; they do not prove actual mail delivery.",
            "לחצו על צומת לעריכת תנאי. החצים מציגים הצעה בלבד."),
            available - 24));
        return diagram;
    }
}
