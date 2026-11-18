using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

// Only consumes bounded, non-secret STATUS CODES from a read-only Linux probe.
// "Potentially public" does not mean accessible from the Internet, and
// "suspected unsafe" does not prove SMTP relay without an authorized live test.
internal sealed class ExistingSmtpAudit
{
    private readonly Dictionary<string, string> values;

    private ExistingSmtpAudit(Dictionary<string, string> values) => this.values = values;
    private string Value(string key) => values.GetValueOrDefault(key) ?? "unknown";

    internal string PublicBind => Value("SMTP_PUBLIC_BIND");
    internal string RelayRisk => Value("SMTP_RELAY_POLICY_RISK");
    internal string Mta => Value("SMTP_AUDIT_MTA");
    internal bool PotentiallyPublic => PublicBind == "potentially_public";
    internal bool SuspectedUnsafeRelay => RelayRisk == "suspected_unsafe_relay";

    internal static ExistingSmtpAudit Parse(string output)
    {
        var data = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            int index = line.IndexOf('=');
            if (index <= 0 || index > 60 || line.Length > 180) continue;
            string key = line[..index];
            string value = line[(index + 1)..];
            if (!Regex.IsMatch(key, @"^SMTP_[A-Z_]+$", RegexOptions.CultureInvariant) ||
                !Regex.IsMatch(value, @"^[a-z0-9_]+$", RegexOptions.CultureInvariant))
                continue;
            data[key] = value;
        }
        if (data.GetValueOrDefault("SMTP_AUDIT_VERSION") != "1" ||
            !data.ContainsKey("SMTP_PUBLIC_BIND") ||
            !data.ContainsKey("SMTP_RELAY_POLICY_RISK") ||
            !data.ContainsKey("SMTP_EXTERNAL_REACHABILITY") ||
            !data.ContainsKey("SMTP_OPEN_RELAY_PROVEN"))
            throw new InvalidDataException("SMTP audit incomplete; cannot claim public exposure is safe.");
        return new ExistingSmtpAudit(data);
    }

    internal string Summary(int language)
    {
        bool english = language == 1;
        bool hebrew = language == 2;
        string bind = PublicBind switch
        {
            "potentially_public" => english ? "Wildcard/public bind detected" :
                hebrew ? "נמצאה האזנה רחבה או ציבורית" : "Обнаружен listener на всех/публичных интерфейсах",
            "private_or_other" => english ? "Private/non-global interface bind" :
                hebrew ? "האזנה ברשת פרטית" : "Listener на частном интерфейсе (NAT неизвестен)",
            "loopback_only" => english ? "Loopback only observed" :
                hebrew ? "גישה מקומית בלבד" : "Обнаружена только локальная прослушка",
            "no_matching_listeners" => english ? "No matching active SMTP listener observed" :
                hebrew ? "לא נמצאה האזנה פעילה תואמת" : "Активный SMTP listener не обнаружен",
            _ => english ? "Cannot determine active SMTP binding" :
                hebrew ? "לא ניתן לקבוע את מצב ההאזנה" : "Не удалось определить активные SMTP-порты"
        };
        string relay = RelayRisk switch
        {
            "suspected_unsafe_relay" => english ? "SUSPECTED UNSAFE RELAY — review immediately" :
                hebrew ? "חשד לשרת relay פתוח, נדרשת בדיקה מידית" : "ПОДОЗРЕНИЕ НА ОТКРЫТЫЙ RELAY — требуется проверка",
            "relay_guard_present" => english ? "Unauthenticated relay restriction configured" :
                hebrew ? "קיימת הגבלת relay" : "Ограничения пересылки присутствуют",
            "not_observed_running" => english ? "No matching running SMTP service" :
                hebrew ? "אין שירות SMTP פעיל תואם" : "Нет совпадающего активного SMTP-сервиса",
            _ => english ? "Relay policy requires manual review" :
                hebrew ? "נדרשת בדיקה ידנית של כללי relay" : "Политику пересылки требуется проверить вручную"
        };
        string note = english
            ? "An SMTP listener is not proof of Internet reachability or open relay; NAT/firewall and an authorized external test are not verified."
            : hebrew
            ? "האזנה אינה הוכחה לגישה מהאינטרנט או ל-relay פתוח. יש לבדוק NAT, חומת אש ובדיקה מורשית."
            : "Listener не доказывает доступ из интернета или открытый relay. NAT, firewall и внешняя проверка не выполнялись.";
        return "MTA: " + Mta + " | " + bind + " | " + relay +
               " | SMTP AUTH=" + Value("SMTP_SMTP_AUTH") +
               " | SMTP TLS=" + Value("SMTP_SMTP_TLS") +
               " | relayhost=" + Value("SMTP_RELAYHOST_CONFIGURED") +
               Environment.NewLine + note;
    }

    internal static bool SelfTest()
    {
        const string common =
            "SMTP_AUDIT_VERSION=1\nSMTP_AUDIT_MTA=postfix\n" +
            "SMTP_EXTERNAL_REACHABILITY=not_tested_from_internet\n" +
            "SMTP_OPEN_RELAY_PROVEN=no_active_probe_performed\n";
        var bind = Parse(common + "SMTP_PUBLIC_BIND=potentially_public\n" +
            "SMTP_RELAY_POLICY_RISK=relay_guard_present\n");
        var risky = Parse(common + "SMTP_PUBLIC_BIND=potentially_public\n" +
            "SMTP_RELAY_POLICY_RISK=suspected_unsafe_relay\n");
        if (!bind.PotentiallyPublic || bind.SuspectedUnsafeRelay ||
            !risky.SuspectedUnsafeRelay ||
            !risky.Summary(0).Contains("ПОДОЗРЕНИЕ", StringComparison.Ordinal)) return false;
        try { Parse("SMTP_PUBLIC_BIND=loopback_only"); return false; }
        catch (InvalidDataException) { return true; }
    }
}
