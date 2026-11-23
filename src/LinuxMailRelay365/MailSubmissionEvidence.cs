namespace LinuxMailRelay365;

// Signals indicate whether local submission paths are available. They DO NOT
// identify the author of a message or establish that local users/jobs send mail.
internal sealed record MailSubmissionEvidence(
    string SendmailCli, string MailCli, string Pickup, string Scheduler, string Systemd)
{
    internal static MailSubmissionEvidence Parse(string report)
    {
        if (report.Length is < 40 or > 4096 || report.Contains('\0'))
            throw new InvalidDataException("Mail submission report length invalid.");
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in report.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var index = line.IndexOf('=');
            if (index < 1 || index > 50) continue;
            var name = line[..index];
            var value = line[(index + 1)..];
            if (!name.StartsWith("MAIL_ORIGIN_", StringComparison.Ordinal) ||
                value.Length > 32 || value.Any(char.IsControl))
                continue;
            if (!values.TryAdd(name, value))
                throw new InvalidDataException("Duplicate mail origin key.");
        }
        if (values.GetValueOrDefault("MAIL_ORIGIN_VERSION") != "1" ||
            values.GetValueOrDefault("MAIL_ORIGIN_CHANGES") != "no")
            throw new InvalidDataException("Unsupported or modified submission report.");
        string Valid(string key, params string[] allowed)
        {
            if (!values.TryGetValue(key, out var v) || !allowed.Contains(v, StringComparer.Ordinal))
                throw new InvalidDataException("Unknown mail submission status: " + key);
            return v;
        }
        return new(
            Valid("MAIL_ORIGIN_SENDMAIL_CLI", "present", "not_observed"),
            Valid("MAIL_ORIGIN_MAIL_CLI", "present", "not_observed"),
            Valid("MAIL_ORIGIN_PICKUP_CONFIG", "configured", "not_observed", "unverified"),
            Valid("MAIL_ORIGIN_SCHEDULER", "present", "not_observed"),
            Valid("MAIL_ORIGIN_SYSTEMD", "available", "unverified"));
    }

    private static string Localized(int lang, string ru, string en, string he) =>
        lang == 0 ? ru : lang == 2 ? he : en;

    internal string Brief(int language)
    {
        string sendmail = SendmailCli == "present"
            ? Localized(language, "команда sendmail доступна", "sendmail command available",
                "פקודת sendmail זמינה")
            : Localized(language, "команда sendmail не обнаружена", "sendmail command not found",
                "פקודת sendmail לא זוהתה");
        string pickup = Pickup == "configured"
            ? Localized(language, "Postfix pickup настроен", "Postfix local pickup configured",
                "קליטה מקומית ב-Postfix הוגדרה")
            : Localized(language, "локальный pickup не подтверждён", "local pickup not verified",
                "קליטה מקומית לא אומתה");
        string jobs = Scheduler == "present"
            ? Localized(language, "планировщик установлен", "job scheduler installed",
                "מתזמן מותקן")
            : Localized(language, "планировщик не обнаружен", "job scheduler not observed",
                "מתזמן לא זוהה");
        return sendmail + " · " + pickup + " · " + jobs +
            Environment.NewLine + Localized(language,
                "Это показывает доступные механизмы, но НЕ доказывает, что пользователи или задания отправляют почту.",
                "These are available mechanisms, NOT proof that users or scheduled jobs actually send mail.",
                "אלה מנגנונים זמינים, לא הוכחה שהמשתמשים או המשימות שולחים דואר.");
    }

    internal static bool SelfTest()
    {
        const string data = "MAIL_ORIGIN_VERSION=1\nMAIL_ORIGIN_SENDMAIL_CLI=present\n" +
            "MAIL_ORIGIN_MAIL_CLI=not_observed\nMAIL_ORIGIN_PICKUP_CONFIG=configured\n" +
            "MAIL_ORIGIN_SCHEDULER=present\nMAIL_ORIGIN_SYSTEMD=available\n" +
            "MAIL_ORIGIN_CHANGES=no\n";
        var result = Parse(data);
        if (!result.Brief(1).Contains("NOT proof", StringComparison.Ordinal) ||
            !result.Brief(0).Contains("НЕ доказывает", StringComparison.Ordinal))
            return false;
        try { Parse(data.Replace("MAIL_ORIGIN_CHANGES=no", "MAIL_ORIGIN_CHANGES=yes")); return false; }
        catch (InvalidDataException) { }
        try { Parse(data + "MAIL_ORIGIN_SENDMAIL_CLI=present\n"); return false; }
        catch (InvalidDataException) { }
        return true;
    }
}
