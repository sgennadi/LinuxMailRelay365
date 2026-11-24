namespace LinuxMailRelay365;

// Separate diagnostic evidence per exact rule. No account identifiers,
// passwords, configuration changes or activation approval are retained.
internal sealed record ConditionalRouteAudit(AdvancedRouteRule Rule,
    CustomSmtpAudit Report, bool PasswordRequested)
{
    internal static ConditionalRouteAudit Parse(AdvancedRouteRule rule,
        string output, bool withAuth)
    {
        var normalized = AdvancedRoutePlanner.Normalize(rule);
        if (withAuth && (normalized.AuthMode != "password" ||
                         normalized.TlsMode == "plain"))
            throw new ArgumentException("This rule does not authorize password diagnostics.");
        var report = CustomSmtpAudit.Parse(output, normalized.Host, normalized.Port,
            normalized.TlsMode, withAuth);
        if (withAuth && report.AuthResult == "accepted" &&
            (report.Auth is not ("plain" or "login") || report.Dns != "resolved"))
            throw new InvalidDataException("Inconsistent route AUTH evidence.");
        return new(normalized, report, withAuth);
    }

    internal bool Passed => Report.Dns == "resolved" && Report.Tcp == "reachable" &&
        Rule.TlsMode != "plain" && Report.Tls == "verified" &&
        (Rule.AuthMode == "none" ||
         (PasswordRequested && Report.AuthResult == "accepted"));

    internal static bool SelfTest()
    {
        var rule = new AdvancedRouteRule(AdvancedRouteMatchKind.ExactEnvelopeSender,
            "user@example.org", "relay.example.net", 46500, "starttls", "password");
        string response = "CUSTOM_SMTP_AUDIT_VERSION=1\n" +
            "CUSTOM_SMTP_AUDIT_HOST=relay.example.net\n" +
            "CUSTOM_SMTP_AUDIT_PORT=46500\nCUSTOM_SMTP_AUDIT_MODE=starttls\n" +
            "CUSTOM_SMTP_AUDIT_DNS=resolved\nCUSTOM_SMTP_AUDIT_TCP=reachable\n" +
            "CUSTOM_SMTP_AUDIT_TLS=verified\nCUSTOM_SMTP_AUDIT_AUTH=login\n" +
            "CUSTOM_SMTP_AUDIT_AUTH_RESULT=accepted\n" +
            "CUSTOM_SMTP_AUDIT_MAIL_SENT=no\nCUSTOM_SMTP_AUDIT_CONFIG_CHANGED=no\n" +
            "CUSTOM_SMTP_AUDIT_SECRETS_ECHOED=no\n";
        if (!Parse(rule, response, true).Passed ||
            Parse(rule, response.Replace("AUTH_RESULT=accepted",
                "AUTH_RESULT=not_requested"), false).Passed ||
            Parse(rule, response.Replace("AUTH_RESULT=accepted",
                "AUTH_RESULT=rejected"), true).Passed)
            return false;
        try { Parse(rule with { Port = 587 }, response, true); return false; }
        catch (InvalidDataException) { }
        try { Parse(rule with { AuthMode = "none" }, response, true); return false; }
        catch (ArgumentException) { }
        try { Parse(rule, response.Replace("AUTH=login", "AUTH=oauth_only"), true); return false; }
        catch (InvalidDataException) { }
        return true;
    }
}
