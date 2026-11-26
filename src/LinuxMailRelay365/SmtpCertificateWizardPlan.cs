namespace LinuxMailRelay365;

internal enum SmtpConnectorIdentity { PublicIp, Certificate }
internal enum SmtpCertificateSource { Existing, Import, Acme }
internal enum SmtpCertificateStep { Identity, Source, Domain, Dns, Certificate, Renewal, Connector, Review }

internal static class SmtpCertificateWizardPlan
{
    internal static SmtpCertificateStep[] Steps(SmtpConnectorIdentity identity, SmtpCertificateSource source)
    {
        if (identity == SmtpConnectorIdentity.PublicIp)
            return [SmtpCertificateStep.Identity, SmtpCertificateStep.Connector, SmtpCertificateStep.Review];
        if (source == SmtpCertificateSource.Acme)
            return [SmtpCertificateStep.Identity, SmtpCertificateStep.Source, SmtpCertificateStep.Domain,
                SmtpCertificateStep.Dns, SmtpCertificateStep.Certificate, SmtpCertificateStep.Renewal,
                SmtpCertificateStep.Connector, SmtpCertificateStep.Review];
        return [SmtpCertificateStep.Identity, SmtpCertificateStep.Source, SmtpCertificateStep.Domain,
            SmtpCertificateStep.Certificate, SmtpCertificateStep.Renewal, SmtpCertificateStep.Connector,
            SmtpCertificateStep.Review];
    }

    internal static bool CanApply(bool certificateRequired, bool certificateVerified,
        bool connectorVerified, bool routePreviewVerified, bool explicitApproval)
        => (!certificateRequired || certificateVerified) && connectorVerified &&
            routePreviewVerified && explicitApproval;
}
