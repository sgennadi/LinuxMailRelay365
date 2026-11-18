using System.Diagnostics;
using Renci.SshNet;
using System.Text;
using System.Text.RegularExpressions;

namespace LinuxMailRelay365;

internal sealed record SshEndpoint(string Host, int Port, string Username, string KeyPath,
    string Password = "", string HostKeySha256 = "", string SudoPassword = "")
{
    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Host) || Host.Length > 253 ||
            !Regex.IsMatch(Host, @"^[A-Za-z0-9][A-Za-z0-9.\-]*$"))
            throw new ArgumentException("Enter a valid DNS host or IPv4 address. IPv6 can be used via a DNS name.");
        if (Port is < 1 or > 65535) throw new ArgumentException("SSH port is invalid.");
        if (!Regex.IsMatch(Username, @"^[a-z_][a-z0-9_-]{0,31}$", RegexOptions.IgnoreCase))
            throw new ArgumentException("SSH username is invalid.");
        if (!string.IsNullOrWhiteSpace(KeyPath) && !File.Exists(KeyPath))
            throw new FileNotFoundException("SSH private key file is not available.");
        if (SudoPassword.Contains('\r') || SudoPassword.Contains('\n'))
            throw new ArgumentException("Sudo password cannot contain line breaks in scripted mode.");
        if (!string.IsNullOrEmpty(Password))
        {
            if (!string.IsNullOrWhiteSpace(KeyPath))
                throw new ArgumentException("Choose either SSH password or a key, not both.");
            string fp = HostKeySha256.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase)
                ? HostKeySha256[7..] : HostKeySha256;
            if (!Regex.IsMatch(fp.TrimEnd('='), @"^[A-Za-z0-9+/]{43}$", RegexOptions.CultureInvariant))
                throw new ArgumentException("Password SSH requires an out-of-band verified SHA256 host key fingerprint.");
        }
    }
}

internal sealed record RemoteResult(int ExitCode, string StdOut, string StdErr)
{
    internal void EnsureSuccess()
    {
        if (ExitCode != 0)
        {
            // stderr may reveal hostnames/paths, but should not contain any OAuth token.
            throw new IOException($"SSH command failed (exit {ExitCode}). {StdErr.Trim()} {StdOut.Trim()}".Trim());
        }
    }
}

internal static class SshRemote
{
    internal static async Task<RemoteResult> ExecuteAsync(
        SshEndpoint endpoint, string command, string? input = null,
        TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        endpoint.Validate();
        if (!string.IsNullOrEmpty(endpoint.Password))
            return await ExecutePasswordSshAsync(endpoint, command, input, timeout, cancellationToken);
        // Windows OpenSSH checks the host key against the user's known_hosts.
        // TOFU auto-accept is deliberately disabled; BatchMode prevents an invisible prompt.
        var psi = new ProcessStartInfo("ssh.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var arg in new[] { "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                  "-o", "ConnectTimeout=15", "-p", endpoint.Port.ToString() })
            psi.ArgumentList.Add(arg);
        if (!string.IsNullOrWhiteSpace(endpoint.KeyPath))
        {
            psi.ArgumentList.Add("-i");
            psi.ArgumentList.Add(Path.GetFullPath(endpoint.KeyPath));
        }
        psi.ArgumentList.Add(endpoint.Username + "@" + endpoint.Host);
        psi.ArgumentList.Add(command);
        using var process = new Process { StartInfo = psi };
        if (!process.Start()) throw new IOException("Failed to start Windows OpenSSH client.");
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(timeout ?? TimeSpan.FromMinutes(2));
        try
        {
            var stdout = process.StandardOutput.ReadToEndAsync(limit.Token);
            var stderr = process.StandardError.ReadToEndAsync(limit.Token);
            if (input is not null)
                await process.StandardInput.WriteAsync(input.AsMemory(), limit.Token);
            process.StandardInput.Close();
            await process.WaitForExitAsync(limit.Token);
            return new RemoteResult(process.ExitCode, await stdout, await stderr);
        }
        catch
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            throw;
        }
    }

    internal static Task<RemoteResult> RunRootScriptAsync(
        SshEndpoint endpoint, string script,
        TimeSpan? timeout = null, CancellationToken cancellationToken = default) =>
        string.IsNullOrEmpty(endpoint.SudoPassword)
            ? ExecuteAsync(endpoint, "sudo -n bash -s", script, timeout, cancellationToken)
            : ExecuteAsync(endpoint, "sudo -S -p '' bash -s", endpoint.SudoPassword + "\n" + script,
                timeout, cancellationToken);

    private static async Task<RemoteResult> ExecutePasswordSshAsync(
        SshEndpoint endpoint, string command, string? input, TimeSpan? timeout,
        CancellationToken cancellationToken)
    {
        // SSH.NET supports encrypted password authentication without exposing the
        // password in process command arguments, environment variables or logs.
        return await Task.Run(async () =>
        {
            string expected = endpoint.HostKeySha256.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase)
                ? endpoint.HostKeySha256[7..] : endpoint.HostKeySha256;
            expected = expected.TrimEnd('=');
            using var client = new SshClient(endpoint.Host, endpoint.Port,
                endpoint.Username, endpoint.Password);
            client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(15);
            bool trusted = false;
            client.HostKeyReceived += (_, args) =>
            {
                trusted = string.Equals(args.FingerPrintSHA256.TrimEnd('='), expected,
                    StringComparison.Ordinal);
                args.CanTrust = trusted;
            };
            client.Connect();
            if (!trusted) throw new IOException("SSH host key did not match the trusted fingerprint.");
            using var job = client.CreateCommand(command);
            job.CommandTimeout = timeout ?? TimeSpan.FromMinutes(2);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            linked.CancelAfter(job.CommandTimeout);
            Task executing = job.ExecuteAsync(linked.Token);
            if (input is not null)
            {
                await using var stdin = job.CreateInputStream();
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                try { await stdin.WriteAsync(bytes, linked.Token); }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
            }
            await executing;
            return new RemoteResult(job.ExitStatus ?? 255, job.Result, job.Error);
        }, cancellationToken);
    }

    // Strictly read-only: never invoke sudo or install packages during a probe.
    internal static Task<RemoteResult> ProbeSecurityAsync(
        SshEndpoint endpoint, string probeScript, CancellationToken token = default) =>
        ExecuteAsync(endpoint, "bash -s", probeScript, TimeSpan.FromSeconds(65), token);

    internal static Task<RemoteResult> CheckAsync(
        SshEndpoint endpoint, CancellationToken token = default) =>
        ExecuteAsync(endpoint,
            "printf 'Kernel: '; uname -s; . /etc/os-release; printf 'Distribution: %s\\n' \"$PRETTY_NAME\"; " +
            "printf 'Python: '; command -v python3 || true; printf 'OpenSSL: '; command -v openssl || true; " +
            "printf 'Postfix: '; command -v postconf || true; " +
            "printf 'Privileges: '; if sudo -n true 2>/dev/null; then echo 'sudo available'; " +
            "else echo 'sudo -n unavailable'; fi", null, TimeSpan.FromSeconds(40), token);

    internal static async Task<string> ReadPublicCertificateAsync(SshEndpoint endpoint, CancellationToken token)
    {
        bool askSudo = !string.IsNullOrEmpty(endpoint.SudoPassword);
        var response = await ExecuteAsync(endpoint,
            askSudo ? "sudo -S -p '' cat /etc/postfix/m365-oauth/app.crt" :
                      "sudo -n cat /etc/postfix/m365-oauth/app.crt",
            askSudo ? endpoint.SudoPassword + "\n" : null,
            TimeSpan.FromSeconds(40), token);
        response.EnsureSuccess();
        if (!response.StdOut.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal) ||
            !response.StdOut.Contains("-----END CERTIFICATE-----", StringComparison.Ordinal) ||
            response.StdOut.Length > 20000)
            throw new InvalidDataException("Linux did not return a valid public PEM certificate.");
        return response.StdOut.Trim() + "\n";
    }

    internal static Task<RemoteResult> DiagnosticsAsync(SshEndpoint endpoint, CancellationToken token) =>
        RunRootScriptAsync(endpoint,
            "echo '=== POSTFIX ==='; systemctl is-active postfix 2>/dev/null || true; " +
            "echo '=== CONFIG ==='; runuser -u m365mailer -- python3 /usr/local/libexec/m365_xoauth2_transport.py --config-check; " +
            "echo '=== TOKEN ==='; runuser -u m365mailer -- python3 /usr/local/libexec/m365_xoauth2_transport.py --token-check; " +
            "echo '=== QUEUE ==='; postqueue -p", TimeSpan.FromMinutes(2), token);

    internal static Task<RemoteResult> SendTestAsync(SshEndpoint endpoint, string mailbox, string recipient, CancellationToken token)
    {
        if (!IsEmail(mailbox) || !IsEmail(recipient)) throw new ArgumentException("Invalid email address.");
        var message = $"From: {mailbox}\r\nTo: {recipient}\r\nSubject: Microsoft 365 Postfix XOAUTH2 test\r\n\r\nSent by Linux Mail Relay 365.\r\n";
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(message));
        return ExecuteAsync(endpoint,
            $"printf %s {encoded} | base64 -d | /usr/sbin/sendmail -t -f {QuoteShell(mailbox)}; sleep 2; postqueue -p",
            null, TimeSpan.FromSeconds(90), token);
    }


    private const string SidecarConfig = "/etc/linuxmailrelay365/sidecar-postfix";
    private const string SidecarIdentity = "/etc/linuxmailrelay365/sidecar-identity/app.json";
    private const string SidecarTransport = "/usr/local/libexec/linuxmailrelay365-sidecar-transport.py";

    // Read-only, no sudo and no server configuration changes.
    internal static async Task<bool> HasIsolatedSidecarAsync(SshEndpoint endpoint, CancellationToken token)
    {
        var result = await ExecuteAsync(endpoint,
            "if test -r " + SidecarConfig + "/main.cf && test -r " + SidecarConfig +
            "/master.cf && test -f " + SidecarIdentity +
            "; then printf SIDECAR_PRESENT; else printf SIDECAR_ABSENT; fi",
            null, TimeSpan.FromSeconds(30), token);
        result.EnsureSuccess();
        return result.StdOut.Trim() == "SIDECAR_PRESENT";
    }

    internal static Task<RemoteResult> SidecarDiagnosticsAsync(SshEndpoint endpoint,
        CancellationToken token) =>
        RunRootScriptAsync(endpoint,
            "set -e\n" +
            "echo '=== ISOLATED M365 POSTFIX ==='\n" +
            "systemctl is-active linuxmailrelay365-sidecar.service\n" +
            "postfix -c " + SidecarConfig + " check\n" +
            "postfix -c " + SidecarConfig + " status\n" +
            "echo '=== ISOLATED IDENTITY ==='\n" +
            "runuser -u m365mailer -- python3 " + SidecarTransport +
            " --config " + SidecarIdentity + " --config-check\n" +
            "echo '=== MICROSOFT ENTRA TOKEN ==='\n" +
            "runuser -u m365mailer -- python3 " + SidecarTransport +
            " --config " + SidecarIdentity + " --token-check\n" +
            "echo '=== ISOLATED QUEUE ==='\n" +
            "postqueue -c " + SidecarConfig + " -p\n",
            TimeSpan.FromMinutes(2), token);

    internal static Task<RemoteResult> SendIsolatedSidecarTestAsync(
        SshEndpoint endpoint, string mailbox, string recipient, CancellationToken token)
    {
        if (!IsEmail(mailbox) || !IsEmail(recipient))
            throw new ArgumentException("Invalid SMTP test sender or recipient.");
        // Only localhost receives the message. No connection to existing Postfix
        // port 25 or invocation of the system sendmail compatibility binary.
        var script = """
            import smtplib
            import sys
            from email.message import EmailMessage
            sender, recipient = sys.argv[1], sys.argv[2]
            message = EmailMessage()
            message['From'] = sender
            message['To'] = recipient
            message['Subject'] = 'LinuxMailRelay365 isolated SMTP test'
            message.set_content('Submitted through the isolated Microsoft 365 relay.')
            with smtplib.SMTP('127.0.0.1', 2525, timeout=25) as smtp:
                smtp.send_message(message, from_addr=sender, to_addrs=[recipient])
            print('ISOLATED_SMTP_ACCEPTED=yes; remote delivery still requires log verification.')
            """;
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(script));
        return ExecuteAsync(endpoint,
            "printf %s " + encoded + " | base64 -d | python3 - " +
            QuoteShell(mailbox) + " " + QuoteShell(recipient),
            null, TimeSpan.FromSeconds(45), token);
    }

    // Shell-safe quoting: an email local part can legally contain apostrophes.
    private static string QuoteShell(string value) => "'" + value.Replace("'", "'\"'\"'") + "'";

    internal static bool IsEmail(string value) => Regex.IsMatch(value,
        @"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$", RegexOptions.CultureInvariant)
        && value.Length <= 254 && !value.Contains("..");
}
