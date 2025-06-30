using System.Net;
using System.Net.Mail;
using System.Text;
using Microsoft.Extensions.Logging;
using ssl_cert_scan.Models;

namespace ssl_cert_scan.Services;

public interface IEmailService
{
    Task<bool> SendReportAsync(ScanResult scanResult, AppConfiguration config);
    Task<bool> TestEmailConfigurationAsync(SmtpSettings smtpSettings);
}

public class EmailService : IEmailService
{
    private readonly ILogger<EmailService> _logger;

    public EmailService(ILogger<EmailService> logger)
    {
        _logger = logger;
    }

    public async Task<bool> SendReportAsync(ScanResult scanResult, AppConfiguration config)
    {
        try
        {
            if (!config.EmailRecipients.Any() || string.IsNullOrWhiteSpace(config.Smtp.Host))
            {
                _logger.LogWarning("Email configuration incomplete. Skipping email notification.");
                return false;
            }

            // Check if we should send email based on settings
            if (config.Notifications.SendOnlyForExpiringCerts && !scanResult.HasIssues)
            {
                _logger.LogInformation("No certificate issues found and SendOnlyForExpiringCerts is enabled. Skipping email notification.");
                return true; // Return true as this is expected behavior
            }

            _logger.LogInformation("Preparing to send email report to {RecipientCount} recipients", config.EmailRecipients.Count);

            using var smtpClient = CreateSmtpClient(config.Smtp);
            using var mailMessage = CreateEmailMessage(scanResult, config);

            await smtpClient.SendMailAsync(mailMessage);
            
            _logger.LogInformation("Email report sent successfully to {Recipients}", string.Join(", ", config.EmailRecipients));
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email report");
            return false;
        }
    }

    public async Task<bool> TestEmailConfigurationAsync(SmtpSettings smtpSettings)
    {
        try
        {
            _logger.LogInformation("Testing email configuration for SMTP host: {Host}:{Port}", smtpSettings.Host, smtpSettings.Port);

            using var smtpClient = CreateSmtpClient(smtpSettings);
            
            // Test connection without sending email
            await Task.Run(() => smtpClient.Send(CreateTestEmail(smtpSettings)));
            
            _logger.LogInformation("Email configuration test successful");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Email configuration test failed");
            return false;
        }
    }

    private SmtpClient CreateSmtpClient(SmtpSettings smtpSettings)
    {
        var smtpClient = new SmtpClient(smtpSettings.Host, smtpSettings.Port)
        {
            EnableSsl = smtpSettings.EnableSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            UseDefaultCredentials = false
        };

        if (!string.IsNullOrWhiteSpace(smtpSettings.Username) && !string.IsNullOrWhiteSpace(smtpSettings.Password))
        {
            smtpClient.Credentials = new NetworkCredential(smtpSettings.Username, smtpSettings.Password);
        }

        return smtpClient;
    }

    private MailMessage CreateEmailMessage(ScanResult scanResult, AppConfiguration config)
    {
        var subject = GenerateEmailSubject(scanResult, config.Notifications.EmailSubject);
        var htmlBody = GenerateHtmlReport(scanResult, config.Notifications);
        var textBody = GenerateTextReport(scanResult, config.Notifications);

        var mailMessage = new MailMessage
        {
            From = new MailAddress(config.Smtp.FromEmail, config.Smtp.FromName),
            Subject = subject,
            IsBodyHtml = true,
            Body = htmlBody
        };

        // Add plain text alternative
        var textView = AlternateView.CreateAlternateViewFromString(textBody, Encoding.UTF8, "text/plain");
        var htmlView = AlternateView.CreateAlternateViewFromString(htmlBody, Encoding.UTF8, "text/html");
        
        mailMessage.AlternateViews.Add(textView);
        mailMessage.AlternateViews.Add(htmlView);

        foreach (var recipient in config.EmailRecipients)
        {
            mailMessage.To.Add(recipient);
        }

        return mailMessage;
    }

    private MailMessage CreateTestEmail(SmtpSettings smtpSettings)
    {
        return new MailMessage
        {
            From = new MailAddress(smtpSettings.FromEmail, smtpSettings.FromName),
            To = { smtpSettings.FromEmail }, // Send test email to sender
            Subject = "SSL Certificate Monitor - Test Email",
            Body = "This is a test email from SSL Certificate Monitor. Configuration is working correctly.",
            IsBodyHtml = false
        };
    }

    private string GenerateEmailSubject(ScanResult scanResult, string baseSubject)
    {
        if (!scanResult.HasIssues)
        {
            return $"{baseSubject} - All Certificates OK";
        }

        var issues = new List<string>();
        if (scanResult.ExpiredCertificates > 0)
            issues.Add($"{scanResult.ExpiredCertificates} expired");
        if (scanResult.CriticalCertificates > 0)
            issues.Add($"{scanResult.CriticalCertificates} critical");
        if (scanResult.WarningCertificates > 0)
            issues.Add($"{scanResult.WarningCertificates} warning");

        return $"{baseSubject} - Issues Found: {string.Join(", ", issues)}";
    }

    private string GenerateHtmlReport(ScanResult scanResult, NotificationSettings settings)
    {
        var html = new StringBuilder();
        
        html.AppendLine("<!DOCTYPE html>");
        html.AppendLine("<html><head><style>");
        html.AppendLine("body { font-family: Arial, sans-serif; margin: 20px; }");
        html.AppendLine("table { border-collapse: collapse; width: 100%; margin: 20px 0; }");
        html.AppendLine("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }");
        html.AppendLine("th { background-color: #f2f2f2; }");
        html.AppendLine(".status-valid { color: green; font-weight: bold; }");
        html.AppendLine(".status-warning { color: orange; font-weight: bold; }");
        html.AppendLine(".status-critical { color: red; font-weight: bold; }");
        html.AppendLine(".status-expired { color: darkred; font-weight: bold; }");
        html.AppendLine(".status-error { color: purple; font-weight: bold; }");
        html.AppendLine(".summary { background-color: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0; }");
        html.AppendLine("</style></head><body>");

        // Header
        html.AppendLine($"<h1>SSL Certificate Status Report</h1>");
        html.AppendLine($"<p><strong>Scan Date:</strong> {scanResult.ScanDate:yyyy-MM-dd HH:mm:ss}</p>");
        html.AppendLine($"<p><strong>Scan Duration:</strong> {scanResult.ScanDuration.TotalSeconds:F2} seconds</p>");

        // Summary
        html.AppendLine("<div class='summary'>");
        html.AppendLine("<h2>Summary</h2>");
        html.AppendLine($"<p><strong>Total Domains:</strong> {scanResult.TotalDomains}</p>");
        html.AppendLine($"<p><strong>Valid Certificates:</strong> {scanResult.ValidCertificates}</p>");
        html.AppendLine($"<p><strong>Warning ({settings.WarningDays} days):</strong> {scanResult.WarningCertificates}</p>");
        html.AppendLine($"<p><strong>Critical ({settings.CriticalDays} days):</strong> {scanResult.CriticalCertificates}</p>");
        html.AppendLine($"<p><strong>Expired:</strong> {scanResult.ExpiredCertificates}</p>");
        html.AppendLine($"<p><strong>Errors:</strong> {scanResult.ErrorCount}</p>");
        html.AppendLine("</div>");

        // Certificate details
        html.AppendLine("<h2>Certificate Details</h2>");
        html.AppendLine("<table>");
        html.AppendLine("<tr><th>Domain</th><th>Status</th><th>Days Until Expiry</th><th>Expires On</th><th>Issuer</th></tr>");

        var sortedCerts = scanResult.Certificates
            .Where(c => !settings.SendOnlyForExpiringCerts || c.Status != CertificateStatus.Valid || settings.IncludeHealthyCerts)
            .OrderBy(c => c.Status)
            .ThenBy(c => c.DaysUntilExpiry);

        foreach (var cert in sortedCerts)
        {
            var statusClass = GetStatusCssClass(cert.Status);
            var daysText = cert.Status == CertificateStatus.Expired ? "Expired" : cert.DaysUntilExpiry.ToString();
            var issuer = cert.Issuer.Split(',')[0].Replace("CN=", "").Trim();

            html.AppendLine($"<tr>");
            html.AppendLine($"<td>{cert.Domain}</td>");
            html.AppendLine($"<td><span class='{statusClass}'>{cert.Status}</span></td>");
            html.AppendLine($"<td>{daysText}</td>");
            html.AppendLine($"<td>{cert.ValidTo:yyyy-MM-dd HH:mm:ss}</td>");
            html.AppendLine($"<td>{issuer}</td>");
            html.AppendLine($"</tr>");
        }

        html.AppendLine("</table>");
        html.AppendLine("</body></html>");

        return html.ToString();
    }

    private string GenerateTextReport(ScanResult scanResult, NotificationSettings settings)
    {
        var text = new StringBuilder();
        
        text.AppendLine("SSL CERTIFICATE STATUS REPORT");
        text.AppendLine("=====================================");
        text.AppendLine();
        text.AppendLine($"Scan Date: {scanResult.ScanDate:yyyy-MM-dd HH:mm:ss}");
        text.AppendLine($"Scan Duration: {scanResult.ScanDuration.TotalSeconds:F2} seconds");
        text.AppendLine();
        
        text.AppendLine("SUMMARY");
        text.AppendLine("-------");
        text.AppendLine($"Total Domains: {scanResult.TotalDomains}");
        text.AppendLine($"Valid Certificates: {scanResult.ValidCertificates}");
        text.AppendLine($"Warning ({settings.WarningDays} days): {scanResult.WarningCertificates}");
        text.AppendLine($"Critical ({settings.CriticalDays} days): {scanResult.CriticalCertificates}");
        text.AppendLine($"Expired: {scanResult.ExpiredCertificates}");
        text.AppendLine($"Errors: {scanResult.ErrorCount}");
        text.AppendLine();

        text.AppendLine("CERTIFICATE DETAILS");
        text.AppendLine("-------------------");
        
        var sortedCerts = scanResult.Certificates
            .Where(c => !settings.SendOnlyForExpiringCerts || c.Status != CertificateStatus.Valid || settings.IncludeHealthyCerts)
            .OrderBy(c => c.Status)
            .ThenBy(c => c.DaysUntilExpiry);

        foreach (var cert in sortedCerts)
        {
            var daysText = cert.Status == CertificateStatus.Expired ? "EXPIRED" : $"{cert.DaysUntilExpiry} days";
            var issuer = cert.Issuer.Split(',')[0].Replace("CN=", "").Trim();
            
            text.AppendLine($"Domain: {cert.Domain}");
            text.AppendLine($"Status: {cert.Status}");
            text.AppendLine($"Days Until Expiry: {daysText}");
            text.AppendLine($"Expires On: {cert.ValidTo:yyyy-MM-dd HH:mm:ss}");
            text.AppendLine($"Issuer: {issuer}");
            
            if (!string.IsNullOrEmpty(cert.ErrorMessage))
            {
                text.AppendLine($"Error: {cert.ErrorMessage}");
            }
            
            text.AppendLine();
        }

        return text.ToString();
    }

    private string GetStatusCssClass(CertificateStatus status)
    {
        return status switch
        {
            CertificateStatus.Valid => "status-valid",
            CertificateStatus.Warning => "status-warning",
            CertificateStatus.Critical => "status-critical",
            CertificateStatus.Expired => "status-expired",
            _ => "status-error"
        };
    }
}