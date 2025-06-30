using System.Text.Json.Serialization;

namespace ssl_cert_scan.Models;

public class AppConfiguration
{
    [JsonPropertyName("domains")]
    public List<string> Domains { get; set; } = new();

    [JsonPropertyName("smtp")]
    public SmtpSettings Smtp { get; set; } = new();

    [JsonPropertyName("emailRecipients")]
    public List<string> EmailRecipients { get; set; } = new();

    [JsonPropertyName("notifications")]
    public NotificationSettings Notifications { get; set; } = new();
}

public class SmtpSettings
{
    [JsonPropertyName("host")]
    public string Host { get; set; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; set; } = 587;

    [JsonPropertyName("enableSsl")]
    public bool EnableSsl { get; set; } = true;

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;

    [JsonPropertyName("fromEmail")]
    public string FromEmail { get; set; } = string.Empty;

    [JsonPropertyName("fromName")]
    public string FromName { get; set; } = "SSL Certificate Monitor";
}

public class NotificationSettings
{
    [JsonPropertyName("warningDays")]
    public int WarningDays { get; set; } = 30;

    [JsonPropertyName("criticalDays")]
    public int CriticalDays { get; set; } = 7;

    [JsonPropertyName("sendOnlyForExpiringCerts")]
    public bool SendOnlyForExpiringCerts { get; set; } = true;

    [JsonPropertyName("includeHealthyCerts")]
    public bool IncludeHealthyCerts { get; set; } = false;

    [JsonPropertyName("emailSubject")]
    public string EmailSubject { get; set; } = "SSL Certificate Status Report";
}