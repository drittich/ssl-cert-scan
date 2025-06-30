using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ssl_cert_scan.Models;
using ssl_cert_scan.Services;

namespace ssl_cert_scan;

internal class Program
{
    static async Task<int> Main(string[] args)
    {
        Console.WriteLine("SSL Certificate Scanner v1.0");
        Console.WriteLine("============================");

        try
        {
            // Build host with dependency injection
            var host = CreateHostBuilder(args).Build();

            // Get services
            var configService = host.Services.GetRequiredService<IConfigurationService>();
            var sslScanner = host.Services.GetRequiredService<ISslScannerService>();
            var emailService = host.Services.GetRequiredService<IEmailService>();
            var logger = host.Services.GetRequiredService<ILogger<Program>>();

            // Load configuration
            logger.LogInformation("Loading configuration...");
            var config = await configService.LoadConfigurationAsync();

            // Validate configuration
            if (!config.Domains.Any())
            {
                logger.LogError("No domains configured for scanning. Please check config.json");
                return 1;
            }

            // Display scan information
            Console.WriteLine($"Scanning {config.Domains.Count} domains...");
            foreach (var domain in config.Domains)
            {
                Console.WriteLine($"  - {domain}");
            }
            Console.WriteLine();

            // Perform SSL certificate scan
            logger.LogInformation("Starting SSL certificate scan...");
            var scanResult = await sslScanner.ScanDomainsAsync(config.Domains, config.Notifications);

            // Display results
            DisplayResults(scanResult, config.Notifications);

            // Send email notification if configured
            if (config.EmailRecipients.Any() && !string.IsNullOrWhiteSpace(config.Smtp.Host))
            {
                logger.LogInformation("Processing email notification...");
                var emailResult = await emailService.SendReportAsync(scanResult, config);
                
                if (emailResult.Success)
                {
                    if (emailResult.EmailSent)
                    {
                        Console.WriteLine("✓ Email notification sent successfully");
                        logger.LogInformation("Email notification sent successfully");
                    }
                    else
                    {
                        Console.WriteLine($"ℹ Email notification skipped: {emailResult.Message}");
                        logger.LogInformation("Email notification skipped: {Message}", emailResult.Message);
                    }
                }
                else
                {
                    Console.WriteLine($"⚠ Failed to send email notification: {emailResult.Message}");
                    logger.LogWarning("Failed to send email notification: {Message}", emailResult.Message);
                }
            }
            else
            {
                Console.WriteLine("⚠ Email notifications not configured - skipping");
                logger.LogInformation("Email notifications not configured - skipping");
            }

            Console.WriteLine();
            Console.WriteLine("Scan completed successfully!");
            
            // Return appropriate exit code
            return scanResult.HasIssues ? 1 : 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
            Console.WriteLine("Run with detailed logging to see full error details.");
            return 1;
        }
    }

    static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.AddConsole();
                logging.SetMinimumLevel(LogLevel.Information);
            })
            .ConfigureServices((context, services) =>
            {
                // Register services
                services.AddHttpClient();
                services.AddSingleton<IConfigurationService, ConfigurationService>();
                services.AddSingleton<ISslScannerService, SslScannerService>();
                services.AddSingleton<IEmailService, EmailService>();
            });

    static void DisplayResults(ScanResult scanResult, NotificationSettings settings)
    {
        Console.WriteLine("Scan Results:");
        Console.WriteLine("=============");
        Console.WriteLine($"Total Domains Scanned: {scanResult.TotalDomains}");
        Console.WriteLine($"Scan Duration: {scanResult.ScanDuration.TotalSeconds:F2} seconds");
        Console.WriteLine();

        // Summary
        Console.WriteLine("Certificate Status Summary:");
        Console.WriteLine($"  ✓ Valid: {scanResult.ValidCertificates}");
        Console.WriteLine($"  ⚠ Warning ({settings.WarningDays}+ days): {scanResult.WarningCertificates}");
        Console.WriteLine($"  🔴 Critical ({settings.CriticalDays}+ days): {scanResult.CriticalCertificates}");
        Console.WriteLine($"  ❌ Expired: {scanResult.ExpiredCertificates}");
        Console.WriteLine($"  ⚠ Errors: {scanResult.ErrorCount}");
        Console.WriteLine();

        // Detailed results - show issues first
        if (scanResult.HasIssues)
        {
            Console.WriteLine("Certificates Requiring Attention:");
            Console.WriteLine("---------------------------------");

            var issueCerts = scanResult.Certificates
                .Where(c => c.Status != CertificateStatus.Valid)
                .OrderBy(c => c.Status)
                .ThenBy(c => c.DaysUntilExpiry);

            foreach (var cert in issueCerts)
            {
                var statusIcon = GetStatusIcon(cert.Status);
                var daysText = cert.Status == CertificateStatus.Expired ? "EXPIRED" : $"{cert.DaysUntilExpiry} days";
                
                Console.WriteLine($"{statusIcon} {cert.Domain}");
                Console.WriteLine($"    Status: {cert.Status}");
                Console.WriteLine($"    Days until expiry: {daysText}");
                Console.WriteLine($"    Expires: {cert.ValidTo:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"    Issuer: {GetShortIssuer(cert.Issuer)}");
                
                if (!string.IsNullOrEmpty(cert.ErrorMessage))
                {
                    Console.WriteLine($"    Error: {cert.ErrorMessage}");
                }
                
                Console.WriteLine();
            }
        }
        else
        {
            Console.WriteLine("🎉 All certificates are valid and healthy!");
            Console.WriteLine();
        }

        // Show healthy certificates if requested
        var healthyCerts = scanResult.Certificates.Where(c => c.Status == CertificateStatus.Valid);
        if (healthyCerts.Any())
        {
            Console.WriteLine("Healthy Certificates:");
            Console.WriteLine("--------------------");
            
            foreach (var cert in healthyCerts.OrderBy(c => c.DaysUntilExpiry))
            {
                Console.WriteLine($"✓ {cert.Domain} - expires in {cert.DaysUntilExpiry} days ({cert.ValidTo:yyyy-MM-dd})");
            }
            Console.WriteLine();
        }
    }

    static string GetStatusIcon(CertificateStatus status)
    {
        return status switch
        {
            CertificateStatus.Valid => "✓",
            CertificateStatus.Warning => "⚠",
            CertificateStatus.Critical => "🔴",
            CertificateStatus.Expired => "❌",
            CertificateStatus.Invalid => "⚠",
            CertificateStatus.Error => "❌",
            _ => "?"
        };
    }

    static string GetShortIssuer(string issuer)
    {
        if (string.IsNullOrEmpty(issuer))
            return "Unknown";

        // Extract the CN (Common Name) from the issuer string
        var parts = issuer.Split(',');
        var cnPart = parts.FirstOrDefault(p => p.Trim().StartsWith("CN="));
        
        if (cnPart != null)
        {
            return cnPart.Replace("CN=", "").Trim();
        }

        return issuer.Length > 50 ? issuer.Substring(0, 47) + "..." : issuer;
    }
}
