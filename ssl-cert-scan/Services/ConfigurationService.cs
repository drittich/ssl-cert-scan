using System.Text.Json;
using Microsoft.Extensions.Logging;
using ssl_cert_scan.Models;

namespace ssl_cert_scan.Services;

public interface IConfigurationService
{
    Task<AppConfiguration> LoadConfigurationAsync(string configPath = "config.json");
    Task SaveConfigurationAsync(AppConfiguration config, string configPath = "config.json");
    Task<AppConfiguration> CreateDefaultConfigurationAsync(string configPath = "config.json");
}

public class ConfigurationService : IConfigurationService
{
    private readonly ILogger<ConfigurationService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public ConfigurationService(ILogger<ConfigurationService> logger)
    {
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
    }

    public async Task<AppConfiguration> LoadConfigurationAsync(string configPath = "config.json")
    {
        try
        {
            if (!File.Exists(configPath))
            {
                _logger.LogWarning("Configuration file {ConfigPath} not found. Creating default configuration.", configPath);
                return await CreateDefaultConfigurationAsync(configPath);
            }

            _logger.LogInformation("Loading configuration from {ConfigPath}", configPath);
            var jsonContent = await File.ReadAllTextAsync(configPath);
            
            var configuration = JsonSerializer.Deserialize<AppConfiguration>(jsonContent, _jsonOptions);
            
            if (configuration == null)
            {
                _logger.LogError("Failed to deserialize configuration file {ConfigPath}", configPath);
                throw new InvalidOperationException($"Invalid configuration file: {configPath}");
            }

            ValidateConfiguration(configuration);
            _logger.LogInformation("Configuration loaded successfully with {DomainCount} domains", configuration.Domains.Count);
            
            return configuration;
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Invalid JSON in configuration file {ConfigPath}", configPath);
            throw new InvalidOperationException($"Invalid JSON in configuration file: {configPath}", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading configuration from {ConfigPath}", configPath);
            throw;
        }
    }

    public async Task SaveConfigurationAsync(AppConfiguration config, string configPath = "config.json")
    {
        try
        {
            _logger.LogInformation("Saving configuration to {ConfigPath}", configPath);
            var jsonContent = JsonSerializer.Serialize(config, _jsonOptions);
            await File.WriteAllTextAsync(configPath, jsonContent);
            _logger.LogInformation("Configuration saved successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error saving configuration to {ConfigPath}", configPath);
            throw;
        }
    }

    public async Task<AppConfiguration> CreateDefaultConfigurationAsync(string configPath = "config.json")
    {
        var defaultConfig = new AppConfiguration
        {
            Domains = new List<string> { "google.com", "github.com", "stackoverflow.com" },
            Smtp = new SmtpSettings
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                Username = "your-email@gmail.com",
                Password = "your-app-password",
                FromEmail = "your-email@gmail.com",
                FromName = "SSL Certificate Monitor"
            },
            EmailRecipients = new List<string> { "admin@company.com" },
            Notifications = new NotificationSettings
            {
                WarningDays = 30,
                CriticalDays = 7,
                SendOnlyForExpiringCerts = true,
                IncludeHealthyCerts = false,
                EmailSubject = "SSL Certificate Status Report"
            }
        };

        await SaveConfigurationAsync(defaultConfig, configPath);
        return defaultConfig;
    }

    private void ValidateConfiguration(AppConfiguration config)
    {
        if (config.Domains == null || !config.Domains.Any())
        {
            throw new InvalidOperationException("Configuration must contain at least one domain to scan");
        }

        if (config.EmailRecipients == null || !config.EmailRecipients.Any())
        {
            _logger.LogWarning("No email recipients configured. Email notifications will be disabled.");
        }

        if (string.IsNullOrWhiteSpace(config.Smtp.Host))
        {
            _logger.LogWarning("SMTP host not configured. Email notifications will be disabled.");
        }

        // Validate domain formats
        var invalidDomains = config.Domains.Where(d => string.IsNullOrWhiteSpace(d) || d.Contains(' '));
        if (invalidDomains.Any())
        {
            _logger.LogWarning("Invalid domain names found: {InvalidDomains}", string.Join(", ", invalidDomains));
        }
    }
}