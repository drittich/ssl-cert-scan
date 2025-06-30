# SSL Certificate Scanner

A .NET 8 console application that scans SSL certificates for multiple domains, checks their expiration dates, and optionally sends email notifications with a summary report.

## Features

- **Multi-domain SSL certificate scanning** with concurrent processing
- **Configurable expiration warnings** (30 days warning, 7 days critical by default)
- **Email notifications** via SMTP with HTML and plain text reports
- **Detailed certificate information** including issuer, expiry dates, and Subject Alternative Names
- **JSON configuration** for easy management
- **Comprehensive logging** with different log levels
- **Exit codes** for integration with monitoring systems

## Quick Start

1. **Clone or download** the repository
2. **Configure** the application by editing `config.json`
3. **Run** the application: `dotnet run --project ssl-cert-scan`

## Configuration

The application uses a `config.json` file for configuration. If the file doesn't exist, a default configuration will be created automatically.

### Sample Configuration

```json
{
  "domains": [
    "google.com",
    "github.com",
    "stackoverflow.com",
    "microsoft.com"
  ],
  "smtp": {
    "host": "smtp.gmail.com",
    "port": 587,
    "enableSsl": true,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "fromEmail": "your-email@gmail.com",
    "fromName": "SSL Certificate Monitor"
  },
  "emailRecipients": [
    "admin@company.com",
    "security@company.com"
  ],
  "notifications": {
    "warningDays": 30,
    "criticalDays": 7,
    "sendOnlyForExpiringCerts": true,
    "includeHealthyCerts": false,
    "emailSubject": "SSL Certificate Status Report"
  }
}
```

### Configuration Options

#### Domains
- **`domains`**: Array of domain names to scan (without https://)

#### SMTP Settings
- **`host`**: SMTP server hostname
- **`port`**: SMTP server port (usually 587 for TLS or 465 for SSL)
- **`enableSsl`**: Enable SSL/TLS encryption
- **`username`**: SMTP authentication username
- **`password`**: SMTP authentication password (use app passwords for Gmail)
- **`fromEmail`**: Sender email address
- **`fromName`**: Sender display name

#### Email Recipients
- **`emailRecipients`**: Array of email addresses to receive reports

#### Notification Settings
- **`warningDays`**: Days before expiry to trigger warning status (default: 30)
- **`criticalDays`**: Days before expiry to trigger critical status (default: 7)
- **`sendOnlyForExpiringCerts`**: Only send emails when certificates have issues (default: true)
- **`includeHealthyCerts`**: Include healthy certificates in reports (default: false)
- **`emailSubject`**: Email subject line template

## Usage

### Basic Usage

```bash
# Run the scanner
dotnet run --project ssl-cert-scan

# Build and run the executable
dotnet build
./ssl-cert-scan/bin/Debug/net8.0/ssl-cert-scan.exe
```

### Integration with Task Scheduler

The application returns appropriate exit codes:
- **0**: Success (no certificate issues)
- **1**: Issues found or errors occurred

This makes it suitable for integration with Windows Task Scheduler or other monitoring systems.

### Sample Output

```
SSL Certificate Scanner v1.0
============================
Scanning 4 domains...
  - google.com
  - github.com
  - stackoverflow.com
  - microsoft.com

Scan Results:
=============
Total Domains Scanned: 4
Scan Duration: 3.45 seconds

Certificate Status Summary:
  ✓ Valid: 3
  ⚠ Warning (30+ days): 1
  🔴 Critical (7+ days): 0
  ❌ Expired: 0
  ⚠ Errors: 0

Certificates Requiring Attention:
---------------------------------
⚠ example.com
    Status: Warning
    Days until expiry: 25 days
    Expires: 2025-07-25 23:59:59
    Issuer: Let's Encrypt Authority X3

✓ Email notification sent successfully

Scan completed successfully!
```

## Email Notifications

The application sends rich HTML email reports with:

- **Executive summary** with certificate counts by status
- **Detailed certificate table** with domain, status, expiry dates, and issuers
- **Color-coded status indicators** for easy identification
- **Plain text alternative** for email clients that don't support HTML

### Gmail Configuration

For Gmail SMTP, you'll need to:

1. Enable 2-factor authentication on your Google account
2. Generate an "App Password" specifically for this application
3. Use the app password (not your regular password) in the configuration

## Requirements

- **.NET 8.0** or later
- **Network access** to the domains being scanned (port 443)
- **SMTP server access** for email notifications (optional)

## Building from Source

```bash
# Restore dependencies
dotnet restore

# Build the application
dotnet build

# Run tests (if any)
dotnet test

# Publish for deployment
dotnet publish -c Release -o publish
```

## Logging

The application uses structured logging with the following levels:

- **Information**: General application flow and results
- **Warning**: Non-critical issues (certificate warnings, email skipped)
- **Error**: Application errors and failures
- **Debug**: Detailed scanning information (enable with logging configuration)

## Security Considerations

- **Store credentials securely**: Consider using environment variables or secure vaults for SMTP passwords
- **Network security**: The application makes outbound HTTPS connections to scan certificates
- **Email security**: Use TLS/SSL for SMTP connections when possible

## Troubleshooting

### Common Issues

1. **"Configuration file not found"**
   - The application will create a default `config.json` file automatically
   - Edit the file with your specific domains and email settings

2. **"Failed to send email notification"**
   - Check SMTP settings (host, port, credentials)
   - Verify network connectivity to SMTP server
   - For Gmail, ensure you're using an app password

3. **"Error scanning SSL certificate"**
   - Verify domain names are correct and accessible
   - Check network connectivity
   - Some domains may have firewall restrictions

4. **Certificate chain validation warnings**
   - Some certificates may have chain validation issues but still be functional
   - These are logged as warnings but don't prevent scanning

### Getting Help

If you encounter issues:

1. Check the console output for detailed error messages
2. Review the configuration file for typos or incorrect settings
3. Test email configuration with a simple SMTP test tool
4. Verify network connectivity to target domains

## License

This project is provided as-is for educational and practical use. Feel free to modify and distribute according to your needs.