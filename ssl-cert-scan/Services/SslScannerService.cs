using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using ssl_cert_scan.Models;

namespace ssl_cert_scan.Services;

public interface ISslScannerService
{
    Task<ScanResult> ScanDomainsAsync(List<string> domains, NotificationSettings settings);
    Task<SslCertificateInfo> ScanDomainAsync(string domain, NotificationSettings settings);
}

public class SslScannerService : ISslScannerService
{
    private readonly ILogger<SslScannerService> _logger;
    private readonly HttpClient _httpClient;

    public SslScannerService(ILogger<SslScannerService> logger, HttpClient httpClient)
    {
        _logger = logger;
        _httpClient = httpClient;
    }

    public async Task<ScanResult> ScanDomainsAsync(List<string> domains, NotificationSettings settings)
    {
        var startTime = DateTime.Now;
        var result = new ScanResult();

        _logger.LogInformation("Starting SSL certificate scan for {DomainCount} domains", domains.Count);

        var tasks = domains.Select(domain => ScanDomainAsync(domain, settings)).ToArray();
        var certificates = await Task.WhenAll(tasks);

        result.Certificates.AddRange(certificates);
        result.ScanDuration = DateTime.Now - startTime;
        result.UpdateCounts();

        _logger.LogInformation("SSL scan completed in {Duration}ms. Results: {Valid} valid, {Warning} warning, {Critical} critical, {Expired} expired, {Errors} errors",
            result.ScanDuration.TotalMilliseconds,
            result.ValidCertificates,
            result.WarningCertificates,
            result.CriticalCertificates,
            result.ExpiredCertificates,
            result.ErrorCount);

        return result;
    }

    public async Task<SslCertificateInfo> ScanDomainAsync(string domain, NotificationSettings settings)
    {
        try
        {
            _logger.LogDebug("Scanning SSL certificate for domain: {Domain}", domain);

            var certificate = await GetSslCertificateAsync(domain);
            if (certificate == null)
            {
                return new SslCertificateInfo
                {
                    Domain = domain,
                    Status = CertificateStatus.Error,
                    ErrorMessage = "Could not retrieve SSL certificate",
                    IsValid = false
                };
            }

            var certInfo = ExtractCertificateInfo(domain, certificate, settings);
            _logger.LogDebug("SSL certificate scan completed for {Domain}. Status: {Status}, Expires: {ExpiryDate}",
                domain, certInfo.Status, certInfo.ValidTo);

            return certInfo;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning SSL certificate for domain: {Domain}", domain);
            return new SslCertificateInfo
            {
                Domain = domain,
                Status = CertificateStatus.Error,
                ErrorMessage = ex.Message,
                IsValid = false
            };
        }
    }

    private async Task<X509Certificate2?> GetSslCertificateAsync(string domain)
    {
        const int httpsPort = 443;
        const int timeoutMs = 10000; // 10 seconds

        try
        {
            using var tcpClient = new TcpClient();
            var connectTask = tcpClient.ConnectAsync(domain, httpsPort);
            
            if (await Task.WhenAny(connectTask, Task.Delay(timeoutMs)) != connectTask)
            {
                _logger.LogWarning("Connection timeout for domain: {Domain}", domain);
                return null;
            }

            if (!tcpClient.Connected)
            {
                _logger.LogWarning("Failed to connect to domain: {Domain}", domain);
                return null;
            }

            using var sslStream = new SslStream(tcpClient.GetStream(), false, ValidateServerCertificate);
            await sslStream.AuthenticateAsClientAsync(domain);

            var certificate = sslStream.RemoteCertificate;
            if (certificate != null)
            {
                return new X509Certificate2(certificate);
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving SSL certificate for domain: {Domain}", domain);
            return null;
        }
    }

    private bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        // We want to capture the certificate even if there are SSL policy errors
        // The validation will be done separately in ExtractCertificateInfo
        return true;
    }

    private SslCertificateInfo ExtractCertificateInfo(string domain, X509Certificate2 certificate, NotificationSettings settings)
    {
        var certInfo = new SslCertificateInfo
        {
            Domain = domain,
            Subject = certificate.Subject,
            Issuer = certificate.Issuer,
            ValidFrom = certificate.NotBefore,
            ValidTo = certificate.NotAfter,
            SignatureAlgorithm = certificate.SignatureAlgorithm.FriendlyName ?? "Unknown",
            SerialNumber = certificate.SerialNumber ?? "Unknown",
            Thumbprint = certificate.Thumbprint,
            SubjectAlternativeNames = GetSubjectAlternativeNames(certificate)
        };

        // Calculate days until expiry
        var now = DateTime.Now;
        certInfo.DaysUntilExpiry = (int)(certificate.NotAfter - now).TotalDays;

        // Determine certificate status
        if (certificate.NotAfter < now)
        {
            certInfo.Status = CertificateStatus.Expired;
            certInfo.IsValid = false;
        }
        else if (certInfo.DaysUntilExpiry <= settings.CriticalDays)
        {
            certInfo.Status = CertificateStatus.Critical;
            certInfo.IsValid = true;
        }
        else if (certInfo.DaysUntilExpiry <= settings.WarningDays)
        {
            certInfo.Status = CertificateStatus.Warning;
            certInfo.IsValid = true;
        }
        else
        {
            certInfo.Status = CertificateStatus.Valid;
            certInfo.IsValid = true;
        }

        // Additional validation
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreInvalidBasicConstraints;
            
            var chainValid = chain.Build(certificate);
            if (!chainValid && certInfo.Status == CertificateStatus.Valid)
            {
                certInfo.Status = CertificateStatus.Invalid;
                certInfo.IsValid = false;
                certInfo.ErrorMessage = "Certificate chain validation failed";
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error validating certificate chain for domain: {Domain}", domain);
        }

        return certInfo;
    }

    private List<string> GetSubjectAlternativeNames(X509Certificate2 certificate)
    {
        var sanList = new List<string>();

        try
        {
            foreach (var extension in certificate.Extensions)
            {
                if (extension.Oid?.Value == "2.5.29.17") // Subject Alternative Name OID
                {
                    var sanExtension = new X509SubjectAlternativeNameExtension(extension.RawData, false);
                    foreach (var san in sanExtension.EnumerateDnsNames())
                    {
                        sanList.Add(san);
                    }
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error extracting Subject Alternative Names from certificate");
        }

        return sanList;
    }
}