namespace ssl_cert_scan.Models;

public class ScanResult
{
    public List<SslCertificateInfo> Certificates { get; set; } = new();
    public DateTime ScanDate { get; set; } = DateTime.Now;
    public int TotalDomains { get; set; }
    public int ValidCertificates { get; set; }
    public int WarningCertificates { get; set; }
    public int CriticalCertificates { get; set; }
    public int ExpiredCertificates { get; set; }
    public int ErrorCount { get; set; }
    public TimeSpan ScanDuration { get; set; }
    public List<string> Errors { get; set; } = new();

    public bool HasIssues => WarningCertificates > 0 || CriticalCertificates > 0 || ExpiredCertificates > 0 || ErrorCount > 0;
    
    public void UpdateCounts()
    {
        TotalDomains = Certificates.Count;
        ValidCertificates = Certificates.Count(c => c.Status == CertificateStatus.Valid);
        WarningCertificates = Certificates.Count(c => c.Status == CertificateStatus.Warning);
        CriticalCertificates = Certificates.Count(c => c.Status == CertificateStatus.Critical);
        ExpiredCertificates = Certificates.Count(c => c.Status == CertificateStatus.Expired);
        ErrorCount = Certificates.Count(c => c.Status == CertificateStatus.Error || c.Status == CertificateStatus.Invalid);
    }
}