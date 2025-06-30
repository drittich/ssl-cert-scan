namespace ssl_cert_scan.Models;

public class SslCertificateInfo
{
    public string Domain { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }
    public int DaysUntilExpiry { get; set; }
    public CertificateStatus Status { get; set; }
    public List<string> SubjectAlternativeNames { get; set; } = new();
    public string SignatureAlgorithm { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public bool IsValid { get; set; }
    public string? ErrorMessage { get; set; }
}

public enum CertificateStatus
{
    Valid,
    Warning,
    Critical,
    Expired,
    Invalid,
    Error
}