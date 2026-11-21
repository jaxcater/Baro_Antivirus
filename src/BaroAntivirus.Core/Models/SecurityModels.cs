namespace BaroAntivirus.Core.Models;

public sealed class QuarantineEntry
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];
    public string OriginalPath { get; init; } = string.Empty;
    public string OriginalFileName { get; init; } = string.Empty;
    public string VaultFileName { get; init; } = string.Empty;
    public string ThreatName { get; init; } = string.Empty;
    public ThreatCategory Category { get; init; }
    public ThreatSeverity Severity { get; init; }
    public int RiskScore { get; init; }
    public List<string> Reasons { get; init; } = new();
    public string Sha256 { get; init; } = string.Empty;
    public long OriginalSize { get; init; }
    public DateTimeOffset QuarantinedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class UrlCheckResult
{
    public string Url { get; init; } = string.Empty;
    public string NormalizedHost { get; init; } = string.Empty;
    public bool IsSafe { get; init; }
    public int RiskScore { get; init; }
    public string Verdict { get; init; } = string.Empty;
    public bool IsPunycode { get; init; }
    public bool IsIpLiteral { get; init; }
    public List<string> Reasons { get; init; } = new();
}

public sealed class ProcessRiskInfo
{
    public int Pid { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string ExecutablePath { get; init; } = string.Empty;
    public string CommandLine { get; init; } = string.Empty;
    public double MemoryMB { get; init; }
    public bool IsSigned { get; init; }
    public string? SignerName { get; init; }
    public int RiskScore { get; init; }
    public string Status { get; init; } = "An toàn";
    public List<string> Reasons { get; init; } = new();
}

public sealed class NetworkConnectionInfo
{
    public string Protocol { get; init; } = "TCP";
    public string LocalEndpoint { get; init; } = string.Empty;
    public string RemoteAddress { get; init; } = string.Empty;
    public int RemotePort { get; init; }
    public string State { get; init; } = string.Empty;
    public int Pid { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string ExecutablePath { get; init; } = string.Empty;
    public bool IsSuspicious { get; init; }
    public string Reason { get; init; } = string.Empty;
}

public sealed class StartupEntryInfo
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..10];
    public string Name { get; init; } = string.Empty;
    public string Location { get; init; } = string.Empty;
    public string Command { get; init; } = string.Empty;
    public string ResolvedPath { get; init; } = string.Empty;
    public bool IsEnabled { get; init; } = true;
    public bool IsSigned { get; init; }
    public string? SignerName { get; init; }
    public int RiskScore { get; init; }
    public string Status { get; init; } = "Bình thường";
    public string Reason { get; init; } = string.Empty;
    public bool IsRegistry { get; init; }
    public bool IsLocalMachine { get; init; }
    public string RegistrySubKey { get; init; } = string.Empty;
}

public sealed class SecurityLogEntry
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..10];
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.Now;
    public SecurityLogLevel Level { get; init; }
    public string Module { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
    public string? Details { get; init; }
}

public sealed class DownloadInspectionEvent
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.Now;
    public string FilePath { get; init; } = string.Empty;
    public string FileName { get; init; } = string.Empty;
    public int? ZoneId { get; init; }
    public string? HostUrl { get; init; }
    public bool IsSigned { get; init; }
    public string? SignerName { get; init; }
    public bool IsThreat { get; init; }
    public int RiskScore { get; init; }
    public string Verdict { get; init; } = string.Empty;
    public ProtectionAction ActionTaken { get; init; }
}

public sealed class ResourceMetrics
{
    public double WorkingSetMB { get; init; }
    public double PrivateMemoryMB { get; init; }
    public double CpuPercent { get; init; }
    public int ThreadCount { get; init; }
}

public sealed class AppSettings
{
    public bool RealtimeProtectionEnabled { get; set; } = true;
    public bool DownloadGuardEnabled { get; set; } = true;
    public bool RansomwareShieldEnabled { get; set; } = true;
    public bool ProcessGuardEnabled { get; set; } = true;
    public bool UsbShieldEnabled { get; set; } = true;
    public bool ClipboardUrlGuardEnabled { get; set; } = true;
    public bool HostsProtectionEnabled { get; set; } = false;
    public bool AutoQuarantineHighRisk { get; set; } = true;
    public bool RunAtWindowsStartup { get; set; } = true;
    public bool MinimizeToTrayOnClose { get; set; } = true;
    public bool LightweightMemoryTrim { get; set; } = true;
    public StrictnessLevel Strictness { get; set; } = StrictnessLevel.Strict;
    public int MaxDeepScanConcurrency { get; set; } = 2;
    public int DeepScanMaxFileSizeMb { get; set; } = 128;
    public int ScheduledQuickScanMinutes { get; set; } = 0; // 0 = off, >0 = periodic background quick scan
    public List<string> ExcludedPaths { get; set; } = new();
    public List<string> ExcludedHashes { get; set; } = new();
    public List<string> ProtectedFolders { get; set; } = new();
    public List<string> CustomBlockedDomains { get; set; } = new();
}
