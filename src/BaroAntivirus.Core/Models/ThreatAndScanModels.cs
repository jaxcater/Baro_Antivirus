namespace BaroAntivirus.Core.Models;

public sealed class ThreatFinding
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];
    public string FilePath { get; init; } = string.Empty;
    public string FileName { get; init; } = string.Empty;
    public string ThreatName { get; init; } = string.Empty;
    public ThreatCategory Category { get; init; }
    public ThreatSeverity Severity { get; init; }
    public int RiskScore { get; init; }
    public List<string> Reasons { get; init; } = new();
    public string Sha256 { get; init; } = string.Empty;
    public long FileSize { get; init; }
    public DateTimeOffset DetectedAt { get; init; } = DateTimeOffset.UtcNow;
    public string EngineSource { get; init; } = "BaroEngine";
    public bool IsAuthenticodeSigned { get; init; }
    public string? SignerName { get; init; }
    public int? ZoneId { get; init; }
    public ProtectionAction ActionTaken { get; set; } = ProtectionAction.None;
}

public sealed class ScanProgress
{
    public long FilesScanned { get; init; }
    public long TotalFilesEstimated { get; init; }
    public int ThreatsFound { get; init; }
    public long SkippedFiles { get; init; }
    public long BytesScanned { get; init; }
    public string CurrentFile { get; init; } = string.Empty;
    public double FilesPerSecond { get; init; }
    public TimeSpan Elapsed { get; init; }
    public bool IsPaused { get; init; }
    public ScanMode Mode { get; init; }
}

public sealed class ScanResult
{
    public string ScanId { get; init; } = Guid.NewGuid().ToString("N")[..10];
    public ScanMode Mode { get; init; }
    public StrictnessLevel Strictness { get; init; }
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset CompletedAt { get; init; }
    public bool Cancelled { get; init; }
    public long FilesScanned { get; init; }
    public long SkippedFiles { get; init; }
    public long BytesScanned { get; init; }
    public List<ThreatFinding> Findings { get; init; } = new();
}
