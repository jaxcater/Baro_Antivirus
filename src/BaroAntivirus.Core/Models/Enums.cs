namespace BaroAntivirus.Core.Models;

public enum ThreatSeverity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum ThreatCategory
{
    MalwareSignature,
    TrojanOrDropper,
    RansomwareBehavior,
    PackedOrObfuscated,
    SuspiciousScript,
    PhishingOrMaliciousUrl,
    MasqueradingOrSpoofing,
    UntrustedDownloadedExecutable,
    ProcessAnomaly,
    PersistenceThreat,
    ArchiveAnomaly
}

public enum ScanMode
{
    Quick,
    DeepScan,
    Custom,
    Realtime,
    Usb
}

public enum StrictnessLevel
{
    Balanced = 0,
    Strict = 1,
    Paranoid = 2
}

public enum ProtectionAction
{
    None,
    Warned,
    Quarantined,
    Blocked,
    Terminated
}

public enum SecurityLogLevel
{
    Info,
    Warning,
    Alert,
    Action
}
