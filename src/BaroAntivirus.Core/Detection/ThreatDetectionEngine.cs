using System.Security.Cryptography;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Detection;

public sealed class ThreatDetectionEngine
{
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".msi", ".com"
    };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip"
    };

    private readonly SignatureDatabase _signatureDb;

    public ThreatDetectionEngine(SignatureDatabase signatureDb)
    {
        _signatureDb = signatureDb;
    }

    public SignatureDatabase SignatureDb => _signatureDb;

    public ThreatFinding? InspectFile(
        string filePath,
        StrictnessLevel strictness,
        bool inspectArchives,
        IEnumerable<string>? excludedPaths = null,
        IEnumerable<string>? excludedHashes = null)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return null;

        if (IsPathExcluded(filePath, excludedPaths))
            return null;

        FileInfo fi;
        try
        {
            fi = new FileInfo(filePath);
            if (fi.Length == 0) return null;
        }
        catch
        {
            return null;
        }

        string fileName = fi.Name;
        string ext = fi.Extension.ToLowerInvariant();
        var reasons = new List<string>();
        int riskScore = 0;
        ThreatCategory category = ThreatCategory.MalwareSignature;
        string? threatName = null;
        string engineSource = "BaroMultiEngine";

        // 1. Filename Masquerading / RLO check (instant, zero disk read)
        var (masqScore, masqReasons) = ScriptAndDocumentAnalyzer.CheckFilenameMasquerading(fileName);
        if (masqScore > 0)
        {
            riskScore = Math.Max(riskScore, masqScore);
            reasons.AddRange(masqReasons);
            category = ThreatCategory.MasqueradingOrSpoofing;
            threatName ??= "Trojan.Masquerade.SpoofedExtension";
        }

        // 2. Compute SHA-256 (streaming) & check exclusions + known malware hashes
        string sha256 = ComputeSha256(filePath);
        if (!string.IsNullOrEmpty(sha256) &&
            excludedHashes != null &&
            excludedHashes.Contains(sha256, StringComparer.OrdinalIgnoreCase))
        {
            return null;
        }

        if (!string.IsNullOrEmpty(sha256))
        {
            var hashHit = _signatureDb.CheckHash(sha256);
            if (hashHit != null)
            {
                return new ThreatFinding
                {
                    FilePath = filePath,
                    FileName = fileName,
                    ThreatName = hashHit.ThreatName,
                    Category = hashHit.Category,
                    Severity = ThreatSeverity.Critical,
                    RiskScore = 100,
                    Reasons = new List<string> { hashHit.Reason },
                    Sha256 = sha256,
                    FileSize = fi.Length,
                    EngineSource = "BaroSignatureHash"
                };
            }
        }

        // 3. Content signature scan (EICAR + YARA-like byte/string patterns) on files up to 16 MB
        if (fi.Length <= 16 * 1024 * 1024)
        {
            try
            {
                int sampleLen = (int)Math.Min(fi.Length, 4 * 1024 * 1024);
                byte[] buffer = new byte[sampleLen];
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    int read = fs.Read(buffer, 0, sampleLen);
                    var sigMatches = _signatureDb.ScanContentBytes(buffer.AsSpan(0, read));
                    foreach (var m in sigMatches)
                    {
                        riskScore = Math.Max(riskScore, m.RiskScore);
                        if (riskScore >= 85) category = m.Category;
                        threatName ??= m.ThreatName;
                        reasons.Add(m.Reason);
                        engineSource = "BaroSignatureYara";
                    }
                }
            }
            catch
            {
                // Locked file fallback
            }
        }

        // 4. Zone.Identifier (Downloaded from Internet check)
        ZoneIdentifierInfo? zone = ZoneIdentifierReader.Read(filePath);
        bool isFromInternet = zone != null && zone.ZoneId >= 3;

        bool isExec = ExecutableExtensions.Contains(ext);
        bool isScriptOrDoc = ScriptAndDocumentAnalyzer.IsScriptOrDocument(ext);
        bool isSigned = false;
        string? signerName = null;

        // 5. Authenticode verification & PE Structural Analysis for executables/DLLs
        if (isExec)
        {
            var auth = AuthenticodeVerifier.Verify(filePath);
            isSigned = auth.IsValidSigned;
            signerName = auth.SignerName;

            var pe = PeAnalyzer.Analyze(filePath);
            if (pe.IsValidPe)
            {
                // Trusted validly signed Microsoft / well-known OS files in Windows dir get strong false-positive protection
                bool isWindowsSystemSigned = isSigned &&
                    (filePath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase)) &&
                    (signerName?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true);

                if (!isWindowsSystemSigned)
                {
                    if (pe.RiskScore > 0)
                    {
                        int adjustedPeScore = isSigned ? pe.RiskScore / 2 : pe.RiskScore;
                        riskScore = Math.Max(riskScore, adjustedPeScore);
                        reasons.AddRange(pe.Reasons);
                        if (!string.IsNullOrEmpty(pe.DetectedRatFamily))
                        {
                            category = ThreatCategory.TrojanOrDropper;
                            threatName ??= $"Trojan.RAT.{pe.DetectedRatFamily}";
                        }
                        else if (pe.HasPackerSection || pe.MaxSectionEntropy >= 7.2)
                        {
                            category = ThreatCategory.PackedOrObfuscated;
                            threatName ??= "Heuristic.Packed.SuspiciousPE";
                        }
                        else if (pe.SuspiciousApis.Count > 0 || pe.RiskScore >= 50)
                        {
                            category = ThreatCategory.TrojanOrDropper;
                            threatName ??= "Heuristic.PE.SuspiciousBehaviorAPI";
                        }
                    }

                    // Strict & Paranoid Internet-download enforcement (stricter than default Windows Defender)
                    if (!isSigned && isFromInternet)
                    {
                        int internetPenalty = strictness switch
                        {
                            StrictnessLevel.Paranoid => 75,
                            StrictnessLevel.Strict => 42,
                            _ => 20
                        };
                        riskScore = Math.Min(100, riskScore + internetPenalty);
                        category = riskScore >= 65 ? ThreatCategory.UntrustedDownloadedExecutable : category;
                        threatName ??= "StrictShield.UnsignedInternetExecutable";
                        reasons.Add($"Tệp thực thi tải từ Internet (ZoneId={zone!.ZoneId}) KHÔNG có chữ ký số hợp lệ ({auth.StatusNote}).");
                    }
                    else if (!isSigned && IsUserStagingLocation(filePath) && strictness >= StrictnessLevel.Strict)
                    {
                        riskScore = Math.Min(100, riskScore + 20);
                        reasons.Add("Tệp thực thi không có chữ ký số nằm trong thư mục nhạy cảm (Temp/Downloads/AppData).");
                    }
                }
            }
            else if (pe.HasMalformedHeaders)
            {
                riskScore = Math.Max(riskScore, pe.RiskScore);
                reasons.AddRange(pe.Reasons);
                threatName ??= "Heuristic.PE.MalformedHeader";
            }
        }

        // 6. Script / LNK / HTML Smuggling Analysis
        if (isScriptOrDoc)
        {
            var scriptRes = ScriptAndDocumentAnalyzer.AnalyzeFile(filePath);
            if (scriptRes.RiskScore > 0)
            {
                int bonus = isFromInternet && strictness >= StrictnessLevel.Strict ? 15 : 0;
                riskScore = Math.Max(riskScore, Math.Min(100, scriptRes.RiskScore + bonus));
                reasons.AddRange(scriptRes.Reasons);
                if (isFromInternet && bonus > 0)
                    reasons.Add($"Script/Shortcut có nguồn gốc tải từ Internet (ZoneId={zone!.ZoneId}).");
                category = ThreatCategory.SuspiciousScript;
                threatName ??= scriptRes.SuggestedThreatName ?? "Heuristic.SuspiciousScript";
            }
            else if (isFromInternet && strictness == StrictnessLevel.Paranoid &&
                     ext is ".vbs" or ".vbe" or ".jse" or ".hta" or ".ps1" or ".bat" or ".cmd")
            {
                riskScore = Math.Max(riskScore, 65);
                reasons.Add($"Chế độ Siêu Chặt (Paranoid): Chặn tệp script ({ext}) tải trực tiếp từ Internet.");
                category = ThreatCategory.SuspiciousScript;
                threatName ??= "ParanoidShield.InternetScriptBlocked";
            }
        }

        // 7. Archive Deep Inspection (.zip)
        if (inspectArchives && ArchiveExtensions.Contains(ext))
        {
            var archRes = ArchiveInspector.InspectZip(filePath, _signatureDb, isFromInternet);
            if (archRes.RiskScore > 0)
            {
                riskScore = Math.Max(riskScore, archRes.RiskScore);
                reasons.AddRange(archRes.Reasons);
                category = ThreatCategory.ArchiveAnomaly;
                threatName ??= archRes.ThreatName ?? "Heuristic.Archive.SuspiciousPayload";
            }
        }

        int threshold = strictness switch
        {
            StrictnessLevel.Paranoid => 40,
            StrictnessLevel.Strict => 50,
            _ => 65
        };

        if (riskScore < threshold)
            return null;

        ThreatSeverity severity = riskScore switch
        {
            >= 85 => ThreatSeverity.Critical,
            >= 68 => ThreatSeverity.High,
            >= 50 => ThreatSeverity.Medium,
            _ => ThreatSeverity.Low
        };

        return new ThreatFinding
        {
            FilePath = filePath,
            FileName = fileName,
            ThreatName = threatName ?? "Heuristic.Malware.Generic",
            Category = category,
            Severity = severity,
            RiskScore = Math.Min(riskScore, 100),
            Reasons = reasons.Distinct().ToList(),
            Sha256 = sha256,
            FileSize = fi.Length,
            EngineSource = engineSource,
            IsAuthenticodeSigned = isSigned,
            SignerName = signerName,
            ZoneId = zone?.ZoneId
        };
    }

    private static bool IsUserStagingLocation(string path)
    {
        string lower = path.ToLowerInvariant();
        return lower.Contains("\\downloads\\") ||
               lower.Contains("\\temp\\") ||
               lower.Contains("\\appdata\\local\\temp\\") ||
               lower.Contains("\\startup\\");
    }

    private static bool IsPathExcluded(string filePath, IEnumerable<string>? excludedPaths)
    {
        if (excludedPaths == null) return false;
        foreach (string ex in excludedPaths)
        {
            if (string.IsNullOrWhiteSpace(ex)) continue;
            string norm = ex.Trim().TrimEnd('\\');
            if (filePath.Equals(norm, StringComparison.OrdinalIgnoreCase) ||
                filePath.StartsWith(norm + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    public static string ComputeSha256(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.SequentialScan);
            byte[] hash = SHA256.HashData(fs);
            return Convert.ToHexStringLower(hash);
        }
        catch
        {
            return string.Empty;
        }
    }
}
