using System.IO.Compression;
using System.Text;

namespace BaroAntivirus.Core.Detection;

public sealed record ArchiveInspectionResult(int RiskScore, List<string> Reasons, string? ThreatName);

public static class ArchiveInspector
{
    private static readonly HashSet<string> HighRiskInnerExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".hta", ".ps1", ".lnk", ".iso", ".img", ".cpl", ".dll"
    };

    public static ArchiveInspectionResult InspectZip(
        string filePath,
        SignatureDatabase sigDb,
        bool isFromInternet)
    {
        var reasons = new List<string>();
        int score = 0;
        string? threatName = null;

        try
        {
            long archiveSize = new FileInfo(filePath).Length;
            if (archiveSize > 150 * 1024 * 1024)
                return new ArchiveInspectionResult(0, reasons, null);

            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var archive = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);

            long totalUncompressed = 0;
            int inspectedCount = 0;

            foreach (var entry in archive.Entries)
            {
                if (inspectedCount++ > 500) break;
                if (string.IsNullOrEmpty(entry.Name)) continue; // Directory

                totalUncompressed += entry.Length;

                // Zip Bomb detection
                if (entry.CompressedLength > 0 && entry.Length > 100 * 1024 * 1024 &&
                    (entry.Length / entry.CompressedLength) > 120)
                {
                    score = Math.Max(score, 85);
                    threatName ??= "Exploit.Archive.ZipBomb";
                    reasons.Add($"Phát hiện dấu hiệu Zip Bomb trong '{entry.FullName}' (tỷ lệ nén > 120:1).");
                    continue;
                }

                // Masquerading check inside archive
                var (masqScore, masqReasons) = ScriptAndDocumentAnalyzer.CheckFilenameMasquerading(entry.Name);
                if (masqScore > 0)
                {
                    score = Math.Max(score, masqScore);
                    threatName ??= "Trojan.Archive.MasqueradedPayload";
                    reasons.AddRange(masqReasons.Select(r => $"[Trong tệp nén {entry.Name}] {r}"));
                }

                string innerExt = Path.GetExtension(entry.Name);
                bool isRiskyExt = HighRiskInnerExtensions.Contains(innerExt);

                // Password-protected / encrypted entry check (bit 0 of GeneralPurposeBitFlag? ZipArchive throws InvalidDataException on open!)
                if (entry.Length <= 8 * 1024 * 1024)
                {
                    try
                    {
                        using var entryStream = entry.Open();
                        if (entry.Length > 0)
                        {
                            using var ms = new MemoryStream((int)Math.Min(entry.Length, 4 * 1024 * 1024));
                            byte[] buf = new byte[16384];
                            int totalRead = 0;
                            while (totalRead < 4 * 1024 * 1024)
                            {
                                int r = entryStream.Read(buf, 0, Math.Min(buf.Length, 4 * 1024 * 1024 - totalRead));
                                if (r <= 0) break;
                                ms.Write(buf, 0, r);
                                totalRead += r;
                            }

                            var sigHits = sigDb.ScanContentBytes(ms.GetBuffer().AsSpan(0, (int)ms.Length));
                            if (sigHits.Count > 0)
                            {
                                var top = sigHits[0];
                                score = Math.Max(score, top.RiskScore);
                                threatName ??= top.ThreatName;
                                reasons.Add($"[Trong tệp nén {entry.Name}] {top.Reason}");
                            }

                            if (ScriptAndDocumentAnalyzer.IsScriptOrDocument(innerExt) && !innerExt.Equals(".lnk", StringComparison.OrdinalIgnoreCase))
                            {
                                string scriptText = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
                                var scriptRes = ScriptAndDocumentAnalyzer.AnalyzeScriptContent(scriptText, innerExt.ToLowerInvariant());
                                if (scriptRes.RiskScore >= 40)
                                {
                                    score = Math.Max(score, scriptRes.RiskScore);
                                    threatName ??= scriptRes.SuggestedThreatName;
                                    reasons.AddRange(scriptRes.Reasons.Select(r => $"[Trong tệp nén {entry.Name}] {r}"));
                                }
                            }
                        }
                    }
                    catch (InvalidDataException)
                    {
                        if (isRiskyExt && isFromInternet)
                        {
                            score = Math.Max(score, 72);
                            threatName ??= "Heuristic.EncryptedArchive.ExecutableDropper";
                            reasons.Add($"Tệp nén tải từ Internet chứa tệp thực thi/script '{entry.Name}' được đặt mật khẩu (kỹ thuật né trình quét).");
                        }
                        else if (isRiskyExt)
                        {
                            score = Math.Max(score, 45);
                            reasons.Add($"Tệp nén chứa tệp thực thi '{entry.Name}' được mã hóa mật khẩu.");
                        }
                    }
                }

                if (isRiskyExt && isFromInternet && score < 55)
                {
                    score = Math.Max(score, 52);
                    threatName ??= "Riskware.DownloadedArchive.ContainsExecutable";
                    reasons.Add($"Tệp nén từ Internet chứa tệp có khả năng thực thi '{entry.Name}'.");
                }
            }

            if (totalUncompressed > 2L * 1024 * 1024 * 1024)
            {
                score = Math.Max(score, 80);
                threatName ??= "Exploit.Archive.Oversized";
                reasons.Add("Tổng dung lượng giải nén vượt quá 2 GB (nguy cơ Zip Bomb).");
            }
        }
        catch
        {
            // Ignore unreadable/corrupt archive
        }

        return new ArchiveInspectionResult(Math.Min(score, 100), reasons, threatName);
    }
}
