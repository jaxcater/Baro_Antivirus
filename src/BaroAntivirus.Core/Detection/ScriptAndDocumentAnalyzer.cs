using System.Text;
using System.Text.RegularExpressions;

namespace BaroAntivirus.Core.Detection;

public sealed record ScriptAnalysisResult(int RiskScore, List<string> Reasons, string? SuggestedThreatName);

public static partial class ScriptAndDocumentAnalyzer
{
    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".hta", ".py", ".html", ".htm", ".svg", ".url"
    };

    private static readonly string[] DocumentDecoyExtensions =
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".txt", ".jpg", ".jpeg", ".png", ".mp3", ".mp4", ".zip", ".rar"
    };

    private static readonly HashSet<string> DangerousExecExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".hta", ".ps1", ".msi", ".dll", ".cpl", ".lnk"
    };

    private static string T(params string[] parts) => string.Concat(parts);

    public static bool IsScriptOrDocument(string ext) =>
        ScriptExtensions.Contains(ext) || ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase);

    public static (int Score, List<string> Reasons) CheckFilenameMasquerading(string fileName)
    {
        var reasons = new List<string>();
        int score = 0;

        if (fileName.Contains('\u202E') || fileName.Contains('\u202D') || fileName.Contains('\u200F'))
        {
            score += 90;
            reasons.Add("Phát hiện ký tự Unicode RLO (\\u202E) giả mạo phần mở rộng tệp để đánh lừa người dùng!");
        }

        string ext = Path.GetExtension(fileName);
        if (DangerousExecExtensions.Contains(ext))
        {
            string stem = Path.GetFileNameWithoutExtension(fileName);
            string innerExt = Path.GetExtension(stem);
            if (!string.IsNullOrEmpty(innerExt) && DocumentDecoyExtensions.Contains(innerExt, StringComparer.OrdinalIgnoreCase))
            {
                score += 80;
                reasons.Add($"Phát hiện giả mạo phần mở rộng kép nguy hiểm ('{innerExt}{ext}') — ngụy trang tệp thực thi thành tài liệu/ảnh.");
            }
        }

        return (score, reasons);
    }

    public static ScriptAnalysisResult AnalyzeFile(string filePath)
    {
        string ext = Path.GetExtension(filePath).ToLowerInvariant();
        if (ext == ".lnk")
            return AnalyzeShortcutLnk(filePath);

        if (!ScriptExtensions.Contains(ext))
            return new ScriptAnalysisResult(0, new List<string>(), null);

        try
        {
            long len = new FileInfo(filePath).Length;
            if (len == 0 || len > 4 * 1024 * 1024)
                return new ScriptAnalysisResult(0, new List<string>(), null);

            string content = File.ReadAllText(filePath, Encoding.UTF8);
            return AnalyzeScriptContent(content, ext);
        }
        catch
        {
            return new ScriptAnalysisResult(0, new List<string>(), null);
        }
    }

    public static ScriptAnalysisResult AnalyzeScriptContent(string content, string ext)
    {
        var reasons = new List<string>();
        int score = 0;
        string lower = content.ToLowerInvariant();

        if (ext is ".html" or ".htm" or ".svg")
        {
            bool hasAtob = lower.Contains("atob(");
            bool hasBlob = lower.Contains("new blob(") || lower.Contains("mssaveoropenblob");
            bool hasOctet = lower.Contains("application/octet-stream") || lower.Contains("x-msdownload");
            if (hasAtob && (hasBlob || hasOctet))
            {
                score += 78;
                reasons.Add("Phát hiện kỹ thuật HTML Smuggling giải mã payload nhị phân ngầm trong tệp HTML/SVG.");
                return new ScriptAnalysisResult(score, reasons, "Trojan.HTMLSmuggling.Dropper");
            }
            return new ScriptAnalysisResult(0, reasons, null);
        }

        if (ext == ".url")
        {
            if (lower.Contains("file://") && (lower.Contains(@"\\") || lower.Contains(".exe") || lower.Contains(".hta")))
            {
                score += 75;
                reasons.Add("Tệp .URL trỏ tới đường dẫn SMB/UNC hoặc tệp thực thi từ xa.");
                return new ScriptAnalysisResult(score, reasons, "Trojan.URL.RemoteShare");
            }
            return new ScriptAnalysisResult(0, reasons, null);
        }

        if (EncodedCommandRegex().IsMatch(content))
        {
            score += 45;
            reasons.Add("Sử dụng tham số mã hóa lệnh PowerShell (-EncodedCommand / -enc).");
        }

        if (lower.Contains(T("invoke-", "expression")) || Regex.IsMatch(lower, @"\biex\s*\(") || lower.Contains("eval(") || lower.Contains("execute("))
        {
            score += 25;
            reasons.Add("Thực thi mã động trong bộ nhớ (IEX / eval / Execute).");
        }

        if (lower.Contains(T("from", "base64", "string")) || LongBase64Regex().IsMatch(content))
        {
            score += 28;
            reasons.Add("Chứa khối dữ liệu Base64 dài bất thường hoặc giải mã Base64.");
        }

        if (lower.Contains(T("down", "loadstring")) || lower.Contains(T("down", "loadfile")) ||
            lower.Contains(T("invoke-", "webrequest")) || lower.Contains("xmlhttp") ||
            lower.Contains("bitsadmin") || lower.Contains("urlmon"))
        {
            score += 24;
            reasons.Add("Có hành vi tải tệp hoặc payload từ Internet.");
        }

        if (lower.Contains("-w hidden") || lower.Contains("-windowstyle hidden") ||
            (lower.Contains(T("wscript", ".shell")) && (lower.Contains(", 0") || lower.Contains(",0"))))
        {
            score += 22;
            reasons.Add("Chạy cửa sổ ẩn (Hidden Window) nhằm che giấu người dùng.");
        }

        if (lower.Contains(T("add-", "mppreference")) && lower.Contains("exclusion"))
        {
            score += 70;
            reasons.Add("Cố gắng thêm ngoại lệ vào trình diệt virus hệ thống (Tampering).");
        }

        if (lower.Contains("currentversion\\run") || lower.Contains("schtasks /create"))
        {
            score += 20;
            reasons.Add("Thiết lập cơ chế tự khởi động cùng Windows (Persistence).");
        }

        if (content.Length > 100)
        {
            int obfChars = 0;
            foreach (char c in content)
            {
                if (c == '^' || c == '`') obfChars++;
            }
            if (obfChars >= 18)
            {
                score += 32;
                reasons.Add($"Phát hiện làm rối mã nguồn (Obfuscation) với mật độ ký tự '^' / '`' cao ({obfChars} ký tự).");
            }
        }

        if (ext == ".hta" && (lower.Contains(T("wscript", ".shell")) || lower.Contains("powershell") || lower.Contains("cmd.exe")))
        {
            score += 45;
            reasons.Add("Tệp HTA thực thi shell lệnh hệ thống (nguy cơ cao lây nhiễm qua web).");
        }

        string? threatName = score >= 75 ? $"Trojan.Script.{ext.TrimStart('.').ToUpperInvariant()}.Dropper"
            : score >= 45 ? $"Heuristic.SuspiciousScript.{ext.TrimStart('.').ToUpperInvariant()}"
            : null;

        return new ScriptAnalysisResult(Math.Min(score, 95), reasons, threatName);
    }

    private static ScriptAnalysisResult AnalyzeShortcutLnk(string filePath)
    {
        var reasons = new List<string>();
        int score = 0;

        try
        {
            byte[] bytes = File.ReadAllBytes(filePath);
            if (bytes.Length < 76 || bytes[0] != 0x4C || bytes[1] != 0x00)
                return new ScriptAnalysisResult(0, reasons, null);

            var sb = new StringBuilder(bytes.Length);
            foreach (byte b in bytes)
            {
                if (b >= 32 && b <= 126) sb.Append((char)b);
                else if (b != 0) sb.Append(' ');
            }
            string text = sb.ToString().ToLowerInvariant();

            string[] lolBins = { "powershell", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil", "bitsadmin" };
            string? hitBin = lolBins.FirstOrDefault(b => text.Contains(b, StringComparison.Ordinal));
            if (hitBin != null)
            {
                score += 45;
                reasons.Add($"Shortcut (.lnk) gọi công cụ hệ thống nguy hiểm '{hitBin}'.");

                if (text.Contains("http://") || text.Contains("https://") || text.Contains("-enc") ||
                    text.Contains(T("from", "base64", "string")) || text.Contains("hidden") || text.Contains("iex"))
                {
                    score += 40;
                    reasons.Add("Shortcut (.lnk) chứa tham số tải từ xa hoặc mã hóa lệnh ẩn.");
                }
            }

            string? name = score >= 70 ? "Trojan.LNK.MaliciousShortcut" : score >= 40 ? "Heuristic.LNK.SuspiciousTarget" : null;
            return new ScriptAnalysisResult(Math.Min(score, 95), reasons, name);
        }
        catch
        {
            return new ScriptAnalysisResult(0, reasons, null);
        }
    }

    [GeneratedRegex(@"-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", RegexOptions.IgnoreCase)]
    private static partial Regex EncodedCommandRegex();

    [GeneratedRegex(@"[A-Za-z0-9+/]{160,}={0,2}")]
    private static partial Regex LongBase64Regex();
}
