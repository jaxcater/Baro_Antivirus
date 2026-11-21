using System.Net;
using System.Text.RegularExpressions;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Detection;

public sealed record ClipboardScanResult(
    bool HasThreat,
    int MaxRiskScore,
    List<UrlCheckResult> FlaggedUrls,
    List<string> CommandWarnings);

public sealed class UrlReputationAnalyzer
{
    private static readonly Regex UrlExtractRegex = new(
        @"(?i)\b((?:https?|ftp)://[^\s""'<>()\[\]{}|\\^`]+)",
        RegexOptions.Compiled);

    private static readonly Regex BareIpUrlRegex = new(
        @"(?i)\b((?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?/[^\s""'<>()\[\]{}|\\^`]*)",
        RegexOptions.Compiled);
    private static readonly HashSet<string> DefaultBlockedDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "testsafebrowsing.appspot.com",
        "malware.wicar.org",
        "eicar.org-phish-test.invalid",
        "login-verify-microsoft-security.xyz",
        "vietcombank-xacthuc-24h.top",
        "mbbank-quatang-online.click",
        "update-chrome-flashplayer.cc",
        "discord-nitro-free-gift.ru",
        "paypal-resolution-center.tk"
    };

    private static readonly string[] AbusedTlds =
    {
        ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click", ".buzz", ".work", ".loan", ".zip", ".mov"
    };

    private static readonly string[] ProtectedBrands =
    {
        "microsoft", "google", "facebook", "paypal", "apple", "binance", "metamask",
        "discord", "steam", "vietcombank", "techcombank", "mbbank", "bidv", "vpbank", "momo", "zalopay"
    };

    private static readonly string[] OfficialBrandDomains =
    {
        "microsoft.com", "google.com", "facebook.com", "paypal.com", "apple.com",
        "binance.com", "metamask.io", "discord.com", "steampowered.com", "steamcommunity.com",
        "vietcombank.com.vn", "techcombank.com", "mbbank.com.vn", "bidv.com.vn", "vpbank.com.vn", "momo.vn", "zalopay.vn"
    };

    private static readonly string[] DangerousDownloadExts =
    {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".hta", ".msi", ".iso", ".lnk", ".pif"
    };

    private readonly HashSet<string> _customBlocked = new(StringComparer.OrdinalIgnoreCase);

    public void SetCustomBlockedDomains(IEnumerable<string> domains)
    {
        _customBlocked.Clear();
        foreach (string d in domains)
        {
            if (!string.IsNullOrWhiteSpace(d))
                _customBlocked.Add(d.Trim().ToLowerInvariant());
        }
    }

    public UrlCheckResult Analyze(string rawUrl)
    {
        var reasons = new List<string>();
        int score = 0;

        if (string.IsNullOrWhiteSpace(rawUrl))
        {
            return new UrlCheckResult { Url = rawUrl, IsSafe = true, Verdict = "URL trống", Reasons = reasons };
        }

        string candidate = rawUrl.Trim();
        if (!candidate.Contains("://", StringComparison.Ordinal))
            candidate = "https://" + candidate;

        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri))
        {
            return new UrlCheckResult
            {
                Url = rawUrl,
                IsSafe = false,
                RiskScore = 60,
                Verdict = "Cảnh báo: URL không hợp lệ hoặc bị làm rối",
                Reasons = new List<string> { "Định dạng URL bất thường, không thể phân tích chuẩn." }
            };
        }

        string host = uri.Host.ToLowerInvariant();
        bool isPunycode = host.Contains("xn--", StringComparison.OrdinalIgnoreCase);
        bool isIpLiteral = IPAddress.TryParse(host, out _);

        if (DefaultBlockedDomains.Contains(host) || _customBlocked.Contains(host) ||
            _customBlocked.Any(b => host.EndsWith("." + b, StringComparison.OrdinalIgnoreCase)))
        {
            score += 95;
            reasons.Add($"Tên miền '{host}' nằm trong danh sách chặn mã độc / lừa đảo của BaroAntivirus.");
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            score += 65;
            reasons.Add("URL chứa ký tự '@' nhúng thông tin đăng nhập giả mạo tên miền (Credential Phishing trick).");
        }

        if (isPunycode)
        {
            score += 45;
            reasons.Add("Tên miền sử dụng mã hóa Punycode (xn--) — có nguy cơ tấn công giả mạo ký tự đồng hình (IDN Homograph).");
        }

        if (isIpLiteral)
        {
            score += 40;
            reasons.Add("Liên kết trỏ trực tiếp tới địa chỉ IP thay vì tên miền hợp lệ.");
        }

        if (uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase))
        {
            score += 12;
            reasons.Add("Sử dụng giao thức HTTP không mã hóa (dễ bị nghe lén hoặc chèn mã độc).");
        }

        if (AbusedTlds.Any(tld => host.EndsWith(tld, StringComparison.OrdinalIgnoreCase)))
        {
            score += 22;
            reasons.Add("Tên miền sử dụng đuôi mở rộng (TLD) có tỷ lệ lạm dụng cao.");
        }

        // Brand impersonation check
        bool isOfficial = OfficialBrandDomains.Any(d => host.Equals(d, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
        if (!isOfficial)
        {
            foreach (string brand in ProtectedBrands)
            {
                if (host.Contains(brand, StringComparison.OrdinalIgnoreCase))
                {
                    score += 55;
                    reasons.Add($"Nghi vấn giả mạo thương hiệu '{brand}' trên tên miền không chính thức ('{host}').");
                    break;
                }
            }
        }

        int dotCount = host.Count(c => c == '.');
        if (dotCount >= 4)
        {
            score += 18;
            reasons.Add($"Tên miền có quá nhiều tên miền phụ ({dotCount + 1} cấp), thường dùng để che giấu trang đích.");
        }

        string pathLower = uri.AbsolutePath.ToLowerInvariant();
        if (DangerousDownloadExts.Any(ext => pathLower.EndsWith(ext, StringComparison.Ordinal)))
        {
            score += 35;
            reasons.Add($"Liên kết tải trực tiếp tệp có khả năng thực thi ({Path.GetExtension(pathLower)}).");
        }

        if (uri.Port is 4444 or 5555 or 1337 or 6667 or 31337)
        {
            score += 65;
            reasons.Add($"Cổng kết nối ({uri.Port}) thường liên quan tới máy chủ C2 / Backdoor.");
        }

        score = Math.Min(score, 100);
        bool isSafe = score < 35;
        string verdict = score >= 70 ? "NGUY HIỂM — Nghi ngờ Lừa đảo / Mã độc"
            : score >= 35 ? "CẢNH BÁO — Liên kết đáng ngờ"
            : "An toàn";

        if (reasons.Count == 0)
            reasons.Add("Không phát hiện dấu hiệu lừa đảo hoặc tải mã độc rõ ràng.");

        return new UrlCheckResult
        {
            Url = rawUrl,
            NormalizedHost = host,
            IsSafe = isSafe,
            RiskScore = score,
            Verdict = verdict,
            IsPunycode = isPunycode,
            IsIpLiteral = isIpLiteral,
            Reasons = reasons
        };
    }

    public static List<string> ExtractUrls(string text)
    {
        var results = new List<string>();
        if (string.IsNullOrWhiteSpace(text)) return results;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Match m in UrlExtractRegex.Matches(text))
        {
            string url = CleanExtractedUrl(m.Groups[1].Value);
            if (!string.IsNullOrEmpty(url) && seen.Add(url))
                results.Add(url);
        }

        foreach (Match m in BareIpUrlRegex.Matches(text))
        {
            string candidate = CleanExtractedUrl(m.Groups[1].Value);
            if (string.IsNullOrEmpty(candidate)) continue;
            string withScheme = "http://" + candidate;
            if (!seen.Any(u => u.Contains(candidate, StringComparison.OrdinalIgnoreCase)) && seen.Add(withScheme))
                results.Add(withScheme);
        }

        return results;
    }

    public ClipboardScanResult AnalyzeClipboardContent(string text)
    {
        var flaggedUrls = new List<UrlCheckResult>();
        var commandWarnings = new List<string>();
        int maxScore = 0;

        if (string.IsNullOrWhiteSpace(text))
            return new ClipboardScanResult(false, 0, flaggedUrls, commandWarnings);

        var urls = ExtractUrls(text);
        foreach (string url in urls)
        {
            var res = Analyze(url);
            if (!res.IsSafe)
            {
                flaggedUrls.Add(res);
                if (res.RiskScore > maxScore) maxScore = res.RiskScore;
            }
        }

        string lower = text.ToLowerInvariant();
        bool hasDownloaderTool =
            lower.Contains("curl ") || lower.Contains("curl.exe") ||
            lower.Contains("wget ") || lower.Contains("invoke-webrequest") ||
            lower.Contains("iwr ") || lower.Contains("irm ") ||
            lower.Contains("bitsadmin") || lower.Contains("certutil") ||
            lower.Contains("mshta ");

        bool hasExecChain =
            lower.Contains("&&") || lower.Contains("| iex") || lower.Contains("|iex") ||
            lower.Contains("invoke-expression") || lower.Contains("start ") ||
            lower.Contains("cmd ") || lower.Contains("powershell") ||
            lower.Contains("-enc") || lower.Contains("-encodedcommand") ||
            lower.Contains("%temp%") || lower.Contains("$env:temp");

        if (hasDownloaderTool && hasExecChain && (urls.Count > 0 || lower.Contains("http")))
        {
            int cmdScore = 88;
            if (cmdScore > maxScore) maxScore = cmdScore;
            commandWarnings.Add("Phát hiện chuỗi lệnh tải tệp từ mạng và thực thi tự động (Dropper / ClickFix pattern).");
        }
        else if (flaggedUrls.Count == 0 && urls.Count > 0 && hasDownloaderTool)
        {
            // Downloading executable via shell command even from a domain
            foreach (string url in urls)
            {
                if (DangerousDownloadExts.Any(ext => url.Contains(ext, StringComparison.OrdinalIgnoreCase)))
                {
                    int cmdScore = 72;
                    if (cmdScore > maxScore) maxScore = cmdScore;
                    commandWarnings.Add($"Phát hiện lệnh dòng lệnh tải tệp thực thi từ liên kết: {url}");
                    break;
                }
            }
        }

        bool hasThreat = flaggedUrls.Count > 0 || commandWarnings.Count > 0;
        return new ClipboardScanResult(hasThreat, maxScore, flaggedUrls, commandWarnings);
    }

    private static string CleanExtractedUrl(string raw)
    {
        return raw.Trim().TrimEnd('"', '\'', ',', ';', '.', ')', ']', '}');
    }
}
