using System.Text;
using System.Text.Json;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Detection;

public sealed record PatternRule(
    string Id,
    string ThreatName,
    ThreatCategory Category,
    ThreatSeverity Severity,
    int RiskBoost,
    string[] RequiredTokens,
    string Description);

public sealed record SignatureMatch(
    string ThreatName,
    ThreatCategory Category,
    ThreatSeverity Severity,
    int RiskScore,
    string Reason);

public sealed class SignatureDatabase
{
    public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    // Assembled dynamically to prevent host AV false-positive on BaroAntivirus source/binaries
    private static string BuildEicarSignature() => string.Concat(
        "x5o!p%",
        "@ap[4\\pzx54",
        "(p^)7cc)7}$",
        "eicar-standard-",
        "antivirus-test-file!",
        "$h+h*");

    private static string T(params string[] parts) => string.Concat(parts);

    private readonly Dictionary<string, string> _maliciousHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        [EicarSha256] = "EICAR-Test-File (Standard AV Verification)",
        ["131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"] = "EICAR-Test-File-Variant",
        ["44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f"] = "Trojan.Sample.TestIndicator",
        ["24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"] = "Ransom.Win32.WannaCry.A",
        ["ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"] = "Ransom.Win32.WannaCry.B",
        ["027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"] = "Ransom.Win32.NotPetya",
        ["db349b97c37d22f5ea1d1841e3c89eb41f2775f78488c1e74d5fd7e1b1847df3"] = "Trojan.Win32.Emotet.Indicator"
    };

    private readonly List<PatternRule> _rules = new()
    {
        new("BARO-RANSOM-01", "Behavior.Ransomware.ShadowCopyWipe", ThreatCategory.RansomwareBehavior, ThreatSeverity.Critical, 95,
            new[] { T("vss", "admin"), T("del", "ete"), T("shad", "ows") },
            "Phát hiện lệnh xóa bản sao lưu Volume Shadow Copy (hành vi đặc trưng của Ransomware)."),

        new("BARO-RANSOM-02", "Behavior.Ransomware.RecoveryDisable", ThreatCategory.RansomwareBehavior, ThreatSeverity.Critical, 90,
            new[] { T("bcd", "edit"), T("recovery", "enabled"), "no" },
            "Phát hiện lệnh vô hiệu hóa Windows Recovery Environment (ngăn khôi phục hệ thống)."),

        new("BARO-RANSOM-03", "Behavior.Ransomware.NoteDropper", ThreatCategory.RansomwareBehavior, ThreatSeverity.High, 80,
            new[] { T("your files ", "have been ", "encrypted"), T("de", "crypt") },
            "Phát hiện chuỗi nội dung thông báo đòi tiền chuộc Ransomware."),

        new("BARO-CRED-01", "HackTool.CredentialDumper.LSASS", ThreatCategory.TrojanOrDropper, ThreatSeverity.Critical, 95,
            new[] { T("seku", "rlsa::", "logon", "passwords") },
            "Phát hiện dấu hiệu công cụ trích xuất mật khẩu LSASS."),

        new("BARO-CRED-02", "Trojan.Stealer.BrowserCreds", ThreatCategory.TrojanOrDropper, ThreatSeverity.High, 82,
            new[] { T("crypt", "unprotect", "data"), T("login ", "data"), T("local ", "state") },
            "Phát hiện kết hợp truy cập dữ liệu mật khẩu trình duyệt và hàm giải mã DPAPI."),

        new("BARO-EVASION-01", "Trojan.Evasion.AmsiBypass", ThreatCategory.SuspiciousScript, ThreatSeverity.Critical, 90,
            new[] { T("amsi", "utils"), T("amsi", "init", "failed") },
            "Phát hiện kỹ thuật vô hiệu hóa Windows AMSI."),

        new("BARO-EVASION-02", "Trojan.Evasion.AmsiBufferPatch", ThreatCategory.SuspiciousScript, ThreatSeverity.Critical, 88,
            new[] { T("amsi", "scan", "buffer"), T("virtual", "protect") },
            "Phát hiện dấu hiệu vá bộ nhớ AmsiScanBuffer để qua mặt trình diệt virus."),

        new("BARO-LOADER-01", "Trojan.Loader.PowerShellHiddenEncoded", ThreatCategory.SuspiciousScript, ThreatSeverity.High, 82,
            new[] { T("from", "base64", "string"), T("invoke-", "expression") },
            "Phát hiện chuỗi giải mã Base64 kết hợp thực thi động Invoke-Expression."),

        new("BARO-LOADER-02", "Trojan.Dropper.CertutilDownload", ThreatCategory.TrojanOrDropper, ThreatSeverity.High, 80,
            new[] { T("cert", "util"), T("-url", "cache"), "-split" },
            "Phát hiện lạm dụng certutil.exe để tải payload từ mạng (LOLBin)."),

        new("BARO-LOADER-03", "Trojan.Dropper.MshtaRemote", ThreatCategory.TrojanOrDropper, ThreatSeverity.High, 85,
            new[] { T("msh", "ta"), "http" },
            "Phát hiện thực thi mã độc từ xa thông qua mshta.exe."),

        new("BARO-LOADER-04", "Trojan.Dropper.Regsvr32Squiblydoo", ThreatCategory.TrojanOrDropper, ThreatSeverity.High, 85,
            new[] { T("reg", "svr32"), "/i:http", T("scro", "bj.dll") },
            "Phát hiện kỹ thuật Squiblydoo tải scriptlet từ xa qua regsvr32."),

        new("BARO-MINER-01", "PUA.CryptoMiner.Stratum", ThreatCategory.MalwareSignature, ThreatSeverity.High, 78,
            new[] { T("stratum", "+tcp://"), T("xm", "rig") },
            "Phát hiện cấu hình đào tiền ảo ngầm (Stratum pool)."),

        new("BARO-REV-01", "Trojan.Backdoor.ReverseShell", ThreatCategory.TrojanOrDropper, ThreatSeverity.Critical, 92,
            new[] { T("net.sockets.", "tcpclient"), T("get", "stream()"), T("cmd", ".exe") },
            "Phát hiện mã thiết lập Reverse Shell TCP kết nối tới máy chủ điều khiển.")
    };

    public void LoadCustomHashes(string customSigJsonPath)
    {
        try
        {
            if (!File.Exists(customSigJsonPath)) return;
            string json = File.ReadAllText(customSigJsonPath);
            var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            if (dict == null) return;
            foreach (var kv in dict)
            {
                if (!string.IsNullOrWhiteSpace(kv.Key) && !string.IsNullOrWhiteSpace(kv.Value))
                    _maliciousHashes[kv.Key.Trim()] = kv.Value.Trim();
            }
        }
        catch { }
    }

    public void AddHash(string sha256, string threatName)
    {
        if (!string.IsNullOrWhiteSpace(sha256))
            _maliciousHashes[sha256.Trim()] = threatName;
    }

    public SignatureMatch? CheckHash(string sha256)
    {
        if (_maliciousHashes.TryGetValue(sha256, out string? name))
        {
            return new SignatureMatch(
                name,
                ThreatCategory.MalwareSignature,
                ThreatSeverity.Critical,
                100,
                $"Khớp chữ ký mã độc SHA-256 trong cơ sở dữ liệu: {name}");
        }
        return null;
    }

    public List<SignatureMatch> ScanContentBytes(ReadOnlySpan<byte> data)
    {
        var matches = new List<SignatureMatch>();
        if (data.IsEmpty) return matches;

        int maxLen = Math.Min(data.Length, 4 * 1024 * 1024);
        string asciiText = ExtractSearchableLowerText(data[..maxLen]);

        if (asciiText.Contains(BuildEicarSignature(), StringComparison.Ordinal))
        {
            matches.Add(new SignatureMatch(
                "EICAR-Standard-Antivirus-Test-File",
                ThreatCategory.MalwareSignature,
                ThreatSeverity.Critical,
                100,
                "Phát hiện mẫu kiểm thử chuẩn EICAR Antivirus Test File."));
            return matches;
        }

        foreach (var rule in _rules)
        {
            bool allPresent = true;
            foreach (string token in rule.RequiredTokens)
            {
                if (!asciiText.Contains(token, StringComparison.Ordinal))
                {
                    allPresent = false;
                    break;
                }
            }

            if (allPresent)
            {
                matches.Add(new SignatureMatch(
                    rule.ThreatName,
                    rule.Category,
                    rule.Severity,
                    rule.RiskBoost,
                    $"{rule.Description} [{rule.Id}]"));
            }
        }

        return matches;
    }

    private static string ExtractSearchableLowerText(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder(Math.Min(data.Length, 256 * 1024));
        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            if (b >= 32 && b <= 126)
            {
                char c = (char)b;
                if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                sb.Append(c);
            }
            else if (b == '\r' || b == '\n' || b == '\t')
            {
                sb.Append(' ');
            }
        }
        return sb.ToString();
    }
}
