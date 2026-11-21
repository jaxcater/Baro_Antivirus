using Microsoft.Win32;
using BaroAntivirus.Core.Detection;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Services;

public sealed class StartupGuardService
{
    private static readonly (bool IsHklm, string SubKey, string Label)[] RegistryRunKeys =
    {
        (false, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
        (false, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
        (true, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
        (true, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce")
    };

    public IReadOnlyList<StartupEntryInfo> InspectStartupEntries()
    {
        var list = new List<StartupEntryInfo>();

        foreach (var (isHklm, subKey, label) in RegistryRunKeys)
        {
            try
            {
                RegistryKey root = isHklm ? Registry.LocalMachine : Registry.CurrentUser;
                using var key = root.OpenSubKey(subKey, writable: false);
                if (key == null) continue;

                foreach (string valName in key.GetValueNames())
                {
                    string cmd = key.GetValue(valName)?.ToString() ?? string.Empty;
                    list.Add(EvaluateEntry(valName, label, cmd, isRegistry: true, isHklm: isHklm, subKey: subKey));
                }
            }
            catch { }
        }

        InspectStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "User Startup Folder", list);
        InspectStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Common Startup Folder", list);

        return list.OrderByDescending(x => x.RiskScore).ThenBy(x => x.Name).ToList();
    }

    public bool RemoveStartupEntry(StartupEntryInfo entry, out string error)
    {
        error = string.Empty;
        try
        {
            if (entry.IsRegistry)
            {
                RegistryKey root = entry.IsLocalMachine ? Registry.LocalMachine : Registry.CurrentUser;
                using var key = root.OpenSubKey(entry.RegistrySubKey, writable: true);
                if (key == null)
                {
                    error = "Không thể mở khóa Registry.";
                    return false;
                }
                key.DeleteValue(entry.Name, throwOnMissingValue: false);
                return true;
            }
            else if (File.Exists(entry.Command))
            {
                File.Delete(entry.Command);
                return true;
            }
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            error = "Cần quyền Administrator để xóa mục khởi động hệ thống (HKLM).";
            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static void InspectStartupFolder(string folder, string label, List<StartupEntryInfo> list)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) return;
            foreach (string file in Directory.GetFiles(folder))
            {
                string name = Path.GetFileName(file);
                if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                list.Add(EvaluateEntry(name, label, file, isRegistry: false, isHklm: false, subKey: ""));
            }
        }
        catch { }
    }

    private static StartupEntryInfo EvaluateEntry(
        string name,
        string location,
        string command,
        bool isRegistry,
        bool isHklm,
        string subKey)
    {
        string resolved = ResolveExecutablePath(command);
        bool isSigned = false;
        string? signer = null;
        int score = 0;
        var reasons = new List<string>();

        if (!string.IsNullOrEmpty(resolved) && File.Exists(resolved))
        {
            var auth = AuthenticodeVerifier.Verify(resolved);
            isSigned = auth.IsValidSigned;
            signer = auth.SignerName;

            string lower = resolved.ToLowerInvariant();
            if (lower.Contains("\\temp\\") || lower.Contains("\\downloads\\"))
            {
                score += isSigned ? 25 : 65;
                reasons.Add("Khởi động cùng Windows từ thư mục Temp/Downloads.");
            }
            else if (!isSigned)
            {
                score += 30;
                reasons.Add("Không có chữ ký số hợp lệ.");
            }

            string ext = Path.GetExtension(resolved).ToLowerInvariant();
            if (ext is ".vbs" or ".js" or ".hta" or ".bat" or ".ps1")
            {
                score += 35;
                reasons.Add($"Tự khởi chạy kịch bản script ({ext}).");
            }
        }
        else if (!string.IsNullOrWhiteSpace(command))
        {
            string lowerCmd = command.ToLowerInvariant();
            if (lowerCmd.Contains(string.Concat("power", "shell")) || lowerCmd.Contains("cmd ") || lowerCmd.Contains(string.Concat("msh", "ta")) || lowerCmd.Contains("http"))
            {
                score += 60;
                reasons.Add("Lệnh khởi động gọi shell/script bất thường.");
            }
        }

        score = Math.Min(score, 100);
        string status = score >= 60 ? "Đáng ngờ cao" : score >= 25 ? "Cần chú ý" : "Tin cậy";

        return new StartupEntryInfo
        {
            Name = name,
            Location = location,
            Command = command,
            ResolvedPath = resolved,
            IsSigned = isSigned,
            SignerName = signer,
            RiskScore = score,
            Status = status,
            Reason = reasons.Count > 0 ? string.Join(" ", reasons) : (isSigned ? $"Đã ký bởi {signer}" : "Bình thường"),
            IsRegistry = isRegistry,
            IsLocalMachine = isHklm,
            RegistrySubKey = subKey
        };
    }

    private static string ResolveExecutablePath(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return string.Empty;
        string trimmed = command.Trim();
        if (trimmed.StartsWith('"'))
        {
            int endQuote = trimmed.IndexOf('"', 1);
            if (endQuote > 1) return Environment.ExpandEnvironmentVariables(trimmed[1..endQuote]);
        }

        int exeIdx = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx > 0)
        {
            return Environment.ExpandEnvironmentVariables(trimmed[..(exeIdx + 4)].Trim());
        }

        return Environment.ExpandEnvironmentVariables(trimmed.Split(' ')[0]);
    }
}
