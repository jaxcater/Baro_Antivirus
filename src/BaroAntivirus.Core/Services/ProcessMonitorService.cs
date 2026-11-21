using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using BaroAntivirus.Core.Detection;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Services;

public sealed class ProcessMonitorService : IDisposable
{
    private static readonly HashSet<string> CriticalSystemNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "smss.exe", "wininit.exe", "winlogon.exe", "explorer.exe"
    };

    private static readonly HashSet<string> LolBinNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin", "wscript", "cscript"
    };

    private readonly SettingsAndLogService _logs;
    private readonly ConcurrentDictionary<int, (DateTime StartTime, ProcessRiskInfo Info)> _cache = new();
    private PeriodicTimer? _timer;
    private CancellationTokenSource? _cts;
    private Task? _loopTask;
    private AppSettings _settings;

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr hProcess,
        uint dwFlags,
        StringBuilder lpExeName,
        ref int lpdwSize);

    public ProcessMonitorService(SettingsAndLogService logs, AppSettings settings)
    {
        _logs = logs;
        _settings = settings;
    }

    public bool IsRunning { get; private set; }

    public event Action<ProcessRiskInfo>? SuspiciousProcessDetected;

    public void UpdateSettings(AppSettings settings) => _settings = settings;

    public void Start()
    {
        if (IsRunning) return;
        _cts = new CancellationTokenSource();
        _timer = new PeriodicTimer(TimeSpan.FromSeconds(4));
        _loopTask = Task.Run(() => MonitorLoopAsync(_cts.Token));
        IsRunning = true;
        _logs.Log(SecurityLogLevel.Info, "ProcessGuard", "Giám sát tiến trình thời gian thực đã khởi động (Chế độ siêu nhẹ).");
    }

    public void Stop()
    {
        if (!IsRunning) return;
        _cts?.Cancel();
        _timer?.Dispose();
        try { _loopTask?.Wait(1000); } catch { }
        _cts?.Dispose();
        _cts = null;
        IsRunning = false;
    }

    public IReadOnlyList<ProcessRiskInfo> SnapshotProcesses()
    {
        var results = new List<ProcessRiskInfo>();
        var activePids = new HashSet<int>();

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                int pid = proc.Id;
                activePids.Add(pid);
                if (pid <= 4) continue;

                DateTime start = DateTime.MinValue;
                try { start = proc.StartTime; } catch { }

                if (_cache.TryGetValue(pid, out var cached) && cached.StartTime == start)
                {
                    results.Add(new ProcessRiskInfo
                    {
                        Pid = cached.Info.Pid,
                        ProcessName = cached.Info.ProcessName,
                        ExecutablePath = cached.Info.ExecutablePath,
                        CommandLine = cached.Info.CommandLine,
                        MemoryMB = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 1),
                        IsSigned = cached.Info.IsSigned,
                        SignerName = cached.Info.SignerName,
                        RiskScore = cached.Info.RiskScore,
                        Status = cached.Info.Status,
                        Reasons = cached.Info.Reasons
                    });
                    continue;
                }

                var evaluated = EvaluateProcess(proc);
                _cache[pid] = (start, evaluated);
                results.Add(evaluated);
            }
            catch { }
            finally
            {
                proc.Dispose();
            }
        }

        foreach (int key in _cache.Keys)
        {
            if (!activePids.Contains(key))
                _cache.TryRemove(key, out _);
        }

        return results.OrderByDescending(p => p.RiskScore).ThenByDescending(p => p.MemoryMB).ToList();
    }

    public bool TerminateProcess(int pid, out string error)
    {
        error = string.Empty;
        try
        {
            using var proc = Process.GetProcessById(pid);
            string name = proc.ProcessName;
            proc.Kill(entireProcessTree: true);
            _logs.Log(SecurityLogLevel.Action, "ProcessGuard", $"Đã chấm dứt tiến trình '{name}' (PID: {pid}).");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private async Task MonitorLoopAsync(CancellationToken ct)
    {
        if (_timer == null) return;
        try
        {
            var initial = SnapshotProcesses();
            foreach (var p in initial.Where(x => x.RiskScore >= 70))
            {
                SuspiciousProcessDetected?.Invoke(p);
            }

            while (await _timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                if (!_settings.ProcessGuardEnabled) continue;

                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        int pid = proc.Id;
                        if (pid <= 4) continue;
                        DateTime start = DateTime.MinValue;
                        try { start = proc.StartTime; } catch { }

                        if (_cache.TryGetValue(pid, out var existing) && existing.StartTime == start)
                            continue;

                        var info = EvaluateProcess(proc);
                        _cache[pid] = (start, info);

                        if (info.RiskScore >= 55)
                        {
                            _logs.Log(SecurityLogLevel.Alert, "ProcessGuard",
                                $"Tiến trình đáng ngờ: {info.ProcessName} (PID {info.Pid}, Điểm {info.RiskScore}/100)",
                                string.Join(" | ", info.Reasons));
                            SuspiciousProcessDetected?.Invoke(info);
                        }
                    }
                    catch { }
                    finally
                    {
                        proc.Dispose();
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    private ProcessRiskInfo EvaluateProcess(Process proc)
    {
        int pid = proc.Id;
        string name = proc.ProcessName;
        double memMb = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 1);
        string exePath = GetProcessPathSafe(proc);

        var reasons = new List<string>();
        int score = 0;
        bool isSigned = false;
        string? signer = null;

        if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
        {
            var auth = AuthenticodeVerifier.Verify(exePath);
            isSigned = auth.IsValidSigned;
            signer = auth.SignerName;

            string lowerPath = exePath.ToLowerInvariant();
            string exeFile = Path.GetFileName(exePath);
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();

            if (CriticalSystemNames.Contains(exeFile) && !lowerPath.StartsWith(winDir, StringComparison.Ordinal))
            {
                score += 85;
                reasons.Add($"Giả mạo tiến trình hệ thống '{exeFile}' chạy ngoài thư mục Windows!");
            }

            if (lowerPath.Contains("\\temp\\") || lowerPath.Contains("\\appdata\\local\\temp\\"))
            {
                score += isSigned ? 20 : 48;
                reasons.Add("Tiến trình đang chạy trực tiếp từ thư mục Temp.");
            }
            else if (lowerPath.Contains("\\downloads\\") && !isSigned)
            {
                score += 36;
                reasons.Add("Tiến trình chưa có chữ ký số đang chạy trực tiếp từ thư mục Downloads.");
            }
            else if (!isSigned && _settings.Strictness >= StrictnessLevel.Strict &&
                     !lowerPath.StartsWith(@"c:\program files", StringComparison.Ordinal))
            {
                score += 18;
                reasons.Add("Tệp thực thi tiến trình không có chữ ký số.");
            }

            var zone = ZoneIdentifierReader.Read(exePath);
            if (zone != null && zone.ZoneId >= 3 && !isSigned)
            {
                score += 28;
                reasons.Add($"Tiến trình xuất phát từ tệp tải Internet (ZoneId={zone.ZoneId}) chưa ký số.");
            }
        }

        if (LolBinNames.Contains(name))
        {
            score += 25;
            reasons.Add($"Công cụ hệ thống '{name}' thường bị mã độc lạm dụng thực thi script/tải payload.");
        }

        score = Math.Min(score, 100);
        string status = score >= 70 ? "NGUY HIỂM" : score >= 45 ? "Đáng ngờ" : "An toàn";

        return new ProcessRiskInfo
        {
            Pid = pid,
            ProcessName = name,
            ExecutablePath = exePath,
            CommandLine = exePath,
            MemoryMB = memMb,
            IsSigned = isSigned,
            SignerName = signer,
            RiskScore = score,
            Status = status,
            Reasons = reasons
        };
    }

    public static string GetProcessPathSafe(Process proc)
    {
        try
        {
            if (proc.MainModule?.FileName is { Length: > 0 } path)
                return path;
        }
        catch { }

        IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, proc.Id);
        if (hProc == IntPtr.Zero) return string.Empty;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            if (QueryFullProcessImageNameW(hProc, 0, sb, ref size))
                return sb.ToString(0, size);
        }
        catch { }
        finally
        {
            CloseHandle(hProc);
        }
        return string.Empty;
    }

    public void Dispose() => Stop();
}
