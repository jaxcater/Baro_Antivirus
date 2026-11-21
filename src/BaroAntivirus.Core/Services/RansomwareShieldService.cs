using System.Collections.Concurrent;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Services;

public sealed record RansomwareAlertEvent(
    DateTimeOffset Timestamp,
    string FolderPath,
    int EventsInWindow,
    string SampleFile,
    string Description);

public sealed class RansomwareShieldService : IDisposable
{
    private static readonly HashSet<string> RansomwareExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".locked", ".encrypted", ".enc", ".cry", ".crypt", ".crypted", ".locky",
        ".cerber", ".wannacry", ".wncry", ".lockbit", ".akira", ".blackcat", ".zepto", ".odin"
    };

    private readonly SettingsAndLogService _logs;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentQueue<(DateTime Utc, string Path)> _eventWindow = new();
    private AppSettings _settings;
    private DateTime _lastAlertUtc = DateTime.MinValue;

    public RansomwareShieldService(SettingsAndLogService logs, AppSettings settings)
    {
        _logs = logs;
        _settings = settings;
    }

    public bool IsRunning { get; private set; }

    public event Action<RansomwareAlertEvent>? RansomwareAlert;

    public void UpdateSettings(AppSettings settings) => _settings = settings;

    public void Start()
    {
        if (IsRunning) return;

        foreach (string folder in _settings.ProtectedFolders.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var w = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                    InternalBufferSize = 16384,
                    EnableRaisingEvents = true
                };

                w.Renamed += (_, e) => OnFolderActivity(folder, e.FullPath, isRename: true);
                w.Changed += (_, e) => OnFolderActivity(folder, e.FullPath, isRename: false);
                _watchers.Add(w);
            }
            catch { }
        }

        IsRunning = true;
        _logs.Log(SecurityLogLevel.Info, "RansomwareShield",
            $"Lá chắn chống Ransomware đang bảo vệ {_watchers.Count} thư mục dữ liệu.");
    }

    public void Stop()
    {
        if (!IsRunning) return;
        foreach (var w in _watchers)
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
        _watchers.Clear();
        IsRunning = false;
    }

    private void OnFolderActivity(string rootFolder, string filePath, bool isRename)
    {
        if (!_settings.RansomwareShieldEnabled) return;

        string ext = Path.GetExtension(filePath);
        if (isRename && RansomwareExtensions.Contains(ext))
        {
            EmitAlert(rootFolder, 1, filePath,
                $"Phát hiện đổi tên tệp sang phần mở rộng đặc trưng của Ransomware ('{ext}'): {Path.GetFileName(filePath)}");
            return;
        }

        DateTime now = DateTime.UtcNow;
        _eventWindow.Enqueue((now, filePath));

        while (_eventWindow.TryPeek(out var head) && (now - head.Utc).TotalSeconds > 5.0)
        {
            _eventWindow.TryDequeue(out _);
        }

        int uniqueFiles = _eventWindow.Select(x => x.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        if (uniqueFiles >= 18)
        {
            EmitAlert(rootFolder, uniqueFiles, filePath,
                $"Phát hiện thay đổi hàng loạt bất thường ({uniqueFiles} tệp trong 5 giây) tại '{rootFolder}' — nghi ngờ mã hóa Ransomware!");
        }
    }

    private void EmitAlert(string folder, int count, string sampleFile, string description)
    {
        DateTime now = DateTime.UtcNow;
        if ((now - _lastAlertUtc).TotalSeconds < 6) return;
        _lastAlertUtc = now;

        _logs.Log(SecurityLogLevel.Alert, "RansomwareShield", description);
        RansomwareAlert?.Invoke(new RansomwareAlertEvent(DateTimeOffset.Now, folder, count, sampleFile, description));
    }

    public void Dispose() => Stop();
}
