using System.Collections.Concurrent;
using System.Threading.Channels;
using BaroAntivirus.Core.Detection;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Services;

public sealed class RealtimeProtectionService : IDisposable
{
    private static readonly HashSet<string> PartialDownloadExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".crdownload", ".part", ".tmp", ".opdownload", ".download"
    };

    private readonly ThreatDetectionEngine _engine;
    private readonly QuarantineService _quarantine;
    private readonly SettingsAndLogService _logs;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, DateTime> _recentCooldown = new(StringComparer.OrdinalIgnoreCase);

    private Channel<string>? _queue;
    private CancellationTokenSource? _cts;
    private Task? _workerTask;
    private AppSettings _settings;
    private string _downloadsDir = string.Empty;

    public RealtimeProtectionService(
        ThreatDetectionEngine engine,
        QuarantineService quarantine,
        SettingsAndLogService logs,
        AppSettings settings)
    {
        _engine = engine;
        _quarantine = quarantine;
        _logs = logs;
        _settings = settings;
    }

    public bool IsRunning { get; private set; }

    public event Action<ThreatFinding>? ThreatIntercepted;
    public event Action<DownloadInspectionEvent>? DownloadInspected;

    public void UpdateSettings(AppSettings settings)
    {
        _settings = settings;
    }

    public void Start(IEnumerable<string>? customWatchFolders = null)
    {
        if (IsRunning) return;

        _cts = new CancellationTokenSource();
        _queue = Channel.CreateBounded<string>(new BoundedChannelOptions(2048)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false
        });

        _downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        var folders = customWatchFolders?.ToList() ?? new List<string>
        {
            _downloadsDir,
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup)
        };

        foreach (string dir in folders.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var watcher = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = !dir.Equals(Path.GetTempPath().TrimEnd('\\'), StringComparison.OrdinalIgnoreCase),
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    InternalBufferSize = 16384,
                    EnableRaisingEvents = true
                };

                watcher.Created += (_, e) => EnqueuePath(e.FullPath);
                watcher.Renamed += (_, e) => EnqueuePath(e.FullPath);
                watcher.Changed += (_, e) => EnqueuePath(e.FullPath);
                _watchers.Add(watcher);
            }
            catch
            {
                // Skip inaccessible watch paths
            }
        }

        _workerTask = Task.Run(() => WorkerLoopAsync(_cts.Token));
        IsRunning = true;
        _logs.Log(SecurityLogLevel.Info, "RealtimeShield",
            $"Lá chắn thời gian thực đang bảo vệ {_watchers.Count} vùng trọng yếu (Chế độ: {_settings.Strictness}).");
    }

    public void Stop()
    {
        if (!IsRunning) return;

        foreach (var w in _watchers)
        {
            try
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            catch { }
        }
        _watchers.Clear();

        _cts?.Cancel();
        _queue?.Writer.TryComplete();
        try { _workerTask?.Wait(1000); } catch { }
        _cts?.Dispose();
        _cts = null;
        IsRunning = false;
        _logs.Log(SecurityLogLevel.Warning, "RealtimeShield", "Lá chắn thời gian thực đã tạm dừng.");
    }

    private void EnqueuePath(string fullPath)
    {
        if (!_settings.RealtimeProtectionEnabled && !_settings.DownloadGuardEnabled)
            return;

        if (string.IsNullOrWhiteSpace(fullPath)) return;
        if (fullPath.StartsWith(_logs.DataDirectory, StringComparison.OrdinalIgnoreCase)) return;

        string ext = Path.GetExtension(fullPath);
        if (PartialDownloadExts.Contains(ext)) return;

        if (_recentCooldown.TryGetValue(fullPath, out var last) &&
            (DateTime.UtcNow - last).TotalMilliseconds < 1200)
        {
            return;
        }
        _recentCooldown[fullPath] = DateTime.UtcNow;

        if (_recentCooldown.Count > 2000)
            _recentCooldown.Clear();

        _queue?.Writer.TryWrite(fullPath);
    }

    private async Task WorkerLoopAsync(CancellationToken ct)
    {
        if (_queue == null) return;

        await foreach (string path in _queue.Reader.ReadAllAsync(ct).ConfigureAwait(false))
        {
            try
            {
                // Brief settle delay so browser/copy releases write lock cleanly
                await Task.Delay(220, ct).ConfigureAwait(false);
                if (!File.Exists(path)) continue;

                bool isInDownloads = !string.IsNullOrEmpty(_downloadsDir) &&
                                     path.StartsWith(_downloadsDir, StringComparison.OrdinalIgnoreCase);

                if (isInDownloads && !_settings.DownloadGuardEnabled && !_settings.RealtimeProtectionEnabled)
                    continue;
                if (!isInDownloads && !_settings.RealtimeProtectionEnabled)
                    continue;

                var finding = _engine.InspectFile(
                    path,
                    _settings.Strictness,
                    inspectArchives: true,
                    _settings.ExcludedPaths,
                    _settings.ExcludedHashes);

                if (finding != null)
                {
                    if (_settings.AutoQuarantineHighRisk && finding.RiskScore >= 55)
                    {
                        var qEntry = _quarantine.QuarantineFile(finding);
                        if (qEntry != null)
                        {
                            finding.ActionTaken = ProtectionAction.Quarantined;
                            _logs.Log(SecurityLogLevel.Action, "RealtimeShield",
                                $"ĐÃ CHẶN & CÁCH LY: {finding.FileName} ({finding.ThreatName}, Điểm: {finding.RiskScore}/100)",
                                string.Join(" | ", finding.Reasons));
                        }
                        else
                        {
                            finding.ActionTaken = ProtectionAction.Warned;
                        }
                    }
                    else
                    {
                        finding.ActionTaken = ProtectionAction.Warned;
                        _logs.Log(SecurityLogLevel.Alert, "RealtimeShield",
                            $"Phát hiện tệp nguy hiểm theo thời gian thực: {finding.FileName} ({finding.ThreatName})");
                    }

                    ThreatIntercepted?.Invoke(finding);

                    if (isInDownloads)
                    {
                        var zone = ZoneIdentifierReader.Read(path);
                        DownloadInspected?.Invoke(new DownloadInspectionEvent
                        {
                            FilePath = path,
                            FileName = finding.FileName,
                            ZoneId = finding.ZoneId ?? zone?.ZoneId,
                            HostUrl = zone?.HostUrl,
                            IsSigned = finding.IsAuthenticodeSigned,
                            SignerName = finding.SignerName,
                            IsThreat = true,
                            RiskScore = finding.RiskScore,
                            Verdict = $"BỊ CHẶN: {finding.ThreatName}",
                            ActionTaken = finding.ActionTaken
                        });
                    }
                }
                else if (isInDownloads && _settings.DownloadGuardEnabled)
                {
                    var zone = ZoneIdentifierReader.Read(path);
                    var auth = AuthenticodeVerifier.Verify(path);
                    DownloadInspected?.Invoke(new DownloadInspectionEvent
                    {
                        FilePath = path,
                        FileName = Path.GetFileName(path),
                        ZoneId = zone?.ZoneId,
                        HostUrl = zone?.HostUrl,
                        IsSigned = auth.IsValidSigned,
                        SignerName = auth.SignerName,
                        IsThreat = false,
                        RiskScore = 0,
                        Verdict = auth.IsValidSigned
                            ? $"An toàn (Chữ ký số: {auth.SignerName})"
                            : "An toàn (Đã kiểm tra tải xuống)",
                        ActionTaken = ProtectionAction.None
                    });
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Keep real-time loop resilient
            }
        }
    }

    public void Dispose() => Stop();
}
