using BaroAntivirus.Core.Detection;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Services;

public sealed class UsbShieldService : IDisposable
{
    private readonly ThreatDetectionEngine _engine;
    private readonly QuarantineService _quarantine;
    private readonly SettingsAndLogService _logs;
    private readonly HashSet<string> _knownDrives = new(StringComparer.OrdinalIgnoreCase);

    private PeriodicTimer? _timer;
    private CancellationTokenSource? _cts;
    private Task? _loopTask;
    private AppSettings _settings;

    public UsbShieldService(
        ThreatDetectionEngine engine,
        QuarantineService quarantine,
        SettingsAndLogService logs,
        AppSettings settings)
    {
        _engine = engine;
        _quarantine = quarantine;
        _logs = logs;
        _settings = settings;

        foreach (var d in GetRemovableRoots())
            _knownDrives.Add(d);
    }

    public bool IsRunning { get; private set; }

    public event Action<string, List<ThreatFinding>>? UsbScanned;

    public void UpdateSettings(AppSettings settings) => _settings = settings;

    public void Start()
    {
        if (IsRunning) return;
        _cts = new CancellationTokenSource();
        _timer = new PeriodicTimer(TimeSpan.FromSeconds(4));
        _loopTask = Task.Run(() => LoopAsync(_cts.Token));
        IsRunning = true;
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

    private async Task LoopAsync(CancellationToken ct)
    {
        if (_timer == null) return;
        try
        {
            while (await _timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                if (!_settings.UsbShieldEnabled) continue;

                var current = GetRemovableRoots();
                foreach (string driveRoot in current)
                {
                    if (_knownDrives.Add(driveRoot))
                    {
                        _logs.Log(SecurityLogLevel.Info, "UsbShield", $"Phát hiện ổ USB mới ({driveRoot}) — đang quét tự động...");
                        var hits = ScanUsbRoot(driveRoot);
                        UsbScanned?.Invoke(driveRoot, hits);
                    }
                }

                _knownDrives.RemoveWhere(d => !current.Contains(d));
            }
        }
        catch (OperationCanceledException) { }
    }

    public List<ThreatFinding> ScanUsbRoot(string driveRoot)
    {
        var findings = new List<ThreatFinding>();
        try
        {
            string autorun = Path.Combine(driveRoot, "autorun.inf");
            if (File.Exists(autorun))
            {
                string txt = File.ReadAllText(autorun);
                if (txt.Contains("open=", StringComparison.OrdinalIgnoreCase) ||
                    txt.Contains("shellexecute=", StringComparison.OrdinalIgnoreCase))
                {
                    var finding = new ThreatFinding
                    {
                        FilePath = autorun,
                        FileName = "autorun.inf",
                        ThreatName = "Worm.USB.AutorunDropper",
                        Category = ThreatCategory.PersistenceThreat,
                        Severity = ThreatSeverity.High,
                        RiskScore = 82,
                        Reasons = new List<string> { "USB chứa tệp autorun.inf tự động kích hoạt mã độc khi mở ổ đĩa." },
                        EngineSource = "BaroUsbShield"
                    };
                    if (_settings.AutoQuarantineHighRisk)
                        _quarantine.QuarantineFile(finding);
                    findings.Add(finding);
                }
            }

            foreach (string file in Directory.EnumerateFiles(driveRoot))
            {
                var hit = _engine.InspectFile(file, _settings.Strictness, inspectArchives: true,
                    _settings.ExcludedPaths, _settings.ExcludedHashes);
                if (hit != null)
                {
                    if (_settings.AutoQuarantineHighRisk && hit.RiskScore >= 55)
                        _quarantine.QuarantineFile(hit);
                    findings.Add(hit);
                }
            }
        }
        catch { }

        return findings;
    }

    private static HashSet<string> GetRemovableRoots()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                if (d.IsReady && d.DriveType == DriveType.Removable)
                    set.Add(d.RootDirectory.FullName);
            }
        }
        catch { }
        return set;
    }

    public void Dispose() => Stop();
}
