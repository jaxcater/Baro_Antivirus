using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Threading;
using BaroAntivirus.Core.Detection;
using BaroAntivirus.Core.Models;
using BaroAntivirus.Core.Services;

namespace BaroAntivirus.App;

public partial class App : System.Windows.Application
{
    private const string MutexName = @"Local\BaroAntivirus_SingleInstance_Mutex";
    private const string WakeEventName = @"Local\BaroAntivirus_ShowWindow_Event";

    private Mutex? _singleInstanceMutex;
    private EventWaitHandle? _wakeEvent;
    private RegisteredWaitHandle? _wakeWaitHandle;

    public SettingsAndLogService SettingsService { get; private set; } = null!;
    public AppSettings Settings { get; private set; } = null!;
    public SignatureDatabase SignatureDb { get; private set; } = null!;
    public ThreatDetectionEngine DetectionEngine { get; private set; } = null!;
    public QuarantineService QuarantineService { get; private set; } = null!;
    public ScanService ScanService { get; private set; } = null!;
    public RealtimeProtectionService RealtimeService { get; private set; } = null!;
    public RansomwareShieldService RansomwareService { get; private set; } = null!;
    public ProcessMonitorService ProcessService { get; private set; } = null!;
    public NetworkMonitorService NetworkService { get; private set; } = null!;
    public UsbShieldService UsbService { get; private set; } = null!;
    public StartupGuardService StartupService { get; private set; } = null!;
    public UrlReputationAnalyzer UrlAnalyzer { get; private set; } = null!;
    public ResourceOptimizer ResourceOptimizer { get; private set; } = null!;
    public TrayService TrayService { get; private set; } = null!;

    private MainWindow? _mainWindow;
    private DispatcherTimer? _backgroundGuardTimer;
    private uint _lastClipboardSeq;
    private DateTime _lastScheduledScanUtc = DateTime.UtcNow;

    [DllImport("user32.dll")]
    private static extern uint GetClipboardSequenceNumber();

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _singleInstanceMutex = new Mutex(true, MutexName, out bool createdNew);
        if (!createdNew)
        {
            try
            {
                using var ev = EventWaitHandle.OpenExisting(WakeEventName);
                ev.Set();
            }
            catch { }
            Shutdown();
            return;
        }

        _wakeEvent = new EventWaitHandle(false, EventResetMode.AutoReset, WakeEventName);
        _wakeWaitHandle = ThreadPool.RegisterWaitForSingleObject(_wakeEvent, (_, _) =>
        {
            Dispatcher.BeginInvoke(ShowMainWindow);
        }, null, -1, false);

        InitializeCoreServices();
        InitializeTray();

        bool startMinimized = e.Args.Any(a => a.Equals("--minimized", StringComparison.OrdinalIgnoreCase));
        _mainWindow = new MainWindow(this);

        if (startMinimized)
        {
            if (Settings.LightweightMemoryTrim)
                ResourceOptimizer.TrimBackgroundMemory();
        }
        else
        {
            _mainWindow.Show();
        }
    }

    private void InitializeCoreServices()
    {
        SettingsService = new SettingsAndLogService();
        Settings = SettingsService.LoadSettings();

        if (Settings.RunAtWindowsStartup && !SettingsService.IsWindowsStartupEnabled())
        {
            SettingsService.SyncWindowsStartup(true);
        }

        SignatureDb = new SignatureDatabase();
        SignatureDb.LoadCustomHashes(SettingsService.CustomSignaturesPath);

        DetectionEngine = new ThreatDetectionEngine(SignatureDb);
        QuarantineService = new QuarantineService(SettingsService.DataDirectory);
        ScanService = new ScanService(DetectionEngine, SettingsService);
        RealtimeService = new RealtimeProtectionService(DetectionEngine, QuarantineService, SettingsService, Settings);
        RansomwareService = new RansomwareShieldService(SettingsService, Settings);
        ProcessService = new ProcessMonitorService(SettingsService, Settings);
        NetworkService = new NetworkMonitorService();
        UsbService = new UsbShieldService(DetectionEngine, QuarantineService, SettingsService, Settings);
        StartupService = new StartupGuardService();
        UrlAnalyzer = new UrlReputationAnalyzer();
        UrlAnalyzer.SetCustomBlockedDomains(Settings.CustomBlockedDomains);
        ResourceOptimizer = new ResourceOptimizer();

        if (Settings.RealtimeProtectionEnabled || Settings.DownloadGuardEnabled)
            RealtimeService.Start();
        if (Settings.RansomwareShieldEnabled)
            RansomwareService.Start();
        if (Settings.ProcessGuardEnabled)
            ProcessService.Start();
        if (Settings.UsbShieldEnabled)
            UsbService.Start();

        RealtimeService.ThreatIntercepted += finding =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                TrayService.ShowNotification(
                    "BaroAntivirus — Đã chặn mối nguy!",
                    $"{finding.FileName} ({finding.ThreatName}) — {finding.ActionTaken}",
                    isWarningOrError: true);
                _mainWindow?.OnRealtimeThreat(finding);
            });
        };

        RealtimeService.DownloadInspected += ev =>
        {
            Dispatcher.BeginInvoke(() => _mainWindow?.OnDownloadInspected(ev));
        };

        RansomwareService.RansomwareAlert += alert =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                TrayService.ShowNotification(
                    "CẢNH BÁO RANSOMWARE!",
                    alert.Description,
                    isWarningOrError: true);
                _mainWindow?.OnRansomwareAlert(alert);
            });
        };

        ProcessService.SuspiciousProcessDetected += proc =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                TrayService.ShowNotification(
                    "Tiến trình đáng ngờ phát hiện",
                    $"{proc.ProcessName} (PID {proc.Pid}) — Điểm rủi ro: {proc.RiskScore}/100",
                    isWarningOrError: true);
            });
        };

        UsbService.UsbScanned += (drive, hits) =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (hits.Count > 0)
                {
                    TrayService.ShowNotification(
                        $"USB {drive}: Phát hiện {hits.Count} mối nguy!",
                        "BaroAntivirus đã xử lý các tệp độc hại trên ổ USB.",
                        isWarningOrError: true);
                }
                else
                {
                    TrayService.ShowNotification(
                        $"USB {drive}: An toàn",
                        "Đã quét nhanh ổ đĩa di động, không thấy mã độc.",
                        isWarningOrError: false);
                }
            });
        };

        _lastClipboardSeq = GetClipboardSequenceNumber();
        _backgroundGuardTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _backgroundGuardTimer.Tick += OnBackgroundTimerTick;
        _backgroundGuardTimer.Start();
    }

    private void InitializeTray()
    {
        TrayService = new TrayService();
        TrayService.OpenRequested += ShowMainWindow;
        TrayService.QuickScanRequested += () =>
        {
            ShowMainWindow();
            _mainWindow?.TriggerScanFromExternal(ScanMode.Quick);
        };
        TrayService.DeepScanRequested += () =>
        {
            ShowMainWindow();
            _mainWindow?.TriggerScanFromExternal(ScanMode.DeepScan);
        };
        TrayService.ToggleRealtimeRequested += () =>
        {
            Settings.RealtimeProtectionEnabled = !Settings.RealtimeProtectionEnabled;
            SettingsService.SaveSettings(Settings);
            SyncShieldStates();
            _mainWindow?.RefreshDashboardBindings();
        };
        TrayService.ExitRequested += ExitApplicationCompletely;
    }

    public void SyncShieldStates()
    {
        RealtimeService.UpdateSettings(Settings);
        RansomwareService.UpdateSettings(Settings);
        ProcessService.UpdateSettings(Settings);
        UsbService.UpdateSettings(Settings);
        UrlAnalyzer.SetCustomBlockedDomains(Settings.CustomBlockedDomains);

        if ((Settings.RealtimeProtectionEnabled || Settings.DownloadGuardEnabled) && !RealtimeService.IsRunning)
            RealtimeService.Start();
        else if (!Settings.RealtimeProtectionEnabled && !Settings.DownloadGuardEnabled && RealtimeService.IsRunning)
            RealtimeService.Stop();

        if (Settings.RansomwareShieldEnabled && !RansomwareService.IsRunning)
            RansomwareService.Start();
        else if (!Settings.RansomwareShieldEnabled && RansomwareService.IsRunning)
            RansomwareService.Stop();

        if (Settings.ProcessGuardEnabled && !ProcessService.IsRunning)
            ProcessService.Start();
        else if (!Settings.ProcessGuardEnabled && ProcessService.IsRunning)
            ProcessService.Stop();

        if (Settings.UsbShieldEnabled && !UsbService.IsRunning)
            UsbService.Start();
        else if (!Settings.UsbShieldEnabled && UsbService.IsRunning)
            UsbService.Stop();
    }

    public void ShowMainWindow()
    {
        if (_mainWindow == null) return;
        if (!_mainWindow.IsVisible) _mainWindow.Show();
        if (_mainWindow.WindowState == WindowState.Minimized)
            _mainWindow.WindowState = WindowState.Normal;
        _mainWindow.Activate();
    }

    private void OnBackgroundTimerTick(object? sender, EventArgs e)
    {
        var metrics = ResourceOptimizer.SampleSelfMetrics();
        TrayService.UpdateStatus(Settings.RealtimeProtectionEnabled, false, metrics.WorkingSetMB);
        _mainWindow?.UpdateResourceMetrics(metrics);

        if (Settings.ClipboardUrlGuardEnabled)
        {
            uint seq = GetClipboardSequenceNumber();
            if (seq != _lastClipboardSeq)
            {
                _lastClipboardSeq = seq;
                CheckClipboardUrl();
            }
        }

        if (Settings.ScheduledQuickScanMinutes > 0 &&
            (DateTime.UtcNow - _lastScheduledScanUtc).TotalMinutes >= Settings.ScheduledQuickScanMinutes)
        {
            _lastScheduledScanUtc = DateTime.UtcNow;
            _ = Task.Run(async () =>
            {
                var res = await ScanService.RunScanAsync(ScanMode.Quick, Settings);
                foreach (var hit in res.Findings.Where(f => Settings.AutoQuarantineHighRisk && f.RiskScore >= 55))
                {
                    QuarantineService.QuarantineFile(hit);
                }
            });
        }
    }

    private void CheckClipboardUrl()
    {
        try
        {
            if (!System.Windows.Clipboard.ContainsText()) return;
            string text = System.Windows.Clipboard.GetText().Trim();
            if (string.IsNullOrEmpty(text) || text.Length > 16384) return;

            var clipResult = UrlAnalyzer.AnalyzeClipboardContent(text);
            if (!clipResult.HasThreat) return;

            var detailParts = new List<string>();
            detailParts.AddRange(clipResult.CommandWarnings);
            foreach (var u in clipResult.FlaggedUrls)
            {
                detailParts.Add($"{u.Url} ({u.RiskScore}/100): {string.Join("; ", u.Reasons)}");
            }

            string summaryTarget = clipResult.FlaggedUrls.Count > 0
                ? string.Join(", ", clipResult.FlaggedUrls.Select(u => u.NormalizedHost).Distinct())
                : "Lệnh tải/thực thi từ mạng";

            SettingsService.Log(SecurityLogLevel.Alert, "ClipboardUrlGuard",
                $"Phát hiện nội dung/liên kết nguy hiểm trong Clipboard: {summaryTarget} (Điểm {clipResult.MaxRiskScore}/100)",
                string.Join(" | ", detailParts));

            string toastTitle = clipResult.CommandWarnings.Count > 0
                ? "Cảnh báo Lệnh & Liên kết Nguy hiểm!"
                : "Cảnh báo Liên kết Nguy hiểm!";

            string toastBody = clipResult.FlaggedUrls.Count > 0
                ? $"{clipResult.FlaggedUrls[0].Verdict}: {summaryTarget}"
                : clipResult.CommandWarnings[0];

            TrayService.ShowNotification(
                toastTitle,
                toastBody,
                isWarningOrError: true);
        }
        catch { }
    }

    public void ExitApplicationCompletely()
    {
        _backgroundGuardTimer?.Stop();
        RealtimeService.Dispose();
        RansomwareService.Dispose();
        ProcessService.Dispose();
        UsbService.Dispose();
        TrayService.Dispose();
        _wakeWaitHandle?.Unregister(null);
        _wakeEvent?.Dispose();
        _singleInstanceMutex?.ReleaseMutex();
        _singleInstanceMutex?.Dispose();
        Shutdown();
    }
}
