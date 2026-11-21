using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using BaroAntivirus.Core.Models;
using BaroAntivirus.Core.Services;
using WinForms = System.Windows.Forms;

namespace BaroAntivirus.App;

public sealed class FindingViewItem
{
    public ThreatFinding Raw { get; }
    public ThreatSeverity Severity => Raw.Severity;
    public int RiskScore => Raw.RiskScore;
    public string ThreatName => Raw.ThreatName;
    public string FileName => Raw.FileName;
    public string FilePath => Raw.FilePath;
    public ProtectionAction ActionTaken => Raw.ActionTaken;
    public string ReasonsText => string.Join(" | ", Raw.Reasons);

    public FindingViewItem(ThreatFinding raw) => Raw = raw;
}

public partial class MainWindow : Window
{
    private readonly App _app;
    private readonly ObservableCollection<FindingViewItem> _scanFindings = new();
    private readonly ObservableCollection<DownloadInspectionEvent> _downloads = new();
    private readonly ObservableCollection<SecurityLogEntry> _logs = new();
    private readonly Dictionary<string, System.Windows.Controls.Button> _navButtons;
    private CancellationTokenSource? _scanCts;
    private bool _isScanning;

    public MainWindow(App app)
    {
        _app = app;
        InitializeComponent();

        _navButtons = new Dictionary<string, System.Windows.Controls.Button>
        {
            ["Dashboard"] = NavDashboard,
            ["Scanner"] = NavScanner,
            ["WebShield"] = NavWebShield,
            ["Process"] = NavProcess,
            ["Quarantine"] = NavQuarantine,
            ["Toolkit"] = NavToolkit,
            ["Settings"] = NavSettings
        };

        GridScanFindings.ItemsSource = _scanFindings;
        GridDownloads.ItemsSource = _downloads;
        GridDashLogs.ItemsSource = _logs;
        GridAllLogs.ItemsSource = _logs;

        _app.SettingsService.LogAdded += entry =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                _logs.Insert(0, entry);
                while (_logs.Count > 250) _logs.RemoveAt(_logs.Count - 1);
                TxtDashAlertCount.Text = _logs.Count(l => l.Level >= SecurityLogLevel.Alert).ToString();
            });
        };

        _app.QuarantineService.QuarantineChanged += () => Dispatcher.BeginInvoke(RefreshQuarantineGrid);

        LoadInitialState();
        SwitchPanel("Dashboard");
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (_app.Settings.MinimizeToTrayOnClose)
        {
            e.Cancel = true;
            Hide();
            if (_app.Settings.LightweightMemoryTrim)
                ResourceOptimizer.TrimBackgroundMemory();
            _app.TrayService.ShowNotification(
                "BaroAntivirus vẫn đang chạy nền",
                "Lá chắn thời gian thực tiếp tục bảo vệ máy tính với mức RAM tối giản.");
            return;
        }
        base.OnClosing(e);
        _app.ExitApplicationCompletely();
    }

    private void LoadInitialState()
    {
        foreach (var l in _app.SettingsService.GetRecentLogs())
            _logs.Add(l);

        RefreshDashboardBindings();
        RefreshQuarantineGrid();
        RefreshToolkitLists();
        LoadSettingsUi();
    }

    public void RefreshDashboardBindings()
    {
        var s = _app.Settings;
        ChkDashRealtime.IsChecked = s.RealtimeProtectionEnabled;
        ChkDashDownload.IsChecked = s.DownloadGuardEnabled;
        ChkDashRansomware.IsChecked = s.RansomwareShieldEnabled;
        ChkDashProcess.IsChecked = s.ProcessGuardEnabled;
        ChkDashUsb.IsChecked = s.UsbShieldEnabled;
        ChkDashClipboard.IsChecked = s.ClipboardUrlGuardEnabled;

        string strictShort = s.Strictness switch
        {
            StrictnessLevel.Paranoid => "Paranoid",
            StrictnessLevel.Strict => "Strict",
            _ => "Balanced"
        };
        TxtDashStrictness.Text = strictShort;
        TxtSidebarScope.Text = $"{strictShort} Shield";
        TxtTopBaseline.Text = $"Chế độ {strictShort} · Nhẹ hơn Defender";

        if (s.RealtimeProtectionEnabled)
        {
            TopStatusPill.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(220, 250, 229)); // #DCFAE5
            TopStatusDot.Fill = new SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 123, 79));       // #1E7B4F
            TxtTopStatus.Text = "Real-time đang bật";
            TxtTopStatus.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(4, 37, 14));   // #04250E
            TxtOverviewSub.Text = "6 lá chắn chủ động đang giám sát tải xuống, tiến trình và thư mục dữ liệu.";
        }
        else
        {
            TopStatusPill.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 251, 235)); // #FFFBEB
            TopStatusDot.Fill = new SolidColorBrush(System.Windows.Media.Color.FromRgb(146, 64, 14));        // #92400E
            TxtTopStatus.Text = "Real-time tạm dừng";
            TxtTopStatus.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(146, 64, 14));
            TxtOverviewSub.Text = "Cảnh báo: Bảo vệ thời gian thực đang tắt — hãy bật lại để bảo vệ liên tục.";
        }

        TxtDashAlertCount.Text = _logs.Count(l => l.Level >= SecurityLogLevel.Alert).ToString();
    }

    public void UpdateResourceMetrics(ResourceMetrics metrics)
    {
        TxtSidebarRam.Text = $"{metrics.WorkingSetMB:F1} MB";
        TxtSidebarCpu.Text = $"{metrics.CpuPercent:F1}%";
        TxtDashRam.Text = $"{metrics.WorkingSetMB:F1} MB";
    }

    public void OnRealtimeThreat(ThreatFinding finding)
    {
        _scanFindings.Insert(0, new FindingViewItem(finding));
        RefreshQuarantineGrid();
    }

    public void OnDownloadInspected(DownloadInspectionEvent ev)
    {
        _downloads.Insert(0, ev);
        while (_downloads.Count > 60) _downloads.RemoveAt(_downloads.Count - 1);
    }

    public void OnRansomwareAlert(RansomwareAlertEvent alert)
    {
        System.Windows.MessageBox.Show(
            $"CẢNH BÁO RANSOMWARE!\n\n{alert.Description}\n\nThư mục: {alert.FolderPath}\nTệp mẫu: {alert.SampleFile}",
            "BaroAntivirus — Chống Ransomware",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
    }

    public void TriggerScanFromExternal(ScanMode mode)
    {
        SwitchPanel("Scanner");
        _ = StartScanAsync(mode, null);
    }

    private void SwitchPanel(string tag)
    {
        PanelDashboard.Visibility = tag == "Dashboard" ? Visibility.Visible : Visibility.Collapsed;
        PanelScanner.Visibility = tag == "Scanner" ? Visibility.Visible : Visibility.Collapsed;
        PanelWebShield.Visibility = tag == "WebShield" ? Visibility.Visible : Visibility.Collapsed;
        PanelProcess.Visibility = tag == "Process" ? Visibility.Visible : Visibility.Collapsed;
        PanelQuarantine.Visibility = tag == "Quarantine" ? Visibility.Visible : Visibility.Collapsed;
        PanelToolkit.Visibility = tag == "Toolkit" ? Visibility.Visible : Visibility.Collapsed;
        PanelSettings.Visibility = tag == "Settings" ? Visibility.Visible : Visibility.Collapsed;

        // Active nav style: neutral #EBEDEE pill & #131416 SemiBold ink (per Taste app-screens.md)
        foreach (var kv in _navButtons)
        {
            bool active = kv.Key == tag;
            kv.Value.Background = active
                ? new SolidColorBrush(System.Windows.Media.Color.FromRgb(235, 237, 238))
                : System.Windows.Media.Brushes.Transparent;
            kv.Value.Foreground = active
                ? new SolidColorBrush(System.Windows.Media.Color.FromRgb(19, 20, 22))
                : new SolidColorBrush(System.Windows.Media.Color.FromRgb(93, 95, 96));
            kv.Value.FontWeight = active ? FontWeights.SemiBold : FontWeights.Normal;
        }

        if (tag == "WebShield") RefreshNetworkGrid();
        else if (tag == "Process") { RefreshProcessesGrid(); RefreshStartupGrid(); }
        else if (tag == "Quarantine") RefreshQuarantineGrid();
        else if (tag == "Toolkit") RefreshToolkitLists();
        else if (tag == "Settings") LoadSettingsUi();
    }

    private void Nav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn && btn.Tag is string tag)
            SwitchPanel(tag);
    }

    private void BtnGoToolkitLogs_Click(object sender, RoutedEventArgs e) => SwitchPanel("Toolkit");

    private void BtnMinimizeToTray_Click(object sender, RoutedEventArgs e)
    {
        Hide();
        if (_app.Settings.LightweightMemoryTrim)
            ResourceOptimizer.TrimBackgroundMemory();
    }

    private void DashShieldToggle_Click(object sender, RoutedEventArgs e)
    {
        _app.Settings.RealtimeProtectionEnabled = ChkDashRealtime.IsChecked == true;
        _app.Settings.DownloadGuardEnabled = ChkDashDownload.IsChecked == true;
        _app.Settings.RansomwareShieldEnabled = ChkDashRansomware.IsChecked == true;
        _app.Settings.ProcessGuardEnabled = ChkDashProcess.IsChecked == true;
        _app.Settings.UsbShieldEnabled = ChkDashUsb.IsChecked == true;
        _app.Settings.ClipboardUrlGuardEnabled = ChkDashClipboard.IsChecked == true;
        _app.SettingsService.SaveSettings(_app.Settings);
        _app.SyncShieldStates();
        RefreshDashboardBindings();
    }

    private void BtnDashQuickScan_Click(object sender, RoutedEventArgs e) => TriggerScanFromExternal(ScanMode.Quick);
    private void BtnDashDeepScan_Click(object sender, RoutedEventArgs e) => TriggerScanFromExternal(ScanMode.DeepScan);

    // ==================== SCANNER ====================
    private void BtnQuickScan_Click(object sender, RoutedEventArgs e) => _ = StartScanAsync(ScanMode.Quick, null);
    private void BtnDeepScan_Click(object sender, RoutedEventArgs e) => _ = StartScanAsync(ScanMode.DeepScan, null);

    private void BtnCustomFolderScan_Click(object sender, RoutedEventArgs e)
    {
        using var dlg = new WinForms.FolderBrowserDialog { Description = "Chọn thư mục cần quét sâu" };
        if (dlg.ShowDialog() == WinForms.DialogResult.OK && !string.IsNullOrWhiteSpace(dlg.SelectedPath))
        {
            _ = StartScanAsync(ScanMode.Custom, new[] { dlg.SelectedPath });
        }
    }

    private void BtnCustomFileScan_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Chọn tệp cần kiểm tra",
            Multiselect = true
        };
        if (dlg.ShowDialog() == true && dlg.FileNames.Length > 0)
        {
            _ = StartScanAsync(ScanMode.Custom, dlg.FileNames);
        }
    }

    private void BtnEicarTest_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string testDir = Path.Combine(Path.GetTempPath(), "BaroAntivirus_Test");
            Directory.CreateDirectory(testDir);
            string testFile = Path.Combine(testDir, "eicar_test_sample.txt");
            string eicar = string.Concat(
                "X5O!P%",
                "@AP[4\\PZX54",
                "(P^)7CC)7}$",
                "EICAR-STANDARD-",
                "ANTIVIRUS-TEST-FILE!",
                "$H+H*");
            File.WriteAllText(testFile, eicar);
            _ = StartScanAsync(ScanMode.Custom, new[] { testFile });
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Không thể tạo mẫu kiểm thử: {ex.Message}");
        }
    }

    private void ScanDropZone_DragOver(object sender, System.Windows.DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop)
            ? System.Windows.DragDropEffects.Copy
            : System.Windows.DragDropEffects.None;
        e.Handled = true;
    }

    private void ScanDropZone_Drop(object sender, System.Windows.DragEventArgs e)
    {
        if (e.Data.GetData(System.Windows.DataFormats.FileDrop) is string[] paths && paths.Length > 0)
        {
            _ = StartScanAsync(ScanMode.Custom, paths);
        }
    }

    private void BtnPauseScan_Click(object sender, RoutedEventArgs e)
    {
        _app.ScanService.IsPaused = !_app.ScanService.IsPaused;
        BtnPauseScan.Content = _app.ScanService.IsPaused ? "Tiếp tục" : "Tạm dừng";
    }

    private void BtnStopScan_Click(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
    }

    private async Task StartScanAsync(ScanMode mode, IEnumerable<string>? customPaths)
    {
        if (_isScanning)
        {
            System.Windows.MessageBox.Show("Đang có một tác vụ quét khác chạy. Vui lòng đợi hoặc bấm Dừng.", "BaroAntivirus");
            return;
        }

        _isScanning = true;
        _scanFindings.Clear();
        _scanCts = new CancellationTokenSource();

        BtnQuickScan.IsEnabled = false;
        BtnDeepScan.IsEnabled = false;
        BtnPauseScan.IsEnabled = true;
        BtnPauseScan.Content = "Tạm dừng";
        BtnStopScan.IsEnabled = true;
        ProgScan.IsIndeterminate = true;
        TxtScanStatus.Text = $"Đang chạy {mode} ({_app.Settings.Strictness})...";

        var progress = new Progress<ScanProgress>(p =>
        {
            TxtScanStatus.Text = p.IsPaused
                ? $"Đang tạm dừng {p.Mode}..."
                : $"Đang quét {p.Mode} ({p.Elapsed:mm\\:ss})...";
            TxtScanStats.Text = $"{p.FilesScanned:N0} tệp · {p.ThreatsFound} mối nguy · {p.FilesPerSecond:F1} tệp/giây";
            TxtCurrentScanFile.Text = p.CurrentFile;
        });

        try
        {
            var result = await _app.ScanService.RunScanAsync(mode, _app.Settings, customPaths, progress, _scanCts.Token);
            foreach (var f in result.Findings)
            {
                if (_app.Settings.AutoQuarantineHighRisk && f.RiskScore >= 75)
                {
                    _app.QuarantineService.QuarantineFile(f);
                }
                _scanFindings.Add(new FindingViewItem(f));
            }

            ProgScan.IsIndeterminate = false;
            ProgScan.Value = 100;
            TxtScanStatus.Text = result.Cancelled
                ? $"Đã dừng {mode}: {result.FilesScanned:N0} tệp, {result.Findings.Count} mối nguy."
                : $"Hoàn tất {mode}: {result.FilesScanned:N0} tệp ({result.BytesScanned / (1024.0 * 1024.0):F1} MB), {result.Findings.Count} mối nguy.";
            TxtCurrentScanFile.Text = "";
            RefreshQuarantineGrid();
        }
        finally
        {
            _isScanning = false;
            BtnQuickScan.IsEnabled = true;
            BtnDeepScan.IsEnabled = true;
            BtnPauseScan.IsEnabled = false;
            BtnStopScan.IsEnabled = false;
            _scanCts.Dispose();
            _scanCts = null;
        }
    }

    private void BtnQuarantineSelected_Click(object sender, RoutedEventArgs e)
    {
        if (GridScanFindings.SelectedItem is not FindingViewItem item) return;
        if (_app.QuarantineService.QuarantineFile(item.Raw) != null)
        {
            _app.SettingsService.Log(SecurityLogLevel.Action, "Scanner", $"Đã cách ly thủ công: {item.FileName}");
            RefreshFindingsGrid();
            RefreshQuarantineGrid();
        }
    }

    private void BtnQuarantineAll_Click(object sender, RoutedEventArgs e)
    {
        int count = 0;
        foreach (var item in _scanFindings.Where(x => x.ActionTaken != ProtectionAction.Quarantined))
        {
            if (_app.QuarantineService.QuarantineFile(item.Raw) != null) count++;
        }
        RefreshFindingsGrid();
        RefreshQuarantineGrid();
        System.Windows.MessageBox.Show($"Đã đưa {count} mối nguy vào Khu Cách Ly an toàn.", "BaroAntivirus");
    }

    private void BtnShredSelected_Click(object sender, RoutedEventArgs e)
    {
        if (GridScanFindings.SelectedItem is not FindingViewItem item) return;
        if (FileShredderService.ShredFile(item.FilePath))
        {
            item.Raw.ActionTaken = ProtectionAction.Blocked;
            _app.SettingsService.Log(SecurityLogLevel.Action, "FileShredder", $"Đã hủy vĩnh viễn tệp độc hại: {item.FilePath}");
            RefreshFindingsGrid();
        }
    }

    private void BtnWhitelistSelected_Click(object sender, RoutedEventArgs e)
    {
        if (GridScanFindings.SelectedItem is not FindingViewItem item) return;
        if (!string.IsNullOrEmpty(item.Raw.Sha256) && !_app.Settings.ExcludedHashes.Contains(item.Raw.Sha256))
            _app.Settings.ExcludedHashes.Add(item.Raw.Sha256);
        if (!_app.Settings.ExcludedPaths.Contains(item.FilePath))
            _app.Settings.ExcludedPaths.Add(item.FilePath);
        _app.SettingsService.SaveSettings(_app.Settings);
        _scanFindings.Remove(item);
        RefreshToolkitLists();
    }

    private void RefreshFindingsGrid() => GridScanFindings.Items.Refresh();

    // ==================== WEB, DOWNLOAD & NETWORK ====================
    private void BtnCheckUrl_Click(object sender, RoutedEventArgs e)
    {
        var res = _app.UrlAnalyzer.Analyze(TxtUrlInput.Text);
        TxtUrlResult.Text = $"{res.Verdict} ({res.RiskScore}/100) · {res.NormalizedHost} — " +
                            string.Join(" | ", res.Reasons);
        TxtUrlResult.Foreground = res.IsSafe
            ? new SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 123, 79))
            : new SolidColorBrush(System.Windows.Media.Color.FromRgb(196, 36, 42));
    }

    private void BtnBlockDomain_Click(object sender, RoutedEventArgs e)
    {
        var res = _app.UrlAnalyzer.Analyze(TxtUrlInput.Text);
        if (string.IsNullOrWhiteSpace(res.NormalizedHost)) return;
        if (!_app.Settings.CustomBlockedDomains.Contains(res.NormalizedHost, StringComparer.OrdinalIgnoreCase))
        {
            _app.Settings.CustomBlockedDomains.Add(res.NormalizedHost);
            _app.SettingsService.SaveSettings(_app.Settings);
            _app.SyncShieldStates();
        }
        TxtUrlResult.Text = $"Đã thêm '{res.NormalizedHost}' vào danh sách chặn của BaroAntivirus.";
    }

    private void BtnEnableHostsShield_Click(object sender, RoutedEventArgs e)
    {
        var (ok, msg) = NetworkMonitorService.ApplyHostsMaliciousDomainBlock(true, _app.Settings.CustomBlockedDomains);
        TxtHostsStatus.Text = msg;
        if (ok)
        {
            _app.Settings.HostsProtectionEnabled = true;
            _app.SettingsService.SaveSettings(_app.Settings);
        }
    }

    private void BtnDisableHostsShield_Click(object sender, RoutedEventArgs e)
    {
        var (ok, msg) = NetworkMonitorService.ApplyHostsMaliciousDomainBlock(false, _app.Settings.CustomBlockedDomains);
        TxtHostsStatus.Text = msg;
        if (ok)
        {
            _app.Settings.HostsProtectionEnabled = false;
            _app.SettingsService.SaveSettings(_app.Settings);
        }
    }

    private void BtnRefreshNetwork_Click(object sender, RoutedEventArgs e) => RefreshNetworkGrid();

    private void RefreshNetworkGrid()
    {
        GridNetwork.ItemsSource = _app.NetworkService.GetActiveTcpConnections();
    }

    private void BtnKillNetworkProcess_Click(object sender, RoutedEventArgs e)
    {
        if (GridNetwork.SelectedItem is not NetworkConnectionInfo conn || conn.Pid <= 4) return;
        if (_app.ProcessService.TerminateProcess(conn.Pid, out string err))
            RefreshNetworkGrid();
        else
            System.Windows.MessageBox.Show($"Không thể dừng tiến trình: {err}");
    }

    // ==================== PROCESS & STARTUP ====================
    private void BtnRefreshProcesses_Click(object sender, RoutedEventArgs e) => RefreshProcessesGrid();
    private void BtnRefreshStartup_Click(object sender, RoutedEventArgs e) => RefreshStartupGrid();

    private void RefreshProcessesGrid()
    {
        GridProcesses.ItemsSource = _app.ProcessService.SnapshotProcesses();
    }

    private void RefreshStartupGrid()
    {
        GridStartup.ItemsSource = _app.StartupService.InspectStartupEntries();
    }

    private void BtnKillSelectedProcess_Click(object sender, RoutedEventArgs e)
    {
        if (GridProcesses.SelectedItem is not ProcessRiskInfo p) return;
        if (_app.ProcessService.TerminateProcess(p.Pid, out string err))
            RefreshProcessesGrid();
        else
            System.Windows.MessageBox.Show($"Không thể chấm dứt tiến trình: {err}");
    }

    private void BtnRemoveStartup_Click(object sender, RoutedEventArgs e)
    {
        if (GridStartup.SelectedItem is not StartupEntryInfo entry) return;
        if (_app.StartupService.RemoveStartupEntry(entry, out string err))
        {
            _app.SettingsService.Log(SecurityLogLevel.Action, "StartupGuard", $"Đã gỡ mục khởi động: {entry.Name}");
            RefreshStartupGrid();
        }
        else
        {
            System.Windows.MessageBox.Show(err, "Startup Guard");
        }
    }

    // ==================== QUARANTINE ====================
    private void RefreshQuarantineGrid()
    {
        var entries = _app.QuarantineService.GetEntries();
        GridQuarantine.ItemsSource = entries;
        TxtDashQuarantineCount.Text = $"{entries.Count} tệp";
        TxtNavQuarantineLabel.Text = entries.Count > 0 ? $"Cách ly {entries.Count}" : "Cách ly";
    }

    private void BtnRestoreQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (GridQuarantine.SelectedItem is not QuarantineEntry entry) return;
        if (_app.QuarantineService.RestoreEntry(entry.Id, out string? restoredPath))
        {
            if (!string.IsNullOrEmpty(entry.Sha256) && !_app.Settings.ExcludedHashes.Contains(entry.Sha256))
                _app.Settings.ExcludedHashes.Add(entry.Sha256);
            _app.SettingsService.SaveSettings(_app.Settings);
            _app.SettingsService.Log(SecurityLogLevel.Action, "Quarantine", $"Đã khôi phục tệp về {restoredPath} và thêm ngoại lệ.");
            RefreshQuarantineGrid();
            RefreshToolkitLists();
        }
    }

    private void BtnDeleteQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (GridQuarantine.SelectedItem is not QuarantineEntry entry) return;
        _app.QuarantineService.DeleteEntryPermanently(entry.Id);
        RefreshQuarantineGrid();
    }

    private void BtnPurgeQuarantine_Click(object sender, RoutedEventArgs e)
    {
        int removed = _app.QuarantineService.PurgeAll();
        System.Windows.MessageBox.Show($"Đã tiêu hủy vĩnh viễn {removed} tệp trong Khu Cách Ly.", "BaroAntivirus");
        RefreshQuarantineGrid();
    }

    // ==================== TOOLKIT ====================
    private void RefreshToolkitLists()
    {
        ListProtectedFolders.ItemsSource = _app.Settings.ProtectedFolders.ToList();
        ListExclusions.ItemsSource = _app.Settings.ExcludedPaths.Concat(_app.Settings.ExcludedHashes).ToList();
    }

    private void BtnBrowseShred_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Chọn tệp cần hủy vĩnh viễn" };
        if (dlg.ShowDialog() == true) TxtShredPath.Text = dlg.FileName;
    }

    private void BtnExecuteShred_Click(object sender, RoutedEventArgs e)
    {
        string path = TxtShredPath.Text.Trim();
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            System.Windows.MessageBox.Show("Tệp không tồn tại.", "File Shredder");
            return;
        }
        if (System.Windows.MessageBox.Show($"Bạn chắc chắn muốn hủy vĩnh viễn (không thể khôi phục) tệp:\n{path}?",
                "Xác nhận File Shredder", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        if (FileShredderService.ShredFile(path, passes: 3))
        {
            _app.SettingsService.Log(SecurityLogLevel.Action, "FileShredder", $"Đã ghi đè 3 lớp và xóa vĩnh viễn: {path}");
            TxtShredPath.Text = string.Empty;
            System.Windows.MessageBox.Show("Đã hủy tệp an toàn hoàn toàn.", "File Shredder");
        }
    }

    private void BtnAddProtectedFolder_Click(object sender, RoutedEventArgs e)
    {
        using var dlg = new WinForms.FolderBrowserDialog();
        if (dlg.ShowDialog() == WinForms.DialogResult.OK &&
            !_app.Settings.ProtectedFolders.Contains(dlg.SelectedPath, StringComparer.OrdinalIgnoreCase))
        {
            _app.Settings.ProtectedFolders.Add(dlg.SelectedPath);
            _app.SettingsService.SaveSettings(_app.Settings);
            _app.RansomwareService.Stop();
            _app.SyncShieldStates();
            RefreshToolkitLists();
        }
    }

    private void BtnRemoveProtectedFolder_Click(object sender, RoutedEventArgs e)
    {
        if (ListProtectedFolders.SelectedItem is not string folder) return;
        _app.Settings.ProtectedFolders.Remove(folder);
        _app.SettingsService.SaveSettings(_app.Settings);
        _app.RansomwareService.Stop();
        _app.SyncShieldStates();
        RefreshToolkitLists();
    }

    private void BtnAddExclusion_Click(object sender, RoutedEventArgs e)
    {
        using var dlg = new WinForms.FolderBrowserDialog();
        if (dlg.ShowDialog() == WinForms.DialogResult.OK &&
            !_app.Settings.ExcludedPaths.Contains(dlg.SelectedPath, StringComparer.OrdinalIgnoreCase))
        {
            _app.Settings.ExcludedPaths.Add(dlg.SelectedPath);
            _app.SettingsService.SaveSettings(_app.Settings);
            RefreshToolkitLists();
        }
    }

    private void BtnRemoveExclusion_Click(object sender, RoutedEventArgs e)
    {
        if (ListExclusions.SelectedItem is not string ex) return;
        _app.Settings.ExcludedPaths.Remove(ex);
        _app.Settings.ExcludedHashes.Remove(ex);
        _app.SettingsService.SaveSettings(_app.Settings);
        RefreshToolkitLists();
    }

    private void BtnExportLogs_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "JSON Files (*.json)|*.json",
            FileName = $"BaroAntivirus_Logs_{DateTime.Now:yyyyMMdd_HHmm}.json"
        };
        if (dlg.ShowDialog() == true)
        {
            _app.SettingsService.ExportLogs(dlg.FileName);
            System.Windows.MessageBox.Show("Đã xuất nhật ký bảo mật thành công.", "BaroAntivirus");
        }
    }

    // ==================== SETTINGS ====================
    private void LoadSettingsUi()
    {
        var s = _app.Settings;
        RadBalanced.IsChecked = s.Strictness == StrictnessLevel.Balanced;
        RadStrict.IsChecked = s.Strictness == StrictnessLevel.Strict;
        RadParanoid.IsChecked = s.Strictness == StrictnessLevel.Paranoid;

        ChkSetStartup.IsChecked = s.RunAtWindowsStartup;
        ChkSetMinimizeTray.IsChecked = s.MinimizeToTrayOnClose;
        ChkSetAutoQuarantine.IsChecked = s.AutoQuarantineHighRisk;
        ChkSetMemTrim.IsChecked = s.LightweightMemoryTrim;

        CmbConcurrency.SelectedIndex = Math.Clamp(s.MaxDeepScanConcurrency - 1, 0, 3);
        foreach (ComboBoxItem item in CmbScheduleMinutes.Items)
        {
            if (int.TryParse(item.Tag?.ToString(), out int m) && m == s.ScheduledQuickScanMinutes)
            {
                CmbScheduleMinutes.SelectedItem = item;
                break;
            }
        }
        if (CmbScheduleMinutes.SelectedIndex < 0) CmbScheduleMinutes.SelectedIndex = 0;
    }

    private void BtnSaveSettings_Click(object sender, RoutedEventArgs e)
    {
        var s = _app.Settings;
        s.Strictness = RadParanoid.IsChecked == true ? StrictnessLevel.Paranoid
            : RadBalanced.IsChecked == true ? StrictnessLevel.Balanced
            : StrictnessLevel.Strict;

        s.RunAtWindowsStartup = ChkSetStartup.IsChecked == true;
        s.MinimizeToTrayOnClose = ChkSetMinimizeTray.IsChecked == true;
        s.AutoQuarantineHighRisk = ChkSetAutoQuarantine.IsChecked == true;
        s.LightweightMemoryTrim = ChkSetMemTrim.IsChecked == true;
        s.MaxDeepScanConcurrency = Math.Clamp(CmbConcurrency.SelectedIndex + 1, 1, 4);

        if (CmbScheduleMinutes.SelectedItem is ComboBoxItem sel &&
            int.TryParse(sel.Tag?.ToString(), out int mins))
        {
            s.ScheduledQuickScanMinutes = mins;
        }

        _app.SettingsService.SyncWindowsStartup(s.RunAtWindowsStartup);
        _app.SettingsService.SaveSettings(s);
        _app.SyncShieldStates();
        RefreshDashboardBindings();

        System.Windows.MessageBox.Show("Đã lưu và áp dụng cài đặt mới!", "BaroAntivirus");
    }

    private void BtnTrimMemoryNow_Click(object sender, RoutedEventArgs e)
    {
        ResourceOptimizer.TrimBackgroundMemory();
        UpdateResourceMetrics(_app.ResourceOptimizer.SampleSelfMetrics());
    }
}
