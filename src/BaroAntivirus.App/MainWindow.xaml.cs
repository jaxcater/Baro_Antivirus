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

public sealed class SelectableItem<T> : INotifyPropertyChanged
{
    private bool _isSelected;
    public T Item { get; }

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value) return;
            _isSelected = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
        }
    }

    public SelectableItem(T item) => Item = item;

    public event PropertyChangedEventHandler? PropertyChanged;
}

public sealed class FindingViewItem : INotifyPropertyChanged
{
    private bool _isSelected;
    public ThreatFinding Raw { get; }
    public ThreatSeverity Severity => Raw.Severity;
    public int RiskScore => Raw.RiskScore;
    public string ThreatName => Raw.ThreatName;
    public string FileName => Raw.FileName;
    public string FilePath => Raw.FilePath;
    public ProtectionAction ActionTaken => Raw.ActionTaken;
    public string ReasonsText => string.Join(" | ", Raw.Reasons);

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value) return;
            _isSelected = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
        }
    }

    public FindingViewItem(ThreatFinding raw) => Raw = raw;

    public event PropertyChangedEventHandler? PropertyChanged;
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

    private static List<T> GetCheckedOrSelected<T>(IEnumerable<T>? source, DataGrid grid, Func<T, bool> isChecked)
    {
        var ticked = source?.Where(isChecked).ToList() ?? new List<T>();
        if (ticked.Count > 0) return ticked;
        return grid.SelectedItems.OfType<T>().ToList();
    }

    private static void SetAllChecked<T>(IEnumerable<T>? source, bool isChecked, Action<T, bool> setter)
    {
        if (source == null) return;
        foreach (var item in source)
            setter(item, isChecked);
    }

    private void ChkSelectAllFindings_Click(object sender, RoutedEventArgs e)
    {
        SetAllChecked(_scanFindings, ChkSelectAllFindings.IsChecked == true, (item, v) => item.IsSelected = v);
    }

    private void ChkSelectAllNetwork_Click(object sender, RoutedEventArgs e)
    {
        SetAllChecked(GridNetwork.ItemsSource as IEnumerable<SelectableItem<NetworkConnectionInfo>>,
            ChkSelectAllNetwork.IsChecked == true, (item, v) => item.IsSelected = v);
    }

    private void ChkSelectAllProcesses_Click(object sender, RoutedEventArgs e)
    {
        SetAllChecked(GridProcesses.ItemsSource as IEnumerable<SelectableItem<ProcessRiskInfo>>,
            ChkSelectAllProcesses.IsChecked == true, (item, v) => item.IsSelected = v);
    }

    private void ChkSelectAllStartup_Click(object sender, RoutedEventArgs e)
    {
        SetAllChecked(GridStartup.ItemsSource as IEnumerable<SelectableItem<StartupEntryInfo>>,
            ChkSelectAllStartup.IsChecked == true, (item, v) => item.IsSelected = v);
    }

    private void ChkSelectAllQuarantine_Click(object sender, RoutedEventArgs e)
    {
        SetAllChecked(GridQuarantine.ItemsSource as IEnumerable<SelectableItem<QuarantineEntry>>,
            ChkSelectAllQuarantine.IsChecked == true, (item, v) => item.IsSelected = v);
    }

    private void BtnQuarantineSelected_Click(object sender, RoutedEventArgs e)
    {
        var targets = GetCheckedOrSelected(_scanFindings, GridScanFindings, x => x.IsSelected);
        if (targets.Count == 0) return;

        int count = 0;
        foreach (var item in targets.Where(x => x.ActionTaken != ProtectionAction.Quarantined))
        {
            if (_app.QuarantineService.QuarantineFile(item.Raw) != null)
            {
                count++;
                _app.SettingsService.Log(SecurityLogLevel.Action, "Scanner", $"Đã cách ly: {item.FileName}");
            }
            item.IsSelected = false;
        }
        ChkSelectAllFindings.IsChecked = false;
        RefreshFindingsGrid();
        RefreshQuarantineGrid();
        if (targets.Count > 1)
            System.Windows.MessageBox.Show($"Đã đưa {count} mục đã chọn vào Khu Cách Ly an toàn.", "BaroAntivirus");
    }

    private void BtnQuarantineAll_Click(object sender, RoutedEventArgs e)
    {
        int count = 0;
        foreach (var item in _scanFindings.Where(x => x.ActionTaken != ProtectionAction.Quarantined))
        {
            if (_app.QuarantineService.QuarantineFile(item.Raw) != null) count++;
        }
        ChkSelectAllFindings.IsChecked = false;
        RefreshFindingsGrid();
        RefreshQuarantineGrid();
        System.Windows.MessageBox.Show($"Đã đưa {count} mối nguy vào Khu Cách Ly an toàn.", "BaroAntivirus");
    }

    private void BtnShredSelected_Click(object sender, RoutedEventArgs e)
    {
        var targets = GetCheckedOrSelected(_scanFindings, GridScanFindings, x => x.IsSelected);
        if (targets.Count == 0) return;

        if (targets.Count > 1 && System.Windows.MessageBox.Show(
                $"Bạn chắc chắn muốn hủy vĩnh viễn {targets.Count} tệp đã chọn?",
                "Xác nhận hủy hàng loạt", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        int count = 0;
        foreach (var item in targets)
        {
            if (FileShredderService.ShredFile(item.FilePath))
            {
                count++;
                item.Raw.ActionTaken = ProtectionAction.Blocked;
                _app.SettingsService.Log(SecurityLogLevel.Action, "FileShredder", $"Đã hủy vĩnh viễn tệp độc hại: {item.FilePath}");
                _scanFindings.Remove(item);
            }
        }
        ChkSelectAllFindings.IsChecked = false;
        RefreshFindingsGrid();
        if (targets.Count > 1)
            System.Windows.MessageBox.Show($"Đã hủy vĩnh viễn {count}/{targets.Count} tệp.", "BaroAntivirus");
    }

    private void BtnWhitelistSelected_Click(object sender, RoutedEventArgs e)
    {
        var targets = GetCheckedOrSelected(_scanFindings, GridScanFindings, x => x.IsSelected);
        if (targets.Count == 0) return;

        foreach (var item in targets)
        {
            if (!string.IsNullOrEmpty(item.Raw.Sha256) && !_app.Settings.ExcludedHashes.Contains(item.Raw.Sha256))
                _app.Settings.ExcludedHashes.Add(item.Raw.Sha256);
            if (!_app.Settings.ExcludedPaths.Contains(item.FilePath))
                _app.Settings.ExcludedPaths.Add(item.FilePath);
            _scanFindings.Remove(item);
        }
        ChkSelectAllFindings.IsChecked = false;
        _app.SettingsService.SaveSettings(_app.Settings);
        RefreshToolkitLists();
    }

    private void RefreshFindingsGrid() => GridScanFindings.Items.Refresh();

    // ==================== WEB, DOWNLOAD & NETWORK ====================
    private void BtnCheckUrl_Click(object sender, RoutedEventArgs e)
    {
        string input = TxtUrlInput.Text.Trim();
        if (input.Contains(' ') || input.Contains('\n'))
        {
            var clip = _app.UrlAnalyzer.AnalyzeClipboardContent(input);
            if (clip.HasThreat)
            {
                var reasons = clip.CommandWarnings.Concat(clip.FlaggedUrls.SelectMany(u => u.Reasons)).Distinct();
                TxtUrlResult.Text = $"NGUY HIỂM ({clip.MaxRiskScore}/100) — " + string.Join(" | ", reasons);
                TxtUrlResult.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(196, 36, 42));
                return;
            }
        }

        var res = _app.UrlAnalyzer.Analyze(input);
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
        ChkSelectAllNetwork.IsChecked = false;
        GridNetwork.ItemsSource = _app.NetworkService.GetActiveTcpConnections()
            .Select(c => new SelectableItem<NetworkConnectionInfo>(c))
            .ToList();
    }

    private void BtnKillNetworkProcess_Click(object sender, RoutedEventArgs e)
    {
        var targets = GetCheckedOrSelected(
            GridNetwork.ItemsSource as IEnumerable<SelectableItem<NetworkConnectionInfo>>,
            GridNetwork,
            x => x.IsSelected);
        var pids = targets.Select(t => t.Item.Pid).Where(pid => pid > 4).Distinct().ToList();
        if (pids.Count == 0) return;

        var errors = new List<string>();
        foreach (int pid in pids)
        {
            if (!_app.ProcessService.TerminateProcess(pid, out string err))
                errors.Add($"PID {pid}: {err}");
        }
        RefreshNetworkGrid();
        if (errors.Count > 0)
            System.Windows.MessageBox.Show("Một số tiến trình không thể dừng:\n" + string.Join("\n", errors));
    }

    // ==================== PROCESS & STARTUP ====================
    private void BtnRefreshProcesses_Click(object sender, RoutedEventArgs e) => RefreshProcessesGrid();
    private void BtnRefreshStartup_Click(object sender, RoutedEventArgs e) => RefreshStartupGrid();

    private void RefreshProcessesGrid()
    {
        ChkSelectAllProcesses.IsChecked = false;
        GridProcesses.ItemsSource = _app.ProcessService.SnapshotProcesses()
            .Select(p => new SelectableItem<ProcessRiskInfo>(p))
            .ToList();
    }

    private void RefreshStartupGrid()
    {
        ChkSelectAllStartup.IsChecked = false;
        GridStartup.ItemsSource = _app.StartupService.InspectStartupEntries()
            .Select(s => new SelectableItem<StartupEntryInfo>(s))
            .ToList();
    }

    private void BtnKillSelectedProcess_Click(object sender, RoutedEventArgs e)
    {
        var targets = GetCheckedOrSelected(
            GridProcesses.ItemsSource as IEnumerable<SelectableItem<ProcessRiskInfo>>,
            GridProcesses,
            x => x.IsSelected);
        if (targets.Count == 0) return;

        var errors = new List<string>();
        foreach (var t in targets)
        {
            if (!_app.ProcessService.TerminateProcess(t.Item.Pid, out string err))
                errors.Add($"{t.Item.ProcessName} ({t.Item.Pid}): {err}");
        }
        RefreshProcessesGrid();
        if (errors.Count > 0)
            System.Windows.MessageBox.Show("Không thể chấm dứt một số tiến trình:\n" + string.Join("\n", errors));
    }

    private void BtnRemoveStartup_Click(object sender, RoutedEventArgs e)
    {
        var targets = GetCheckedOrSelected(
            GridStartup.ItemsSource as IEnumerable<SelectableItem<StartupEntryInfo>>,
            GridStartup,
            x => x.IsSelected);
        if (targets.Count == 0) return;

        var errors = new List<string>();
        foreach (var t in targets)
        {
            if (_app.StartupService.RemoveStartupEntry(t.Item, out string err))
                _app.SettingsService.Log(SecurityLogLevel.Action, "StartupGuard", $"Đã gỡ mục khởi động: {t.Item.Name}");
            else
                errors.Add($"{t.Item.Name}: {err}");
        }
        RefreshStartupGrid();
        if (errors.Count > 0)
            System.Windows.MessageBox.Show(string.Join("\n", errors), "Startup Guard");
    }

    // ==================== QUARANTINE ====================
    private void RefreshQuarantineGrid()
    {
        ChkSelectAllQuarantine.IsChecked = false;
        var entries = _app.QuarantineService.GetEntries();
        GridQuarantine.ItemsSource = entries.Select(q => new SelectableItem<QuarantineEntry>(q)).ToList();
        TxtDashQuarantineCount.Text = $"{entries.Count} tệp";
        TxtNavQuarantineLabel.Text = entries.Count > 0 ? $"Cách ly {entries.Count}" : "Cách ly";
    }

    private void BtnRestoreQuarantine_Click(object sender, RoutedEventArgs e)
    {
        var targets = GetCheckedOrSelected(
            GridQuarantine.ItemsSource as IEnumerable<SelectableItem<QuarantineEntry>>,
            GridQuarantine,
            x => x.IsSelected);
        if (targets.Count == 0) return;

        int restoredCount = 0;
        foreach (var t in targets)
        {
            if (_app.QuarantineService.RestoreEntry(t.Item.Id, out string? restoredPath))
            {
                restoredCount++;
                if (!string.IsNullOrEmpty(t.Item.Sha256) && !_app.Settings.ExcludedHashes.Contains(t.Item.Sha256))
                    _app.Settings.ExcludedHashes.Add(t.Item.Sha256);
                _app.SettingsService.Log(SecurityLogLevel.Action, "Quarantine", $"Đã khôi phục tệp về {restoredPath} và thêm ngoại lệ.");
            }
        }
        _app.SettingsService.SaveSettings(_app.Settings);
        RefreshQuarantineGrid();
        RefreshToolkitLists();
        if (targets.Count > 1)
            System.Windows.MessageBox.Show($"Đã khôi phục {restoredCount}/{targets.Count} tệp đã chọn.", "BaroAntivirus");
    }

    private void BtnDeleteQuarantine_Click(object sender, RoutedEventArgs e)
    {
        var targets = GetCheckedOrSelected(
            GridQuarantine.ItemsSource as IEnumerable<SelectableItem<QuarantineEntry>>,
            GridQuarantine,
            x => x.IsSelected);
        if (targets.Count == 0) return;

        if (targets.Count > 1 && System.Windows.MessageBox.Show(
                $"Bạn chắc chắn muốn xóa vĩnh viễn {targets.Count} tệp đã chọn khỏi Khu Cách Ly?",
                "Xác nhận xóa hàng loạt", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        int deleted = 0;
        foreach (var t in targets)
        {
            if (_app.QuarantineService.DeleteEntryPermanently(t.Item.Id))
                deleted++;
        }
        RefreshQuarantineGrid();
        if (targets.Count > 1)
            System.Windows.MessageBox.Show($"Đã xóa vĩnh viễn {deleted} tệp đã chọn.", "BaroAntivirus");
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
        ListProtectedFolders.ItemsSource = _app.Settings.ProtectedFolders
            .Select(f => new SelectableItem<string>(f))
            .ToList();
        ListExclusions.ItemsSource = _app.Settings.ExcludedPaths
            .Concat(_app.Settings.ExcludedHashes)
            .Select(x => new SelectableItem<string>(x))
            .ToList();
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
        var items = (ListProtectedFolders.ItemsSource as IEnumerable<SelectableItem<string>>)?.ToList();
        var targets = items?.Where(x => x.IsSelected).Select(x => x.Item).ToList() ?? new List<string>();
        if (targets.Count == 0)
            targets = ListProtectedFolders.SelectedItems.OfType<SelectableItem<string>>().Select(x => x.Item).ToList();
        if (targets.Count == 0) return;

        foreach (string folder in targets)
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
        var items = (ListExclusions.ItemsSource as IEnumerable<SelectableItem<string>>)?.ToList();
        var targets = items?.Where(x => x.IsSelected).Select(x => x.Item).ToList() ?? new List<string>();
        if (targets.Count == 0)
            targets = ListExclusions.SelectedItems.OfType<SelectableItem<string>>().Select(x => x.Item).ToList();
        if (targets.Count == 0) return;

        foreach (string ex in targets)
        {
            _app.Settings.ExcludedPaths.Remove(ex);
            _app.Settings.ExcludedHashes.Remove(ex);
        }
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
