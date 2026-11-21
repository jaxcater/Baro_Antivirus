using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Windows;
using Microsoft.Win32;
using WinForms = System.Windows.Forms;

namespace BaroAntivirus.Setup;

public partial class SetupWindow : Window
{
    private const string AppName = "BaroAntivirus";
    private const string UninstallRegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BaroAntivirus";
    private const string RunRegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

    private readonly bool _isUninstall;
    private readonly bool _isSilent;
    private bool _finished;

    public SetupWindow(bool isUninstall, bool isSilent)
    {
        _isUninstall = isUninstall;
        _isSilent = isSilent;
        InitializeComponent();

        string defaultDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs",
            AppName);

        if (_isUninstall)
        {
            string? existing = ReadExistingInstallDir();
            TxtInstallDir.Text = existing ?? defaultDir;
            Title = "Gỡ cài đặt BaroAntivirus";
            TxtTitle.Text = "Gỡ cài đặt BaroAntivirus";
            TxtSub.Text = "Xóa chương trình khỏi hệ thống";
            PanelInstallOptions.Visibility = Visibility.Collapsed;
            PanelUninstallInfo.Visibility = Visibility.Visible;
            BtnPrimary.Content = "Gỡ cài đặt";
            BtnPrimary.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(196, 36, 42));
        }
        else
        {
            TxtInstallDir.Text = ReadExistingInstallDir() ?? defaultDir;
        }
    }

    public async Task RunSilentAsync()
    {
        if (_isUninstall)
            await PerformUninstallAsync(TxtInstallDir.Text.Trim());
        else
            await PerformInstallAsync(TxtInstallDir.Text.Trim(), desktop: true, startMenu: true, startup: true, launch: false);

        System.Windows.Application.Current.Shutdown();
    }

    private void BtnBrowse_Click(object sender, RoutedEventArgs e)
    {
        using var dlg = new WinForms.FolderBrowserDialog
        {
            SelectedPath = TxtInstallDir.Text,
            Description = "Chọn thư mục cài đặt BaroAntivirus"
        };
        if (dlg.ShowDialog() == WinForms.DialogResult.OK && !string.IsNullOrWhiteSpace(dlg.SelectedPath))
        {
            string chosen = dlg.SelectedPath;
            if (!chosen.EndsWith(AppName, StringComparison.OrdinalIgnoreCase))
                chosen = Path.Combine(chosen, AppName);
            TxtInstallDir.Text = chosen;
        }
    }

    private void BtnCancel_Click(object sender, RoutedEventArgs e) => Close();

    private async void BtnPrimary_Click(object sender, RoutedEventArgs e)
    {
        if (_finished)
        {
            Close();
            return;
        }

        BtnPrimary.IsEnabled = false;
        BtnCancel.IsEnabled = false;
        BtnBrowse.IsEnabled = false;
        ProgInstall.Visibility = Visibility.Visible;
        TxtStatus.Visibility = Visibility.Visible;

        if (_isUninstall)
        {
            await PerformUninstallAsync(TxtInstallDir.Text.Trim());
        }
        else
        {
            await PerformInstallAsync(
                TxtInstallDir.Text.Trim(),
                ChkDesktopShortcut.IsChecked == true,
                ChkStartMenuShortcut.IsChecked == true,
                ChkAutoStartup.IsChecked == true,
                ChkLaunchAfter.IsChecked == true);
        }
    }

    private async Task PerformInstallAsync(string installDir, bool desktop, bool startMenu, bool startup, bool launch)
    {
        try
        {
            SetStatus("Đang dừng phiên bản BaroAntivirus đang chạy...", 10);
            StopRunningAppInstances();
            await Task.Delay(300);

            Directory.CreateDirectory(installDir);

            SetStatus("Đang sao chép nền tảng .NET 9 dùng chung...", 20);
            CopySharedRuntimeFiles(installDir);

            SetStatus("Đang giải nén các thành phần BaroAntivirus...", 45);
            using var payloadStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("BaroPayload.zip")
                ?? throw new InvalidOperationException("Không tìm thấy gói cài đặt nhúng BaroPayload.zip.");

            using (var archive = new ZipArchive(payloadStream, ZipArchiveMode.Read))
            {
                int total = Math.Max(1, archive.Entries.Count);
                int done = 0;
                foreach (var entry in archive.Entries)
                {
                    string destPath = Path.GetFullPath(Path.Combine(installDir, entry.FullName));
                    if (!destPath.StartsWith(Path.GetFullPath(installDir), StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (string.IsNullOrEmpty(entry.Name))
                    {
                        Directory.CreateDirectory(destPath);
                    }
                    else
                    {
                        Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
                        entry.ExtractToFile(destPath, overwrite: true);
                    }

                    done++;
                    if (done % 5 == 0 || done == total)
                    {
                        int pct = 45 + (int)(35.0 * done / total);
                        SetStatus($"Đang cài đặt ({done}/{total} tệp)...", pct);
                    }
                }
            }

            string exePath = Path.Combine(installDir, "BaroAntivirus.exe");
            string uninstallerPath = Path.Combine(installDir, "Baro_uninstall.exe");
            string? selfExe = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(selfExe) && File.Exists(selfExe) &&
                !selfExe.Equals(uninstallerPath, StringComparison.OrdinalIgnoreCase))
            {
                File.Copy(selfExe, uninstallerPath, overwrite: true);
            }

            SetStatus("Đang tạo lối tắt và đăng ký Windows...", 88);

            if (desktop)
            {
                string desktopLnk = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "BaroAntivirus.lnk");
                CreateShortcut(desktopLnk, exePath, installDir, "BaroAntivirus — Bảo vệ Real-time & DeepScan");
            }

            if (startMenu)
            {
                string smDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), AppName);
                Directory.CreateDirectory(smDir);
                CreateShortcut(Path.Combine(smDir, "BaroAntivirus.lnk"), exePath, installDir, "BaroAntivirus");
                CreateShortcut(Path.Combine(smDir, "Gỡ cài đặt BaroAntivirus.lnk"), uninstallerPath, installDir, "Gỡ cài đặt BaroAntivirus", "--uninstall");
            }

            RegisterUninstallEntry(installDir, exePath, uninstallerPath);
            SetStartupRegistry(startup, exePath);

            SetStatus("Cài đặt hoàn tất!", 100);
            _finished = true;
            BtnPrimary.Content = "Hoàn tất";
            BtnPrimary.IsEnabled = true;

            if (launch && File.Exists(exePath))
            {
                Process.Start(new ProcessStartInfo(exePath) { UseShellExecute = true, WorkingDirectory = installDir });
            }

            if (!_isSilent)
            {
                Close();
            }
        }
        catch (Exception ex)
        {
            SetStatus($"Lỗi cài đặt: {ex.Message}", 0);
            BtnPrimary.IsEnabled = true;
            BtnCancel.IsEnabled = true;
            if (!_isSilent)
            {
                System.Windows.MessageBox.Show($"Không thể hoàn tất cài đặt:\n{ex.Message}", "BaroAntivirus Setup", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private async Task PerformUninstallAsync(string installDir)
    {
        try
        {
            SetStatus("Đang dừng BaroAntivirus...", 20);
            StopRunningAppInstances();
            await Task.Delay(300);

            SetStatus("Đang xóa lối tắt & khóa Registry...", 50);
            string desktopLnk = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "BaroAntivirus.lnk");
            if (File.Exists(desktopLnk)) File.Delete(desktopLnk);

            string smDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), AppName);
            if (Directory.Exists(smDir)) Directory.Delete(smDir, recursive: true);

            SetStartupRegistry(false, string.Empty);
            Registry.CurrentUser.DeleteSubKeyTree(UninstallRegPath, throwOnMissingSubKey: false);

            SetStatus("Đang dọn tệp cài đặt...", 85);
            if (Directory.Exists(installDir))
            {
                string? selfExe = Environment.ProcessPath;
                foreach (string file in Directory.GetFiles(installDir, "*", SearchOption.AllDirectories))
                {
                    if (!string.IsNullOrEmpty(selfExe) && file.Equals(selfExe, StringComparison.OrdinalIgnoreCase))
                        continue;
                    try { File.Delete(file); } catch { }
                }

                // Schedule cleanup of uninstaller itself after process exits
                if (!string.IsNullOrEmpty(selfExe) && selfExe.StartsWith(installDir, StringComparison.OrdinalIgnoreCase))
                {
                    Process.Start(new ProcessStartInfo("cmd.exe", $"/c timeout /t 2 /nobreak >nul & rmdir /s /q \"{installDir}\"")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false
                    });
                }
            }

            SetStatus("Đã gỡ cài đặt BaroAntivirus thành công.", 100);
            _finished = true;
            BtnPrimary.Content = "Đóng";
            BtnPrimary.IsEnabled = true;
        }
        catch (Exception ex)
        {
            SetStatus($"Lỗi gỡ cài đặt: {ex.Message}", 0);
            BtnPrimary.IsEnabled = true;
            BtnCancel.IsEnabled = true;
        }
    }

    private void SetStatus(string text, int percent)
    {
        if (_isSilent) return;
        TxtStatus.Text = text;
        ProgInstall.Value = percent;
    }

    private static void CopySharedRuntimeFiles(string installDir)
    {
        string baseDir = Path.GetFullPath(AppContext.BaseDirectory);
        if (!Directory.Exists(baseDir)) return;

        foreach (string srcFile in Directory.EnumerateFiles(baseDir, "*", SearchOption.AllDirectories))
        {
            string fileName = Path.GetFileName(srcFile);
            if (fileName.StartsWith("Baro_setup", StringComparison.OrdinalIgnoreCase) ||
                fileName.Equals("createdump.exe", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string relPath = Path.GetRelativePath(baseDir, srcFile);
            string destPath = Path.GetFullPath(Path.Combine(installDir, relPath));
            if (!destPath.StartsWith(Path.GetFullPath(installDir), StringComparison.OrdinalIgnoreCase))
                continue;

            Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
            File.Copy(srcFile, destPath, overwrite: true);
        }
    }

    private static void StopRunningAppInstances()
    {
        foreach (var p in Process.GetProcessesByName("BaroAntivirus"))
        {
            try
            {
                p.Kill(entireProcessTree: true);
                p.WaitForExit(2000);
            }
            catch { }
            finally { p.Dispose(); }
        }
    }

    private static string? ReadExistingInstallDir()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(UninstallRegPath);
            return key?.GetValue("InstallLocation")?.ToString();
        }
        catch { return null; }
    }

    private static void RegisterUninstallEntry(string installDir, string exePath, string uninstallerPath)
    {
        using var key = Registry.CurrentUser.CreateSubKey(UninstallRegPath, writable: true);
        if (key == null) return;
        key.SetValue("DisplayName", "BaroAntivirus");
        key.SetValue("DisplayVersion", "1.1.0");
        key.SetValue("Publisher", "BaroSecurity");
        key.SetValue("DisplayIcon", exePath);
        key.SetValue("InstallLocation", installDir);
        key.SetValue("UninstallString", $"\"{uninstallerPath}\" --uninstall");
        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
        key.SetValue("EstimatedSize", 65000, RegistryValueKind.DWord);
    }

    private static void SetStartupRegistry(bool enable, string exePath)
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunRegPath, writable: true)
                        ?? Registry.CurrentUser.CreateSubKey(RunRegPath, writable: true);
        if (key == null) return;
        if (enable && !string.IsNullOrWhiteSpace(exePath))
            key.SetValue("BaroAntivirus", $"\"{exePath}\" --minimized", RegistryValueKind.String);
        else
            key.DeleteValue("BaroAntivirus", throwOnMissingValue: false);
    }

    private static void CreateShortcut(string shortcutPath, string targetPath, string workingDir, string description, string arguments = "")
    {
        Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType == null) return;
        dynamic shell = Activator.CreateInstance(shellType)!;
        dynamic shortcut = shell.CreateShortcut(shortcutPath);
        shortcut.TargetPath = targetPath;
        shortcut.WorkingDirectory = workingDir;
        shortcut.Description = description;
        shortcut.Arguments = arguments;
        shortcut.IconLocation = targetPath;
        shortcut.Save();
    }
}
