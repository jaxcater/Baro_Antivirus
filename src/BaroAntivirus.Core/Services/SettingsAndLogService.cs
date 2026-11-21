using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Win32;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Services;

public sealed class SettingsAndLogService
{
    private const string RunRegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string AppRegistryName = "BaroAntivirus";
    private const int MaxInMemoryLogs = 500;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private readonly string _dataDir;
    private readonly string _settingsPath;
    private readonly string _logPath;
    private readonly string _customSigPath;
    private readonly ConcurrentQueue<SecurityLogEntry> _recentLogs = new();
    private readonly object _fileLock = new();

    public SettingsAndLogService(string? customDataDir = null)
    {
        _dataDir = customDataDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BaroAntivirus");

        Directory.CreateDirectory(_dataDir);
        _settingsPath = Path.Combine(_dataDir, "settings.json");
        _logPath = Path.Combine(_dataDir, "audit_logs.jsonl");
        _customSigPath = Path.Combine(_dataDir, "custom_signatures.json");
        LoadRecentLogs();
    }

    public string DataDirectory => _dataDir;
    public string CustomSignaturesPath => _customSigPath;

    public event Action<SecurityLogEntry>? LogAdded;

    public AppSettings LoadSettings()
    {
        try
        {
            if (File.Exists(_settingsPath))
            {
                string json = File.ReadAllText(_settingsPath);
                var loaded = JsonSerializer.Deserialize<AppSettings>(json, JsonOpts);
                if (loaded != null)
                {
                    EnsureDefaultProtectedFolders(loaded);
                    return loaded;
                }
            }
        }
        catch
        {
            // Fallback to defaults
        }

        var defaults = new AppSettings();
        EnsureDefaultProtectedFolders(defaults);
        SaveSettings(defaults);
        return defaults;
    }

    public void SaveSettings(AppSettings settings)
    {
        lock (_fileLock)
        {
            string json = JsonSerializer.Serialize(settings, JsonOpts);
            File.WriteAllText(_settingsPath, json);
        }
    }

    public bool SyncWindowsStartup(bool enable, string? executablePath = null)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunRegistryPath, writable: true)
                            ?? Registry.CurrentUser.CreateSubKey(RunRegistryPath, writable: true);
            if (key == null) return false;

            if (enable)
            {
                string exe = executablePath ?? Environment.ProcessPath ?? string.Empty;
                if (string.IsNullOrWhiteSpace(exe)) return false;
                key.SetValue(AppRegistryName, $"\"{exe}\" --minimized", RegistryValueKind.String);
            }
            else
            {
                key.DeleteValue(AppRegistryName, throwOnMissingValue: false);
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    public bool IsWindowsStartupEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunRegistryPath, writable: false);
            return key?.GetValue(AppRegistryName) != null;
        }
        catch
        {
            return false;
        }
    }

    public void Log(SecurityLogLevel level, string module, string message, string? details = null)
    {
        var entry = new SecurityLogEntry
        {
            Timestamp = DateTimeOffset.Now,
            Level = level,
            Module = module,
            Message = message,
            Details = details
        };

        _recentLogs.Enqueue(entry);
        while (_recentLogs.Count > MaxInMemoryLogs)
        {
            _recentLogs.TryDequeue(out _);
        }

        try
        {
            string line = JsonSerializer.Serialize(entry) + Environment.NewLine;
            lock (_fileLock)
            {
                // Rotate log if over 5 MB so disk & startup stay lean
                if (File.Exists(_logPath) && new FileInfo(_logPath).Length > 5 * 1024 * 1024)
                {
                    string backup = _logPath + ".old";
                    if (File.Exists(backup)) File.Delete(backup);
                    File.Move(_logPath, backup);
                }
                File.AppendAllText(_logPath, line);
            }
        }
        catch
        {
            // Do not crash app on log write contention
        }

        LogAdded?.Invoke(entry);
    }

    public IReadOnlyList<SecurityLogEntry> GetRecentLogs() => _recentLogs.Reverse().ToList();

    public void ExportLogs(string destinationPath)
    {
        var logs = GetRecentLogs();
        string json = JsonSerializer.Serialize(logs, JsonOpts);
        File.WriteAllText(destinationPath, json);
    }

    private void LoadRecentLogs()
    {
        try
        {
            if (!File.Exists(_logPath)) return;
            var lines = File.ReadLines(_logPath).TakeLast(MaxInMemoryLogs);
            foreach (string line in lines)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var item = JsonSerializer.Deserialize<SecurityLogEntry>(line);
                if (item != null) _recentLogs.Enqueue(item);
            }
        }
        catch
        {
            // Ignore corrupt tail
        }
    }

    private static void EnsureDefaultProtectedFolders(AppSettings settings)
    {
        if (settings.ProtectedFolders.Count > 0) return;
        string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string pics = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
        foreach (string dir in new[] { docs, desktop, pics })
        {
            if (!string.IsNullOrWhiteSpace(dir) && Directory.Exists(dir))
                settings.ProtectedFolders.Add(dir);
        }
    }
}
