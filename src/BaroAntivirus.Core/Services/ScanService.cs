using System.Collections.Concurrent;
using System.Diagnostics;
using BaroAntivirus.Core.Detection;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Services;

public sealed class ScanService
{
    private readonly ThreatDetectionEngine _engine;
    private readonly SettingsAndLogService _logs;
    private volatile bool _isPaused;

    private static readonly HashSet<string> QuickScanPriorityExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".hta", ".msi", ".lnk", ".url", ".zip", ".html", ".htm", ".py", ".cpl", ".com"
    };

    public ScanService(ThreatDetectionEngine engine, SettingsAndLogService logs)
    {
        _engine = engine;
        _logs = logs;
    }

    public bool IsPaused
    {
        get => _isPaused;
        set => _isPaused = value;
    }

    public async Task<ScanResult> RunScanAsync(
        ScanMode mode,
        AppSettings settings,
        IEnumerable<string>? customPaths = null,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        _isPaused = false;
        var started = DateTimeOffset.UtcNow;
        var sw = Stopwatch.StartNew();

        var roots = ResolveRoots(mode, customPaths);
        var findings = new ConcurrentBag<ThreatFinding>();

        long scanned = 0;
        long skipped = 0;
        long bytes = 0;
        string currentFile = string.Empty;

        int maxConcurrency = mode == ScanMode.DeepScan
            ? Math.Clamp(settings.MaxDeepScanConcurrency, 1, Math.Max(2, Environment.ProcessorCount / 2))
            : Math.Clamp(settings.MaxDeepScanConcurrency, 1, 3);

        long maxFileBytes = (long)Math.Max(16, settings.DeepScanMaxFileSizeMb) * 1024L * 1024L;
        bool inspectArchives = mode == ScanMode.DeepScan || mode == ScanMode.Custom || mode == ScanMode.Usb;
        string baroDataDir = _logs.DataDirectory;

        _logs.Log(SecurityLogLevel.Info, "Scanner", $"Bắt đầu quét chế độ {mode} (Mức độ: {settings.Strictness}, Luồng nhẹ: {maxConcurrency}).");

        // Enumerate lazily to keep RAM near zero even on huge drives
        IEnumerable<string> EnumerateAllTargets()
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (mode == ScanMode.Quick)
            {
                // Include running process executables in Quick Scan
                foreach (var proc in Process.GetProcesses())
                {
                    string? pPath = null;
                    try { pPath = proc.MainModule?.FileName; } catch { }
                    finally { proc.Dispose(); }

                    if (!string.IsNullOrWhiteSpace(pPath) && File.Exists(pPath) && seen.Add(pPath))
                        yield return pPath;
                }
            }

            foreach (string root in roots)
            {
                if (File.Exists(root))
                {
                    if (seen.Add(root)) yield return root;
                    continue;
                }

                if (!Directory.Exists(root)) continue;

                foreach (string file in SafeEnumerateFiles(root, baroDataDir, mode))
                {
                    if (seen.Add(file)) yield return file;
                }
            }
        }

        using var semaphore = new SemaphoreSlim(maxConcurrency);
        var activeTasks = new List<Task>();

        await Task.Run(async () =>
        {
            Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
            var lastProgressReport = DateTime.UtcNow;

            foreach (string filePath in EnumerateAllTargets())
            {
                if (ct.IsCancellationRequested) break;

                while (_isPaused && !ct.IsCancellationRequested)
                {
                    progress?.Report(new ScanProgress
                    {
                        FilesScanned = Interlocked.Read(ref scanned),
                        ThreatsFound = findings.Count,
                        SkippedFiles = Interlocked.Read(ref skipped),
                        BytesScanned = Interlocked.Read(ref bytes),
                        CurrentFile = currentFile,
                        FilesPerSecond = sw.Elapsed.TotalSeconds > 0 ? scanned / sw.Elapsed.TotalSeconds : 0,
                        Elapsed = sw.Elapsed,
                        IsPaused = true,
                        Mode = mode
                    });
                    await Task.Delay(200, ct).ConfigureAwait(false);
                }

                await semaphore.WaitAsync(ct).ConfigureAwait(false);

                var task = Task.Run(() =>
                {
                    Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
                    try
                    {
                        currentFile = filePath;
                        var fi = new FileInfo(filePath);
                        if (!fi.Exists || fi.Length == 0 || (mode != ScanMode.DeepScan && fi.Length > 64 * 1024 * 1024) || fi.Length > maxFileBytes)
                        {
                            Interlocked.Increment(ref skipped);
                            return;
                        }

                        if (mode == ScanMode.Quick)
                        {
                            string ext = fi.Extension;
                            if (!QuickScanPriorityExtensions.Contains(ext) && fi.Length > 4 * 1024 * 1024)
                            {
                                Interlocked.Increment(ref skipped);
                                return;
                            }
                        }

                        var hit = _engine.InspectFile(
                            filePath,
                            settings.Strictness,
                            inspectArchives,
                            settings.ExcludedPaths,
                            settings.ExcludedHashes);

                        if (hit != null)
                        {
                            findings.Add(hit);
                            _logs.Log(SecurityLogLevel.Alert, "Scanner",
                                $"Phát hiện mối nguy [{hit.ThreatName}] tại {hit.FilePath} (Điểm rủi ro: {hit.RiskScore}/100)");
                        }

                        Interlocked.Add(ref bytes, fi.Length);
                        Interlocked.Increment(ref scanned);
                    }
                    catch
                    {
                        Interlocked.Increment(ref skipped);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, ct);

                activeTasks.Add(task);
                if (activeTasks.Count > 64)
                {
                    activeTasks.RemoveAll(t => t.IsCompleted);
                }

                if ((DateTime.UtcNow - lastProgressReport).TotalMilliseconds >= 150)
                {
                    lastProgressReport = DateTime.UtcNow;
                    long s = Interlocked.Read(ref scanned);
                    progress?.Report(new ScanProgress
                    {
                        FilesScanned = s,
                        ThreatsFound = findings.Count,
                        SkippedFiles = Interlocked.Read(ref skipped),
                        BytesScanned = Interlocked.Read(ref bytes),
                        CurrentFile = currentFile,
                        FilesPerSecond = sw.Elapsed.TotalSeconds > 0.1 ? Math.Round(s / sw.Elapsed.TotalSeconds, 1) : 0,
                        Elapsed = sw.Elapsed,
                        IsPaused = _isPaused,
                        Mode = mode
                    });
                }
            }

            try
            {
                await Task.WhenAll(activeTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
        }, CancellationToken.None).ConfigureAwait(false);

        sw.Stop();
        var resultList = findings.OrderByDescending(f => f.RiskScore).ToList();

        progress?.Report(new ScanProgress
        {
            FilesScanned = scanned,
            ThreatsFound = resultList.Count,
            SkippedFiles = skipped,
            BytesScanned = bytes,
            CurrentFile = "Hoàn tất",
            FilesPerSecond = sw.Elapsed.TotalSeconds > 0.1 ? Math.Round(scanned / sw.Elapsed.TotalSeconds, 1) : 0,
            Elapsed = sw.Elapsed,
            IsPaused = false,
            Mode = mode
        });

        _logs.Log(SecurityLogLevel.Info, "Scanner",
            $"Kết thúc quét {mode}: {scanned:N0} tệp đã quét, {resultList.Count} mối nguy, thời gian {sw.Elapsed:mm\\:ss}.");

        return new ScanResult
        {
            Mode = mode,
            Strictness = settings.Strictness,
            StartedAt = started,
            CompletedAt = DateTimeOffset.UtcNow,
            Cancelled = ct.IsCancellationRequested,
            FilesScanned = scanned,
            SkippedFiles = skipped,
            BytesScanned = bytes,
            Findings = resultList
        };
    }

    private static List<string> ResolveRoots(ScanMode mode, IEnumerable<string>? customPaths)
    {
        if (customPaths != null)
        {
            var list = customPaths.Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (list.Count > 0) return list;
        }

        if (mode == ScanMode.DeepScan)
        {
            return DriveInfo.GetDrives()
                .Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable))
                .Select(d => d.RootDirectory.FullName)
                .ToList();
        }

        // Quick scan locations: Downloads, Desktop, Documents, Temp, Startup
        var quickDirs = new List<string>
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        };

        return quickDirs.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static IEnumerable<string> SafeEnumerateFiles(string rootDir, string baroDataDir, ScanMode mode)
    {
        var stack = new Stack<string>();
        stack.Push(rootDir);

        while (stack.Count > 0)
        {
            string current = stack.Pop();
            if (current.StartsWith(baroDataDir, StringComparison.OrdinalIgnoreCase))
                continue;

            string name = Path.GetFileName(current);
            if (mode == ScanMode.DeepScan &&
                (name.Equals("WinSxS", StringComparison.OrdinalIgnoreCase) ||
                 name.Equals("$Recycle.Bin", StringComparison.OrdinalIgnoreCase) ||
                 name.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            string[] files;
            try
            {
                files = Directory.GetFiles(current);
            }
            catch
            {
                continue;
            }

            foreach (string f in files)
                yield return f;

            string[] subDirs;
            try
            {
                subDirs = Directory.GetDirectories(current);
            }
            catch
            {
                continue;
            }

            foreach (string sub in subDirs)
            {
                try
                {
                    var attrs = File.GetAttributes(sub);
                    if ((attrs & FileAttributes.ReparsePoint) != 0) continue; // Avoid symlink cycles
                    stack.Push(sub);
                }
                catch { }
            }
        }
    }
}
