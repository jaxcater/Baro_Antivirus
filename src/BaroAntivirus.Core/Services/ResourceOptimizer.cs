using System.Diagnostics;
using System.Runtime.InteropServices;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Services;

public sealed class ResourceOptimizer
{
    private DateTime _lastCheckUtc = DateTime.UtcNow;
    private TimeSpan _lastCpuTime = Process.GetCurrentProcess().TotalProcessorTime;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessWorkingSetSizeEx(
        IntPtr hProcess,
        IntPtr dwMinimumWorkingSetSize,
        IntPtr dwMaximumWorkingSetSize,
        uint flags);

    public ResourceMetrics SampleSelfMetrics()
    {
        var proc = Process.GetCurrentProcess();
        proc.Refresh();

        DateTime now = DateTime.UtcNow;
        TimeSpan cpuNow = proc.TotalProcessorTime;
        double elapsedMs = (now - _lastCheckUtc).TotalMilliseconds;
        double cpuUsedMs = (cpuNow - _lastCpuTime).TotalMilliseconds;

        double cpuPercent = 0;
        if (elapsedMs > 50)
        {
            cpuPercent = Math.Clamp((cpuUsedMs / (elapsedMs * Environment.ProcessorCount)) * 100.0, 0.0, 100.0);
        }

        _lastCheckUtc = now;
        _lastCpuTime = cpuNow;

        return new ResourceMetrics
        {
            WorkingSetMB = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 1),
            PrivateMemoryMB = Math.Round(proc.PrivateMemorySize64 / (1024.0 * 1024.0), 1),
            CpuPercent = Math.Round(cpuPercent, 2),
            ThreadCount = proc.Threads.Count
        };
    }

    public static void TrimBackgroundMemory()
    {
        try
        {
            GC.Collect(2, GCCollectionMode.Optimized, blocking: false, compacting: true);
            GC.WaitForPendingFinalizers();
            using var proc = Process.GetCurrentProcess();
            SetProcessWorkingSetSizeEx(proc.Handle, new IntPtr(-1), new IntPtr(-1), 0);
        }
        catch
        {
            // Best-effort memory trim
        }
    }
}
