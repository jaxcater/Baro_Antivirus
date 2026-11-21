using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Services;

public sealed class NetworkMonitorService
{
    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    private static readonly HashSet<int> SuspiciousPorts = new()
    {
        4444, 5555, 1337, 6666, 6667, 31337, 9001, 9050, 14444, 3333, 12345, 27374
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public int owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        int tblClass,
        uint reserved = 0);

    public IReadOnlyList<NetworkConnectionInfo> GetActiveTcpConnections()
    {
        var list = new List<NetworkConnectionInfo>();
        var pidMap = BuildPidInfoMap();

        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        if (bufferSize <= 0) return list;

        IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint ret = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
            if (ret != 0) return list;

            int rowCount = Marshal.ReadInt32(tcpTablePtr);
            IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                string localIp = new IPAddress(row.localAddr).ToString();
                int localPort = (ushort)IPAddress.NetworkToHostOrder((short)(row.localPort & 0xFFFF));
                string remoteIp = new IPAddress(row.remoteAddr).ToString();
                int remotePort = (ushort)IPAddress.NetworkToHostOrder((short)(row.remotePort & 0xFFFF));
                string state = ((TcpState)row.state).ToString();

                pidMap.TryGetValue(row.owningPid, out var pInfo);
                string procName = pInfo.Name ?? $"PID:{row.owningPid}";
                string exePath = pInfo.Path ?? string.Empty;

                bool suspicious = false;
                string reason = string.Empty;

                if (remotePort > 0 && SuspiciousPorts.Contains(remotePort))
                {
                    suspicious = true;
                    reason = $"Kết nối tới cổng thường gặp của Backdoor/C2/Miner (Port {remotePort}).";
                }
                else if (!string.IsNullOrEmpty(exePath) &&
                         (exePath.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                          exePath.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase)) &&
                         remoteIp != "0.0.0.0" && remoteIp != "127.0.0.1")
                {
                    suspicious = true;
                    reason = "Tiến trình chạy từ Temp/Downloads đang mở kết nối mạng ra ngoài.";
                }

                list.Add(new NetworkConnectionInfo
                {
                    Protocol = "TCP",
                    LocalEndpoint = $"{localIp}:{localPort}",
                    RemoteAddress = remoteIp,
                    RemotePort = remotePort,
                    State = state,
                    Pid = row.owningPid,
                    ProcessName = procName,
                    ExecutablePath = exePath,
                    IsSuspicious = suspicious,
                    Reason = reason
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(tcpTablePtr);
        }

        return list.OrderByDescending(c => c.IsSuspicious).ThenBy(c => c.ProcessName).ToList();
    }

    public static (bool Success, string Message) ApplyHostsMaliciousDomainBlock(bool enable, IEnumerable<string> customDomains)
    {
        const string startMarker = "# >>> BaroAntivirus Malicious Domain Shield START";
        const string endMarker = "# <<< BaroAntivirus Malicious Domain Shield END";

        string hostsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"drivers\etc\hosts");

        try
        {
            string existing = File.Exists(hostsPath) ? File.ReadAllText(hostsPath) : string.Empty;
            var lines = existing.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None).ToList();

            int startIdx = lines.FindIndex(l => l.Trim() == startMarker);
            int endIdx = lines.FindIndex(l => l.Trim() == endMarker);
            if (startIdx >= 0 && endIdx >= startIdx)
            {
                lines.RemoveRange(startIdx, endIdx - startIdx + 1);
            }

            if (enable)
            {
                var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "malware.wicar.org",
                    "login-verify-microsoft-security.xyz",
                    "vietcombank-xacthuc-24h.top",
                    "mbbank-quatang-online.click",
                    "discord-nitro-free-gift.ru",
                    "paypal-resolution-center.tk"
                };
                foreach (string d in customDomains)
                {
                    if (!string.IsNullOrWhiteSpace(d)) domains.Add(d.Trim().ToLowerInvariant());
                }

                lines.Add(startMarker);
                foreach (string d in domains)
                {
                    lines.Add($"0.0.0.0 {d}");
                }
                lines.Add(endMarker);
            }

            File.WriteAllLines(hostsPath, lines);
            return (true, enable ? "Đã bật lá chắn chặn tên miền độc hại cấp hệ thống (hosts)." : "Đã gỡ cấu hình chặn trong tệp hosts.");
        }
        catch (UnauthorizedAccessException)
        {
            return (false, "Cần chạy BaroAntivirus với quyền Administrator để cập nhật lá chắn tệp hosts Windows.");
        }
        catch (Exception ex)
        {
            return (false, $"Không thể cập nhật hosts: {ex.Message}");
        }
    }

    private static Dictionary<int, (string Name, string Path)> BuildPidInfoMap()
    {
        var map = new Dictionary<int, (string, string)>();
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                map[proc.Id] = (proc.ProcessName, ProcessMonitorService.GetProcessPathSafe(proc));
            }
            catch { }
            finally
            {
                proc.Dispose();
            }
        }
        return map;
    }
}
