using System.Text;

namespace BaroAntivirus.Core.Detection;

public sealed class PeAnalysisResult
{
    public bool IsValidPe { get; init; }
    public bool Is64Bit { get; init; }
    public bool IsDll { get; init; }
    public bool IsDotNet { get; init; }
    public int SectionCount { get; init; }
    public double MaxSectionEntropy { get; init; }
    public bool HasRwxSection { get; init; }
    public bool HasPackerSection { get; init; }
    public string? DetectedPacker { get; init; }
    public string? DetectedRatFamily { get; init; }
    public bool HasMalformedHeaders { get; init; }
    public long OverlaySizeBytes { get; init; }
    public double OverlayEntropy { get; init; }
    public HashSet<string> SuspiciousApis { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public int RiskScore { get; init; }
    public List<string> Reasons { get; init; } = new();
}

internal readonly record struct PeSectionInfo(
    string Name,
    uint VirtualSize,
    uint VirtualAddress,
    uint RawSize,
    uint RawPointer,
    uint Characteristics,
    double Entropy);

public static class PeAnalyzer
{
    private static readonly string[] PackerSectionPrefixes =
    {
        ".upx", "upx0", "upx1", "upx2", ".vmp", "vmp0", "vmp1",
        ".themida", ".enigma", ".aspack", ".adata", ".mpress", ".petite", ".nsp", ".packed"
    };

    private static readonly HashSet<string> TrackedApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "NtWriteVirtualMemory", "CreateRemoteThread", "NtCreateThreadEx",
        "QueueUserAPC", "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext",
        "ResumeThread", "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
        "CallNextHookEx", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
        "GetForegroundWindow", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "AdjustTokenPrivileges", "OpenProcessToken",
        "CryptEncrypt", "BCryptEncrypt", "CryptUnprotectData",
        "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
        "WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW", "CreateProcessInternalW",
        "capCreateCaptureWindow", "capCreateCaptureWindowA", "capCreateCaptureWindowW"
    };

    private static string T(params string[] parts) => string.Concat(parts);

    private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    private const uint IMAGE_SCN_MEM_WRITE = 0x80000000;

    public static PeAnalysisResult Analyze(string filePath)
    {
        var reasons = new List<string>();
        var suspiciousApis = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int score = 0;

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length < 128)
                return new PeAnalysisResult { IsValidPe = false };

            using var br = new BinaryReader(fs, Encoding.ASCII, leaveOpen: true);

            ushort dosMagic = br.ReadUInt16();
            if (dosMagic != 0x5A4D) // "MZ"
                return new PeAnalysisResult { IsValidPe = false };

            fs.Seek(0x3C, SeekOrigin.Begin);
            int eLfanew = br.ReadInt32();
            if (eLfanew < 64 || eLfanew > fs.Length - 260)
            {
                return new PeAnalysisResult
                {
                    IsValidPe = false,
                    HasMalformedHeaders = true,
                    RiskScore = 35,
                    Reasons = new List<string> { "Cấu trúc PE header bị biến dạng (e_lfanew bất thường)." }
                };
            }

            fs.Seek(eLfanew, SeekOrigin.Begin);
            uint peSig = br.ReadUInt32();
            if (peSig != 0x00004550) // "PE\0\0"
                return new PeAnalysisResult { IsValidPe = false };

            // IMAGE_FILE_HEADER (20 bytes)
            br.ReadUInt16(); // Machine
            ushort numberOfSections = br.ReadUInt16();
            br.ReadUInt32(); // TimeDateStamp
            br.ReadUInt32(); // PointerToSymbolTable
            br.ReadUInt32(); // NumberOfSymbols
            ushort sizeOfOptionalHeader = br.ReadUInt16();
            ushort characteristics = br.ReadUInt16();

            bool isDll = (characteristics & 0x2000) != 0;
            if (numberOfSections == 0 || numberOfSections > 96)
            {
                score += 35;
                reasons.Add($"Số lượng section PE bất thường ({numberOfSections}).");
            }

            long optionalStart = fs.Position;
            ushort optMagic = br.ReadUInt16();
            bool is64 = optMagic == 0x020B;
            if (optMagic != 0x010B && optMagic != 0x020B)
            {
                return new PeAnalysisResult
                {
                    IsValidPe = false,
                    HasMalformedHeaders = true,
                    RiskScore = 30,
                    Reasons = new List<string> { "OptionalHeader magic không hợp lệ." }
                };
            }

            // Read Import Directory RVA & Size + CLR Runtime Header RVA & Size
            uint importDirRva = 0;
            uint importDirSize = 0;
            uint clrDirRva = 0;
            uint clrDirSize = 0;
            int dataDirOffset = is64 ? 112 : 96;
            if (sizeOfOptionalHeader >= dataDirOffset + 16)
            {
                fs.Seek(optionalStart + dataDirOffset + 8, SeekOrigin.Begin); // entry[1] = Import Table
                importDirRva = br.ReadUInt32();
                importDirSize = br.ReadUInt32();
            }
            if (sizeOfOptionalHeader >= dataDirOffset + 120)
            {
                fs.Seek(optionalStart + dataDirOffset + 112, SeekOrigin.Begin); // entry[14] = CLR Descriptor
                clrDirRva = br.ReadUInt32();
                clrDirSize = br.ReadUInt32();
            }

            long sectionTableStart = optionalStart + sizeOfOptionalHeader;
            if (sectionTableStart + (long)numberOfSections * 40 > fs.Length)
            {
                return new PeAnalysisResult
                {
                    IsValidPe = true,
                    Is64Bit = is64,
                    IsDll = isDll,
                    HasMalformedHeaders = true,
                    RiskScore = 40,
                    Reasons = new List<string> { "Bảng section PE vượt quá kích thước tệp (bị cắt xén hoặc đóng gói bất thường)." }
                };
            }

            var sections = new List<PeSectionInfo>(Math.Min((int)numberOfSections, 64));
            double maxEntropy = 0;
            bool hasRwx = false;
            bool hasPacker = false;
            string? detectedPacker = null;
            long maxRawEnd = 0;

            for (int i = 0; i < Math.Min((int)numberOfSections, 64); i++)
            {
                fs.Seek(sectionTableStart + i * 40L, SeekOrigin.Begin);
                byte[] nameBytes = br.ReadBytes(8);
                string secName = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0', ' ');
                uint vSize = br.ReadUInt32();
                uint vAddr = br.ReadUInt32();
                uint rawSize = br.ReadUInt32();
                uint rawPtr = br.ReadUInt32();
                fs.Seek(12, SeekOrigin.Current); // Reloc, Linenumbers, counts
                uint secChar = br.ReadUInt32();

                long end = (long)rawPtr + rawSize;
                if (end > maxRawEnd && end <= fs.Length) maxRawEnd = end;

                double secEntropy = 0;
                if (rawSize > 0 && rawPtr < fs.Length)
                {
                    long readable = Math.Min(rawSize, fs.Length - rawPtr);
                    long sampleSize = Math.Min(readable, 512 * 1024);
                    if (sampleSize > 0)
                    {
                        fs.Seek(rawPtr, SeekOrigin.Begin);
                        byte[] buf = new byte[sampleSize];
                        int read = fs.Read(buf, 0, buf.Length);
                        secEntropy = EntropyCalculator.ComputeBytesEntropy(buf.AsSpan(0, read));
                        if (secEntropy > maxEntropy) maxEntropy = secEntropy;
                    }
                }

                sections.Add(new PeSectionInfo(secName, vSize, vAddr, rawSize, rawPtr, secChar, secEntropy));

                if ((secChar & IMAGE_SCN_MEM_WRITE) != 0 && (secChar & IMAGE_SCN_MEM_EXECUTE) != 0)
                {
                    hasRwx = true;
                }

                string lowerName = secName.ToLowerInvariant();
                foreach (string p in PackerSectionPrefixes)
                {
                    if (lowerName.StartsWith(p, StringComparison.Ordinal))
                    {
                        hasPacker = true;
                        detectedPacker ??= secName;
                    }
                }

                if (rawSize == 0 && vSize > 65536)
                {
                    score += 18;
                    reasons.Add($"Section '{secName}' có RawSize=0 nhưng VirtualSize={vSize:N0} bytes (dấu hiệu tự giải nén trong RAM).");
                }
            }

            if (hasRwx)
            {
                score += 24;
                reasons.Add("Có section vừa ghi vừa thực thi (RWX) — đặc trưng mã tự giải mã / shellcode.");
            }

            if (hasPacker)
            {
                score += 22;
                reasons.Add($"Phát hiện dấu hiệu Packer/Protector ({detectedPacker}) thường dùng để che giấu mã độc.");
            }

            if (maxEntropy >= 7.45)
            {
                score += 26;
                reasons.Add($"Entropy section rất cao ({maxEntropy:F2}/8.0) — mã bị nén hoặc mã hóa bất thường.");
            }
            else if (maxEntropy >= 7.10)
            {
                score += 14;
                reasons.Add($"Entropy section cao ({maxEntropy:F2}/8.0) — có thể đã được đóng gói/nén.");
            }

            // Check PE Overlay (extra appended payload after last section)
            long overlaySize = maxRawEnd > 0 && fs.Length > maxRawEnd ? fs.Length - maxRawEnd : 0;
            double overlayEntropy = 0;
            if (overlaySize > 64 * 1024)
            {
                fs.Seek(maxRawEnd, SeekOrigin.Begin);
                int toSample = (int)Math.Min(overlaySize, 512 * 1024);
                byte[] overBuf = new byte[toSample];
                int read = fs.Read(overBuf, 0, toSample);
                overlayEntropy = EntropyCalculator.ComputeBytesEntropy(overBuf.AsSpan(0, read));
                if (overlayEntropy >= 7.3 && overlaySize > 256 * 1024)
                {
                    score += 15;
                    reasons.Add($"Có dữ liệu đính kèm (PE Overlay) lớn ({overlaySize / 1024:N0} KB) với entropy cao ({overlayEntropy:F2}).");
                }
            }

            // Parse Imports cleanly
            if (importDirRva > 0 && importDirSize > 0)
            {
                ExtractSuspiciousImports(fs, br, sections, importDirRva, is64, suspiciousApis);
            }

            // Inspect .NET CLR Metadata (#Strings / #US) for P/Invoke & RAT/Stealer capabilities
            bool isDotNet = clrDirRva > 0 && clrDirSize > 0;
            string? detectedRatFamily = null;
            if (isDotNet)
            {
                InspectClrMetadata(fs, br, sections, clrDirRva, suspiciousApis, ref score, reasons, ref detectedRatFamily);
            }

            EvaluateApiClusters(suspiciousApis, ref score, reasons);

            return new PeAnalysisResult
            {
                IsValidPe = true,
                Is64Bit = is64,
                IsDll = isDll,
                IsDotNet = isDotNet,
                SectionCount = numberOfSections,
                MaxSectionEntropy = maxEntropy,
                HasRwxSection = hasRwx,
                HasPackerSection = hasPacker,
                DetectedPacker = detectedPacker,
                DetectedRatFamily = detectedRatFamily,
                OverlaySizeBytes = overlaySize,
                OverlayEntropy = overlayEntropy,
                SuspiciousApis = suspiciousApis,
                RiskScore = Math.Min(score, 98),
                Reasons = reasons
            };
        }
        catch
        {
            return new PeAnalysisResult { IsValidPe = false };
        }
    }

    private static void EvaluateApiClusters(HashSet<string> apis, ref int score, List<string> reasons)
    {
        bool hasAlloc = apis.Contains("VirtualAllocEx") || apis.Contains("VirtualAlloc");
        bool hasWrite = apis.Contains("WriteProcessMemory") || apis.Contains("NtWriteVirtualMemory");
        bool hasRemoteExec = apis.Contains("CreateRemoteThread") || apis.Contains("NtCreateThreadEx") || apis.Contains("QueueUserAPC");

        if (apis.Contains("VirtualAllocEx") && hasWrite && hasRemoteExec)
        {
            score += 38;
            reasons.Add("Tổ hợp API Process Injection nguy hiểm: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread.");
        }
        else if (hasAlloc && hasWrite)
        {
            score += 18;
            reasons.Add("Sử dụng API cấp phát & ghi bộ nhớ tiến trình khác.");
        }

        if ((apis.Contains("NtUnmapViewOfSection") || apis.Contains("ZwUnmapViewOfSection")) &&
            apis.Contains("SetThreadContext") && apis.Contains("ResumeThread"))
        {
            score += 40;
            reasons.Add("Tổ hợp API Process Hollowing (NtUnmapViewOfSection + SetThreadContext + ResumeThread).");
        }

        if ((apis.Contains("SetWindowsHookEx") || apis.Contains("SetWindowsHookExA") || apis.Contains("SetWindowsHookExW")) &&
            (apis.Contains("GetAsyncKeyState") || apis.Contains("GetKeyState") || apis.Contains("GetKeyboardState") || apis.Contains("GetForegroundWindow")))
        {
            score += 28;
            reasons.Add("Tổ hợp API ghi nhận thao tác bàn phím / Keylogger (SetWindowsHookEx + Input/Foreground API).");
        }

        if (apis.Contains("IsDebuggerPresent") && apis.Contains("CheckRemoteDebuggerPresent"))
        {
            score += 12;
            reasons.Add("Chứa API chống phân tích / Anti-Debugging.");
        }

        if (apis.Contains("URLDownloadToFile") || apis.Contains("URLDownloadToFileA") || apis.Contains("URLDownloadToFileW"))
        {
            score += 14;
            reasons.Add("Gọi trực tiếp URLDownloadToFile để tải tệp ngầm.");
        }
    }

    private static void InspectClrMetadata(
        FileStream fs,
        BinaryReader br,
        List<PeSectionInfo> sections,
        uint clrDirRva,
        HashSet<string> suspiciousApis,
        ref int score,
        List<string> reasons,
        ref string? detectedRatFamily)
    {
        try
        {
            long clrOffset = RvaToFileOffset(sections, clrDirRva);
            if (clrOffset < 0 || clrOffset + 16 > fs.Length) return;

            fs.Seek(clrOffset + 8, SeekOrigin.Begin);
            uint metaRva = br.ReadUInt32();
            uint metaSize = br.ReadUInt32();
            if (metaRva == 0 || metaSize < 32) return;

            long metaOffset = RvaToFileOffset(sections, metaRva);
            if (metaOffset < 0 || metaOffset + 32 > fs.Length) return;

            fs.Seek(metaOffset, SeekOrigin.Begin);
            if (br.ReadUInt32() != 0x424A5342) return; // "BSJB"

            fs.Seek(metaOffset + 12, SeekOrigin.Begin);
            int verLen = br.ReadInt32();
            if (verLen < 0 || verLen > 256) return;

            long pos = metaOffset + 16 + ((verLen + 3) & ~3);
            if (pos + 4 > fs.Length) return;

            fs.Seek(pos + 2, SeekOrigin.Begin);
            ushort numStreams = br.ReadUInt16();
            pos += 4;

            long stringsOff = -1;
            int stringsSize = 0;
            long usOff = -1;
            int usSize = 0;

            for (int s = 0; s < Math.Min((int)numStreams, 16); s++)
            {
                if (pos + 8 > fs.Length) break;
                fs.Seek(pos, SeekOrigin.Begin);
                uint sOff = br.ReadUInt32();
                uint sSize = br.ReadUInt32();
                pos += 8;

                var nameBytes = new List<byte>(16);
                while (pos < fs.Length && nameBytes.Count < 32)
                {
                    byte b = br.ReadByte();
                    pos++;
                    if (b == 0) break;
                    nameBytes.Add(b);
                }
                while ((pos - metaOffset) % 4 != 0 && pos < fs.Length) { pos++; }

                string streamName = Encoding.ASCII.GetString(nameBytes.ToArray());
                long absOff = metaOffset + sOff;
                if (absOff < 0 || absOff >= fs.Length) continue;

                int clampedSize = (int)Math.Min(sSize, Math.Min(2 * 1024 * 1024, fs.Length - absOff));
                if (streamName == "#Strings")
                {
                    stringsOff = absOff;
                    stringsSize = clampedSize;
                }
                else if (streamName == "#US")
                {
                    usOff = absOff;
                    usSize = clampedSize;
                }
            }

            bool hasKeylogCap = false;
            bool hasSurveillanceCap = false;
            bool hasRemoteShellOrProxyCap = false;
            bool hasCredentialStealerCap = false;
            bool hasPersistenceString = false;
            bool hasGeoIpString = false;

            if (stringsOff > 0 && stringsSize > 0)
            {
                fs.Seek(stringsOff, SeekOrigin.Begin);
                byte[] buf = new byte[stringsSize];
                int read = fs.Read(buf, 0, stringsSize);
                string utf8 = Encoding.UTF8.GetString(buf, 0, read);

                string q1 = T("quasar", ".client");
                string q2 = T("quasar", ".common.messages");
                string a1 = T("async", "rat");
                string x1 = T("x", "worm");
                string n1 = T("nj", "rat");
                string v1 = T("venom", "rat");
                string d1 = T("dc", "rat");
                string r1 = T("redline", ".client");

                foreach (string token in utf8.Split('\0', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (TrackedApis.Contains(token))
                        suspiciousApis.Add(token);

                    string lower = token.ToLowerInvariant();
                    if (detectedRatFamily == null)
                    {
                        if (lower.Contains(q1) || lower.Contains(q2)) detectedRatFamily = "QuasarRAT";
                        else if (lower.Contains(a1)) detectedRatFamily = "AsyncRAT";
                        else if (lower.Contains(v1)) detectedRatFamily = "VenomRAT";
                        else if (lower.Contains(n1)) detectedRatFamily = "NjRAT";
                        else if (lower.Contains(x1) && lower.Contains("client")) detectedRatFamily = "XWorm";
                        else if (lower.Contains(d1) && (lower.Contains("plugin") || lower.Contains("recovery"))) detectedRatFamily = "DcRat";
                        else if (lower.Contains(r1)) detectedRatFamily = "RedLine";
                    }

                    if (lower.Contains(T("key", "log")) || lower.Contains(T("global", "hookproc")) ||
                        lower.Contains(T("setwindows", "hookex")) || lower.Contains(T("getasync", "keystate")))
                    {
                        hasKeylogCap = true;
                    }
                    if (lower.Contains(T("remote", "desktop")) || lower.Contains(T("desktop", "duplicator")) ||
                        lower.Contains(T("get", "webcam")) || lower.Contains(T("web", "cam")) ||
                        lower.Contains(T("capcreate", "capturewindow")))
                    {
                        hasSurveillanceCap = true;
                    }
                    if (lower.Contains(T("reverse", "proxy")) || lower.Contains(T("doshell", "execute")) ||
                        lower.Contains(T("remote", "shell")) || lower.Contains(T("shell", "execute")))
                    {
                        hasRemoteShellOrProxyCap = true;
                    }
                    if (lower.Contains(T("recovery.", "browsers")) || lower.Contains(T("browser", "recovery")) ||
                        lower.Contains(T("steal", "er")) || lower.Contains(T("crypt", "unprotectdata")))
                    {
                        hasCredentialStealerCap = true;
                    }
                }
            }

            if (usOff > 0 && usSize > 0)
            {
                fs.Seek(usOff, SeekOrigin.Begin);
                byte[] usBuf = new byte[usSize];
                int usRead = fs.Read(usBuf, 0, usSize);
                string usText = Encoding.Unicode.GetString(usBuf, 0, usRead).ToLowerInvariant();

                if (usText.Contains(T("currentversion", "\\run")) || usText.Contains(T("sch", "tasks")))
                    hasPersistenceString = true;

                if (usText.Contains(T("ipwho", ".is")) || usText.Contains(T("ip-api", ".com")) ||
                    usText.Contains(T("api.ipify", ".org")) || usText.Contains(T("check", "ip.")))
                    hasGeoIpString = true;

                if (detectedRatFamily == null && usText.Contains(T("quasar", " client")))
                    detectedRatFamily = "QuasarRAT";
            }

            if (detectedRatFamily != null)
            {
                score += 88;
                reasons.Add($"Phát hiện dấu hiệu mã độc điều khiển từ xa (.NET RAT Family: {detectedRatFamily}) trong metadata.");
            }

            int capCount = 0;
            var caps = new List<string>();
            if (hasKeylogCap) { capCount++; caps.Add("Keylogger/Hook bàn phím"); }
            if (hasSurveillanceCap) { capCount++; caps.Add("Theo dõi màn hình/Webcam"); }
            if (hasRemoteShellOrProxyCap) { capCount++; caps.Add("Remote Shell / Reverse Proxy"); }
            if (hasCredentialStealerCap) { capCount++; caps.Add("Trích xuất mật khẩu trình duyệt"); }
            if (hasPersistenceString && hasGeoIpString) { capCount++; caps.Add("Tự khởi chạy bền bỉ + định vị GeoIP"); }

            if (capCount >= 2)
            {
                int boost = capCount >= 3 ? 72 : 52;
                score += boost;
                reasons.Add($"Phân tích CLR .NET phát hiện tổ hợp {capCount} hành vi Trojan/RAT: {string.Join(", ", caps)}.");
            }
            else if (capCount == 1 && (hasPersistenceString || hasGeoIpString))
            {
                score += 36;
                reasons.Add($"Phân tích CLR .NET phát hiện hành vi nhạy cảm ({caps[0]}) kèm cơ chế bền bỉ/truy vấn IP.");
            }
        }
        catch
        {
            // Keep PE analyzer resilient on malformed CLR headers
        }
    }

    private static long RvaToFileOffset(List<PeSectionInfo> sections, uint rva)
    {
        foreach (var sec in sections)
        {
            uint span = Math.Max(sec.VirtualSize, sec.RawSize);
            if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + span)
            {
                long offset = sec.RawPointer + (rva - sec.VirtualAddress);
                return offset;
            }
        }
        return -1;
    }

    private static void ExtractSuspiciousImports(
        FileStream fs,
        BinaryReader br,
        List<PeSectionInfo> sections,
        uint importDirRva,
        bool is64,
        HashSet<string> foundApis)
    {
        long importOffset = RvaToFileOffset(sections, importDirRva);
        if (importOffset < 0 || importOffset + 20 > fs.Length) return;

        for (int descIdx = 0; descIdx < 64; descIdx++)
        {
            long pos = importOffset + descIdx * 20L;
            if (pos + 20 > fs.Length) break;

            fs.Seek(pos, SeekOrigin.Begin);
            uint originalFirstThunk = br.ReadUInt32();
            uint timeDateStamp = br.ReadUInt32();
            uint forwarderChain = br.ReadUInt32();
            uint nameRva = br.ReadUInt32();
            uint firstThunk = br.ReadUInt32();

            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                break;

            uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            long thunkOffset = RvaToFileOffset(sections, thunkRva);
            if (thunkOffset < 0) continue;

            int entrySize = is64 ? 8 : 4;
            for (int t = 0; t < 256; t++)
            {
                long tPos = thunkOffset + (long)t * entrySize;
                if (tPos + entrySize > fs.Length) break;

                fs.Seek(tPos, SeekOrigin.Begin);
                ulong thunkVal = is64 ? br.ReadUInt64() : br.ReadUInt32();
                if (thunkVal == 0) break;

                bool isOrdinal = is64 ? (thunkVal & 0x8000000000000000UL) != 0 : (thunkVal & 0x80000000UL) != 0;
                if (isOrdinal) continue;

                uint hintNameRva = (uint)(thunkVal & 0x7FFFFFFF);
                long hintOffset = RvaToFileOffset(sections, hintNameRva);
                if (hintOffset < 0 || hintOffset + 4 >= fs.Length) continue;

                fs.Seek(hintOffset + 2, SeekOrigin.Begin);
                string apiName = ReadNullTerminatedAscii(fs, 96);
                if (!string.IsNullOrEmpty(apiName) && TrackedApis.Contains(apiName))
                {
                    foundApis.Add(apiName);
                }
            }
        }
    }

    private static string ReadNullTerminatedAscii(FileStream fs, int maxLen)
    {
        Span<byte> buf = stackalloc byte[maxLen];
        int read = fs.Read(buf);
        int end = 0;
        while (end < read && buf[end] != 0)
        {
            if (buf[end] < 32 || buf[end] > 126) return string.Empty;
            end++;
        }
        return end > 0 ? Encoding.ASCII.GetString(buf[..end]) : string.Empty;
    }
}
