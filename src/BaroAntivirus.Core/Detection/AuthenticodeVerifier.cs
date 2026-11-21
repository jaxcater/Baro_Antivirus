using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace BaroAntivirus.Core.Detection;

public sealed record AuthenticodeResult(bool IsValidSigned, string? SignerName, string StatusNote);

public static class AuthenticodeVerifier
{
    private static readonly ConcurrentDictionary<string, (DateTime UtcWrite, long Size, AuthenticodeResult Result)> Cache = new(StringComparer.OrdinalIgnoreCase);
    private const int MaxCacheEntries = 4096;

    private static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    public static AuthenticodeResult Verify(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return new AuthenticodeResult(false, null, "File not found");

        try
        {
            var fi = new FileInfo(filePath);
            if (Cache.TryGetValue(filePath, out var cached) &&
                cached.UtcWrite == fi.LastWriteTimeUtc &&
                cached.Size == fi.Length)
            {
                return cached.Result;
            }

            bool isValid = VerifyTrustCore(filePath, out int hr);
            string? signer = null;
            if (isValid)
            {
                signer = TryExtractSignerSubject(filePath);
            }

            string note = isValid
                ? $"Chữ ký số hợp lệ ({signer ?? "Trusted Publisher"})"
                : hr == unchecked((int)0x800B0100)
                    ? "Không có chữ ký số (Unsigned)"
                    : $"Chữ ký số không hợp lệ hoặc không tin cậy (0x{hr:X8})";

            var result = new AuthenticodeResult(isValid, signer, note);

            if (Cache.Count >= MaxCacheEntries)
            {
                Cache.Clear();
            }
            Cache[filePath] = (fi.LastWriteTimeUtc, fi.Length, result);
            return result;
        }
        catch (Exception ex)
        {
            return new AuthenticodeResult(false, null, $"Lỗi kiểm tra chữ ký: {ex.Message}");
        }
    }

    private static bool VerifyTrustCore(string filePath, out int hresult)
    {
        IntPtr filePathPtr = Marshal.StringToCoTaskMemUni(filePath);
        IntPtr fileInfoPtr = IntPtr.Zero;
        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePathPtr,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };
            fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
            };

            Guid action = WintrustActionGenericVerifyV2;
            hresult = WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            return hresult == 0;
        }
        finally
        {
            if (fileInfoPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(fileInfoPtr);
            if (filePathPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(filePathPtr);
        }
    }

    private static string? TryExtractSignerSubject(string filePath)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            string subject = cert.Subject;
            int cnIdx = subject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
            if (cnIdx >= 0)
            {
                string rest = subject[(cnIdx + 3)..];
                if (rest.StartsWith('"'))
                {
                    int endQuote = rest.IndexOf('"', 1);
                    if (endQuote > 1) return rest[1..endQuote];
                }
                int comma = rest.IndexOf(',');
                return comma > 0 ? rest[..comma].Trim() : rest.Trim();
            }
            return subject;
        }
        catch
        {
            return null;
        }
    }
}
