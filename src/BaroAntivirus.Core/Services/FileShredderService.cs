using System.Security.Cryptography;

namespace BaroAntivirus.Core.Services;

public static class FileShredderService
{
    public static bool ShredFile(string filePath, int passes = 3)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return false;

        try
        {
            File.SetAttributes(filePath, FileAttributes.Normal);
            long length = new FileInfo(filePath).Length;

            if (length > 0)
            {
                byte[] buffer = new byte[65536];
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None);

                for (int pass = 0; pass < Math.Max(1, passes); pass++)
                {
                    fs.Seek(0, SeekOrigin.Begin);
                    long remaining = length;
                    while (remaining > 0)
                    {
                        int chunk = (int)Math.Min(buffer.Length, remaining);
                        if (pass == 0)
                            Array.Fill<byte>(buffer, 0x00, 0, chunk);
                        else if (pass == 1)
                            Array.Fill<byte>(buffer, 0xFF, 0, chunk);
                        else
                            RandomNumberGenerator.Fill(buffer.AsSpan(0, chunk));

                        fs.Write(buffer, 0, chunk);
                        remaining -= chunk;
                    }
                    fs.Flush(flushToDisk: true);
                }
            }

            string dir = Path.GetDirectoryName(filePath) ?? string.Empty;
            string randomName = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".shred");
            File.Move(filePath, randomName);
            File.Delete(randomName);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
