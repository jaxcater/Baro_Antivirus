namespace BaroAntivirus.Core.Detection;

public sealed record ZoneIdentifierInfo(int ZoneId, string? HostUrl, string? ReferrerUrl);

public static class ZoneIdentifierReader
{
    public static ZoneIdentifierInfo? Read(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return null;

        try
        {
            string adsPath = filePath + ":Zone.Identifier";
            if (!File.Exists(adsPath)) return null;

            string content = File.ReadAllText(adsPath);
            int zoneId = -1;
            string? hostUrl = null;
            string? referrerUrl = null;

            using var reader = new StringReader(content);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                string key = line[..eq].Trim();
                string val = line[(eq + 1)..].Trim();

                if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase) && int.TryParse(val, out int z))
                {
                    zoneId = z;
                }
                else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase))
                {
                    hostUrl = val;
                }
                else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase))
                {
                    referrerUrl = val;
                }
            }

            return zoneId >= 0 ? new ZoneIdentifierInfo(zoneId, hostUrl, referrerUrl) : null;
        }
        catch
        {
            return null;
        }
    }
}
