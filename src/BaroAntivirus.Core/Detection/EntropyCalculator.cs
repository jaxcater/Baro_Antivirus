using System.Buffers;

namespace BaroAntivirus.Core.Detection;

public static class EntropyCalculator
{
    public static double ComputeBytesEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return 0.0;

        Span<int> counts = stackalloc int[256];
        for (int i = 0; i < data.Length; i++)
        {
            counts[data[i]]++;
        }

        double entropy = 0.0;
        double len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            int c = counts[i];
            if (c == 0) continue;
            double p = c / len;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    public static double ComputeStreamEntropy(Stream stream, long maxBytesToSample = 2 * 1024 * 1024)
    {
        long[] counts = new long[256];
        long total = 0;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(65536);
        try
        {
            while (total < maxBytesToSample)
            {
                int toRead = (int)Math.Min(buffer.Length, maxBytesToSample - total);
                int read = stream.Read(buffer, 0, toRead);
                if (read <= 0) break;

                for (int i = 0; i < read; i++)
                {
                    counts[buffer[i]]++;
                }
                total += read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        if (total == 0) return 0.0;

        double entropy = 0.0;
        double len = total;
        for (int i = 0; i < 256; i++)
        {
            long c = counts[i];
            if (c == 0) continue;
            double p = c / len;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}
