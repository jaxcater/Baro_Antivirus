using System.Security.Cryptography;
using System.Text.Json;
using BaroAntivirus.Core.Models;

namespace BaroAntivirus.Core.Services;

public sealed class QuarantineService
{
    private readonly string _vaultDir;
    private readonly string _indexPath;
    private readonly string _keyPath;
    private readonly byte[] _masterKey;
    private readonly object _lock = new();
    private readonly List<QuarantineEntry> _entries = new();

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public QuarantineService(string dataDirectory)
    {
        _vaultDir = Path.Combine(dataDirectory, "Quarantine");
        Directory.CreateDirectory(_vaultDir);
        _indexPath = Path.Combine(_vaultDir, "quarantine_index.json");
        _keyPath = Path.Combine(_vaultDir, ".vault.key");
        _masterKey = LoadOrCreateKey();
        LoadIndex();
    }

    public event Action? QuarantineChanged;

    public IReadOnlyList<QuarantineEntry> GetEntries()
    {
        lock (_lock)
        {
            return _entries.OrderByDescending(e => e.QuarantinedAt).ToList();
        }
    }

    public QuarantineEntry? QuarantineFile(ThreatFinding finding)
    {
        if (string.IsNullOrWhiteSpace(finding.FilePath) || !File.Exists(finding.FilePath))
            return null;

        try
        {
            string id = Guid.NewGuid().ToString("N")[..12];
            string vaultName = $"{id}.baroq";
            string vaultPath = Path.Combine(_vaultDir, vaultName);

            byte[] plainBytes = File.ReadAllBytes(finding.FilePath);
            EncryptToVault(plainBytes, vaultPath);

            // Clear restrictive attributes before deleting original threat
            try
            {
                File.SetAttributes(finding.FilePath, FileAttributes.Normal);
            }
            catch { }

            File.Delete(finding.FilePath);

            var entry = new QuarantineEntry
            {
                Id = id,
                OriginalPath = finding.FilePath,
                OriginalFileName = finding.FileName,
                VaultFileName = vaultName,
                ThreatName = finding.ThreatName,
                Category = finding.Category,
                Severity = finding.Severity,
                RiskScore = finding.RiskScore,
                Reasons = finding.Reasons.ToList(),
                Sha256 = finding.Sha256,
                OriginalSize = plainBytes.LongLength,
                QuarantinedAt = DateTimeOffset.UtcNow
            };

            lock (_lock)
            {
                _entries.Add(entry);
                SaveIndex();
            }

            finding.ActionTaken = ProtectionAction.Quarantined;
            QuarantineChanged?.Invoke();
            return entry;
        }
        catch
        {
            return null;
        }
    }

    public bool RestoreEntry(string id, out string? restoredPath)
    {
        restoredPath = null;
        QuarantineEntry? target;
        lock (_lock)
        {
            target = _entries.FirstOrDefault(e => e.Id == id);
        }
        if (target == null) return false;

        string vaultPath = Path.Combine(_vaultDir, target.VaultFileName);
        if (!File.Exists(vaultPath)) return false;

        try
        {
            byte[] plain = DecryptFromVault(vaultPath);
            string dest = target.OriginalPath;
            string? dir = Path.GetDirectoryName(dest);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            if (File.Exists(dest))
            {
                string stem = Path.GetFileNameWithoutExtension(dest);
                string ext = Path.GetExtension(dest);
                dest = Path.Combine(dir ?? "", $"{stem}_restored_{DateTime.Now:yyyyMMddHHmmss}{ext}");
            }

            File.WriteAllBytes(dest, plain);
            File.Delete(vaultPath);

            lock (_lock)
            {
                _entries.RemoveAll(e => e.Id == id);
                SaveIndex();
            }

            restoredPath = dest;
            QuarantineChanged?.Invoke();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public bool DeleteEntryPermanently(string id)
    {
        QuarantineEntry? target;
        lock (_lock)
        {
            target = _entries.FirstOrDefault(e => e.Id == id);
        }
        if (target == null) return false;

        try
        {
            string vaultPath = Path.Combine(_vaultDir, target.VaultFileName);
            if (File.Exists(vaultPath))
                FileShredderService.ShredFile(vaultPath, passes: 1);

            lock (_lock)
            {
                _entries.RemoveAll(e => e.Id == id);
                SaveIndex();
            }

            QuarantineChanged?.Invoke();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public int PurgeAll()
    {
        List<QuarantineEntry> copy;
        lock (_lock)
        {
            copy = _entries.ToList();
        }
        int deleted = 0;
        foreach (var e in copy)
        {
            if (DeleteEntryPermanently(e.Id)) deleted++;
        }
        return deleted;
    }

    private void EncryptToVault(byte[] plainBytes, string vaultPath)
    {
        byte[] nonce = new byte[12];
        byte[] tag = new byte[16];
        byte[] cipher = new byte[plainBytes.Length];
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(_masterKey, 16);
        aes.Encrypt(nonce, plainBytes, cipher, tag);

        using var fs = new FileStream(vaultPath, FileMode.Create, FileAccess.Write, FileShare.None);
        fs.Write(nonce, 0, nonce.Length);
        fs.Write(tag, 0, tag.Length);
        fs.Write(cipher, 0, cipher.Length);
    }

    private byte[] DecryptFromVault(string vaultPath)
    {
        byte[] blob = File.ReadAllBytes(vaultPath);
        if (blob.Length < 28) throw new InvalidDataException("Invalid quarantine file.");

        ReadOnlySpan<byte> nonce = blob.AsSpan(0, 12);
        ReadOnlySpan<byte> tag = blob.AsSpan(12, 16);
        ReadOnlySpan<byte> cipher = blob.AsSpan(28);
        byte[] plain = new byte[cipher.Length];

        using var aes = new AesGcm(_masterKey, 16);
        aes.Decrypt(nonce, cipher, tag, plain);
        return plain;
    }

    private byte[] LoadOrCreateKey()
    {
        if (File.Exists(_keyPath))
        {
            byte[] existing = File.ReadAllBytes(_keyPath);
            if (existing.Length == 32) return existing;
        }
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        File.WriteAllBytes(_keyPath, key);
        try { File.SetAttributes(_keyPath, FileAttributes.Hidden); } catch { }
        return key;
    }

    private void LoadIndex()
    {
        try
        {
            if (!File.Exists(_indexPath)) return;
            string json = File.ReadAllText(_indexPath);
            var items = JsonSerializer.Deserialize<List<QuarantineEntry>>(json, JsonOpts);
            if (items != null) _entries.AddRange(items);
        }
        catch { }
    }

    private void SaveIndex()
    {
        string json = JsonSerializer.Serialize(_entries, JsonOpts);
        File.WriteAllText(_indexPath, json);
    }
}
