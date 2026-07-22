using Checksec.Mac.Collectors;
using Checksec.Mac.Core;

// ─── CHECKSEC for macOS — CLI d'audit de posture de securite ───────────────────
// Usage : checksec [--json <chemin>] [--quiet]
//   --json <chemin>  : ecrit le rapport JSON forensique (defaut : ~/Desktop ou repertoire courant)
//   --quiet          : n'affiche pas le tableau, ecrit seulement le JSON

var jsonPath = GetOption(args, "--json");
var quiet = args.Contains("--quiet");

// Enregistrement des collecteurs (equivalent BuildCollectors() cote Windows).
var collectors = new IMacCollector[]
{
    new FileVaultCollector(),
    new GatekeeperCollector(),
    new SipCollector(),
    new FirewallCollector(),
    new XProtectCollector(),
    new SharingCollector(),
    new SoftwareUpdateCollector(),
};

if (!quiet)
{
    Console.WriteLine("╔══════════════════════════════════════════════════╗");
    Console.WriteLine("║   CHECKSEC for macOS — audit de securite  v0.1.0  ║");
    Console.WriteLine("╚══════════════════════════════════════════════════╝");
    if (!ProcessRunner.IsMacOs)
        Console.WriteLine("⚠  Hote non-macOS : collecteurs compiles mais non evalues (NotApplicable).\n");
}

using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));
var engine = new ScanEngine(collectors);
var result = await engine.RunAsync(cts.Token);

if (!quiet)
    PrintReport(result);

// Ecriture du rapport JSON.
var json = JsonReportBuilder.Build(result);
var outPath = jsonPath ?? DefaultOutputPath();
await File.WriteAllTextAsync(outPath, json, cts.Token);
Console.WriteLine($"\n📄 Rapport JSON : {outPath}");

return result.GlobalScore < 40 ? 2 : 0; // code retour exploitable en CI

// ─── Helpers ───────────────────────────────────────────────────────────────────

static string? GetOption(string[] args, string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

static string DefaultOutputPath()
{
    var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
    var file = $"CHECKSEC_{Environment.MachineName}_{stamp}.json";
    var desktop = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop");
    var dir = Directory.Exists(desktop) ? desktop : Directory.GetCurrentDirectory();
    return Path.Combine(dir, file);
}

static void PrintReport(ScanResult r)
{
    Console.WriteLine($"\nHote     : {r.HostName} ({r.OsVersion})");
    Console.WriteLine($"Elevation: {(r.Elevated ? "root" : "utilisateur standard")}");
    Console.WriteLine($"Score    : {r.GlobalScore}/100\n");

    foreach (var report in r.Reports.OrderBy(x => x.Category))
    {
        Console.WriteLine($"── {report.Category} / {report.Collector} " +
                          $"({report.DurationMs:F0} ms)");
        foreach (var f in report.Findings)
            Console.WriteLine($"   {Icon(f.Severity)} [{f.Severity,-11}] {f.Title} : {f.Observed}");
    }
}

static string Icon(Severity s) => s switch
{
    Severity.Ok => "✔",
    Severity.Critical => "⛔",
    Severity.High => "✖",
    Severity.Medium => "▲",
    Severity.Low => "•",
    Severity.Error => "!",
    Severity.NotApplicable => "–",
    _ => "ℹ"
};
