using Checksec.Mac.Collectors;
using Checksec.Mac.Core;
using Checksec.Mac.Mscp;

// ─── MacSecCheck — CLI d'audit de posture de securite macOS ────────────────────
// Usage : macseccheck [--json <chemin>] [--quiet] [--baseline <nom>] [--mscp <dir>] [--list-baselines]
//   --json <chemin>   : ecrit le rapport JSON forensique (defaut : ~/Desktop ou repertoire courant)
//   --quiet           : n'affiche pas le tableau, ecrit seulement le JSON
//   --baseline <nom>  : baseline mSCP a evaluer (defaut : cis_lvl1 ; ex. cis_lvl2, disa_stig, 800-53r5_high)
//   --mscp <dir>      : utilise un checkout externe du depot mSCP au lieu des donnees embarquees
//   --list-baselines  : liste les baselines disponibles puis quitte

var jsonPath = GetOption(args, "--json");
var quiet = args.Contains("--quiet");
var baseline = GetOption(args, "--baseline") ?? "cis_lvl1";
var mscpDir = GetOption(args, "--mscp");

// Detection de la version majeure de macOS (pour resoudre les regles mSCP versionnees).
var macMajor = GetOption(args, "--os-version")
               ?? await ProcessRunner.MacOsMajorAsync(CancellationToken.None)
               ?? "26";

// Chargement des donnees mSCP (embarquees par defaut, ou depuis --mscp).
var mscp = mscpDir is not null
    ? MscpDataLoader.FromDirectory(mscpDir, macMajor)
    : MscpDataLoader.FromEmbedded(macMajor);

if (args.Contains("--list-baselines"))
{
    Console.WriteLine("Baselines mSCP disponibles :");
    foreach (var b in mscp.BaselineNames.OrderBy(x => x))
        Console.WriteLine($"  - {b}");
    return 0;
}

// Diagnostic : affiche la resolution d'une regle mSCP (check/attendu/fix) pour la version cible.
if (GetOption(args, "--dump-rule") is { } dumpId)
{
    var section = mscp.ResolveBaseline(baseline).SelectMany(s => s.Rules)
        .FirstOrDefault(r => string.Equals(r.Id, dumpId, StringComparison.OrdinalIgnoreCase));
    if (section is null) { Console.WriteLine($"Regle '{dumpId}' absente de la baseline {baseline}."); return 1; }
    Console.WriteLine($"Id        : {section.Id}");
    Console.WriteLine($"Titre     : {section.Title}");
    Console.WriteLine($"CIS       : {section.CisBenchmark}");
    Console.WriteLine($"DISA sev. : {section.DisaSeverity}");
    Console.WriteLine($"Attendu   : {section.Expected}");
    Console.WriteLine($"Check     : {section.CheckShell}");
    Console.WriteLine($"Fix       : {section.FixShell}");
    return 0;
}

// Collecteurs natifs (equivalent BuildCollectors() cote Windows).
var collectors = new List<IMacCollector>
{
    new FileVaultCollector(),
    new GatekeeperCollector(),
    new SipCollector(),
    new FirewallCollector(),
    new XProtectCollector(),
    new SharingCollector(),
    new SoftwareUpdateCollector(),
};

// Collecteurs pilotes par la baseline mSCP (un par section).
var sections = mscp.ResolveBaseline(baseline);
foreach (var section in sections)
    collectors.Add(new MscpSectionCollector(section, baseline));
var mscpRuleCount = sections.Sum(s => s.Rules.Count);

if (!quiet)
{
    Console.WriteLine("MacSecCheck — auditeur de securite macOS  v0.2.0");
    Console.WriteLine(new string('=', 48));
    Console.WriteLine($"Baseline mSCP : {baseline} (macOS {macMajor}) — " +
                      $"{mscpRuleCount} regles sur {sections.Count} sections, {mscp.RuleCount} regles indexees.");
    if (mscpRuleCount == 0)
        Console.WriteLine($"⚠  Baseline '{baseline}' inconnue. Essayez --list-baselines.");
    if (!ProcessRunner.IsMacOs)
        Console.WriteLine("⚠  Hote non-macOS : collecteurs compiles mais non evalues (NotApplicable).");
    Console.WriteLine();
}

using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
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
    var file = $"MacSecCheck_{Environment.MachineName}_{stamp}.json";
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
