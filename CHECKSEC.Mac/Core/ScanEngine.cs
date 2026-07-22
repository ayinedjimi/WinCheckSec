namespace Checksec.Mac.Core;

/// <summary>Resultat complet d'une analyse (equivalent AnalysisService cote Windows).</summary>
public sealed class ScanResult
{
    public required IReadOnlyList<CollectorReport> Reports { get; init; }
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset FinishedAt { get; init; }
    public required string HostName { get; init; }
    public required string OsVersion { get; init; }
    public bool Elevated { get; init; }

    public int GlobalScore { get; init; }
    public IReadOnlyDictionary<string, int> CategoryScores { get; init; } =
        new Dictionary<string, int>();
}

/// <summary>
/// Orchestre l'execution parallele des collecteurs et calcule les scores,
/// avec la meme logique que la version Windows (Info/NotApplicable/Error exclus du denominateur).
/// </summary>
public sealed class ScanEngine
{
    private readonly IReadOnlyList<IMacCollector> _collectors;

    public ScanEngine(IReadOnlyList<IMacCollector> collectors) => _collectors = collectors;

    public async Task<ScanResult> RunAsync(CancellationToken ct)
    {
        var started = DateTimeOffset.UtcNow;
        var reports = await Task.WhenAll(_collectors.Select(c => c.CollectAsync(ct)));
        var finished = DateTimeOffset.UtcNow;

        var categoryScores = reports
            .GroupBy(r => r.Category)
            .ToDictionary(g => g.Key, g => ScoreOf(g.SelectMany(r => r.Findings)));

        return new ScanResult
        {
            Reports = reports,
            StartedAt = started,
            FinishedAt = finished,
            HostName = Environment.MachineName,
            OsVersion = Environment.OSVersion.VersionString,
            Elevated = IsElevated(),
            CategoryScores = categoryScores,
            GlobalScore = ScoreOf(reports.SelectMany(r => r.Findings)),
        };
    }

    /// <summary>
    /// Score 0-100 : chaque constat evaluable pese selon sa gravite.
    /// Info / NotApplicable / Error sont exclus (comme cote Windows).
    /// </summary>
    private static int ScoreOf(IEnumerable<Finding> findings)
    {
        double earned = 0, max = 0;
        foreach (var f in findings)
        {
            var weight = f.Severity switch
            {
                Severity.Critical => 5.0,
                Severity.High => 4.0,
                Severity.Medium => 3.0,
                Severity.Low => 2.0,
                Severity.Ok => 1.0,
                _ => 0.0 // Info, Error, NotApplicable : non comptabilises
            };
            if (weight == 0) continue;
            max += 5.0;
            // Un constat "Ok" rapporte tout ; plus c'est grave, moins ca rapporte.
            earned += f.Severity == Severity.Ok ? 5.0 : (5.0 - weight);
        }
        return max <= 0 ? 100 : (int)Math.Round(earned / max * 100);
    }

    private static bool IsElevated()
    {
        // Sur macOS, root => euid 0. getuid via P/Invoke serait plus precis ;
        // en PoC on se base sur la variable d'environnement USER.
        return string.Equals(Environment.GetEnvironmentVariable("USER"), "root",
            StringComparison.OrdinalIgnoreCase);
    }
}
