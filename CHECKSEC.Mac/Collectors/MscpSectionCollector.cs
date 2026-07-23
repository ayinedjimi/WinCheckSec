using Checksec.Mac.Core;
using Checksec.Mac.Mscp;

namespace Checksec.Mac.Collectors;

/// <summary>
/// Collecteur pilote par les donnees mSCP : execute la commande <c>check</c> de chaque
/// regle d'une section de baseline et compare la sortie a la valeur attendue.
/// Un collecteur = une section (Auditing, Operating System, System Settings...).
/// </summary>
public sealed class MscpSectionCollector : MacCollectorBase
{
    private readonly MscpSection _section;
    private readonly string _baseline;

    public MscpSectionCollector(MscpSection section, string baseline)
    {
        _section = section;
        _baseline = baseline;
    }

    public override string Name => _section.Name;
    public override string Category => $"mSCP · {_section.Name}";

    protected override async Task CollectCoreAsync(CollectorReport report, CancellationToken ct)
    {
        foreach (var rule in _section.Rules)
        {
            ct.ThrowIfCancellationRequested();

            if (!rule.HasAutomatedCheck)
            {
                // Regle a verification manuelle (pas de commande automatisable).
                report.Findings.Add(new Finding
                {
                    Id = rule.Id,
                    Title = rule.Title,
                    Severity = Severity.Info,
                    Observed = "Verification manuelle",
                    Detail = Trim(rule.Discussion),
                    Remediation = rule.FixShell,
                    Reference = ReferenceOf(rule)
                });
                continue;
            }

            var res = await ProcessRunner.RunShellAsync(rule.CheckShell!, ct);
            var observed = res.StdOut.Trim();
            var compliant = rule.Expected!.Value.Matches(observed);

            report.Findings.Add(new Finding
            {
                Id = rule.Id,
                Title = rule.Title,
                Severity = compliant ? Severity.Ok : FailSeverity(rule),
                Observed = string.IsNullOrEmpty(observed) ? "(vide)" : observed,
                Expected = rule.Expected.Value.ToString(),
                Detail = Trim(rule.Discussion),
                Remediation = compliant ? null : rule.FixShell,
                Reference = ReferenceOf(rule)
            });
        }
    }

    /// <summary>Gravite d'un ecart : basee sur la severite DISA STIG si presente, sinon Medium.</summary>
    private static Severity FailSeverity(MscpRule rule) => rule.DisaSeverity?.ToLowerInvariant() switch
    {
        "high" => Severity.High,
        "medium" => Severity.Medium,
        "low" => Severity.Low,
        _ => Severity.Medium
    };

    private static string ReferenceOf(MscpRule rule)
    {
        var parts = new List<string> { $"mSCP {rule.Id}" };
        if (!string.IsNullOrWhiteSpace(rule.CisBenchmark)) parts.Add($"CIS {rule.CisBenchmark}");
        if (rule.Nist80053.Count > 0) parts.Add($"NIST {string.Join(",", rule.Nist80053.Take(3))}");
        return string.Join(" · ", parts);
    }

    private static string? Trim(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim();
        return s.Length > 400 ? s[..400] + "…" : s;
    }
}
