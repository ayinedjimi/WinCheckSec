namespace Checksec.Mac.Core;

/// <summary>Gravite d'un constat, alignee sur la version Windows de CHECKSEC.</summary>
public enum Severity
{
    Info,
    Ok,
    Low,
    Medium,
    High,
    Critical,
    Error,
    NotApplicable
}

/// <summary>Un constat unitaire produit par un collecteur.</summary>
public sealed class Finding
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public Severity Severity { get; init; } = Severity.Info;

    /// <summary>Valeur observee sur le systeme.</summary>
    public string? Observed { get; init; }

    /// <summary>Valeur attendue / conforme (baseline CIS/mSCP).</summary>
    public string? Expected { get; init; }

    /// <summary>Explication et impact.</summary>
    public string? Detail { get; init; }

    /// <summary>Commande de remediation suggeree.</summary>
    public string? Remediation { get; init; }

    /// <summary>Reference baseline (ex. "CIS 2.5.1", "mSCP os_sip_enable").</summary>
    public string? Reference { get; init; }

    /// <summary>Techniques MITRE ATT&amp;CK associees (ex. "T1547").</summary>
    public IReadOnlyList<string> MitreTechniques { get; init; } = Array.Empty<string>();
}

/// <summary>Rapport d'un collecteur (equivalent CollectorReport cote Windows).</summary>
public sealed class CollectorReport
{
    public required string Collector { get; init; }
    public required string Category { get; init; }
    public List<Finding> Findings { get; init; } = new();

    /// <summary>Renseigne si le collecteur a echoue (outil absent, permission refusee...).</summary>
    public string? Error { get; set; }

    public DateTimeOffset CollectedAt { get; init; } = DateTimeOffset.UtcNow;
    public double DurationMs { get; set; }
}
