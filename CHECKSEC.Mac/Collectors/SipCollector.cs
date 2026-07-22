using Checksec.Mac.Core;

namespace Checksec.Mac.Collectors;

/// <summary>
/// System Integrity Protection — protection des fichiers/processus systeme
/// (analogue a la protection du noyau/PPL cote Windows) via <c>csrutil status</c>.
/// </summary>
public sealed class SipCollector : MacCollectorBase
{
    public override string Name => "SIP";
    public override string Category => "Integrite systeme";

    protected override async Task CollectCoreAsync(CollectorReport report, CancellationToken ct)
    {
        var res = await Run("/usr/bin/csrutil", ct, "status");
        var output = res.Combined;
        var enabled = output.Contains("status: enabled", StringComparison.OrdinalIgnoreCase);

        report.Findings.Add(new Finding
        {
            Id = "SIP.Enabled",
            Title = "System Integrity Protection (SIP)",
            Severity = enabled ? Severity.Ok : Severity.Critical,
            Observed = enabled ? "Active" : "Desactive",
            Expected = "Active",
            Detail = enabled
                ? "Les emplacements systeme proteges ne peuvent pas etre modifies, meme par root."
                : "SIP est desactive : un attaquant root peut alterer le systeme et persister durablement.",
            Remediation = enabled ? null : "Redemarrer en mode Recovery puis : csrutil enable",
            Reference = "CIS 5.1.x · mSCP os_sip_enable",
            MitreTechniques = new[] { "T1562.001" }
        });
    }
}
