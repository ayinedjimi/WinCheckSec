using Checksec.Mac.Core;

namespace Checksec.Mac.Collectors;

/// <summary>
/// Gatekeeper — controle d'execution des apps signees/notariees
/// (equivalent SmartScreen cote Windows) via <c>spctl --status</c>.
/// </summary>
public sealed class GatekeeperCollector : MacCollectorBase
{
    public override string Name => "Gatekeeper";
    public override string Category => "Controle applicatif";

    protected override async Task CollectCoreAsync(CollectorReport report, CancellationToken ct)
    {
        var res = await Run("/usr/sbin/spctl", ct, "--status");
        var output = res.Combined;
        var enabled = output.Contains("assessments enabled", StringComparison.OrdinalIgnoreCase);

        report.Findings.Add(new Finding
        {
            Id = "Gatekeeper.Enabled",
            Title = "Gatekeeper (evaluation des applications)",
            Severity = enabled ? Severity.Ok : Severity.High,
            Observed = enabled ? "Active" : "Desactive",
            Expected = "Active",
            Detail = enabled
                ? "Seules les applications signees/notariees peuvent s'executer sans confirmation."
                : "Gatekeeper est desactive : des applications non signees peuvent s'executer librement.",
            Remediation = enabled ? null : "sudo spctl --master-enable",
            Reference = "CIS 2.6.2 · mSCP os_gatekeeper_enable",
            MitreTechniques = new[] { "T1553.001" }
        });
    }
}
