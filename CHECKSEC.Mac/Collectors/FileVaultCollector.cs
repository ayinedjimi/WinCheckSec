using Checksec.Mac.Core;

namespace Checksec.Mac.Collectors;

/// <summary>Chiffrement du disque (equivalent BitLocker cote Windows) via <c>fdesetup status</c>.</summary>
public sealed class FileVaultCollector : MacCollectorBase
{
    public override string Name => "FileVault";
    public override string Category => "Chiffrement";

    protected override async Task CollectCoreAsync(CollectorReport report, CancellationToken ct)
    {
        var res = await Run("/usr/bin/fdesetup", ct, "status");
        var output = res.Combined;
        var on = output.Contains("FileVault is On", StringComparison.OrdinalIgnoreCase);

        report.Findings.Add(new Finding
        {
            Id = "FileVault.Enabled",
            Title = "Chiffrement FileVault du disque de demarrage",
            Severity = on ? Severity.Ok : Severity.High,
            Observed = on ? "Actif" : "Inactif",
            Expected = "Actif",
            Detail = on
                ? "Le volume systeme est chiffre par FileVault."
                : "Le disque n'est pas chiffre : en cas de vol, les donnees sont lisibles.",
            Remediation = on ? null : "sudo fdesetup enable",
            Reference = "CIS 2.6.1.1 · mSCP os_filevault_enable",
            MitreTechniques = new[] { "T1005" }
        });

        // Detection d'un deploiement en cours (chiffrement partiel).
        if (output.Contains("Encryption in progress", StringComparison.OrdinalIgnoreCase))
        {
            report.Findings.Add(new Finding
            {
                Id = "FileVault.InProgress",
                Title = "Chiffrement FileVault en cours",
                Severity = Severity.Medium,
                Observed = "Chiffrement partiel",
                Detail = "Le chiffrement n'est pas termine : protection incomplete jusqu'a son achevement."
            });
        }
    }
}
