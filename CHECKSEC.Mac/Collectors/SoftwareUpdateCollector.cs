using Checksec.Mac.Core;

namespace Checksec.Mac.Collectors;

/// <summary>
/// Politique de mise a jour automatique (equivalent Windows Update cote Windows).
/// Lit les cles com.apple.SoftwareUpdate.
/// </summary>
public sealed class SoftwareUpdateCollector : MacCollectorBase
{
    private const string Domain = "/Library/Preferences/com.apple.SoftwareUpdate";

    public override string Name => "Mises a jour";
    public override string Category => "Maintenance";

    protected override async Task CollectCoreAsync(CollectorReport report, CancellationToken ct)
    {
        await AddBoolFinding(report, ct, "AutomaticCheckEnabled",
            "Recherche automatique des mises a jour", Severity.Medium,
            "Le systeme verifie automatiquement la disponibilite des mises a jour.",
            "CIS 1.2 · mSCP os_auto_update_enforce");

        await AddBoolFinding(report, ct, "AutomaticDownload",
            "Telechargement automatique des mises a jour", Severity.Low,
            "Les mises a jour sont telechargees des qu'elles sont disponibles.",
            "CIS 1.3");

        await AddBoolFinding(report, ct, "CriticalUpdateInstall",
            "Installation automatique des correctifs de securite", Severity.High,
            "Les mises a jour de securite critiques (dont Rapid Security Response) s'installent automatiquement.",
            "CIS 1.5 · mSCP os_security_update_enforce");

        await AddBoolFinding(report, ct, "AutomaticallyInstallMacOSUpdates",
            "Installation automatique des mises a jour macOS", Severity.Low,
            "Les mises a jour majeures du systeme s'installent automatiquement.",
            "CIS 1.6");
    }

    private static async Task AddBoolFinding(
        CollectorReport report, CancellationToken ct,
        string key, string title, Severity failSeverity, string okDetail, string reference)
    {
        var res = await Run("/usr/bin/defaults", ct, "read", Domain, key);
        // defaults renvoie 1 / 0 ; absence de cle => valeur par defaut / non definie.
        var value = res.StdOut.Trim();
        var on = value == "1";
        var undefined = !res.Success;

        report.Findings.Add(new Finding
        {
            Id = $"SoftwareUpdate.{key}",
            Title = title,
            Severity = on ? Severity.Ok : (undefined ? Severity.Info : failSeverity),
            Observed = undefined ? "Non defini" : (on ? "Active" : "Desactive"),
            Expected = "Active",
            Detail = on ? okDetail
                        : undefined ? "Cle non definie : valeur par defaut du systeme."
                        : $"Desactive : {okDetail}",
            Remediation = on ? null : $"sudo defaults write {Domain} {key} -bool true",
            Reference = reference
        });
    }
}
