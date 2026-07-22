using Checksec.Mac.Core;

namespace Checksec.Mac.Collectors;

/// <summary>
/// XProtect — antimalware integre d'Apple (equivalent Defender cote Windows).
/// Verifie la presence et la version des definitions XProtect.
/// </summary>
public sealed class XProtectCollector : MacCollectorBase
{
    // Emplacement des metadonnees XProtect (les definitions modernes vivent aussi
    // sous /Library/Apple/System/Library/CoreServices/XProtect.bundle).
    private const string XProtectPlist =
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist";

    public override string Name => "XProtect";
    public override string Category => "Antimalware";

    protected override async Task CollectCoreAsync(CollectorReport report, CancellationToken ct)
    {
        var res = await Run("/usr/bin/defaults", ct, "read", XProtectPlist, "CFBundleShortVersionString");
        var present = res.Success && !string.IsNullOrWhiteSpace(res.StdOut);
        var version = present ? res.StdOut.Trim() : null;

        report.Findings.Add(new Finding
        {
            Id = "XProtect.Present",
            Title = "Definitions antimalware XProtect",
            Severity = present ? Severity.Ok : Severity.Medium,
            Observed = present ? $"Version {version}" : "Introuvable",
            Expected = "Present et a jour",
            Detail = present
                ? "XProtect est present ; les signatures sont mises a jour par Apple en arriere-plan."
                : "Impossible de lire la version XProtect (droits insuffisants ou emplacement modifie).",
            Reference = "mSCP os_xprotect_version",
            MitreTechniques = new[] { "T1204" }
        });

        // XProtect Remediator (scans periodiques) — presence du bundle.
        var rem = await Run("/bin/ls", ct, "/Library/Apple/System/Library/CoreServices/XProtect.app");
        report.Findings.Add(new Finding
        {
            Id = "XProtect.Remediator",
            Title = "XProtect Remediator",
            Severity = rem.Success ? Severity.Ok : Severity.Info,
            Observed = rem.Success ? "Present" : "Non detecte",
            Detail = "Composant de remediation qui execute des scans planifies contre les familles de malwares connues."
        });
    }
}
