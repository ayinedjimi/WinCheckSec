using Checksec.Mac.Core;

namespace Checksec.Mac.Collectors;

/// <summary>
/// Services de partage/acces distant (equivalent RDP/SMB/services exposes cote Windows).
/// Un service active elargit la surface d'attaque reseau.
/// </summary>
public sealed class SharingCollector : MacCollectorBase
{
    public override string Name => "Services de partage";
    public override string Category => "Surface d'attaque";

    protected override async Task CollectCoreAsync(CollectorReport report, CancellationToken ct)
    {
        // Connexion distante SSH. systemsetup exige root ; sans droits on tombe sur launchctl.
        var ssh = await Run("/usr/sbin/systemsetup", ct, "-getremotelogin");
        bool? sshOn = ssh.Combined.Contains("On", StringComparison.OrdinalIgnoreCase) ? true
                    : ssh.Combined.Contains("Off", StringComparison.OrdinalIgnoreCase) ? false
                    : null;
        if (sshOn is null)
        {
            var lc = await Run("/bin/launchctl", ct, "print", "system/com.openssh.sshd");
            sshOn = lc.Success;
        }

        report.Findings.Add(new Finding
        {
            Id = "Sharing.RemoteLogin",
            Title = "Connexion distante (SSH)",
            Severity = sshOn == true ? Severity.Medium : Severity.Ok,
            Observed = sshOn == true ? "Active" : sshOn == false ? "Inactive" : "Indetermine",
            Expected = "Inactive (sauf besoin explicite)",
            Detail = sshOn == true
                ? "Le service SSH est en ecoute : verifier l'authentification par cle et la restriction d'acces."
                : "Aucun acces SSH entrant detecte.",
            Remediation = sshOn == true ? "sudo systemsetup -setremotelogin off" : null,
            Reference = "CIS 2.3.x · mSCP os_sshd_service_disable",
            MitreTechniques = new[] { "T1021.004" }
        });

        // Partage d'ecran (VNC/Screen Sharing).
        var screen = await Run("/bin/launchctl", ct, "print", "system/com.apple.screensharing");
        report.Findings.Add(new Finding
        {
            Id = "Sharing.ScreenSharing",
            Title = "Partage d'ecran",
            Severity = screen.Success ? Severity.Medium : Severity.Ok,
            Observed = screen.Success ? "Actif" : "Inactif",
            Expected = "Inactif (sauf besoin explicite)",
            Detail = screen.Success
                ? "Le partage d'ecran est active : acces graphique distant possible."
                : "Le partage d'ecran n'est pas actif.",
            Reference = "CIS 2.3.x · mSCP os_screen_sharing_disable",
            MitreTechniques = new[] { "T1021.005" }
        });
    }
}
