using Checksec.Mac.Core;

namespace Checksec.Mac.Collectors;

/// <summary>
/// Pare-feu applicatif macOS (equivalent pare-feu Windows Defender) via
/// <c>socketfilterfw</c>. Verifie l'etat global et le mode furtif.
/// </summary>
public sealed class FirewallCollector : MacCollectorBase
{
    private const string Alf = "/usr/libexec/ApplicationFirewall/socketfilterfw";

    public override string Name => "Pare-feu applicatif";
    public override string Category => "Reseau";

    protected override async Task CollectCoreAsync(CollectorReport report, CancellationToken ct)
    {
        var state = await Run(Alf, ct, "--getglobalstate");
        // "Firewall is enabled. (State = 1)" | "... (State = 2)" (bloque tout) | "State = 0"
        var enabled = state.Combined.Contains("enabled", StringComparison.OrdinalIgnoreCase)
                      && !state.Combined.Contains("State = 0");

        report.Findings.Add(new Finding
        {
            Id = "Firewall.Enabled",
            Title = "Pare-feu applicatif",
            Severity = enabled ? Severity.Ok : Severity.Medium,
            Observed = enabled ? "Actif" : "Inactif",
            Expected = "Actif",
            Detail = enabled
                ? "Le pare-feu applicatif filtre les connexions entrantes."
                : "Le pare-feu est desactive : tous les services en ecoute sont joignables.",
            Remediation = enabled ? null : $"sudo {Alf} --setglobalstate on",
            Reference = "CIS 2.2.1 · mSCP os_firewall_enable",
            MitreTechniques = new[] { "T1021" }
        });

        var stealth = await Run(Alf, ct, "--getstealthmode");
        var stealthOn = stealth.Combined.Contains("enabled", StringComparison.OrdinalIgnoreCase);
        report.Findings.Add(new Finding
        {
            Id = "Firewall.StealthMode",
            Title = "Mode furtif du pare-feu",
            Severity = stealthOn ? Severity.Ok : Severity.Low,
            Observed = stealthOn ? "Actif" : "Inactif",
            Expected = "Actif",
            Detail = stealthOn
                ? "La machine ne repond pas aux sondes ICMP/port fermes (moins visible sur le reseau)."
                : "Le mode furtif est inactif : la machine repond aux pings et scans de decouverte.",
            Remediation = stealthOn ? null : $"sudo {Alf} --setstealthmode on",
            Reference = "CIS 2.2.2 · mSCP os_firewall_stealth_enable"
        });
    }
}
