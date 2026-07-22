using System;
using System.Collections.Generic;
using System.Linq;

namespace CHECKSEC.Core.Services.Analysis;

/// <summary>
/// Décrit une technique MITRE ATT&CK associée à un contrôle de sécurité.
/// Id : identifiant ATT&CK (ex. T1003.001) ; Name : libellé ; Tactic : tactique ATT&CK.
/// </summary>
public sealed record MitreTechnique(string Id, string Name, string Tactic);

/// <summary>
/// Mappe les contrôles de sécurité de CHECKSEC vers le framework MITRE ATT&CK.
/// Le mapping est effectué UNIQUEMENT à l'export (léger, sans effet de bord) par
/// correspondance de mots-clés (insensible à la casse) sur le nom du contrôle et sa catégorie.
///
/// Principe de prudence : en cas de doute, on préfère ne RIEN mapper plutôt qu'un mapping faux.
/// Un contrôle peut correspondre à 0, 1 ou plusieurs techniques.
/// </summary>
public static class MitreMapper
{
	// Techniques réutilisées (instances partagées pour éviter les duplications).
	private static readonly MitreTechnique T1003_001 = new("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access");
	private static readonly MitreTechnique T1557_001 = new("T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay", "Credential Access");
	private static readonly MitreTechnique T1557 = new("T1557", "Adversary-in-the-Middle", "Credential Access");
	private static readonly MitreTechnique T1187 = new("T1187", "Forced Authentication", "Credential Access");
	private static readonly MitreTechnique T1548_002 = new("T1548.002", "Abuse Elevation Control Mechanism: Bypass User Account Control", "Privilege Escalation");
	private static readonly MitreTechnique T1562_001 = new("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion");
	private static readonly MitreTechnique T1562 = new("T1562", "Impair Defenses", "Defense Evasion");
	private static readonly MitreTechnique T1204_002 = new("T1204.002", "User Execution: Malicious File", "Execution");
	private static readonly MitreTechnique T1059_005 = new("T1059.005", "Command and Scripting Interpreter: Visual Basic", "Execution");
	private static readonly MitreTechnique T1059_001 = new("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution");
	private static readonly MitreTechnique T1547_001 = new("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence");
	private static readonly MitreTechnique T1546_012 = new("T1546.012", "Event Triggered Execution: Image File Execution Options Injection", "Privilege Escalation");
	private static readonly MitreTechnique T1546_015 = new("T1546.015", "Event Triggered Execution: Component Object Model Hijacking", "Persistence");
	private static readonly MitreTechnique T1546_010 = new("T1546.010", "Event Triggered Execution: AppInit DLLs", "Persistence");
	private static readonly MitreTechnique T1546_009 = new("T1546.009", "Event Triggered Execution: AppCert DLLs", "Persistence");
	private static readonly MitreTechnique T1053_005 = new("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence");
	// Correctif N1: T1543_003 (Windows Service) supprimé — mapping « Service » retiré (faux positifs).
	private static readonly MitreTechnique T1021_001 = new("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement");
	private static readonly MitreTechnique T1021_006 = new("T1021.006", "Remote Services: Windows Remote Management", "Lateral Movement");
	private static readonly MitreTechnique T1558 = new("T1558", "Steal or Forge Kerberos Tickets", "Credential Access");
	private static readonly MitreTechnique T1068 = new("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation");
	private static readonly MitreTechnique T1553_006 = new("T1553.006", "Subvert Trust Controls: Code Signing Policy Modification", "Defense Evasion");
	private static readonly MitreTechnique T1547_005 = new("T1547.005", "Boot or Logon Autostart Execution: Security Support Provider", "Persistence");
	private static readonly MitreTechnique T1091 = new("T1091", "Replication Through Removable Media", "Lateral Movement");
	private static readonly MitreTechnique T1090 = new("T1090", "Proxy", "Command and Control");

	/// <summary>
	/// Une règle de correspondance : si l'un des <see cref="Keywords"/> apparaît (insensible à la casse)
	/// dans le nom du contrôle ou dans la catégorie, alors les <see cref="Techniques"/> sont ajoutées.
	/// <see cref="RequireAlso"/> (optionnel) impose une condition ET supplémentaire : au moins un de
	/// ces motifs doit AUSSI être présent pour que la règle s'applique (resserrement des faux positifs).
	/// </summary>
	private sealed record MappingRule(string[] Keywords, MitreTechnique[] Techniques, string[]? RequireAlso = null);

	// Table de correspondance mot-clé -> technique(s). Ordre = ordre d'évaluation.
	private static readonly MappingRule[] Rules = new[]
	{
		// --- Credential Access : vol d'identifiants LSASS ---
		new MappingRule(new[] { "WDigest", "LSASS", "Credential Guard", "RunAsPPL", "LSA Protection" }, new[] { T1003_001 }),

		// --- Credential Access : empoisonnement de résolution de noms ---
		// Correctif N1: « NBT » court retiré (trop générique) → on exige « NBT-NS ».
		new MappingRule(new[] { "LLMNR", "NBT-NS", "mDNS", "WPAD" }, new[] { T1557_001 }),

		// --- Credential Access : SMB signing (relais AiTM) ---
		new MappingRule(new[] { "SMB Signing", "SMB signing" }, new[] { T1557 }),

		// --- Credential Access : NTLM / rétro-compatibilité LM ---
		new MappingRule(new[] { "NTLM", "LmCompatibility" }, new[] { T1187 }),

		// --- Privilege Escalation : élévation via installeur MSI ---
		new MappingRule(new[] { "AlwaysInstallElevated" }, new[] { T1548_002 }),

		// --- Privilege Escalation : contournement UAC ---
		new MappingRule(new[] { "UAC" }, new[] { T1548_002 }),

		// --- Defense Evasion : AMSI ---
		new MappingRule(new[] { "AMSI" }, new[] { T1562_001 }),

		// --- Defense Evasion : désactivation/altération de l'antivirus (Defender) ---
		new MappingRule(new[] { "Defender", "Exclusion", "DisableAntiVirus", "DisableRealtime" }, new[] { T1562_001 }),

		// --- Defense Evasion : Attack Surface Reduction ---
		new MappingRule(new[] { "ASR", "Attack Surface Reduction" }, new[] { T1562 }),

		// --- Execution : macros Office / VBA (exécution utilisateur + interpréteur VBA) ---
		// Correctif N1: « Office » seul retiré (matchait tout contrôle Office). On ne mappe que
		// sur des vecteurs réels : Macro, VBA, ActiveX ou DDE.
		new MappingRule(new[] { "Macro", "VBA", "ActiveX", "DDE" }, new[] { T1204_002, T1059_005 }),

		// --- Execution : PowerShell ---
		new MappingRule(new[] { "PowerShell" }, new[] { T1059_001 }),

		// --- Persistence : clés Run / dossiers de démarrage / Winlogon ---
		new MappingRule(new[] { "Run Key", "RunOnce", "Autoruns", "Startup", "Winlogon" }, new[] { T1547_001 }),

		// --- Persistence/PrivEsc : IFEO / touches d'accessibilité ---
		new MappingRule(new[] { "IFEO", "Accessibility", "sethc", "utilman" }, new[] { T1546_012 }),

		// --- Persistence : détournement COM ---
		new MappingRule(new[] { "COM Hijack" }, new[] { T1546_015 }),

		// --- Persistence : AppInit DLLs ---
		new MappingRule(new[] { "AppInit" }, new[] { T1546_010 }),

		// --- Persistence : AppCert DLLs ---
		new MappingRule(new[] { "AppCertDlls", "AppCert" }, new[] { T1546_009 }),

		// --- Execution/Persistence : tâches planifiées ---
		new MappingRule(new[] { "Scheduled Task", "schtasks" }, new[] { T1053_005 }),

		// --- Persistence : services Windows ---
		// Correctif N1: mapping T1543.003 basé sur « Service » RETIRÉ. Le mot-clé « Service »
		// était bien trop générique (Print Spooler, Remote Registry, etc.) et aucun collecteur
		// ne détecte réellement la création de service malveillant → 19 faux positifs au re-audit.

		// --- Lateral Movement : RDP ---
		new MappingRule(new[] { "RDP", "Bureau à distance" }, new[] { T1021_001 }),

		// --- Lateral Movement : WinRM / PowerShell Remoting ---
		new MappingRule(new[] { "WinRM", "PowerShell Remoting" }, new[] { T1021_006 }),

		// --- Credential Access : Wi-Fi ouvert (contexte AiTM) ---
		// Correctif N1: « open » (sous-chaîne trop générique) retiré au profit de motifs explicites
		// correspondant au check WiFi réel.
		// Resserrement MITRE: le mot-clé générique « WiFi » est RETIRÉ — T1557 ne doit viser QUE les
		// réseaux ouverts (contexte AiTM), pas tout contrôle WiFi. On ne garde que les motifs explicites.
		new MappingRule(new[] { "réseau ouvert", "Réseaux ouverts", "open network" }, new[] { T1557 }),

		// --- Credential Access : Kerberos (types de chiffrement faibles) ---
		// Correctif N1: « RC4 » retiré (cipher Schannel, pas du Kerberoasting). On exige désormais
		// « Kerberos » ET (« encryption type » OU « chiffrement »).
		new MappingRule(new[] { "Kerberos" }, new[] { T1558 }, new[] { "encryption type", "chiffrement" }),

		// --- Privilege Escalation : pilotes vulnérables (BYOVD) ---
		new MappingRule(new[] { "Vulnerable Driver", "BYOVD", "Blocklist" }, new[] { T1068 }),

		// --- Defense Evasion : signature de pilotes / test signing ---
		new MappingRule(new[] { "Test Signing", "testsigning", "Driver Signature" }, new[] { T1553_006 }),

		// --- Persistence : Security Support Provider (LSA / paquets d'authentification) ---
		// Correctif N1: « SSP » seul (trop court) retiré → on exige « Security Support Provider » ou « LSA ».
		new MappingRule(new[] { "Security Package", "Authentication Package", "Security Support Provider", "LSA" }, new[] { T1547_005 }),

		// --- Privilege Escalation : spouleur d'impression (PrintNightmare) ---
		// Correctif N1: « Print » seul (trop générique) retiré → on exige « Spooler » ou « PrintNightmare ».
		new MappingRule(new[] { "Spooler", "PrintNightmare" }, new[] { T1068 }),

		// --- Lateral Movement / Initial Access : médias amovibles ---
		new MappingRule(new[] { "AutoRun", "AutoPlay", "USB", "Removable" }, new[] { T1091 }),

		// --- Command and Control : proxy / PAC ---
		new MappingRule(new[] { "Proxy", "AutoConfigURL", "PAC" }, new[] { T1090 }),
	};

	/// <summary>
	/// Retourne les techniques ATT&CK correspondant à un contrôle donné (0..n).
	/// Correspondance de mots-clés insensible à la casse sur <paramref name="checkName"/> et <paramref name="category"/>.
	/// </summary>
	/// <param name="checkName">Nom du contrôle (SecurityResult.CheckName).</param>
	/// <param name="category">Catégorie du contrôle (SecurityResult.Category).</param>
	public static IReadOnlyList<MitreTechnique> Map(string checkName, string category)
	{
		// Concatène les deux champs : un mot-clé peut apparaître dans l'un ou l'autre.
		string haystack = ((checkName ?? string.Empty) + " " + (category ?? string.Empty));

		// On préserve l'ordre et on évite les doublons (par Id).
		List<MitreTechnique> matches = new List<MitreTechnique>();
		HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		foreach (MappingRule rule in Rules)
		{
			bool ruleMatches = rule.Keywords.Any(k =>
				haystack.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0);

			// Condition ET optionnelle : au moins un motif de RequireAlso doit aussi être présent.
			if (ruleMatches && rule.RequireAlso != null)
			{
				ruleMatches = rule.RequireAlso.Any(k =>
					haystack.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0);
			}

			if (!ruleMatches)
			{
				continue;
			}

			foreach (MitreTechnique tech in rule.Techniques)
			{
				if (seen.Add(tech.Id))
				{
					matches.Add(tech);
				}
			}
		}

		return matches;
	}
}
