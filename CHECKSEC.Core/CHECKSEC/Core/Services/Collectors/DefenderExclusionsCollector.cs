using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services.Helpers;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur dédié aux ANGLES MORTS de Windows Defender :
//   - Exclusions (chemins, extensions, processus, IP) — surface d'angle mort classique
//   - Planification et fraîcheur des analyses
//   - Modes précis (MAPS/Cloud, Network Protection, PUA, SmartScreen)
// Ne duplique PAS les vérifications de DefenderCollector (temps réel, tamper, signatures de base).
public class DefenderExclusionsCollector : ISecurityCollector
{
	// Espace de noms WMI de Windows Defender (préfixe \\.\ requis par ManagementScope).
	private const string DefenderWmiNamespace = "\\\\.\\root\\Microsoft\\Windows\\Defender";

	// Racine registre des exclusions (souvent illisible sans SYSTEM).
	private const string ExclusionsRegKey = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions";

	public string Name => "Defender — Exclusions & Analyses";

	public string Category => "Antivirus";

	public Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport collectorReport = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch stopwatch = Stopwatch.StartNew();
		try
		{
			ct.ThrowIfCancellationRequested();
			// 1) Exclusions (WMI MSFT_MpPreference, repli registre)
			CollectExclusions(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			// 2) Planification d'analyse + dernière analyse + modes (MAPS, NP, PUA)
			CollectMpPreferenceSettings(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectScanAges(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			// 3) SmartScreen mode précis (registre uniquement)
			CollectSmartScreenMode(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "DefenderExclusionsCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// =====================================================================
	//  EXCLUSIONS
	// =====================================================================
	private void CollectExclusions(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// Récupération des 4 types d'exclusions depuis MSFT_MpPreference.
		List<string> exclusionPaths = new List<string>();
		List<string> exclusionExtensions = new List<string>();
		List<string> exclusionProcesses = new List<string>();
		List<string> exclusionIps = new List<string>();
		bool wmiOk = false;

		try
		{
			// MSFT_MpPreference expose les exclusions sous forme de tableaux de chaînes.
			foreach (ManagementObject pref in WmiHelper.Query("SELECT ExclusionPath, ExclusionExtension, ExclusionProcess, ExclusionIpAddress FROM MSFT_MpPreference", DefenderWmiNamespace))
			{
				try
				{
					ct.ThrowIfCancellationRequested();
					exclusionPaths.AddRange(ReadStringArray(pref, "ExclusionPath"));
					exclusionExtensions.AddRange(ReadStringArray(pref, "ExclusionExtension"));
					exclusionProcesses.AddRange(ReadStringArray(pref, "ExclusionProcess"));
					exclusionIps.AddRange(ReadStringArray(pref, "ExclusionIpAddress"));
					wmiOk = true;
				}
				finally
				{
					((IDisposable)pref)?.Dispose();
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			// WMI indisponible : on tente le repli registre (souvent illisible sans SYSTEM).
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Exclusions Defender (WMI)",
				CurrentValue = "Erreur WMI : " + ex.Message,
				ExpectedValue = "MSFT_MpPreference lisible",
				Status = SecurityStatus.Info,
				Description = "Impossible d'interroger MSFT_MpPreference pour lister les exclusions. Repli sur le registre en cours (généralement illisible sans privilèges SYSTEM).",
				Recommendation = "Exécuter en tant qu'administrateur/SYSTEM et vérifier que le service Windows Defender est actif.",
				Reference = "https://learn.microsoft.com/powershell/module/defender/get-mppreference"
			});
		}

		// Repli registre si WMI n'a rien retourné.
		if (!wmiOk)
		{
			bool registryReadable = TryReadExclusionsFromRegistry(exclusionPaths, exclusionExtensions, exclusionProcesses);
			if (!registryReadable)
			{
				// Cas fréquent : la clé Exclusions est protégée (ACL SYSTEM only) → non fatal.
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Exclusions Defender (registre)",
					CurrentValue = "Non lisibles (accès refusé ou clés absentes)",
					ExpectedValue = "Lisibles",
					Status = SecurityStatus.Info,
					Description = "La clé HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions est habituellement protégée et illisible sans le contexte SYSTEM. L'inventaire des exclusions n'a pas pu être établi.",
					Recommendation = "Relancer l'analyse avec des privilèges SYSTEM (ex. via PsExec -s) ou vérifier les exclusions via 'Get-MpPreference'.",
					Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-exclusions-microsoft-defender-antivirus"
				});
				return;
			}
		}

		// Émet un résultat par type d'exclusion.
		AddExclusionResult(results, "Exclusions de chemins (ExclusionPath)", exclusionPaths, isPathType: true, isExtensionType: false);
		AddExclusionResult(results, "Exclusions d'extensions (ExclusionExtension)", exclusionExtensions, isPathType: false, isExtensionType: true);
		AddExclusionResult(results, "Exclusions de processus (ExclusionProcess)", exclusionProcesses, isPathType: false, isExtensionType: false);
		AddExclusionResult(results, "Exclusions d'adresses IP (ExclusionIpAddress)", exclusionIps, isPathType: false, isExtensionType: false);
	}

	// Ajoute un SecurityResult pour un type d'exclusion donné, avec évaluation de sévérité.
	private void AddExclusionResult(List<SecurityResult> results, string checkName, List<string> exclusions, bool isPathType, bool isExtensionType)
	{
		// Dédoublonnage défensif.
		List<string> unique = exclusions
			.Where(e => !string.IsNullOrWhiteSpace(e))
			.Select(e => e.Trim())
			.Distinct(StringComparer.OrdinalIgnoreCase)
			.ToList();

		if (unique.Count == 0)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = checkName,
				CurrentValue = "Aucune exclusion",
				ExpectedValue = "Aucune ou strictement justifiée",
				Status = SecurityStatus.OK,
				Description = "Aucune exclusion de ce type n'est configurée. Les exclusions constituent un angle mort : les fichiers/processus exclus ne sont pas analysés par l'antivirus.",
				Recommendation = "Aucune action. Continuer à limiter les exclusions au strict nécessaire.",
				Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-exclusions-microsoft-defender-antivirus"
			});
			return;
		}

		// Détection des exclusions dangereuses.
		List<string> dangerous = new List<string>();
		foreach (string entry in unique)
		{
			if (isExtensionType)
			{
				if (IsDangerousExtension(entry))
				{
					dangerous.Add(entry);
				}
			}
			else if (isPathType)
			{
				if (IsDangerousPath(entry))
				{
					dangerous.Add(entry);
				}
			}
		}

		bool hasDangerous = dangerous.Count > 0;
		string detail = string.Join(", ", unique.Count > 20 ? unique.Take(20) : unique)
			+ (unique.Count > 20 ? $" ... +{unique.Count - 20} autres" : "");

		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = checkName,
			CurrentValue = $"{unique.Count} exclusion(s) : {detail}"
				+ (hasDangerous ? $" | DANGEREUSES : {string.Join(", ", dangerous)}" : ""),
			ExpectedValue = "Aucune exclusion large ou exécutable",
			// Sévérité : dangereuse → Critical ; sinon présence → Warning.
			Status = (hasDangerous ? SecurityStatus.Critical : SecurityStatus.Warning),
			Description = "Les exclusions Windows Defender désactivent l'analyse pour les éléments listés. C'est un angle mort exploité par les attaquants : un malware placé dans un chemin exclu (ou portant une extension exclue) ne sera jamais détecté."
				+ (hasDangerous ? " Certaines exclusions sont particulièrement dangereuses (racine système, dossiers utilisateurs/Temp, ou extensions exécutables)." : ""),
			Recommendation = (hasDangerous
				? "CRITIQUE : supprimer immédiatement les exclusions larges ou exécutables (racines type C:\\, C:\\Users, \\Temp, ou .exe/.dll/.ps1). Vérifier qu'elles n'ont pas été ajoutées par un attaquant pour masquer une charge utile."
				: "Auditer chaque exclusion et supprimer celles qui ne sont plus justifiées. Restreindre au maximum leur périmètre."),
			Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-exclusions-microsoft-defender-antivirus"
		});
	}

	// =====================================================================
	//  PLANIFICATION & MODES (MSFT_MpPreference)
	// =====================================================================
	private void CollectMpPreferenceSettings(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		ManagementObject pref = null;
		try
		{
			pref = WmiHelper.Query("SELECT ScanScheduleDay, ScanScheduleQuickScanTime, ScanParameters, MAPSReporting, SubmitSamplesConsent, EnableNetworkProtection, PUAProtection FROM MSFT_MpPreference", DefenderWmiNamespace).FirstOrDefault();
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Paramètres MpPreference (planification/modes)",
				CurrentValue = "Erreur WMI : " + ex.Message,
				ExpectedValue = "MSFT_MpPreference lisible",
				Status = SecurityStatus.Info,
				Description = "Impossible d'interroger MSFT_MpPreference pour la planification et les modes de protection.",
				Recommendation = "Vérifier que le service Windows Defender est actif et que l'analyse s'exécute avec des privilèges suffisants.",
				Reference = "https://learn.microsoft.com/powershell/module/defender/get-mppreference"
			});
			return;
		}

		if (pref == null)
		{
			return;
		}

		try
		{
			// --- Planification de l'analyse ---
			TryAdd(results, delegate
			{
				// ScanScheduleDay : 0=Tous les jours, 1..7=jour de semaine, 8=Jamais.
				int scanDay = WmiInt(pref, "ScanScheduleDay");
				int scanParameters = WmiInt(pref, "ScanParameters"); // 1=Quick, 2=Full
				string quickTime = FormatScanTime(WmiInt(pref, "ScanScheduleQuickScanTime"));
				bool neverScheduled = scanDay == 8;
				string dayLabel = scanDay switch
				{
					0 => "0 - Tous les jours",
					1 => "1 - Dimanche",
					2 => "2 - Lundi",
					3 => "3 - Mardi",
					4 => "4 - Mercredi",
					5 => "5 - Jeudi",
					6 => "6 - Vendredi",
					7 => "7 - Samedi",
					8 => "8 - Jamais",
					_ => $"{scanDay} - Inconnu",
				};
				string scanTypeLabel = scanParameters switch
				{
					1 => "Analyse rapide",
					2 => "Analyse complète",
					_ => "Non défini",
				};
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Planification d'analyse",
					CurrentValue = $"Jour={dayLabel}, Heure rapide={quickTime}, Type={scanTypeLabel}",
					ExpectedValue = "Analyse planifiée (au moins hebdomadaire)",
					Status = (neverScheduled ? SecurityStatus.Warning : ((scanDay >= 0 && scanDay <= 7) ? SecurityStatus.OK : SecurityStatus.Info)),
					Description = "Une analyse planifiée régulière détecte les menaces dormantes que la protection en temps réel a pu manquer (fichiers déposés avant activation, exclusions temporaires levées, etc.).",
					Recommendation = (neverScheduled
						? "Aucune analyse planifiée (ScanScheduleDay=8). Configurer une analyse au moins hebdomadaire via GPO/Intune ou 'Set-MpPreference -ScanScheduleDay 0'."
						: "Analyse planifiée configurée."),
					Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/schedule-antivirus-scans"
				};
			});

			// --- MAPS / Cloud ---
			TryAdd(results, delegate
			{
				// MAPSReporting : 0=Désactivé, 1=Basique, 2=Avancé.
				int maps = WmiInt(pref, "MAPSReporting");
				int submit = WmiInt(pref, "SubmitSamplesConsent");
				string mapsLabel = maps switch
				{
					0 => "0 - Désactivé",
					1 => "1 - Basique",
					2 => "2 - Avancé (recommandé)",
					_ => $"{maps} - Inconnu",
				};
				string submitLabel = submit switch
				{
					0 => "0 - Toujours demander",
					1 => "1 - Envoi auto échantillons sûrs",
					2 => "2 - Ne jamais envoyer",
					3 => "3 - Envoi auto de tous les échantillons",
					_ => $"{submit}",
				};
				return new SecurityResult
				{
					Category = Category,
					CheckName = "MAPS / Protection cloud",
					CurrentValue = $"MAPSReporting={mapsLabel}, SubmitSamplesConsent={submitLabel}",
					ExpectedValue = "MAPSReporting=2 (Avancé)",
					Status = (maps == 0 ? SecurityStatus.Warning : (maps == 2 ? SecurityStatus.OK : SecurityStatus.Info)),
					Description = "MAPS (Microsoft Active Protection Service) est la protection cloud de Defender. Le mode Avancé accélère la détection des menaces émergentes en s'appuyant sur l'intelligence cloud et l'envoi d'échantillons.",
					Recommendation = (maps == 2
						? "Protection cloud au niveau Avancé."
						: (maps == 0
							? "Protection cloud désactivée. Activer via 'Set-MpPreference -MAPSReporting Advanced'."
							: "Passer la protection cloud en mode Avancé (MAPSReporting=2) pour une détection optimale.")),
					Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/cloud-protection-microsoft-defender-antivirus"
				};
			});

			// --- Network Protection (mode distinct de l'ASR) ---
			TryAdd(results, delegate
			{
				// EnableNetworkProtection : 0=Off, 1=Block, 2=Audit.
				int np = WmiInt(pref, "EnableNetworkProtection");
				string npLabel = np switch
				{
					0 => "0 - Désactivé",
					1 => "1 - Block",
					2 => "2 - Audit",
					_ => $"{np} - Inconnu",
				};
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Network Protection (mode)",
					CurrentValue = npLabel,
					ExpectedValue = "1 (Block)",
					Status = (np == 1 ? SecurityStatus.OK : SecurityStatus.Warning),
					Description = "Network Protection bloque les connexions sortantes vers des IP/domaines malveillants connus (C2, phishing, exploits). Le mode Audit journalise sans bloquer, laissant la menace active.",
					Recommendation = (np == 1
						? "Network Protection en mode Block."
						: (np == 2
							? "Network Protection en mode Audit (ne bloque pas). Passer en mode Block : 'Set-MpPreference -EnableNetworkProtection Enabled'."
							: "Network Protection désactivée. L'activer en mode Block.")),
					Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/enable-network-protection"
				};
			});

			// --- PUA Protection ---
			TryAdd(results, delegate
			{
				// PUAProtection : 0=Off, 1=Block, 2=Audit.
				int pua = WmiInt(pref, "PUAProtection");
				string puaLabel = pua switch
				{
					0 => "0 - Désactivé",
					1 => "1 - Block",
					2 => "2 - Audit",
					_ => $"{pua} - Inconnu",
				};
				return new SecurityResult
				{
					Category = Category,
					CheckName = "PUA Protection (mode)",
					CurrentValue = puaLabel,
					ExpectedValue = "1 (Block)",
					Status = (pua == 1 ? SecurityStatus.OK : SecurityStatus.Warning),
					Description = "La protection contre les applications potentiellement indésirables (PUA) bloque adwares, mineurs et logiciels groupés qui dégradent la sécurité. Le mode Audit ne bloque pas.",
					Recommendation = (pua == 1
						? "PUA Protection en mode Block."
						: (pua == 2
							? "PUA Protection en mode Audit. Passer en Block : 'Set-MpPreference -PUAProtection Enabled'."
							: "PUA Protection désactivée. L'activer en mode Block.")),
					Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus"
				};
			});
		}
		finally
		{
			((IDisposable)pref)?.Dispose();
		}
	}

	// =====================================================================
	//  DERNIÈRE ANALYSE (MSFT_MpComputerStatus)
	// =====================================================================
	private void CollectScanAges(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		ManagementObject status = null;
		try
		{
			status = WmiHelper.Query("SELECT QuickScanAge, FullScanAge FROM MSFT_MpComputerStatus", DefenderWmiNamespace).FirstOrDefault();
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Fraîcheur des analyses",
				CurrentValue = "Erreur WMI : " + ex.Message,
				ExpectedValue = "MSFT_MpComputerStatus lisible",
				Status = SecurityStatus.Info,
				Description = "Impossible d'interroger MSFT_MpComputerStatus pour la date des dernières analyses.",
				Recommendation = "Vérifier que Windows Defender est actif.",
				Reference = "https://learn.microsoft.com/powershell/module/defender/get-mpcomputerstatus"
			});
			return;
		}

		if (status == null)
		{
			return;
		}

		try
		{
			// QuickScanAge / FullScanAge en jours. Valeur très élevée (ex. 4294967295) = jamais.
			TryAdd(results, () => BuildScanAgeResult("Dernière analyse rapide (QuickScanAge)", WmiLong(status, "QuickScanAge"), "rapide"));
			TryAdd(results, () => BuildScanAgeResult("Dernière analyse complète (FullScanAge)", WmiLong(status, "FullScanAge"), "complète"));
		}
		finally
		{
			((IDisposable)status)?.Dispose();
		}
	}

	private SecurityResult BuildScanAgeResult(string checkName, long ageDays, string scanType)
	{
		// Une valeur négative ou >= UInt32.MaxValue indique « jamais analysé ».
		bool never = ageDays < 0 || ageDays >= 4294967295L;
		bool stale = !never && ageDays > 7;
		return new SecurityResult
		{
			Category = Category,
			CheckName = checkName,
			CurrentValue = (never ? "Jamais" : $"{ageDays} jour(s)"),
			ExpectedValue = "<= 7 jours",
			Status = (never ? SecurityStatus.Warning : (stale ? SecurityStatus.Warning : SecurityStatus.OK)),
			Description = $"Nombre de jours écoulés depuis la dernière analyse {scanType}. Une analyse trop ancienne laisse le temps à des menaces dormantes de rester non détectées.",
			Recommendation = (never
				? $"Aucune analyse {scanType} n'a jamais été exécutée. Lancer une analyse et planifier des exécutions régulières."
				: (stale
					? $"La dernière analyse {scanType} remonte à plus de 7 jours. Vérifier la planification des analyses."
					: $"Analyse {scanType} récente.")),
			Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/schedule-antivirus-scans"
		};
	}

	// =====================================================================
	//  SMARTSCREEN (mode précis, registre)
	// =====================================================================
	private void CollectSmartScreenMode(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\System");
			// ShellSmartScreenLevel : "Block" (bloque) ou "Warn" (avertit seulement).
			string level = systemKey?.GetValue("ShellSmartScreenLevel")?.ToString();
			object enableValue = systemKey?.GetValue("EnableSmartScreen");
			int enable = ((enableValue != null) ? Convert.ToInt32(enableValue) : (-1));
			bool isBlock = string.Equals(level, "Block", StringComparison.OrdinalIgnoreCase);
			bool isWarn = string.Equals(level, "Warn", StringComparison.OrdinalIgnoreCase);
			bool enabled = enable == 1;
			// SmartScreen désactivé → Warning ; activé mais mode Warn → Warning ; Block → OK.
			SecurityStatus st;
			if (enable == 0)
			{
				st = SecurityStatus.Warning;
			}
			else if (isBlock)
			{
				st = SecurityStatus.OK;
			}
			else if (isWarn || enabled)
			{
				st = SecurityStatus.Warning;
			}
			else
			{
				st = SecurityStatus.Info;
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "SmartScreen — mode précis",
				CurrentValue = $"EnableSmartScreen={(enable == -1 ? "Non configuré" : enable.ToString())}, ShellSmartScreenLevel={(level ?? "Non configuré")}",
				ExpectedValue = "EnableSmartScreen=1 et ShellSmartScreenLevel=Block",
				Status = st,
				Description = "SmartScreen vérifie les fichiers/applications contre une base cloud de réputation. Le mode 'Block' empêche l'exécution des éléments non reconnus, alors que 'Warn' se contente d'un avertissement contournable par l'utilisateur.",
				Recommendation = (isBlock
					? "SmartScreen configuré en mode Block."
					: (enable == 0
						? "SmartScreen désactivé. L'activer via GPO (EnableSmartScreen=1) et fixer ShellSmartScreenLevel=Block."
						: "SmartScreen en mode 'Warn' (contournable). Fixer HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\ShellSmartScreenLevel = Block.")),
				Reference = "https://learn.microsoft.com/windows/security/threat-protection/microsoft-defender-smartscreen/microsoft-defender-smartscreen-overview"
			};
		});
	}

	// =====================================================================
	//  REPLI REGISTRE POUR LES EXCLUSIONS
	// =====================================================================
	// Retourne true si au moins une des sous-clés a pu être ouverte (donc lisible).
	private bool TryReadExclusionsFromRegistry(List<string> paths, List<string> extensions, List<string> processes)
	{
		bool anyReadable = false;
		anyReadable |= TryReadExclusionSubKey("Paths", paths);
		anyReadable |= TryReadExclusionSubKey("Extensions", extensions);
		anyReadable |= TryReadExclusionSubKey("Processes", processes);
		return anyReadable;
	}

	private bool TryReadExclusionSubKey(string subKeyName, List<string> target)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey exclusionsKey = baseKey.OpenSubKey(ExclusionsRegKey + "\\" + subKeyName);
			if (exclusionsKey == null)
			{
				return false;
			}
			// Les exclusions sont stockées comme NOMS de valeurs (la donnée vaut 0).
			foreach (string valueName in exclusionsKey.GetValueNames())
			{
				if (!string.IsNullOrWhiteSpace(valueName))
				{
					target.Add(valueName);
				}
			}
			return true;
		}
		catch
		{
			// Accès refusé (ACL SYSTEM) ou autre : non lisible, non fatal.
			return false;
		}
	}

	// =====================================================================
	//  HEURISTIQUES DE DANGEROSITÉ
	// =====================================================================
	private static bool IsDangerousPath(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return false;
		}
		string p = path.Trim().TrimEnd('\\', '/').ToLowerInvariant();
		// Racines de lecteur type "C:" ou "C:\".
		if (p.Length <= 3 && p.EndsWith(":"))
		{
			return true;
		}
		// Dossiers profils/utilisateurs et Temp = très larges.
		string[] dangerousRoots = new[]
		{
			"c:\\users",
			"c:\\programdata",
			"c:\\windows\\temp",
			"c:\\temp",
		};
		if (dangerousRoots.Any(r => p == r))
		{
			return true;
		}
		// Tout chemin contenant un segment \temp\ ou se terminant par \temp.
		if (p.Contains("\\temp\\") || p.EndsWith("\\temp"))
		{
			return true;
		}
		return false;
	}

	private static bool IsDangerousExtension(string ext)
	{
		if (string.IsNullOrWhiteSpace(ext))
		{
			return false;
		}
		string e = ext.Trim().TrimStart('*', '.').ToLowerInvariant();
		string[] executableExtensions = new[]
		{
			"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "scr", "com", "msi", "hta", "wsf"
		};
		return executableExtensions.Contains(e);
	}

	// =====================================================================
	//  HELPERS WMI
	// =====================================================================
	// Lit une propriété tableau de chaînes (les exclusions WMI sont des string[]).
	private static IEnumerable<string> ReadStringArray(ManagementObject obj, string prop)
	{
		try
		{
			object raw = obj[prop];
			if (raw is string[] arr)
			{
				return arr.Where(s => !string.IsNullOrWhiteSpace(s));
			}
			if (raw is string single && !string.IsNullOrWhiteSpace(single))
			{
				return new[] { single };
			}
		}
		catch
		{
		}
		return Array.Empty<string>();
	}

	private static int WmiInt(ManagementObject obj, string prop, int def = -1)
	{
		try
		{
			object rawValue = obj[prop];
			return (rawValue != null && !(rawValue is DBNull)) ? Convert.ToInt32(rawValue) : def;
		}
		catch
		{
			return def;
		}
	}

	private static long WmiLong(ManagementObject obj, string prop, long def = -1)
	{
		try
		{
			object rawValue = obj[prop];
			return (rawValue != null && !(rawValue is DBNull)) ? Convert.ToInt64(rawValue) : def;
		}
		catch
		{
			return def;
		}
	}

	// Convertit ScanScheduleQuickScanTime (minutes depuis minuit) en HH:mm.
	private static string FormatScanTime(int minutesSinceMidnight)
	{
		if (minutesSinceMidnight < 0 || minutesSinceMidnight >= 1440)
		{
			return "Non défini";
		}
		int h = minutesSinceMidnight / 60;
		int m = minutesSinceMidnight % 60;
		return $"{h:D2}:{m:D2}";
	}

	private static void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			results.Add(factory());
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = "Antivirus",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier l'accès WMI et registre pour Windows Defender.",
				Reference = ""
			});
		}
	}
}
