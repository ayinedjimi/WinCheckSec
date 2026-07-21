using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur AMSI (Antimalware Scan Interface).
// Vérifie l'enregistrement des providers AMSI, la présence du provider Microsoft Defender,
// les clés de désactivation d'AMSI et l'intégrité des DLL des providers.
// Contrat ISecurityCollector : constructeur sans paramètre.
public class AmsiCollector : ISecurityCollector
{
	// CLSID du provider AMSI de Microsoft Defender (Windows Defender IOfficeAntivirus).
	private const string DefenderProviderClsid = "{2781761E-28E0-4109-99FE-B9D127C57AFE}";

	public string Name => "AMSI";

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
			// Énumère les providers AMSI enregistrés et vérifie l'intégrité de leurs DLL.
			CollectAmsiProviders(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			// Vérifie les clés de politique désactivant AMSI (Windows Script).
			CollectAmsiDisableKeys(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			// Note explicite : la détection de patch mémoire runtime n'est pas couverte.
			CollectRuntimeCoverageNote(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "AmsiCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// Énumère HKLM\SOFTWARE\Microsoft\AMSI\Providers (les sous-clés sont des CLSID),
	// résout chaque CLSID vers sa DLL via HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32.
	private void CollectAmsiProviders(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// Structure locale décrivant un provider AMSI résolu.
		List<AmsiProvider> providers = new List<AmsiProvider>();
		bool enumerationFailed = false;

		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey providersKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\AMSI\\Providers");
			if (providersKey != null)
			{
				string[] clsids = providersKey.GetSubKeyNames();
				foreach (string clsid in clsids)
				{
					ct.ThrowIfCancellationRequested();
					AmsiProvider provider = new AmsiProvider
					{
						Clsid = clsid
					};
					ResolveProviderClsid(baseKey, clsid, provider);
					providers.Add(provider);
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch
		{
			enumerationFailed = true;
		}

		// 1) Résultat : liste des providers AMSI enregistrés.
		bool enumFailedCapture = enumerationFailed;
		List<AmsiProvider> providersCapture = providers;
		TryAdd(results, delegate
		{
			if (enumFailedCapture)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "AMSI: Providers enregistrés",
					CurrentValue = "Erreur de lecture du registre AMSI",
					ExpectedValue = "Au moins un provider AMSI (ex : Microsoft Defender)",
					Status = SecurityStatus.Error,
					Description = "Impossible d'énumérer HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers. AMSI (Antimalware Scan Interface) permet aux applications (PowerShell, VBScript, Office, etc.) de soumettre du contenu aux moteurs antivirus enregistrés avant exécution.",
					Recommendation = "Exécuter en tant qu'administrateur et vérifier l'intégrité du registre AMSI.",
					Reference = "https://learn.microsoft.com/windows/win32/amsi/antimalware-scan-interface-portal"
				};
			}
			int count = providersCapture.Count;
			string summary = ((count == 0)
				? "Aucun provider AMSI enregistré"
				: string.Join("; ", providersCapture.Select((AmsiProvider p) => p.FriendlyName + " " + p.Clsid)));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "AMSI: Providers enregistrés",
				CurrentValue = $"{count} provider(s) : {summary}",
				ExpectedValue = "Au moins un provider AMSI actif",
				// Aucun provider = Critical : AMSI ne peut analyser aucun contenu.
				Status = ((count == 0) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "AMSI délègue l'analyse du contenu (scripts, macros, chargements en mémoire) aux providers antimalware enregistrés sous HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers. Chaque sous-clé est un CLSID résolu vers une DLL via HKLM\\SOFTWARE\\Classes\\CLSID. En l'absence de tout provider, AMSI n'offre aucune protection : le contenu malveillant (PowerShell obfusqué, scripts fileless) n'est plus inspecté.",
				Recommendation = ((count == 0)
					? "CRITIQUE : Aucun provider AMSI enregistré. Vérifier que Microsoft Defender ou une solution AV compatible AMSI est installée et active. Une absence de provider peut indiquer une désactivation malveillante de l'antivirus."
					: "Des providers AMSI sont enregistrés. Vérifier qu'ils correspondent à des solutions antimalware légitimes."),
				Reference = "https://learn.microsoft.com/windows/win32/amsi/how-amsi-helps"
			};
		});

		// 2) Résultat : présence du provider AMSI de Microsoft Defender.
		TryAdd(results, delegate
		{
			bool defenderPresent = providersCapture.Any((AmsiProvider p) =>
				string.Equals(p.Clsid, DefenderProviderClsid, StringComparison.OrdinalIgnoreCase));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "AMSI: Provider Microsoft Defender",
				CurrentValue = (defenderPresent ? "Présent (" + DefenderProviderClsid + ")" : "Absent"),
				ExpectedValue = "Présent (" + DefenderProviderClsid + ")",
				Status = (defenderPresent ? SecurityStatus.OK : SecurityStatus.Warning),
				Description = "Le provider AMSI de Microsoft Defender (CLSID " + DefenderProviderClsid + ") est le moteur d'analyse AMSI par défaut sous Windows. Son absence peut être normale si une solution AV tierce fournit son propre provider AMSI, mais peut aussi trahir une désactivation de Defender par un attaquant.",
				Recommendation = (defenderPresent
					? "Le provider AMSI Microsoft Defender est enregistré."
					: "Provider AMSI Defender absent. Si aucun autre AV compatible AMSI n'est présent, réactiver Microsoft Defender. Vérifier qu'aucune manipulation n'a supprimé ce provider."),
				Reference = "https://learn.microsoft.com/windows/win32/amsi/antimalware-scan-interface-portal"
			};
		});

		// 3) Résultat : intégrité des DLL des providers (chemins non standard = indicateur de hijack).
		TryAdd(results, delegate
		{
			List<AmsiProvider> suspicious = providersCapture
				.Where((AmsiProvider p) => p.HasSuspiciousPath)
				.ToList();
			List<AmsiProvider> unresolved = providersCapture
				.Where((AmsiProvider p) => string.IsNullOrEmpty(p.DllPath))
				.ToList();

			bool hasSuspicious = suspicious.Count > 0;
			string details;
			if (hasSuspicious)
			{
				details = "Chemin(s) non standard : " + string.Join("; ",
					suspicious.Select((AmsiProvider p) => p.FriendlyName + " -> " + p.DllPath));
			}
			else if (unresolved.Count > 0)
			{
				details = $"{unresolved.Count} provider(s) sans DLL résolue (InprocServer32 introuvable)";
			}
			else if (providersCapture.Count == 0)
			{
				details = "Aucun provider à analyser";
			}
			else
			{
				details = "Toutes les DLL de providers sont dans des chemins système standard";
			}

			// Chemin non standard = Warning (indicateur de hijack). DLL non résolue = Info.
			SecurityStatus status = (hasSuspicious
				? SecurityStatus.Warning
				: ((unresolved.Count > 0) ? SecurityStatus.Info : SecurityStatus.OK));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "AMSI: Intégrité des DLL des providers",
				CurrentValue = details,
				ExpectedValue = "DLL dans System32 ou Program Files",
				Status = status,
				Description = "Un provider AMSI légitime pointe vers une DLL dans un emplacement protégé (System32, Program Files). Une DLL de provider située dans Temp, AppData ou un profil utilisateur (Users) est un indicateur fort de détournement (AMSI provider hijacking) : un attaquant peut enregistrer un faux provider qui neutralise l'analyse ou exécute du code. Le chemin est lu depuis InprocServer32 du CLSID.",
				Recommendation = (hasSuspicious
					? "SUSPECT : Un ou plusieurs providers AMSI pointent vers une DLL dans un chemin non standard. Investiguer immédiatement l'origine de ces DLL et vérifier la légitimité du CLSID associé."
					: ((unresolved.Count > 0)
						? "Certains providers n'ont pas de DLL résolue via InprocServer32. Vérifier manuellement leur enregistrement dans HKLM\\SOFTWARE\\Classes\\CLSID."
						: "Les DLL des providers AMSI sont dans des emplacements système standard.")),
				Reference = "https://learn.microsoft.com/windows/win32/amsi/dev-audience"
			};
		});
	}

	// Résout un CLSID de provider vers sa DLL via HKLM\SOFTWARE\Classes\CLSID\{CLSID}
	// (nom convivial dans la valeur par défaut, DLL dans InprocServer32).
	private static void ResolveProviderClsid(RegistryKey baseKey, string clsid, AmsiProvider provider)
	{
		try
		{
			using RegistryKey clsidKey = baseKey.OpenSubKey("SOFTWARE\\Classes\\CLSID\\" + clsid);
			if (clsidKey != null)
			{
				// Valeur par défaut = nom convivial du composant COM.
				provider.FriendlyName = clsidKey.GetValue(null)?.ToString() ?? "";
				using RegistryKey inprocKey = clsidKey.OpenSubKey("InprocServer32");
				if (inprocKey != null)
				{
					provider.DllPath = (inprocKey.GetValue(null)?.ToString() ?? "").Trim().Trim('"');
				}
			}
		}
		catch
		{
			// Résolution best-effort : on garde le CLSID brut si la lecture échoue.
		}
		if (string.IsNullOrEmpty(provider.FriendlyName))
		{
			// Cas connu : provider Defender identifié par son CLSID.
			provider.FriendlyName = (string.Equals(clsid, DefenderProviderClsid, StringComparison.OrdinalIgnoreCase)
				? "Microsoft Defender"
				: "(nom inconnu)");
		}
	}

	// Vérifie les clés de politique/registre pouvant désactiver AMSI pour Windows Script Host.
	private void CollectAmsiDisableKeys(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			// Clé de POLITIQUE (GPO) : prioritaire.
			int policyValue = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows Script\\Settings", "AmsiEnable");
			// Clé équivalente non-GPO (peut être posée par un attaquant).
			int legacyValue = RegInt("HKLM", "SOFTWARE\\Microsoft\\Windows Script\\Settings", "AmsiEnable");

			bool disabledByPolicy = policyValue == 0;
			bool disabledByLegacy = legacyValue == 0;
			bool disabled = disabledByPolicy || disabledByLegacy;

			string policyText = ((policyValue == -1) ? "Non configuré" : policyValue.ToString());
			string legacyText = ((legacyValue == -1) ? "Non configuré" : legacyValue.ToString());

			return new SecurityResult
			{
				Category = Category,
				CheckName = "AMSI: Désactivation via Windows Script (AmsiEnable)",
				CurrentValue = "Policy=" + policyText + ", Registre=" + legacyText,
				ExpectedValue = "1 (activé) ou non configuré",
				// AmsiEnable=0 = Critical : neutralise AMSI pour VBScript/JScript.
				Status = (disabled ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "La valeur AmsiEnable=0 sous 'Windows Script\\Settings' désactive l'intégration AMSI pour Windows Script Host (VBScript/JScript). C'est une technique de contournement (bypass) documentée : un attaquant pose cette clé pour empêcher l'analyse des scripts avant exécution. La clé de politique (SOFTWARE\\Policies) et la clé non-GPO sont toutes deux vérifiées.",
				Recommendation = (disabled
					? "CRITIQUE : AMSI est désactivé pour Windows Script (AmsiEnable=0). Restaurer AmsiEnable=1 (ou supprimer la valeur) sous HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Script\\Settings et HKLM\\SOFTWARE\\Microsoft\\Windows Script\\Settings. Investiguer l'origine de cette modification."
					: "AMSI n'est pas désactivé via les clés Windows Script."),
				Reference = "https://learn.microsoft.com/windows/win32/amsi/how-amsi-helps"
			};
		});
	}

	// Ajoute un résultat Info explicite indiquant que la vérification runtime (patch mémoire
	// d'AmsiScanBuffer) n'est PAS couverte par une analyse statique du registre.
	private void CollectRuntimeCoverageNote(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "AMSI: Patch mémoire runtime (non couvert)",
			CurrentValue = "Non vérifié par analyse statique",
			ExpectedValue = "Vérification runtime dédiée requise",
			Status = SecurityStatus.Info,
			Description = "Les techniques de contournement AMSI les plus courantes patchent en mémoire la fonction amsi.dll!AmsiScanBuffer (ou corrompent le contexte AMSI) au sein d'un processus, sans laisser de trace dans le registre. Ce collecteur repose sur une lecture statique du registre et ne peut PAS détecter ces altérations runtime.",
			Recommendation = "Ne pas déduire de ces résultats qu'AMSI est intègre à l'exécution. Pour détecter un patch mémoire d'AmsiScanBuffer, utiliser une solution EDR, l'analyse comportementale, ou une inspection mémoire par processus.",
			Reference = "https://learn.microsoft.com/windows/win32/amsi/antimalware-scan-interface-portal"
		});
	}

	// --- Helpers registre (identiques au style AdditionalSecurityCollector) ---

	private static int RegInt(string hive, string path, string valueName, int def = -1)
	{
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKLM") ? RegistryHive.LocalMachine : ((!(hiveName == "HKCU")) ? RegistryHive.LocalMachine : RegistryHive.CurrentUser));
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			object value = subKey?.GetValue(valueName);
			return (value != null && !(value is DBNull)) ? Convert.ToInt32(value) : def;
		}
		catch
		{
			return def;
		}
	}

	private static string? RegString(string hive, string path, string valueName)
	{
		string result;
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKLM") ? RegistryHive.LocalMachine : ((!(hiveName == "HKCU")) ? RegistryHive.LocalMachine : RegistryHive.CurrentUser));
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			result = subKey?.GetValue(valueName)?.ToString();
		}
		catch
		{
			result = null;
		}
		return result;
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
				Recommendation = "Vérifier les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}

	// Représentation interne d'un provider AMSI résolu.
	private sealed class AmsiProvider
	{
		public string Clsid { get; set; } = "";

		public string FriendlyName { get; set; } = "";

		public string DllPath { get; set; } = "";

		// True si la DLL du provider est dans un chemin non standard (Temp/AppData/Users)
		// au lieu de System32/Program Files : indicateur de hijack.
		public bool HasSuspiciousPath
		{
			get
			{
				if (string.IsNullOrEmpty(DllPath))
				{
					return false;
				}
				string lower = DllPath.ToLowerInvariant();
				bool inStandardLocation = lower.Contains("\\windows\\system32")
					|| lower.Contains("\\windows\\syswow64")
					|| lower.Contains("\\windows\\winsxs")
					|| lower.Contains("\\program files")
					|| lower.Contains("\\programdata\\microsoft");
				bool inSuspiciousLocation = lower.Contains("\\temp\\")
					|| lower.Contains("\\appdata\\")
					|| lower.Contains("\\users\\")
					|| lower.Contains("\\downloads\\");
				return inSuspiciousLocation && !inStandardLocation;
			}
		}
	}
}
