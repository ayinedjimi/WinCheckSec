using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur dédié aux fonctionnalités récentes de Windows 11 (23H2 / 24H2, Copilot+)
// susceptibles d'introduire de nouvelles surfaces d'attaque ou de fuite de données :
// Windows Recall, Quick Assist, Sudo for Windows, Developer Mode et Copilot.
// On distingue explicitement le « non configuré » (Info) du « non sécurisé » (Warning).
public class ModernWindowsFeaturesCollector : ISecurityCollector
{
	public string Name => "Fonctionnalités Windows 11 récentes";

	public string Category => "Durcissement";

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
			CollectWindowsRecall(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectQuickAssist(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectSudoForWindows(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectDeveloperMode(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectCopilot(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "ModernWindowsFeaturesCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// ------------------------------------------------------------------
	// Windows Recall (Copilot+ PC) : capture périodique de captures d'écran
	// indexées localement. Sur un poste sensible, la fonctionnalité doit être
	// désactivée par stratégie (DisableAIDataAnalysis = 1).
	// ------------------------------------------------------------------
	private void CollectWindowsRecall(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			// La stratégie machine prime ; on regarde aussi la stratégie utilisateur.
			int machinePolicy = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI", "DisableAIDataAnalysis");
			int userPolicy = RegInt("HKCU", "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI", "DisableAIDataAnalysis");
			// Recall est considéré désactivé si l'une des deux stratégies vaut 1.
			bool recallDisabled = machinePolicy == 1 || userPolicy == 1;
			bool notConfigured = machinePolicy == -1 && userPolicy == -1;
			string currentValue = $"HKLM\\...\\WindowsAI\\DisableAIDataAnalysis={FormatReg(machinePolicy)}, " +
				$"HKCU\\...\\WindowsAI\\DisableAIDataAnalysis={FormatReg(userPolicy)}";
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows Recall (capture d'écran IA)",
				CurrentValue = currentValue,
				ExpectedValue = "1 (Recall désactivé) sur postes sensibles",
				// Désactivé = OK ; sinon Warning (Recall potentiellement actif).
				Status = (recallDisabled ? SecurityStatus.OK : SecurityStatus.Warning),
				Description = "Windows Recall (PC Copilot+) capture périodiquement des captures d'écran de l'activité utilisateur et les indexe localement (texte, applications, sites visités). En cas de compromission ou d'accès physique, cette base peut révéler mots de passe affichés, documents confidentiels et historique complet. La stratégie DisableAIDataAnalysis=1 désactive complètement l'analyse et la capture.",
				Recommendation = (recallDisabled
					? "Windows Recall est désactivé par stratégie (DisableAIDataAnalysis=1). Configuration recommandée pour les postes sensibles."
					: (notConfigured
						? "Recall potentiellement actif (capture d'écran périodique). Sur un poste sensible, désactiver via GPO : Computer Configuration > Administrative Templates > Windows Components > Windows AI > Turn off saving snapshots for Windows, ou définir HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI\\DisableAIDataAnalysis = 1."
						: "Recall n'est pas désactivé (DisableAIDataAnalysis != 1). Définir HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI\\DisableAIDataAnalysis = 1 pour bloquer la capture d'écran périodique.")),
				Reference = "https://learn.microsoft.com/windows/client-management/manage-recall"
			};
		});
	}

	// ------------------------------------------------------------------
	// Quick Assist : outil d'assistance à distance intégré, vecteur documenté
	// d'ingénierie sociale (fraude au support technique), au même titre que
	// TeamViewer/AnyDesk. On détecte la présence de l'AppX ou du binaire.
	// ------------------------------------------------------------------
	private void CollectQuickAssist(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			// 1) Recherche du package AppX dans le dépôt des packages.
			bool appxPresent = false;
			string detectedPackage = string.Empty;
			try
			{
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey packagesKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages");
				if (packagesKey != null)
				{
					string[] subKeyNames = packagesKey.GetSubKeyNames();
					foreach (string subKeyName in subKeyNames)
					{
						ct.ThrowIfCancellationRequested();
						if (subKeyName.IndexOf("MicrosoftCorporationII.QuickAssist", StringComparison.OrdinalIgnoreCase) >= 0)
						{
							appxPresent = true;
							detectedPackage = subKeyName;
							break;
						}
					}
				}
			}
			catch
			{
				// En cas d'accès refusé au dépôt AppX, on se rabat sur la détection fichier.
			}

			// 2) Recherche du binaire hérité quickassist.exe dans System32.
			string quickAssistExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "quickassist.exe");
			bool exePresent = false;
			try
			{
				exePresent = File.Exists(quickAssistExe);
			}
			catch
			{
			}

			bool present = appxPresent || exePresent;
			string currentValue = present
				? ("Présent — " + (appxPresent ? ("AppX : " + detectedPackage) : ("Binaire : " + quickAssistExe)))
				: "Non détecté (AppX absent et quickassist.exe absent)";
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Quick Assist (assistance à distance)",
				CurrentValue = currentValue,
				ExpectedValue = "Absent ou désinstallé sur postes exposés à la fraude",
				// Présence = Info/Warning (surface d'ingénierie sociale) ; absence = OK.
				Status = (present ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Quick Assist permet de prendre le contrôle d'un poste à distance. C'est un vecteur d'ingénierie sociale documenté (notamment employé par des groupes comme Storm-1811 pour la fraude au support technique menant à des déploiements de ransomware), au même titre que TeamViewer ou AnyDesk. Sa simple présence n'est pas une compromission mais augmente la surface d'attaque sociale.",
				Recommendation = (present
					? "Si Quick Assist n'est pas nécessaire, le désinstaller (Get-AppxPackage *QuickAssist* | Remove-AppxPackage, ou Paramètres > Applications) et sensibiliser les utilisateurs à ne jamais accorder l'accès à un « support » non sollicité. Sinon, restreindre son usage par stratégie."
					: "Quick Assist n'est pas détecté. Aucune action requise ; rester vigilant lors des installations futures."),
				Reference = "https://learn.microsoft.com/windows/client-management/client-tools/quick-assist"
			};
		});
	}

	// ------------------------------------------------------------------
	// Sudo for Windows (24H2+) : élévation en ligne de commande. Le mode Inline
	// (3) exécute la commande élevée dans le terminal courant (moins isolé),
	// ce qui est moins sûr que NewWindow (1).
	// ------------------------------------------------------------------
	private void CollectSudoForWindows(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int enabled = RegInt("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Sudo", "Enabled");
			// 0 = désactivé, 1 = NewWindow, 2 = InputDisabled, 3 = Inline.
			string modeLabel = enabled switch
			{
				0 => "0 - Désactivé",
				1 => "1 - Nouvelle fenêtre (NewWindow)",
				2 => "2 - Entrée désactivée (InputDisabled)",
				3 => "3 - Inline (dans le terminal courant)",
				-1 => "Non configuré (désactivé par défaut)",
				_ => enabled.ToString(),
			};
			// Inline (3) => Warning (moins sûr) ; NewWindow (1) ou InputDisabled (2) => Info ;
			// désactivé (0) ou non configuré => OK.
			SecurityStatus status = enabled switch
			{
				3 => SecurityStatus.Warning,
				1 => SecurityStatus.Info,
				2 => SecurityStatus.Info,
				_ => SecurityStatus.OK,
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Sudo for Windows",
				CurrentValue = modeLabel,
				ExpectedValue = "0 (désactivé) ou 1 (NewWindow) si nécessaire",
				Status = status,
				Description = "Sudo for Windows (introduit en 24H2) permet d'élever une commande directement depuis une console non privilégiée. Le mode Inline (3) exécute le processus élevé dans le même terminal que le processus non élevé, réduisant l'isolation et exposant potentiellement le processus privilégié à des manipulations depuis la session non privilégiée. Le mode NewWindow (1) ouvre une fenêtre séparée, plus sûre.",
				Recommendation = (enabled == 3
					? "Le mode Inline est le moins sûr. Basculer vers NewWindow (Enabled=1) ou désactiver Sudo (Enabled=0) via Paramètres > Système > Pour les développeurs, ou HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Sudo\\Enabled."
					: (enabled == 1 || enabled == 2
						? "Sudo for Windows est activé dans un mode raisonnablement isolé. Vérifier que cet usage est intentionnel et documenté."
						: "Sudo for Windows est désactivé. Configuration recommandée sur les postes n'en ayant pas l'usage.")),
				Reference = "https://learn.microsoft.com/windows/advanced-settings/sudo/"
			};
		});
	}

	// ------------------------------------------------------------------
	// Developer Mode / sideloading : autorise l'installation d'applications non
	// signées par le Store, contournant une protection importante.
	// ------------------------------------------------------------------
	private void CollectDeveloperMode(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int devMode = RegInt("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock", "AllowDevelopmentWithoutDevLicense");
			int allTrusted = RegInt("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock", "AllowAllTrustedApps");
			bool devModeOn = devMode == 1;
			bool sideloadOn = allTrusted == 1;
			bool anyOn = devModeOn || sideloadOn;
			string currentValue = $"AllowDevelopmentWithoutDevLicense={FormatReg(devMode)}, AllowAllTrustedApps={FormatReg(allTrusted)}";
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Mode Développeur / Sideloading",
				CurrentValue = currentValue,
				ExpectedValue = "0 ou non configuré (mode développeur désactivé)",
				Status = (anyOn ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Le Mode Développeur (AllowDevelopmentWithoutDevLicense=1) et le sideloading (AllowAllTrustedApps=1) autorisent l'installation d'applications non validées par le Microsoft Store, y compris des paquets AppX signés par des certificats arbitraires. Sur un poste de production, cela contourne un contrôle d'intégrité et élargit la surface d'attaque (installation de logiciels non approuvés).",
				Recommendation = (anyOn
					? "Désactiver le mode développeur et le sideloading sur les postes de production : Paramètres > Système > Pour les développeurs > désactiver, ou GPO « Autoriser le déploiement de toutes les applications approuvées » et « Autoriser le développement d'applications du Windows Store sans licence de développeur » = Désactivé."
					: "Le mode développeur et le sideloading sont désactivés. Configuration recommandée pour les postes de production."),
				Reference = "https://learn.microsoft.com/windows/apps/get-started/enable-your-device-for-development"
			};
		});
	}

	// ------------------------------------------------------------------
	// Copilot : purement contextuel/informatif (choix organisationnel de
	// confidentialité, pas une faille en soi).
	// ------------------------------------------------------------------
	private void CollectCopilot(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int turnOff = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot", "TurnOffWindowsCopilot");
			bool copilotDisabled = turnOff == 1;
			string currentValue = turnOff switch
			{
				1 => "1 - Copilot désactivé par stratégie",
				0 => "0 - Copilot autorisé par stratégie",
				-1 => "Non configuré (comportement par défaut)",
				_ => turnOff.ToString(),
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows Copilot",
				CurrentValue = currentValue,
				ExpectedValue = "Selon la politique de l'organisation",
				// Purement informatif : la présence de Copilot n'est pas une faille.
				Status = SecurityStatus.Info,
				Description = "Windows Copilot est un assistant IA intégré. Sa désactivation relève d'un choix organisationnel (confidentialité, envoi de données vers des services cloud) plutôt que d'une vulnérabilité directe. Cette vérification est fournie à titre contextuel.",
				Recommendation = (copilotDisabled
					? "Copilot est désactivé par stratégie (TurnOffWindowsCopilot=1)."
					: "Si la politique de confidentialité de l'organisation l'exige, désactiver Copilot via GPO : User Configuration > Administrative Templates > Windows Components > Windows Copilot > Turn off Windows Copilot, ou HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot\\TurnOffWindowsCopilot = 1."),
				Reference = "https://learn.microsoft.com/windows/client-management/manage-windows-copilot"
			};
		});
	}

	// ------------------------------------------------------------------
	// Helpers registre 64 bits (RegistryView.Registry64) — même contrat que les
	// autres collecteurs.
	// ------------------------------------------------------------------
	private static int RegInt(string hive, string path, string valueName, int def = -1)
	{
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine);
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
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine);
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			return subKey?.GetValue(valueName)?.ToString();
		}
		catch
		{
			return null;
		}
	}

	// Formatte une valeur DWORD : -1 signifie « valeur absente ».
	private static string FormatReg(int value)
	{
		return (value == -1) ? "absent" : value.ToString();
	}

	private void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			SecurityResult result = factory();
			if (result != null)
			{
				results.Add(result);
			}
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Erreur de vérification",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}
}
