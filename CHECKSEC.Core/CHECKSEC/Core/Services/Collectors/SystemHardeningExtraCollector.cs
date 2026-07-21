using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur "extra" de durcissement système : vérifications complémentaires
// non couvertes par les autres collecteurs (élévation MSI, stockage USB,
// Windows Defender Application Guard). Chaque vérification est isolée via TryAdd
// afin qu'une erreur unitaire n'interrompe pas les autres.
public class SystemHardeningExtraCollector : ISecurityCollector
{
	public string Name => "Durcissement système (extra)";

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
			CollectAlwaysInstallElevated(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectUsbStorage(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectApplicationGuard(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			// Annulation demandée : on propage sans polluer le rapport.
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "SystemHardeningExtraCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// --- AlwaysInstallElevated : escalade de privilèges triviale via paquet MSI ---
	// Windows n'installe en tant que SYSTEM que si les DEUX clés (HKLM ET HKCU)
	// valent 1. Un seul côté à 1 est sans effet. On reproduit ce comportement réel :
	// Critical UNIQUEMENT si les deux valent 1, sinon OK.
	private void CollectAlwaysInstallElevated(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int hklm = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", "AlwaysInstallElevated");
			int hkcu = RegInt("HKCU", "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", "AlwaysInstallElevated");
			bool bothElevated = hklm == 1 && hkcu == 1;
			string hklmText = ((hklm == -1) ? "Non configuré" : hklm.ToString());
			string hkcuText = ((hkcu == -1) ? "Non configuré" : hkcu.ToString());
			return new SecurityResult
			{
				Category = Category,
				CheckName = "AlwaysInstallElevated (escalade via MSI)",
				CurrentValue = "HKLM=" + hklmText + ", HKCU=" + hkcuText,
				ExpectedValue = "Au moins une des deux clés != 1 (idéalement les deux à 0 / non configurées)",
				Status = (bothElevated ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "AlwaysInstallElevated permet à un utilisateur standard d'installer un paquet MSI avec les privilèges SYSTEM. Windows n'applique cette élévation que si les DEUX valeurs — HKLM (SOFTWARE\\Policies\\Microsoft\\Windows\\Installer) ET HKCU (même chemin) — valent 1. Lorsque c'est le cas, n'importe quel utilisateur peut obtenir une exécution SYSTEM via un MSI malveillant : c'est une élévation de privilèges triviale, fréquemment exploitée en post-exploitation.",
				Recommendation = (bothElevated ? "CRITIQUE : les deux clés AlwaysInstallElevated valent 1, tout utilisateur peut obtenir SYSTEM via un MSI. Définir HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated = 0 ET HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated = 0 (ou supprimer les valeurs), via GPO : Configuration ordinateur/utilisateur > Modèles d'administration > Composants Windows > Windows Installer > Toujours installer avec des privilèges élevés = Désactivé." : "AlwaysInstallElevated n'est pas activé des deux côtés : aucune élévation MSI possible. Conserver au moins une des clés différente de 1."),
				Reference = "https://learn.microsoft.com/windows/win32/msi/alwaysinstallelevated"
			};
		});
	}

	// --- Stockage USB : USBSTOR et refus d'écriture sur périphériques amovibles ---
	// Selon la politique de l'organisation, l'absence de restriction est souvent
	// acceptable (Info) ; sur poste sensible avec écriture USB totalement libre on
	// remonte un Warning. On reste nuancé (jamais Critical).
	private void CollectUsbStorage(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			// USBSTOR\Start : 3 = actif (démarrage manuel), 4 = désactivé.
			int usbStorStart = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Services\\USBSTOR", "Start");
			// Deny_Write : 1 = écriture sur périphériques amovibles refusée par stratégie.
			int denyWrite = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}", "Deny_Write");

			bool usbStorageDisabled = usbStorStart == 4;
			bool writeDenied = denyWrite == 1;

			string startLabel;
			switch (usbStorStart)
			{
			case 3:
				startLabel = "3 - Actif (démarrage à la demande)";
				break;
			case 4:
				startLabel = "4 - Désactivé";
				break;
			case -1:
				startLabel = "Non configuré (pilote présent par défaut)";
				break;
			default:
				startLabel = usbStorStart.ToString();
				break;
			}
			string denyLabel = ((denyWrite == -1) ? "Non configuré (écriture autorisée par défaut)" : (writeDenied ? "1 - Écriture refusée" : denyWrite + " - Écriture autorisée"));

			// Non restreint = Info (choix d'organisation) ; écriture totalement libre = Warning.
			SecurityStatus status;
			if (usbStorageDisabled || writeDenied)
			{
				// Le stockage USB est bloqué ou en lecture seule : conforme au durcissement.
				status = SecurityStatus.OK;
			}
			else if (usbStorStart == -1 && denyWrite == -1)
			{
				// Rien de configuré : simple constat (politique de l'org).
				status = SecurityStatus.Info;
			}
			else
			{
				// Stockage USB actif ET écriture libre : à surveiller sur poste sensible.
				status = SecurityStatus.Warning;
			}

			return new SecurityResult
			{
				Category = Category,
				CheckName = "Stockage USB (USBSTOR / écriture amovible)",
				CurrentValue = "USBSTOR Start=" + startLabel + ", Deny_Write=" + denyLabel,
				ExpectedValue = "Sur poste sensible : USBSTOR désactivé (Start=4) ou écriture refusée (Deny_Write=1)",
				Status = status,
				Description = "Le pilote USBSTOR contrôle l'accès aux périphériques de stockage USB. Start=4 désactive complètement le stockage USB. La stratégie Deny_Write des périphériques amovibles (classe GUID {53f56307-b6bf-11d0-94f2-00a0c91efb8b}) empêche l'écriture, limitant l'exfiltration de données et l'introduction de logiciels malveillants par clé USB. L'opportunité de ces restrictions dépend de la politique de l'organisation.",
				Recommendation = (status == SecurityStatus.OK ? "Le stockage USB est désactivé ou en lecture seule : configuration conforme au durcissement." : (status == SecurityStatus.Info ? "Aucune restriction de stockage USB configurée. Selon la politique de l'organisation, envisager de désactiver USBSTOR (Start=4) ou de refuser l'écriture (Deny_Write=1) sur les postes sensibles." : "Le stockage USB est actif et l'écriture est autorisée. Sur un poste sensible, envisager de désactiver USBSTOR (HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\\Start = 4) ou de refuser l'écriture via GPO : Configuration ordinateur > Modèles d'administration > Système > Accès au stockage amovible > Disques amovibles : Refuser l'accès en écriture.")),
				Reference = "https://learn.microsoft.com/windows/client-management/manage-device-installation-with-group-policy"
			};
		});
	}

	// --- Windows Defender Application Guard : fonctionnalité optionnelle ---
	// Absente par défaut ; recommandée sur postes sensibles. Info si non activée.
	private void CollectApplicationGuard(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int allowAppHvsi = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\AppHVSI", "AllowAppHVSI_ProviderSet");
			bool enabled = allowAppHvsi > 0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows Defender Application Guard (WDAG)",
				CurrentValue = ((allowAppHvsi == -1) ? "Non activé (clé absente)" : "AllowAppHVSI_ProviderSet=" + allowAppHvsi),
				ExpectedValue = "> 0 sur postes sensibles (Edge et/ou Office isolés)",
				Status = (enabled ? SecurityStatus.OK : SecurityStatus.Info),
				Description = "Windows Defender Application Guard (WDAG) isole la navigation Microsoft Edge et les documents Office non fiables dans un conteneur virtualisé matériellement, empêchant un contenu malveillant d'atteindre le système hôte. C'est une fonctionnalité optionnelle (non installée par défaut), particulièrement recommandée sur les postes exposés à du contenu externe. La valeur AllowAppHVSI_ProviderSet indique les cibles isolées activées (bitmask : 1 = Edge, 2 = Office).",
				Recommendation = (enabled ? "Application Guard est activé — bonne isolation du contenu non fiable." : "Application Guard non activé — recommandé sur postes sensibles. Installer la fonctionnalité (Windows Defender Application Guard) puis activer via GPO/Intune (AllowAppHVSI_ProviderSet) pour isoler Edge et/ou Office."),
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-isolation/microsoft-defender-application-guard/md-app-guard-overview"
			};
		});
	}

	// --- Helpers d'accès registre (vue 64 bits explicite) ---

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
		string? result;
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine);
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

	// Isole chaque vérification : une exception unitaire produit un résultat Error
	// sans interrompre les autres checks.
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
				Category = "Durcissement",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}
}
