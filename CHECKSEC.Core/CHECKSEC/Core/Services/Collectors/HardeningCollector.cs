using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class HardeningCollector : ISecurityCollector
{
	public string Name => "Durcissement Avancé";

	public string Category => "Durcissement Système";

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
			CollectUnquotedServicePaths(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectServiceBinaryPermissions(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectUsbDeviceRestrictions(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectPointAndPrintRestrictions(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectProcessCreationAudit(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectNtlmAuditSettings(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception exception)
		{
			collectorReport.ErrorMessage = "HardeningCollector fatal error: " + exception.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectUnquotedServicePaths(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			List<string> servicesNonQuotes = new List<string>();
			List<string> servicesCritiques = new List<string>();
			try
			{
				ManagementObjectSearcher rechercheServices = new ManagementObjectSearcher("SELECT Name, PathName, StartMode FROM Win32_Service");
				try
				{
					using ManagementObjectCollection managementObjectCollection = rechercheServices.Get();
					foreach (ManagementObject service in managementObjectCollection)
					{
						ManagementObject serviceCourant = service;
						try
						{
							ct.ThrowIfCancellationRequested();
							string nomService = service["Name"]?.ToString() ?? "";
							string cheminService = service["PathName"]?.ToString() ?? "";
							if (!string.IsNullOrWhiteSpace(cheminService) && !cheminService.TrimStart().StartsWith("\""))
							{
								string cheminExe = ExtractExePath(cheminService);
								if (cheminExe.Contains(' '))
								{
									if (IsAnyParentDirectoryWritable(cheminExe))
									{
										servicesCritiques.Add(nomService + " → " + cheminService);
									}
									else
									{
										servicesNonQuotes.Add(nomService + " → " + cheminService);
									}
								}
							}
						}
						finally
						{
							((IDisposable)serviceCourant)?.Dispose();
						}
					}
				}
				finally
				{
					((IDisposable)rechercheServices)?.Dispose();
				}
			}
			catch (Exception exception)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Chemins de services non quotés",
					CurrentValue = "Erreur WMI : " + exception.Message,
					ExpectedValue = "Aucun chemin de service non quoté avec espaces",
					Status = SecurityStatus.Error,
					Description = "Impossible d'interroger les services via WMI.",
					Recommendation = "Vérifier les permissions WMI.",
					Reference = "https://attack.mitre.org/techniques/T1574/009/"
				};
			}
			int nombreTotal = servicesNonQuotes.Count + servicesCritiques.Count;
			bool presenceCritiques = servicesCritiques.Count > 0;
			StringBuilder stringBuilder = new StringBuilder();
			if (nombreTotal == 0)
			{
				stringBuilder.Append("Aucun chemin de service non quoté avec espaces détecté.");
			}
			else
			{
				if (servicesCritiques.Count > 0)
				{
					StringBuilder stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder3 = stringBuilder2;
					StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(70, 1, stringBuilder2);
					handler.AppendLiteral("CRITIQUE - ");
					handler.AppendFormatted(servicesCritiques.Count);
					handler.AppendLiteral(" service(s) avec répertoire parent accessible en écriture :");
					stringBuilder3.AppendLine(ref handler);
					foreach (string item2 in servicesCritiques)
					{
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder4 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
						handler.AppendLiteral("  • ");
						handler.AppendFormatted(item2);
						stringBuilder4.AppendLine(ref handler);
					}
				}
				if (servicesNonQuotes.Count > 0)
				{
					StringBuilder stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder5 = stringBuilder2;
					StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(51, 1, stringBuilder2);
					handler.AppendLiteral("AVERTISSEMENT - ");
					handler.AppendFormatted(servicesNonQuotes.Count);
					handler.AppendLiteral(" service(s) avec chemin non quoté :");
					stringBuilder5.AppendLine(ref handler);
					foreach (string item3 in servicesNonQuotes)
					{
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder6 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
						handler.AppendLiteral("  • ");
						handler.AppendFormatted(item3);
						stringBuilder6.AppendLine(ref handler);
					}
				}
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Chemins de services non quotés (Unquoted Service Paths)",
				CurrentValue = ((nombreTotal == 0) ? "Aucun détecté" : stringBuilder.ToString().TrimEnd()),
				ExpectedValue = "Aucun chemin de service non quoté avec espaces",
				Status = (presenceCritiques ? SecurityStatus.Critical : ((nombreTotal > 0) ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = "Un chemin de service non quoté contenant des espaces permet à un attaquant de placer un exécutable malveillant dans un répertoire intermédiaire du chemin. Windows résoudra le chemin en essayant chaque combinaison possible, exécutant potentiellement le binaire malveillant avec les privilèges du service. Les chemins avec répertoires parents accessibles en écriture sont particulièrement critiques.",
				Recommendation = ((nombreTotal == 0) ? "Aucune action requise. Tous les chemins de services sont correctement quotés." : "Corriger les chemins de services en ajoutant des guillemets doubles autour du chemin complet de l'exécutable dans la configuration du service. Utiliser : sc config \"NomService\" binPath= \"\\\"C:\\Chemin Avec Espaces\\service.exe\\\"\"."),
				Reference = "https://attack.mitre.org/techniques/T1574/009/"
			};
		});
	}

	private void CollectServiceBinaryPermissions(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			List<string> binairesVulnerables = new List<string>();
			int nombreVerifies = 0;
			try
			{
				ManagementObjectSearcher rechercheServices = new ManagementObjectSearcher("SELECT Name, PathName FROM Win32_Service");
				try
				{
					using ManagementObjectCollection managementObjectCollection = rechercheServices.Get();
					List<(string, string)> servicesACollecter = new List<(string, string)>();
					foreach (ManagementObject service in managementObjectCollection)
					{
						ManagementObject serviceCourant = service;
						try
						{
							ct.ThrowIfCancellationRequested();
							string nomService = service["Name"]?.ToString() ?? "";
							string cheminService = service["PathName"]?.ToString() ?? "";
							if (!string.IsNullOrWhiteSpace(cheminService))
							{
								string cheminExe = ExtractExePath(cheminService);
								if (!cheminExe.StartsWith("C:\\Windows", StringComparison.OrdinalIgnoreCase) && !cheminExe.StartsWith("C:\\WINDOWS", StringComparison.OrdinalIgnoreCase))
								{
									servicesACollecter.Add((nomService, cheminExe));
								}
							}
						}
						finally
						{
							((IDisposable)serviceCourant)?.Dispose();
						}
					}
					int nombreAVerifier = Math.Min(20, servicesACollecter.Count);
					for (int index = 0; index < nombreAVerifier; index++)
					{
						ct.ThrowIfCancellationRequested();
						(string, string) serviceTuple = servicesACollecter[index];
						string nomServiceCourant = serviceTuple.Item1;
						string cheminExeCourant = serviceTuple.Item2;
						nombreVerifies++;
						if (IsFileWritableByNonAdmin(cheminExeCourant))
						{
							binairesVulnerables.Add(nomServiceCourant + " → " + cheminExeCourant);
						}
					}
				}
				finally
				{
					((IDisposable)rechercheServices)?.Dispose();
				}
			}
			catch (Exception exception)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Permissions des binaires de services",
					CurrentValue = "Erreur : " + exception.Message,
					ExpectedValue = "Aucun binaire de service accessible en écriture par des non-administrateurs",
					Status = SecurityStatus.Error,
					Description = "Impossible de vérifier les permissions des binaires de services.",
					Recommendation = "Vérifier les permissions d'accès au système de fichiers.",
					Reference = "https://attack.mitre.org/techniques/T1574/010/"
				};
			}
			StringBuilder stringBuilder = new StringBuilder();
			if (binairesVulnerables.Count > 0)
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder3 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(50, 1, stringBuilder2);
				handler.AppendFormatted(binairesVulnerables.Count);
				handler.AppendLiteral(" binaire(s) de service accessible(s) en écriture :");
				stringBuilder3.AppendLine(ref handler);
				foreach (string item5 in binairesVulnerables)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder4 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
					handler.AppendLiteral("  • ");
					handler.AppendFormatted(item5);
					stringBuilder4.AppendLine(ref handler);
				}
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Permissions des binaires de services",
				CurrentValue = ((binairesVulnerables.Count == 0) ? $"Aucun binaire vulnérable détecté ({nombreVerifies} services vérifiés)" : stringBuilder.ToString().TrimEnd()),
				ExpectedValue = "Aucun binaire de service accessible en écriture par des non-administrateurs",
				Status = ((binairesVulnerables.Count > 0) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Si un binaire de service est accessible en écriture par des utilisateurs non-administrateurs, un attaquant peut remplacer le fichier exécutable par un programme malveillant qui sera exécuté avec les privilèges du service (souvent SYSTEM). C'est une technique classique d'élévation de privilèges.",
				Recommendation = ((binairesVulnerables.Count == 0) ? "Aucune action requise. Les binaires de services vérifiés sont correctement protégés." : "Corriger les permissions des fichiers identifiés pour n'autoriser l'écriture qu'aux administrateurs et au compte SYSTEM. Utiliser : icacls \"chemin\" /inheritance:r /grant:r \"BUILTIN\\Administrators:(F)\" \"NT AUTHORITY\\SYSTEM:(F)\" \"BUILTIN\\Users:(RX)\"."),
				Reference = "https://attack.mitre.org/techniques/T1574/010/"
			};
		});
	}

	private void CollectUsbDeviceRestrictions(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string cheminRestrictions = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions";
			int denyRemovableDevices = RegInt("HKLM", cheminRestrictions, "DenyRemovableDevices");
			bool deviceIdsConfigures = false;
			int nombreDeviceIds = 0;
			try
			{
				using RegistryKey cleBase = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey cleDenyDeviceIds = cleBase.OpenSubKey(cheminRestrictions + "\\DenyDeviceIDs");
				if (cleDenyDeviceIds != null)
				{
					nombreDeviceIds = cleDenyDeviceIds.ValueCount;
					deviceIdsConfigures = nombreDeviceIds > 0;
				}
			}
			catch
			{
			}
			bool deviceClassesConfigures = false;
			int nombreDeviceClasses = 0;
			List<string> classesBloquees = new List<string>();
			try
			{
				using RegistryKey cleBaseClasses = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey cleDenyDeviceClasses = cleBaseClasses.OpenSubKey(cheminRestrictions + "\\DenyDeviceClasses");
				if (cleDenyDeviceClasses != null)
				{
					nombreDeviceClasses = cleDenyDeviceClasses.ValueCount;
					deviceClassesConfigures = nombreDeviceClasses > 0;
					string[] valueNames = cleDenyDeviceClasses.GetValueNames();
					foreach (string nomValeur in valueNames)
					{
						string valeurClasse = cleDenyDeviceClasses.GetValue(nomValeur)?.ToString();
						if (!string.IsNullOrEmpty(valeurClasse))
						{
							classesBloquees.Add(valeurClasse);
						}
					}
				}
			}
			catch
			{
			}
			bool denyRemovableActive = denyRemovableDevices == 1;
			bool auMoinsUneRestriction = deviceIdsConfigures || deviceClassesConfigures || denyRemovableActive;
			bool sbp2Bloque = classesBloquees.Exists((string classe) => classe.Contains("d48179be", StringComparison.OrdinalIgnoreCase));
			bool firewireBloque = classesBloquees.Exists((string classe) => classe.Contains("7ebefbc0", StringComparison.OrdinalIgnoreCase));
			StringBuilder stringBuilder = new StringBuilder();
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(23, 1, stringBuilder2);
			handler.AppendLiteral("DenyRemovableDevices : ");
			handler.AppendFormatted(denyRemovableDevices switch
			{
				-1 => "Non configuré",
				1 => "Activé",
				_ => denyRemovableDevices.ToString(),
			});
			stringBuilder3.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(16, 1, stringBuilder2);
			handler.AppendLiteral("DenyDeviceIDs : ");
			handler.AppendFormatted(deviceIdsConfigures ? $"{nombreDeviceIds} entrée(s)" : "Non configuré");
			stringBuilder4.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder5 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(20, 1, stringBuilder2);
			handler.AppendLiteral("DenyDeviceClasses : ");
			handler.AppendFormatted(deviceClassesConfigures ? $"{nombreDeviceClasses} classe(s)" : "Non configuré");
			stringBuilder5.AppendLine(ref handler);
			if (classesBloquees.Count > 0)
			{
				stringBuilder.AppendLine("Classes bloquées :");
				foreach (string item in classesBloquees)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder6 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
					handler.AppendLiteral("  • ");
					handler.AppendFormatted(item);
					stringBuilder6.AppendLine(ref handler);
				}
			}
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder7 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(42, 2, stringBuilder2);
			handler.AppendLiteral("SBP-2 (DMA) bloqué : ");
			handler.AppendFormatted(sbp2Bloque ? "Oui" : "Non");
			handler.AppendLiteral(" | FireWire bloqué : ");
			handler.AppendFormatted(firewireBloque ? "Oui" : "Non");
			stringBuilder7.Append(ref handler);
			SecurityStatus securityStatus = ((!(denyRemovableActive && deviceClassesConfigures && sbp2Bloque && firewireBloque)) ? (auMoinsUneRestriction ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Restrictions d'installation de périphériques USB",
				CurrentValue = stringBuilder.ToString().TrimEnd(),
				ExpectedValue = "DenyRemovableDevices=1, DenyDeviceClasses avec SBP-2 et FireWire bloqués",
				Status = securityStatus,
				Description = "Les restrictions d'installation de périphériques empêchent la connexion de dispositifs USB non autorisés, réduisant les risques d'attaque DMA (Direct Memory Access), d'exfiltration de données et d'injection de charges malveillantes via des périphériques physiques. Le blocage des classes SBP-2 et FireWire est critique pour prévenir les attaques DMA.",
				Recommendation = ((securityStatus == SecurityStatus.OK) ? "Les restrictions de périphériques USB sont correctement configurées." : "Configurer via GPO : Computer Configuration > Administrative Templates > System > Device Installation > Device Installation Restrictions. Activer 'Prevent installation of removable devices' et bloquer les classes SBP-2 ({d48179be-ec20-11d1-b6b8-00c04fa372a7}) et FireWire ({7ebefbc0-3200-11d2-b4c2-00a0C9697d07})."),
				Reference = "https://docs.microsoft.com/windows/client-management/mdm/policy-csp-deviceinstallation"
			};
		});
	}

	private void CollectPointAndPrintRestrictions(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string path = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint";
			int restrictDriverInstall = RegInt("HKLM", path, "RestrictDriverInstallationToAdministrators");
			int noWarningNoElevation = RegInt("HKLM", path, "NoWarningNoElevationOnInstall");
			int updatePromptSettings = RegInt("HKLM", path, "UpdatePromptSettings");
			bool restrictActive = restrictDriverInstall == 1;
			bool noWarningOk = noWarningNoElevation == 0;
			bool updatePromptOk = updatePromptSettings == 0;
			bool configurationCorrecte = restrictActive && noWarningOk && updatePromptOk;
			StringBuilder stringBuilder = new StringBuilder();
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(59, 1, stringBuilder2);
			handler.AppendLiteral("RestrictDriverInstallationToAdministrators : ");
			handler.AppendFormatted((restrictDriverInstall == -1) ? "Non configuré" : restrictDriverInstall.ToString());
			handler.AppendLiteral(" (attendu : 1)");
			stringBuilder3.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(46, 1, stringBuilder2);
			handler.AppendLiteral("NoWarningNoElevationOnInstall : ");
			handler.AppendFormatted((noWarningNoElevation == -1) ? "Non configuré" : noWarningNoElevation.ToString());
			handler.AppendLiteral(" (attendu : 0)");
			stringBuilder4.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder5 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(37, 1, stringBuilder2);
			handler.AppendLiteral("UpdatePromptSettings : ");
			handler.AppendFormatted((updatePromptSettings == -1) ? "Non configuré" : updatePromptSettings.ToString());
			handler.AppendLiteral(" (attendu : 0)");
			stringBuilder5.Append(ref handler);
			SecurityStatus status = ((!configurationCorrecte) ? ((restrictActive || noWarningNoElevation != 1) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Restrictions Point and Print (PrintNightmare)",
				CurrentValue = stringBuilder.ToString(),
				ExpectedValue = "RestrictDriverInstallationToAdministrators=1, NoWarningNoElevationOnInstall=0, UpdatePromptSettings=0",
				Status = status,
				Description = "Les restrictions Point and Print contrôlent l'installation de pilotes d'imprimante. Une mauvaise configuration peut permettre l'exploitation de vulnérabilités PrintNightmare (CVE-2021-34527) pour exécuter du code arbitraire avec les privilèges SYSTEM. Il est essentiel de limiter l'installation de pilotes aux administrateurs et d'exiger une élévation de privilèges.",
				Recommendation = (configurationCorrecte ? "Les restrictions Point and Print sont correctement configurées contre PrintNightmare." : "Configurer via GPO ou registre :\n• HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint\\RestrictDriverInstallationToAdministrators = 1\n• HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint\\NoWarningNoElevationOnInstall = 0\n• HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint\\UpdatePromptSettings = 0\nAppliquer également le correctif KB5005010."),
				Reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"
			};
		});
	}

	private void CollectProcessCreationAudit(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int valeurAudit = RegInt("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit", "ProcessCreationIncludeCmdLine_Enabled");
			bool auditActive = valeurAudit == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Audit de la ligne de commande à la création de processus",
				CurrentValue = ((valeurAudit == -1) ? "Non configuré (désactivé par défaut)" : valeurAudit.ToString()),
				ExpectedValue = "1 (Activé)",
				Status = ((!auditActive) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "L'audit de la ligne de commande à la création de processus (Event ID 4688) enregistre la ligne de commande complète utilisée pour lancer chaque processus. C'est une source de télémétrie essentielle pour détecter les activités malveillantes, les scripts obfusqués et les mouvements latéraux. Sans cette fonctionnalité, les événements 4688 ne contiennent que le nom du processus sans ses arguments.",
				Recommendation = (auditActive ? "L'audit de la ligne de commande de création de processus est activé." : "Activer via GPO : Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events. Ou définir la valeur de registre HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled = 1. S'assurer également que la stratégie d'audit 'Process Creation' est activée (subcategory Audit Process Creation)."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/auditing/audit-process-creation"
			};
		});
	}

	private void CollectNtlmAuditSettings(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string path = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0";
			int auditReceiving = RegInt("HKLM", path, "AuditReceivingNTLMTraffic");
			int restrictReceiving = RegInt("HKLM", path, "RestrictReceivingNTLMTraffic");
			bool auditActive = auditReceiving == 2;
			bool restrictionActive = restrictReceiving == 2;
			bool configurationCorrecte = auditActive && restrictionActive;
			StringBuilder stringBuilder = new StringBuilder();
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(54, 1, stringBuilder2);
			handler.AppendLiteral("AuditReceivingNTLMTraffic : ");
			handler.AppendFormatted((auditReceiving == -1) ? "Non configuré" : auditReceiving.ToString());
			handler.AppendLiteral(" (attendu : 2 = Audit all)");
			stringBuilder3.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(56, 1, stringBuilder2);
			handler.AppendLiteral("RestrictReceivingNTLMTraffic : ");
			handler.AppendFormatted((restrictReceiving == -1) ? "Non configuré" : restrictReceiving.ToString());
			handler.AppendLiteral(" (attendu : 2 = Deny all)");
			stringBuilder4.Append(ref handler);
			SecurityStatus status = ((!configurationCorrecte) ? ((restrictReceiving == 2 && !auditActive) ? SecurityStatus.Warning : ((restrictReceiving != -1 || auditReceiving != -1) ? SecurityStatus.Warning : SecurityStatus.Warning)) : SecurityStatus.OK);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Audit et restriction du trafic NTLM",
				CurrentValue = stringBuilder.ToString(),
				ExpectedValue = "AuditReceivingNTLMTraffic=2, RestrictReceivingNTLMTraffic=2",
				Status = status,
				Description = "NTLM est un protocole d'authentification hérité vulnérable aux attaques de relais (NTLM Relay), de pass-the-hash et de capture de credentials. L'audit du trafic NTLM entrant permet de détecter les systèmes qui utilisent encore NTLM avant de le restreindre. La restriction à la valeur 2 (Deny all) bloque toutes les authentifications NTLM entrantes, forçant l'utilisation de Kerberos.",
				Recommendation = (configurationCorrecte ? "L'audit et la restriction NTLM sont correctement configurés." : "Phase 1 : Activer l'audit NTLM en définissant AuditReceivingNTLMTraffic = 2 dans HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0. Analyser les événements 8001/8002/8003 dans le journal Microsoft-Windows-NTLM/Operational pour identifier les applications dépendantes de NTLM.\nPhase 2 : Après correction des dépendances, définir RestrictReceivingNTLMTraffic = 2 pour bloquer le trafic NTLM.\nGPO : Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: Restrict NTLM."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-incoming-ntlm-traffic"
			};
		});
	}

	private static string ExtractExePath(string pathName)
	{
		if (string.IsNullOrWhiteSpace(pathName))
		{
			return string.Empty;
		}
		string cheminNettoye = pathName.Trim();
		if (cheminNettoye.StartsWith("\""))
		{
			int indexGuillemet = cheminNettoye.IndexOf('"', 1);
			if (indexGuillemet <= 1)
			{
				return cheminNettoye.TrimStart('"');
			}
			return cheminNettoye.Substring(1, indexGuillemet - 1);
		}
		int indexExe = cheminNettoye.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
		if (indexExe >= 0)
		{
			return cheminNettoye.Substring(0, indexExe + 4);
		}
		int indexEspace = cheminNettoye.IndexOf(' ');
		if (indexEspace <= 0)
		{
			return cheminNettoye;
		}
		return cheminNettoye.Substring(0, indexEspace);
	}

	private static bool IsAnyParentDirectoryWritable(string exePath)
	{
		try
		{
			string directoryName = Path.GetDirectoryName(exePath);
			while (!string.IsNullOrEmpty(directoryName))
			{
				if (IsDirectoryWritableByNonAdmin(directoryName))
				{
					return true;
				}
				directoryName = Path.GetDirectoryName(directoryName);
			}
		}
		catch
		{
		}
		return false;
	}

	private static bool IsDirectoryWritableByNonAdmin(string dirPath)
	{
		try
		{
			if (!Directory.Exists(dirPath))
			{
				return false;
			}
			AuthorizationRuleCollection accessRules = new DirectoryInfo(dirPath).GetAccessControl().GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
			SecurityIdentifier sidUtilisateurs = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
			SecurityIdentifier sidTout = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
			SecurityIdentifier sidAuthentifies = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
			foreach (FileSystemAccessRule regle in accessRules)
			{
				if (regle.AccessControlType == AccessControlType.Allow)
				{
					SecurityIdentifier identifiantRegle = (SecurityIdentifier)regle.IdentityReference;
					if ((identifiantRegle.Equals(sidUtilisateurs) || identifiantRegle.Equals(sidTout) || identifiantRegle.Equals(sidAuthentifies)) && ((regle.FileSystemRights & FileSystemRights.Write) != 0 || (regle.FileSystemRights & FileSystemRights.Modify) != 0 || (regle.FileSystemRights & FileSystemRights.FullControl) != 0))
					{
						return true;
					}
				}
			}
		}
		catch
		{
		}
		return false;
	}

	private static bool IsFileWritableByNonAdmin(string filePath)
	{
		try
		{
			if (!File.Exists(filePath))
			{
				return false;
			}
			AuthorizationRuleCollection accessRules = new FileInfo(filePath).GetAccessControl().GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
			SecurityIdentifier sidUtilisateurs = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
			SecurityIdentifier sidTout = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
			SecurityIdentifier sidAuthentifies = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
			foreach (FileSystemAccessRule regle in accessRules)
			{
				if (regle.AccessControlType == AccessControlType.Allow)
				{
					SecurityIdentifier identifiantRegle = (SecurityIdentifier)regle.IdentityReference;
					if ((identifiantRegle.Equals(sidUtilisateurs) || identifiantRegle.Equals(sidTout) || identifiantRegle.Equals(sidAuthentifies)) && ((regle.FileSystemRights & FileSystemRights.Write) != 0 || (regle.FileSystemRights & FileSystemRights.Modify) != 0 || (regle.FileSystemRights & FileSystemRights.FullControl) != 0))
					{
						return true;
					}
				}
			}
		}
		catch
		{
		}
		return false;
	}

	private static int RegInt(string hive, string path, string valueName, int def = -1)
	{
		try
		{
			string hiveNormalise = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveNormalise == "HKLM") ? RegistryHive.LocalMachine : ((!(hiveNormalise == "HKCU")) ? RegistryHive.LocalMachine : RegistryHive.CurrentUser));
			using RegistryKey cleBase = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey cleSousCle = cleBase.OpenSubKey(path);
			object valeurBrute = cleSousCle?.GetValue(valueName);
			return (valeurBrute != null && !(valeurBrute is DBNull)) ? Convert.ToInt32(valeurBrute) : def;
		}
		catch
		{
			return def;
		}
	}

	private static string? RegString(string hive, string path, string valueName)
	{
		string valeur;
		try
		{
			string hiveNormalise = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveNormalise == "HKLM") ? RegistryHive.LocalMachine : ((!(hiveNormalise == "HKCU")) ? RegistryHive.LocalMachine : RegistryHive.CurrentUser));
			using RegistryKey cleBase = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey cleSousCle = cleBase.OpenSubKey(path);
			valeur = cleSousCle?.GetValue(valueName)?.ToString();
		}
		catch
		{
			valeur = null;
		}
		return valeur;
	}

	private void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			results.Add(factory());
		}
		catch (Exception exception)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + exception.Message,
				Recommendation = "Vérifier les permissions d'accès au registre, WMI et au système de fichiers.",
				Reference = ""
			});
		}
	}
}
