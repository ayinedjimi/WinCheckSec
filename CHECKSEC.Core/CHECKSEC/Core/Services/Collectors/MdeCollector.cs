using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services.Helpers;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class MdeCollector : ISecurityCollector
{
	private const string MdeStatusKey = "SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\Status";

	private const string MdeOnboardKey = "SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\OnboardingInfo";

	private const string MdePolicyKey = "SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection";

	private const string DefenderKey = "SOFTWARE\\Microsoft\\Windows Defender";

	private const string DefenderSigKey = "SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates";

	private const string DefenderPlatKey = "SOFTWARE\\Microsoft\\Windows Defender\\Platform";

	private const string AsrRulesKey = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules";

	private static readonly Dictionary<string, string> AsrRuleNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
	{
		["d4f940ab-401b-4efc-aadc-ad5f3c50688a"] = "Bloquer toutes les applications Office de créer des processus enfants",
		["9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"] = "Bloquer le vol de credentials depuis LSASS",
		["3b576869-a4ec-4529-8536-b80a7769e899"] = "Bloquer les applications Office de créer du contenu exécutable",
		["75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"] = "Bloquer les applications Office d'injecter du code dans d'autres processus",
		["d3e037e1-3eb8-44c8-a917-57927947596d"] = "Bloquer JavaScript/VBScript de lancer du contenu exécutable téléchargé",
		["5beb7efe-fd9a-4556-801d-275e5ffc04cc"] = "Bloquer l'exécution de scripts potentiellement obfusqués",
		["be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"] = "Bloquer le contenu exécutable des clients de messagerie et webmail",
		["26190899-1602-49e8-8b27-eb1d0a1ce869"] = "Bloquer les applications Office Communication de créer des processus enfants",
		["7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"] = "Bloquer Adobe Reader de créer des processus enfants",
		["e6db77e5-3df2-4cf1-b95a-636979351e5b"] = "Bloquer la persistance via les abonnements WMI",
		["01443614-cd74-433a-b99e-2ecdc07bfc25"] = "Bloquer les processus non signés depuis des périphériques USB",
		["c1db55ab-c21a-4637-bb3f-a12568109d35"] = "Utiliser la protection avancée contre les ransomwares"
	};

	public string Name => "Microsoft Defender for Endpoint";

	public string Category => "EDR & Threat Protection";

	public Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		Stopwatch stopwatch = Stopwatch.StartNew();
		CollectorReport collectorReport = new CollectorReport
		{
			CollectorName = Name
		};
		try
		{
			ct.ThrowIfCancellationRequested();
			CollectMdeEnrollmentStatus(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectSenseServiceStatus(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectMdeCapabilities(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectRelatedSecurityServices(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectDefenderVersionsAndSignatures(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectAsrRules(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception fatalException)
		{
			collectorReport.ErrorMessage = "MdeCollector erreur fatale : " + fatalException.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectMdeEnrollmentStatus(List<SecurityResult> results, CancellationToken ct)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey statusKey = localMachineKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\Status", writable: false);
			if (statusKey == null)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "A. MDE — Statut d'Enrôlement",
					CurrentValue = "Clé de registre MDE absente",
					ExpectedValue = "OnboardingState = 1 (Enrôlé)",
					Status = SecurityStatus.Critical,
					Description = "La clé de registre HKLM\\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\Status est absente. Microsoft Defender for Endpoint (MDE) n'est pas installé ou n'a jamais été enrôlé sur cette machine.\n\nSans MDE, la machine ne bénéficie pas de la protection EDR avancée : pas de détection comportementale, pas de réponse automatisée aux incidents, pas de télémétrie de sécurité vers le portail Microsoft 365 Defender.",
					Recommendation = "Enrôler cette machine dans Microsoft Defender for Endpoint via le portail Microsoft 365 Defender (https://security.microsoft.com). Utiliser un package d'onboarding via Intune, GPO, ou script local.",
					Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/onboarding",
					CollectedAt = DateTime.Now
				};
			}
			int onboardingState = Convert.ToInt32(statusKey.GetValue("OnboardingState", -1));
			string orgId = statusKey.GetValue("OrgId", "Non disponible")?.ToString() ?? "Non disponible";
			string senseId = statusKey.GetValue("SenseId", "Non disponible")?.ToString() ?? "Non disponible";
			bool autoSenseLogEnabled = Convert.ToInt32(statusKey.GetValue("AutoSenseLogEnabled", 0)) == 1;
			bool isOnboarded = onboardingState == 1;
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.AppendLine("=== MDE — STATUT D'ENRÔLEMENT ===");
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(28, 2, stringBuilder2);
			handler.AppendLiteral("  OnboardingState      : ");
			handler.AppendFormatted(onboardingState);
			handler.AppendLiteral(" (");
			handler.AppendFormatted(isOnboarded ? "Enrôlé ✓" : "NON ENRÔLÉ ✗");
			handler.AppendLiteral(")");
			stringBuilder3.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(25, 1, stringBuilder2);
			handler.AppendLiteral("  Organisation ID      : ");
			handler.AppendFormatted(orgId);
			stringBuilder4.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder5 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(25, 1, stringBuilder2);
			handler.AppendLiteral("  Device SenseId       : ");
			handler.AppendFormatted(senseId);
			stringBuilder5.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder6 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(25, 1, stringBuilder2);
			handler.AppendLiteral("  AutoSenseLogEnabled  : ");
			handler.AppendFormatted(autoSenseLogEnabled ? "Oui" : "Non");
			stringBuilder6.AppendLine(ref handler);
			stringBuilder.AppendLine();
			if (isOnboarded)
			{
				stringBuilder.AppendLine("  [OK] Cette machine est enrôlée dans Microsoft Defender for Endpoint.");
			}
			else
			{
				stringBuilder.AppendLine("  [CRITIQUE] OnboardingState != 1. La machine N'EST PAS protégée par l'EDR MDE.");
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "A. MDE — Statut d'Enrôlement",
				CurrentValue = $"OnboardingState = {onboardingState} | OrgId: {orgId}",
				ExpectedValue = "OnboardingState = 1 (Enrôlé)",
				Status = ((!isOnboarded) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = stringBuilder.ToString().TrimEnd(),
				Recommendation = (isOnboarded ? "La machine est correctement enrôlée dans MDE. Vérifier le statut dans le portail Microsoft 365 Defender." : "CRITIQUE : Machine non enrôlée dans MDE. Aucune protection EDR active. Procéder à l'enrôlement immédiatement."),
				Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/onboarding",
				CollectedAt = DateTime.Now
			};
		});
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey policyKey = localMachineKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection", writable: false);
			using RegistryKey onboardingInfoKey = localMachineKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\OnboardingInfo", writable: false);
			bool hasPolicyKey = policyKey != null;
			bool hasOnboardingInfoKey = onboardingInfoKey != null;
			string onboardingMethod = ((hasPolicyKey && hasOnboardingInfoKey) ? "GPO et onboarding direct détectés" : (hasPolicyKey ? "Onboarding via GPO/MDM uniquement" : ((!hasOnboardingInfoKey) ? "Aucune méthode d'onboarding détectée" : "Onboarding direct (script/package)")));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "A2. MDE — Méthode d'Onboarding",
				CurrentValue = onboardingMethod,
				ExpectedValue = "Onboarding via GPO/Intune ou package direct",
				Status = ((!(hasPolicyKey || hasOnboardingInfoKey)) ? SecurityStatus.Warning : SecurityStatus.Info),
				Description = $"Méthode d'enrôlement MDE détectée : {onboardingMethod}.\n  Clé GPO   (SOFTWARE\\Policies\\...ATP) : {(hasPolicyKey ? "Présente" : "Absente")}\n  Clé OnboardingInfo                     : {(hasOnboardingInfoKey ? "Présente" : "Absente")}",
				Recommendation = "L'enrôlement via Intune (MDM) ou GPO est recommandé pour une gestion centralisée.",
				Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-endpoints",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CollectSenseServiceStatus(List<SecurityResult> results, CancellationToken ct)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			(string State, string StartMode) senseService = QueryServiceWmi("Sense");
			string state = senseService.State;
			string startMode = senseService.StartMode;
			bool isRunning = state.Equals("Running", StringComparison.OrdinalIgnoreCase);
			bool isAutoStart = startMode.Equals("Auto", StringComparison.OrdinalIgnoreCase);
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.AppendLine("=== SERVICE SENSE (AGENT MDE) ===");
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(17, 1, stringBuilder2);
			handler.AppendLiteral("  État actuel  : ");
			handler.AppendFormatted(state);
			stringBuilder3.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(19, 1, stringBuilder2);
			handler.AppendLiteral("  Mode démarrage : ");
			handler.AppendFormatted(startMode);
			stringBuilder4.AppendLine(ref handler);
			stringBuilder.AppendLine();
			if (isRunning && isAutoStart)
			{
				stringBuilder.AppendLine("  [OK] Le service Sense (MDE) est actif et configuré en démarrage automatique.");
			}
			else if (!isRunning)
			{
				stringBuilder.AppendLine("  [CRITIQUE] Le service Sense est arrêté. L'agent EDR MDE est INACTIF.");
			}
			else
			{
				stringBuilder.AppendLine("  [AVERTISSEMENT] Le service Sense fonctionne mais n'est pas en démarrage automatique.");
			}
			stringBuilder.AppendLine();
			stringBuilder.AppendLine("  Note : Le service 'Sense' (Windows Defender Advanced Threat Protection Service)");
			stringBuilder.AppendLine("  est le composant central de l'agent MDE. Son arrêt signifie l'absence totale de");
			stringBuilder.AppendLine("  protection EDR, de détection comportementale et de remontée de télémétrie.");
			SecurityStatus status = ((!isRunning) ? SecurityStatus.Critical : ((!isAutoStart) ? SecurityStatus.Warning : SecurityStatus.OK));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "B1. Service Sense — Agent MDE",
				CurrentValue = "État : " + state + " | Démarrage : " + startMode,
				ExpectedValue = "Running, Automatic",
				Status = status,
				Description = stringBuilder.ToString().TrimEnd(),
				Recommendation = ((!isRunning) ? "Démarrer le service Sense : 'sc start Sense'. Si le service refuse de démarrer, vérifier l'enrôlement MDE et les journaux système." : ((!isAutoStart) ? "Configurer le service Sense en démarrage automatique : 'sc config Sense start=auto'." : "Service Sense opérationnel.")),
				Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/troubleshoot-onboarding",
				CollectedAt = DateTime.Now
			};
		});
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			(string State, string StartMode) diagTrackService = QueryServiceWmi("DiagTrack");
			string state = diagTrackService.State;
			string startMode = diagTrackService.StartMode;
			bool isRunning = state.Equals("Running", StringComparison.OrdinalIgnoreCase);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "B2. Service DiagTrack — Télémétrie Windows",
				CurrentValue = "État : " + state + " | Démarrage : " + startMode,
				ExpectedValue = "Running (requis pour MDE)",
				Status = ((!isRunning) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = $"Le service DiagTrack (Windows Connected User Experiences and Telemetry) est requis pour le fonctionnement de Microsoft Defender for Endpoint.\nÉtat actuel : {state} | Mode démarrage : {startMode}\n\nSi DiagTrack est désactivé, MDE peut ne pas remonter correctement la télémétrie de sécurité.",
				Recommendation = (isRunning ? "Service DiagTrack actif — télémétrie MDE fonctionnelle." : "Activer le service DiagTrack pour assurer le bon fonctionnement de MDE."),
				Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-proxy-internet",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CollectMdeCapabilities(List<SecurityResult> results, CancellationToken ct)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey statusKey = localMachineKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\Status", writable: false);
			string azureAdJoined = "Non disponible";
			string managementEnvironment = "Non disponible";
			if (statusKey != null)
			{
				azureAdJoined = Convert.ToInt32(statusKey.GetValue("IsAadJoined", -1)) switch
				{
					1 => "Oui (Azure AD Joined)",
					0 => "Non (pas Azure AD Joined)",
					_ => "Non disponible",
				};
				managementEnvironment = statusKey.GetValue("ManagementEnvironment", "Non disponible")?.ToString() ?? "Non disponible";
			}
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.AppendLine("=== MDE — CAPACITÉS ET CONFIGURATION ===");
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(26, 1, stringBuilder2);
			handler.AppendLiteral("  Azure AD Joined       : ");
			handler.AppendFormatted(azureAdJoined);
			stringBuilder3.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(29, 1, stringBuilder2);
			handler.AppendLiteral("  Environnement de gestion : ");
			handler.AppendFormatted(managementEnvironment);
			stringBuilder4.AppendLine(ref handler);
			stringBuilder.AppendLine();
			stringBuilder.AppendLine("  L'Azure AD Join est nécessaire pour certaines fonctionnalités MDE avancées comme");
			stringBuilder.AppendLine("  l'accès conditionnel, la gestion des risques de périphériques et l'intégration Intune.");
			return new SecurityResult
			{
				Category = Category,
				CheckName = "C. MDE — Capacités (AAD Join, Gestion)",
				CurrentValue = "AAD: " + azureAdJoined + " | Gestion: " + managementEnvironment,
				ExpectedValue = "Azure AD Joined recommandé pour MDE complet",
				Status = ((!azureAdJoined.StartsWith("Oui")) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = stringBuilder.ToString().TrimEnd(),
				Recommendation = (azureAdJoined.StartsWith("Non (") ? "Envisager l'Azure AD Join pour activer les fonctionnalités MDE avancées et la gestion Intune." : "Configuration Azure AD correcte pour MDE."),
				Reference = "https://learn.microsoft.com/azure/active-directory/devices/concept-azure-ad-join",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CollectRelatedSecurityServices(List<SecurityResult> results, CancellationToken ct)
	{
		(string, string, bool)[] serviceDefinitions = new(string, string, bool)[7]
		{
			("WdNisSvc", "Defender Network Inspection Service", false),
			("WinDefend", "Windows Defender Antivirus Service", true),
			("Sense", "MDE — Windows Defender ATP", true),
			("wscsvc", "Windows Security Center Service", true),
			("SecurityHealthService", "Windows Security Health Service", false),
			("mpssvc", "Windows Defender Firewall", true),
			("EventLog", "Windows Event Log (CRITIQUE si arrêté)", true)
		};
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.AppendLine("=== SERVICES DE SÉCURITÉ WINDOWS ===");
		stringBuilder.AppendLine();
		int criticalStoppedCount = 0;
		int nonCriticalStoppedCount = 0;
		List<(string, string, string, bool)> serviceStatuses = new List<(string, string, string, bool)>();
		(string, string, bool)[] services = serviceDefinitions;
		StringBuilder stringBuilder2;
		StringBuilder.AppendInterpolatedStringHandler handler;
		for (int i = 0; i < services.Length; i++)
		{
			(string, string, bool) service = services[i];
			ct.ThrowIfCancellationRequested();
			(string State, string StartMode) serviceStatus = QueryServiceWmi(service.Item1);
			string state = serviceStatus.State;
			string startMode = serviceStatus.StartMode;
			bool isRunning = state.Equals("Running", StringComparison.OrdinalIgnoreCase);
			string statusTag = (isRunning ? "[OK]" : ((!service.Item3) ? "[AVERT.]" : "[CRITIQUE]"));
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(22, 4, stringBuilder2);
			handler.AppendLiteral("  ");
			handler.AppendFormatted<string>(statusTag, -12);
			handler.AppendLiteral(" ");
			handler.AppendFormatted<string>(service.Item1, -28);
			handler.AppendLiteral(" État: ");
			handler.AppendFormatted<string>(state, -12);
			handler.AppendLiteral(" Démarrage: ");
			handler.AppendFormatted(startMode);
			stringBuilder3.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(15, 1, stringBuilder2);
			handler.AppendLiteral("             → ");
			handler.AppendFormatted(service.Item2);
			stringBuilder4.AppendLine(ref handler);
			if (!isRunning && service.Item3)
			{
				criticalStoppedCount++;
			}
			if (!isRunning && !service.Item3)
			{
				nonCriticalStoppedCount++;
			}
			serviceStatuses.Add((service.Item1, state, startMode, service.Item3));
		}
		stringBuilder.AppendLine();
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder5 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(31, 1, stringBuilder2);
		handler.AppendLiteral("  Services critiques arrêtés : ");
		handler.AppendFormatted(criticalStoppedCount);
		stringBuilder5.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder6 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(35, 1, stringBuilder2);
		handler.AppendLiteral("  Services non critiques arrêtés : ");
		handler.AppendFormatted(nonCriticalStoppedCount);
		stringBuilder6.AppendLine(ref handler);
		SecurityStatus status = ((criticalStoppedCount > 0) ? SecurityStatus.Critical : ((nonCriticalStoppedCount > 0) ? SecurityStatus.Warning : SecurityStatus.OK));
		string stoppedCriticalList = string.Empty;
		foreach (var serviceEntry in serviceStatuses)
		{
			var (serviceName, serviceState, _, _) = serviceEntry;
			if (serviceEntry.Item4 && !serviceState.Equals("Running", StringComparison.OrdinalIgnoreCase))
			{
				stoppedCriticalList = stoppedCriticalList + serviceName + " (arrêté), ";
			}
		}
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "D. Services de Sécurité Associés",
			CurrentValue = $"{criticalStoppedCount} service(s) critique(s) arrêté(s) | {nonCriticalStoppedCount} avertissement(s)",
			ExpectedValue = "Tous les services critiques en état Running",
			Status = status,
			Description = stringBuilder.ToString().TrimEnd(),
			Recommendation = ((criticalStoppedCount > 0) ? ("Services critiques arrêtés : " + stoppedCriticalList.TrimEnd(',', ' ') + ". Redémarrer immédiatement et investiguer la cause.") : ((nonCriticalStoppedCount > 0) ? "Certains services de sécurité non critiques sont arrêtés. Vérifier leur nécessité." : "Tous les services de sécurité sont opérationnels.")),
			Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/check-sensor-status",
			CollectedAt = DateTime.Now
		});
	}

	private void CollectDefenderVersionsAndSignatures(List<SecurityResult> results, CancellationToken ct)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey defenderKey = localMachineKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender", writable: false);
			using RegistryKey signatureKey = localMachineKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates", writable: false);
			using RegistryKey platformKey = localMachineKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Platform", writable: false);
			string platformVersion = platformKey?.GetValue(null, "Non disponible")?.ToString() ?? "Non disponible";
			string avEngineVersion = defenderKey?.GetValue("AVEngine", "Non disponible")?.ToString() ?? "Non disponible";
			string signatureVersion = signatureKey?.GetValue("SignatureVersion", "Non disponible")?.ToString() ?? "Non disponible";
			string lastUpdatedRaw = signatureKey?.GetValue("SignaturesLastUpdated", null)?.ToString() ?? string.Empty;
			DateTime lastUpdated = DateTime.MinValue;
			int signatureAgeDays = -1;
			if (!string.IsNullOrEmpty(lastUpdatedRaw))
			{
				try
				{
					lastUpdated = ManagementDateTimeConverter.ToDateTime(lastUpdatedRaw);
					signatureAgeDays = (int)(DateTime.Now - lastUpdated).TotalDays;
				}
				catch (Exception)
				{
					if (DateTime.TryParse(lastUpdatedRaw, out var parsedDate))
					{
						lastUpdated = parsedDate;
						signatureAgeDays = (int)(DateTime.Now - parsedDate).TotalDays;
					}
				}
			}
			if (signatureAgeDays < 0)
			{
				try
				{
					ManagementObjectSearcher searcher = new ManagementObjectSearcher(WmiHelper.GetScope("\\\\.\\root\\Microsoft\\Windows\\Defender"), new ObjectQuery("SELECT AntivirusSignatureAge FROM MSFT_MpComputerStatus"));
					try
					{
						using ManagementObjectCollection collection = searcher.Get();
						using ManagementObjectCollection.ManagementObjectEnumerator enumerator = collection.GetEnumerator();
						if (enumerator.MoveNext())
						{
							ManagementObject statusObject = (ManagementObject)enumerator.Current;
							ManagementObject disposableStatus = statusObject;
							try
							{
								object signatureAgeValue = statusObject["AntivirusSignatureAge"];
								if (signatureAgeValue != null)
								{
									signatureAgeDays = Convert.ToInt32(signatureAgeValue);
								}
							}
							finally
							{
								((IDisposable)disposableStatus)?.Dispose();
							}
						}
					}
					finally
					{
						((IDisposable)searcher)?.Dispose();
					}
				}
				catch (ManagementException)
				{
				}
				catch (Exception)
				{
				}
			}
			string signatureAgeText = ((signatureAgeDays >= 0) ? $"{signatureAgeDays} jour(s)" : "Inconnu");
			SecurityStatus status = ((signatureAgeDays < 0) ? SecurityStatus.Info : ((signatureAgeDays > 14) ? SecurityStatus.Critical : ((signatureAgeDays > 7) ? SecurityStatus.Warning : SecurityStatus.OK)));
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.AppendLine("=== MICROSOFT DEFENDER ANTIVIRUS — VERSIONS ET SIGNATURES ===");
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(24, 1, stringBuilder2);
			handler.AppendLiteral("  Version Plateforme  : ");
			handler.AppendFormatted(platformVersion);
			stringBuilder3.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(24, 1, stringBuilder2);
			handler.AppendLiteral("  Version Moteur AV   : ");
			handler.AppendFormatted(avEngineVersion);
			stringBuilder4.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder5 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(24, 1, stringBuilder2);
			handler.AppendLiteral("  Version Signature   : ");
			handler.AppendFormatted(signatureVersion);
			stringBuilder5.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder6 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(24, 1, stringBuilder2);
			handler.AppendLiteral("  Âge des signatures  : ");
			handler.AppendFormatted(signatureAgeText);
			stringBuilder6.AppendLine(ref handler);
			if (lastUpdated != DateTime.MinValue)
			{
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder7 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(24, 1, stringBuilder2);
				handler.AppendLiteral("  Dernière mise à jour: ");
				handler.AppendFormatted(lastUpdated, "yyyy-MM-dd HH:mm:ss");
				stringBuilder7.AppendLine(ref handler);
			}
			stringBuilder.AppendLine();
			if (signatureAgeDays > 7)
			{
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder8 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(102, 1, stringBuilder2);
				handler.AppendLiteral("  [ALERTE] Les signatures Defender ont ");
				handler.AppendFormatted(signatureAgeDays);
				handler.AppendLiteral(" jours. Des menaces récentes pourraient ne pas être détectées !");
				stringBuilder8.AppendLine(ref handler);
			}
			else if (signatureAgeDays >= 0)
			{
				stringBuilder.AppendLine("  [OK] Les signatures Defender sont à jour.");
			}
			string recommendation = ((signatureAgeDays > 14) ? $"CRITIQUE : Signatures Defender vieilles de {signatureAgeDays} jours. Forcer une mise à jour : 'Update-MpSignature' (PowerShell) ou via Windows Update." : ((signatureAgeDays <= 7) ? "Signatures Defender à jour. Maintenir les mises à jour automatiques actives." : $"Signatures Defender vieilles de {signatureAgeDays} jours. Planifier une mise à jour urgente."));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "E. Defender AV — Versions et Signatures",
				CurrentValue = $"Plateforme: {platformVersion} | Moteur: {avEngineVersion} | Sig: {signatureAgeText}",
				ExpectedValue = "Signatures < 7 jours",
				Status = status,
				Description = stringBuilder.ToString().TrimEnd(),
				Recommendation = recommendation,
				Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/manage-updates-baselines-microsoft-defender-antivirus",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CollectAsrRules(List<SecurityResult> results, CancellationToken ct)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey asrRulesKey = localMachineKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules", writable: false);
			if (asrRulesKey == null)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "F. ASR — Règles de Réduction de la Surface d'Attaque",
					CurrentValue = "Clé de registre ASR absente (règles non configurées via GPO/Intune)",
					ExpectedValue = "Toutes les règles ASR en mode Block (1)",
					Status = SecurityStatus.Warning,
					Description = "La clé de registre des règles ASR est absente :\n  HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules\n\nCela signifie que les règles ASR ne sont pas configurées via GPO ou Intune. Les règles ASR peuvent cependant être actives via la configuration locale de Windows Defender.\n\nLes règles ASR bloquent les vecteurs d'attaque courants : macros Office malveillantes, vol de credentials LSASS, scripts obfusqués, exécutables téléchargés via scripts web, etc.",
					Recommendation = "Configurer les règles ASR via GPO ou Intune. Les règles recommandées en mode Block sont documentées sur Microsoft Learn.",
					Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-deployment",
					CollectedAt = DateTime.Now
				};
			}
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.AppendLine("=== ASR — RÈGLES DE RÉDUCTION DE LA SURFACE D'ATTAQUE ===");
			stringBuilder.AppendLine();
			int disabledCount = 0;
			int auditCount = 0;
			int blockCount = 0;
			int unknownCount = 0;
			string[] valueNames = asrRulesKey.GetValueNames();
			StringBuilder stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler;
			foreach (string ruleGuid in valueNames)
			{
				ct.ThrowIfCancellationRequested();
				int ruleValue = Convert.ToInt32(asrRulesKey.GetValue(ruleGuid, -1));
				string modeLabel = ruleValue switch
				{
					0 => "Désactivée (0)",
					1 => "Bloquée — Mode actif (1)",
					2 => "Audit seulement (2)",
					_ => $"Valeur inconnue ({ruleValue})",
				};
				string matchedRuleName;
				string ruleDisplayName = (AsrRuleNames.TryGetValue(ruleGuid, out matchedRuleName) ? matchedRuleName : ("Règle inconnue (GUID: " + ruleGuid + ")"));
				string modeTag = ruleValue switch
				{
					1 => "[BLOCK]",
					2 => "[AUDIT]",
					0 => "[OFF  ]",
					_ => "[????]",
				};
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder3 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(3, 2, stringBuilder2);
				handler.AppendLiteral("  ");
				handler.AppendFormatted(modeTag);
				handler.AppendLiteral(" ");
				handler.AppendFormatted<string>(modeLabel, -30);
				stringBuilder3.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder4 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(9, 1, stringBuilder2);
				handler.AppendLiteral("         ");
				handler.AppendFormatted(ruleDisplayName);
				stringBuilder4.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder5 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(15, 1, stringBuilder2);
				handler.AppendLiteral("         GUID: ");
				handler.AppendFormatted(ruleGuid);
				stringBuilder5.AppendLine(ref handler);
				stringBuilder.AppendLine();
				switch (ruleValue)
				{
				case 0:
					disabledCount++;
					break;
				case 2:
					auditCount++;
					break;
				case 1:
					blockCount++;
					break;
				default:
					unknownCount++;
					break;
				}
			}
			int totalRules = asrRulesKey.GetValueNames().Length;
			stringBuilder.AppendLine("  ─────────────────────────────────────────────────");
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder6 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(29, 1, stringBuilder2);
			handler.AppendLiteral("  TOTAL règles configurées : ");
			handler.AppendFormatted(totalRules);
			stringBuilder6.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder7 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(30, 1, stringBuilder2);
			handler.AppendLiteral("  Mode Block (actif)        : ");
			handler.AppendFormatted(blockCount);
			stringBuilder7.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder8 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(30, 1, stringBuilder2);
			handler.AppendLiteral("  Mode Audit                : ");
			handler.AppendFormatted(auditCount);
			stringBuilder8.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder9 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(30, 1, stringBuilder2);
			handler.AppendLiteral("  Désactivées               : ");
			handler.AppendFormatted(disabledCount);
			stringBuilder9.AppendLine(ref handler);
			SecurityStatus status = ((disabledCount > 0 || totalRules == 0) ? SecurityStatus.Warning : ((auditCount > 0) ? SecurityStatus.Info : SecurityStatus.OK));
			string recommendation = ((disabledCount > 0) ? $"{disabledCount} règle(s) ASR désactivée(s). Activer toutes les règles recommandées en mode Block pour réduire la surface d'attaque." : ((auditCount > 0) ? $"{auditCount} règle(s) en mode Audit. Envisager de passer en mode Block après validation de l'impact sur les applications métier." : ((blockCount <= 0) ? "Aucune règle ASR configurée. Configurer les règles ASR recommandées via GPO ou Intune." : $"Toutes les {blockCount} règle(s) ASR configurées sont en mode Block. Bonne configuration.")));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "F. ASR — Règles de Réduction de la Surface d'Attaque",
				CurrentValue = $"{totalRules} règle(s) | Block: {blockCount} | Audit: {auditCount} | Désactivées: {disabledCount}",
				ExpectedValue = "Toutes les règles critiques en mode Block (1)",
				Status = status,
				Description = stringBuilder.ToString().TrimEnd(),
				Recommendation = recommendation,
				Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference",
				CollectedAt = DateTime.Now
			};
		});
	}

	private static (string State, string StartMode) QueryServiceWmi(string serviceName)
	{
		try
		{
			ManagementObjectSearcher searcher = new ManagementObjectSearcher(WmiHelper.GetScope(), new ObjectQuery("SELECT State, StartMode FROM Win32_Service WHERE Name='" + serviceName + "'"));
			try
			{
				using ManagementObjectCollection collection = searcher.Get();
				using (ManagementObjectCollection.ManagementObjectEnumerator enumerator = collection.GetEnumerator())
				{
					if (enumerator.MoveNext())
					{
						ManagementObject serviceObject = (ManagementObject)enumerator.Current;
						ManagementObject disposableService = serviceObject;
						try
						{
							string? state = serviceObject["State"]?.ToString() ?? "Unknown";
							string startMode = serviceObject["StartMode"]?.ToString() ?? "Unknown";
							return (State: state, StartMode: startMode);
						}
						finally
						{
							((IDisposable)disposableService)?.Dispose();
						}
					}
				}
				return (State: "Not Found", StartMode: "N/A");
			}
			finally
			{
				((IDisposable)searcher)?.Dispose();
			}
		}
		catch (ManagementException)
		{
			return (State: "Erreur WMI", StartMode: "N/A");
		}
		catch (Exception)
		{
			return (State: "Erreur WMI", StartMode: "N/A");
		}
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
				Category = "EDR & Threat Protection",
				CheckName = "Erreur de vérification",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Vérification MDE échouée : " + ex.Message,
				Recommendation = "Vérifier les accès WMI et registre (exécuter en tant qu'administrateur).",
				Reference = ""
			});
		}
	}
}
