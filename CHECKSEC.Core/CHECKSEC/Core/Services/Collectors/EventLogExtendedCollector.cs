using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Core.Services.Collectors;

public class EventLogExtendedCollector : ISecurityCollector
{
	private sealed class EventEntry
	{
		public DateTime TimeCreated { get; init; }

		public int Id { get; init; }

		public string ProviderName { get; init; } = string.Empty;

		public string Message { get; init; } = string.Empty;
	}

	private sealed class SectionResult
	{
		public List<SecurityResult> Results { get; init; } = new List<SecurityResult>();

		public int EventCount { get; init; }

		public bool LogClearedFound { get; init; }

		public bool ActiveThreatFound { get; init; }

		public int NewServiceTaskCount { get; init; }
	}

	private const int MaxSecurityEvents = 100;

	private const int MaxSystemEvents = 50;

	private const int MaxPowerShellEvents = 20;

	private const int MaxDefenderEvents = 50;

	private const int MaxAppLockerEvents = 30;

	private const int MaxRdpEvents = 30;

	private const int MaxMessageLength = 400;

	private static readonly string[] SuspiciousPsKeywords = new string[10] { "Invoke-Expression", "IEX", "DownloadString", "Invoke-WebRequest", "Base64", "FromBase64String", "EncodedCommand", "bypass", "hidden", "noprofile" };

	private static readonly int[] SecurityEventIds = new int[16]
	{
		4616, 4657, 4697, 4698, 4699, 4700, 4702, 4720, 4722, 4724,
		4726, 4728, 4732, 4756, 1102, 4739
	};

	private static readonly int[] SystemEventIds = new int[5] { 7045, 7034, 7036, 104, 4199 };

	private static readonly int[] DefenderEventIds = new int[11]
	{
		1006, 1007, 1008, 1116, 1117, 1118, 1119, 1121, 1122, 5001,
		5004
	};

	private static readonly HashSet<int> ActiveThreatIds = new HashSet<int> { 1006, 1007, 1116, 1117 };

	public string Name => "Journaux Forensiques";

	public string Category => "Forensics";

	private static DateTime LastMonth => DateTime.UtcNow.AddDays(-30.0);

	private static DateTime LastWeek => DateTime.UtcNow.AddDays(-7.0);

	public async Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		Stopwatch sw = Stopwatch.StartNew();
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		int countSecurity = 0;
		int countSystem = 0;
		int countPowerShell = 0;
		int countDefender = 0;
		int countAppLocker = 0;
		int countRdp = 0;
		bool logClearedFound = false;
		bool activeThreatFound = false;
		int newServiceTaskCount = 0;
		try
		{
			await Task.Run(delegate
			{
				ct.ThrowIfCancellationRequested();
				SectionResult securityCriticalSection = CollectSecurityCriticalEvents(ct);
				report.Results.AddRange(securityCriticalSection.Results);
				countSecurity = securityCriticalSection.EventCount;
				logClearedFound |= securityCriticalSection.LogClearedFound;
				newServiceTaskCount += securityCriticalSection.NewServiceTaskCount;
				ct.ThrowIfCancellationRequested();
				SectionResult systemSuspiciousSection = CollectSystemSuspiciousEvents(ct);
				report.Results.AddRange(systemSuspiciousSection.Results);
				countSystem = systemSuspiciousSection.EventCount;
				logClearedFound |= systemSuspiciousSection.LogClearedFound;
				newServiceTaskCount += systemSuspiciousSection.NewServiceTaskCount;
				ct.ThrowIfCancellationRequested();
				SectionResult powerShellSection = CollectPowerShellForensics(ct);
				report.Results.AddRange(powerShellSection.Results);
				countPowerShell = powerShellSection.EventCount;
				ct.ThrowIfCancellationRequested();
				SectionResult defenderSection = CollectDefenderThreatHistory(ct);
				report.Results.AddRange(defenderSection.Results);
				countDefender = defenderSection.EventCount;
				activeThreatFound |= defenderSection.ActiveThreatFound;
				ct.ThrowIfCancellationRequested();
				SectionResult appLockerSection = CollectAppLockerWdacEvents(ct);
				report.Results.AddRange(appLockerSection.Results);
				countAppLocker = appLockerSection.EventCount;
				ct.ThrowIfCancellationRequested();
				SectionResult rdpSection = CollectRdpRemoteAccessEvents(ct);
				report.Results.AddRange(rdpSection.Results);
				countRdp = rdpSection.EventCount;
				ct.ThrowIfCancellationRequested();
				AddSummaryStatistics(report.Results, countSecurity, countSystem, countPowerShell, countDefender, countAppLocker, countRdp, logClearedFound, activeThreatFound, newServiceTaskCount);
			}, ct);
		}
		catch (OperationCanceledException)
		{
			report.ErrorMessage = "Collecte forensique des journaux annulée par l'utilisateur.";
		}
		catch (Exception collectException)
		{
			report.ErrorMessage = "Erreur EventLogExtendedCollector : " + collectException.Message;
		}
		finally
		{
			sw.Stop();
			report.Duration = sw.Elapsed;
		}
		return report;
	}

	private SectionResult CollectSecurityCriticalEvents(CancellationToken ct)
	{
		string monthCutoff = LastMonth.ToString("yyyy-MM-ddTHH:mm:ss.000Z");
		string idFilter = BuildIdXpath(SecurityEventIds);
		string xpathQuery = $"*[System[({idFilter}) and TimeCreated[@SystemTime>='{monthCutoff}']]]";
		(List<EventEntry> Events, string ErrorNote) readResult = ReadEvents("Security", xpathQuery, 100, ct);
		List<EventEntry> events = readResult.Events;
		string errorNote = readResult.ErrorNote;
		bool logCleared = events.Exists((EventEntry e) => e.Id == 1102);
		int newServiceCount = events.FindAll((EventEntry e) => e.Id == 4697 || e.Id == 4698 || e.Id == 4700 || e.Id == 4702).Count;
		StringBuilder descriptionBuilder = FormatEventSection(events, errorNote, "Journal de Sécurité Windows — Événements Critiques (30 jours)", 100);
		SecurityStatus statusFromEvents = DetermineStatus(events, errorNote, new HashSet<int> { 1102, 4616, 4697 });
		SecurityResult securityResult = new SecurityResult
		{
			Category = Category,
			CheckName = "A. Événements Sécurité Critiques",
			CurrentValue = (string.IsNullOrEmpty(errorNote) ? $"{events.Count} événement(s) sur 30 jours" : errorNote),
			ExpectedValue = "Aucun événement critique de sécurité",
			Status = (logCleared ? SecurityStatus.Critical : statusFromEvents),
			Description = descriptionBuilder.ToString().TrimEnd(),
			Recommendation = (logCleared ? "CRITIQUE : Journal d'audit effacé (EventID 1102) — Indicateur fort d'une tentative de dissimulation. Investiguer immédiatement." : ((events.Count > 0) ? "Analyser les événements détectés dans l'Observateur d'Événements > Journal de Sécurité. Porter une attention particulière aux créations de comptes et modifications de stratégies." : "Aucune action requise.")),
			Reference = "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor",
			CollectedAt = DateTime.Now
		};
		return new SectionResult
		{
			Results = new List<SecurityResult> { securityResult },
			EventCount = events.Count,
			LogClearedFound = logCleared,
			NewServiceTaskCount = newServiceCount
		};
	}

	private SectionResult CollectSystemSuspiciousEvents(CancellationToken ct)
	{
		string monthCutoff = LastMonth.ToString("yyyy-MM-ddTHH:mm:ss.000Z");
		string idFilter = BuildIdXpath(SystemEventIds);
		string xpathQuery = $"*[System[({idFilter}) and TimeCreated[@SystemTime>='{monthCutoff}']]]";
		(List<EventEntry> Events, string ErrorNote) readResult = ReadEvents("System", xpathQuery, 50, ct);
		List<EventEntry> events = readResult.Events;
		string errorNote = readResult.ErrorNote;
		bool logCleared = events.Exists((EventEntry e) => e.Id == 104);
		int newServiceCount = events.FindAll((EventEntry e) => e.Id == 7045).Count;
		StringBuilder descriptionBuilder = FormatEventSection(events, errorNote, "Journal Système Windows — Événements Suspects (30 jours)", 50);
		SecurityStatus statusFromEvents = DetermineStatus(events, errorNote, new HashSet<int> { 104 });
		SecurityResult securityResult = new SecurityResult
		{
			Category = Category,
			CheckName = "B. Événements Système Suspects",
			CurrentValue = (string.IsNullOrEmpty(errorNote) ? $"{events.Count} événement(s) sur 30 jours" : errorNote),
			ExpectedValue = "Aucun service inconnu installé, aucun journal effacé",
			Status = (logCleared ? SecurityStatus.Critical : statusFromEvents),
			Description = descriptionBuilder.ToString().TrimEnd(),
			Recommendation = (logCleared ? "CRITIQUE : Journal Système effacé (EventID 104) — Investiguer immédiatement." : ((newServiceCount > 0) ? $"{newServiceCount} nouveau(x) service(s) installé(s) (EventID 7045) — Vérifier leur légitimité." : ((events.Count > 0) ? "Examiner les crashs de services répétés (EventID 7034) pouvant indiquer une tentative d'exploitation." : "Aucune action requise."))),
			Reference = "https://learn.microsoft.com/windows-server/administration/windows-commands/wevtutil",
			CollectedAt = DateTime.Now
		};
		return new SectionResult
		{
			Results = new List<SecurityResult> { securityResult },
			EventCount = events.Count,
			LogClearedFound = logCleared,
			NewServiceTaskCount = newServiceCount
		};
	}

	private SectionResult CollectPowerShellForensics(CancellationToken ct)
	{
		string monthCutoff = LastMonth.ToString("yyyy-MM-ddTHH:mm:ss.000Z");
		List<SecurityResult> results = new List<SecurityResult>();
		int totalEventCount = 0;
		string xpathQuery = "*[System[EventID=4104 and TimeCreated[@SystemTime>='" + monthCutoff + "']]]";
		(List<EventEntry> Events, string ErrorNote) scriptBlockResult = ReadEvents("Microsoft-Windows-PowerShell/Operational", xpathQuery, 200, ct);
		List<EventEntry> scriptBlockEvents = scriptBlockResult.Events;
		string scriptBlockError = scriptBlockResult.ErrorNote;
		totalEventCount += scriptBlockEvents.Count;
		List<EventEntry> suspiciousScripts = new List<EventEntry>();
		foreach (EventEntry scriptEvent in scriptBlockEvents)
		{
			ct.ThrowIfCancellationRequested();
			// Correctif M2 : les messages sont tronqués à 400 caractères dans ReadEvents, seuil abaissé à 350 pour rester dans la limite
			bool isSuspicious = scriptEvent.Message.Length > 350;
			if (!isSuspicious)
			{
				string[] suspiciousPsKeywords = SuspiciousPsKeywords;
				foreach (string keyword in suspiciousPsKeywords)
				{
					if (scriptEvent.Message.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
					{
						isSuspicious = true;
						break;
					}
				}
			}
			if (isSuspicious)
			{
				suspiciousScripts.Add(scriptEvent);
			}
			if (suspiciousScripts.Count >= 20)
			{
				break;
			}
		}
		StringBuilder scriptDescriptionBuilder = FormatEventSection(suspiciousScripts, scriptBlockError, "PowerShell — Blocs de Script Suspects (EventID 4104, 30 jours)", 20, $"[INFO] {scriptBlockEvents.Count} événement(s) 4104 total | {suspiciousScripts.Count} script(s) suspect(s) filtré(s) (longueur > 350 ou mots-clés dangereux)");
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "C1. PowerShell — Exécution de Scripts (4104)",
			CurrentValue = (string.IsNullOrEmpty(scriptBlockError) ? $"{suspiciousScripts.Count} script(s) suspect(s) / {scriptBlockEvents.Count} total" : scriptBlockError),
			ExpectedValue = "Aucun script obfusqué ou avec encodage Base64",
			Status = ((suspiciousScripts.Count > 0) ? SecurityStatus.Warning : SecurityStatus.OK),
			Description = scriptDescriptionBuilder.ToString().TrimEnd(),
			Recommendation = ((suspiciousScripts.Count > 0) ? "Scripts PowerShell suspects détectés. Analyser le contenu des blocs (EventID 4104) pour détecter l'obfuscation, le téléchargement ou le contournement de politique." : "Aucun script PowerShell suspect détecté."),
			Reference = "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows",
			CollectedAt = DateTime.Now
		});
		string xpathQuery2 = "*[System[(EventID=4103 or EventID=40961 or EventID=40962) and TimeCreated[@SystemTime>='" + monthCutoff + "']]]";
		(List<EventEntry> Events, string ErrorNote) sessionResult = ReadEvents("Microsoft-Windows-PowerShell/Operational", xpathQuery2, 50, ct);
		List<EventEntry> sessionEvents = sessionResult.Events;
		string sessionError = sessionResult.ErrorNote;
		totalEventCount += sessionEvents.Count;
		StringBuilder sessionDescriptionBuilder = FormatEventSection(sessionEvents, sessionError, "PowerShell — Sessions et Module Logging (4103/40961/40962, 30 jours)", 50);
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "C2. PowerShell — Sessions et Module Logging",
			CurrentValue = (string.IsNullOrEmpty(sessionError) ? $"{sessionEvents.Count} événement(s) sur 30 jours" : sessionError),
			ExpectedValue = "Activité PowerShell normale et attendue",
			Status = ((sessionEvents.Count > 0) ? SecurityStatus.Info : SecurityStatus.OK),
			Description = sessionDescriptionBuilder.ToString().TrimEnd(),
			Recommendation = "Vérifier que les sessions PowerShell correspondent à des activités légitimes d'administration.",
			Reference = "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows",
			CollectedAt = DateTime.Now
		});
		return new SectionResult
		{
			Results = results,
			EventCount = totalEventCount
		};
	}

	private SectionResult CollectDefenderThreatHistory(CancellationToken ct)
	{
		string monthCutoff = LastMonth.ToString("yyyy-MM-ddTHH:mm:ss.000Z");
		LastWeek.ToString("yyyy-MM-ddTHH:mm:ss.000Z");
		string idFilter = BuildIdXpath(DefenderEventIds);
		string xpathQuery = $"*[System[({idFilter}) and TimeCreated[@SystemTime>='{monthCutoff}']]]";
		(List<EventEntry> Events, string ErrorNote) readResult = ReadEvents("Microsoft-Windows-Windows Defender/Operational", xpathQuery, 50, ct);
		List<EventEntry> events = readResult.Events;
		string errorNote = readResult.ErrorNote;
		bool activeThreat = events.Exists((EventEntry e) => ActiveThreatIds.Contains(e.Id) && e.TimeCreated >= DateTime.UtcNow.AddDays(-7.0));
		bool realtimeDisabled = events.Exists((EventEntry e) => e.Id == 5001 || e.Id == 5004);
		StringBuilder descriptionBuilder = FormatEventSection(events, errorNote, "Windows Defender — Détections et Actions (30 jours)", 50, activeThreat ? "[ALERTE] MENACE ACTIVE DÉTECTÉE : Événements de détection de malware dans les 7 derniers jours !" : null);
		SecurityStatus status = ((!string.IsNullOrEmpty(errorNote)) ? SecurityStatus.Error : (activeThreat ? SecurityStatus.Critical : (realtimeDisabled ? SecurityStatus.Critical : ((events.Count > 0) ? SecurityStatus.Warning : SecurityStatus.OK))));
		string recommendation = (activeThreat ? "CRITIQUE : Menace active détectée par Windows Defender dans les 7 derniers jours. Isoler la machine et lancer une analyse complète immédiatement." : (realtimeDisabled ? "CRITIQUE : La protection en temps réel Windows Defender a été désactivée (EventID 5001/5004). Réactiver immédiatement." : ((events.Count <= 0) ? "Aucune détection de menace Defender sur 30 jours." : "Des événements Defender ont été trouvés sur 30 jours. Vérifier que toutes les menaces ont été correctement traitées.")));
		SecurityResult securityResult = new SecurityResult
		{
			Category = Category,
			CheckName = "D. Windows Defender — Menaces Détectées",
			CurrentValue = (string.IsNullOrEmpty(errorNote) ? $"{events.Count} événement(s) | Menace active (7j) : {(activeThreat ? "OUI" : "non")}" : errorNote),
			ExpectedValue = "Aucune menace active, protection en temps réel activée",
			Status = status,
			Description = descriptionBuilder.ToString().TrimEnd(),
			Recommendation = recommendation,
			Reference = "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/review-alerts",
			CollectedAt = DateTime.Now
		};
		return new SectionResult
		{
			Results = new List<SecurityResult> { securityResult },
			EventCount = events.Count,
			ActiveThreatFound = activeThreat
		};
	}

	private SectionResult CollectAppLockerWdacEvents(CancellationToken ct)
	{
		string monthCutoff = LastMonth.ToString("yyyy-MM-ddTHH:mm:ss.000Z");
		List<SecurityResult> results = new List<SecurityResult>();
		int totalEventCount = 0;
		string xpathQuery = "*[System[(EventID=8003 or EventID=8004 or EventID=8006 or EventID=8007) and TimeCreated[@SystemTime>='" + monthCutoff + "']]]";
		(List<EventEntry> Events, string ErrorNote) appLockerResult = ReadEvents("Microsoft-Windows-AppLocker/EXE and DLL", xpathQuery, 30, ct);
		List<EventEntry> appLockerEvents = appLockerResult.Events;
		string appLockerError = appLockerResult.ErrorNote;
		totalEventCount += appLockerEvents.Count;
		int blockedCount = appLockerEvents.FindAll((EventEntry e) => e.Id == 8003 || e.Id == 8004).Count;
		int auditCount = appLockerEvents.FindAll((EventEntry e) => e.Id == 8006 || e.Id == 8007).Count;
		StringBuilder appLockerDescriptionBuilder = FormatEventSection(appLockerEvents, appLockerError, "AppLocker EXE/DLL — Blocages et Audits (30 jours)", 30);
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "E1. AppLocker — Blocages EXE/DLL",
			CurrentValue = (string.IsNullOrEmpty(appLockerError) ? $"{blockedCount} blocage(s) | {auditCount} audit(s) sur 30 jours" : appLockerError),
			ExpectedValue = "Aucun blocage inattendu",
			Status = ((blockedCount > 0) ? SecurityStatus.Warning : SecurityStatus.OK),
			Description = appLockerDescriptionBuilder.ToString().TrimEnd(),
			Recommendation = ((blockedCount > 0) ? "Des exécutables ont été bloqués par AppLocker. Vérifier si ces blocages sont intentionnels ou si une politique trop restrictive gêne la productivité." : "Aucun blocage AppLocker détecté sur 30 jours."),
			Reference = "https://learn.microsoft.com/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview",
			CollectedAt = DateTime.Now
		});
		string xpathQuery2 = "*[System[(EventID=3076 or EventID=3077) and TimeCreated[@SystemTime>='" + monthCutoff + "']]]";
		(List<EventEntry> Events, string ErrorNote) wdacResult = ReadEvents("Microsoft-Windows-CodeIntegrity/Operational", xpathQuery2, 30, ct);
		List<EventEntry> wdacEvents = wdacResult.Events;
		string wdacError = wdacResult.ErrorNote;
		totalEventCount += wdacEvents.Count;
		int wdacBlockCount = wdacEvents.FindAll((EventEntry e) => e.Id == 3077).Count;
		int wdacAuditCount = wdacEvents.FindAll((EventEntry e) => e.Id == 3076).Count;
		StringBuilder wdacDescriptionBuilder = FormatEventSection(wdacEvents, wdacError, "Code Integrity / WDAC — Blocages de Politique (30 jours)", 30);
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "E2. WDAC Code Integrity — Politique de Blocage",
			CurrentValue = (string.IsNullOrEmpty(wdacError) ? $"{wdacBlockCount} blocage(s) en vigueur | {wdacAuditCount} audit(s) sur 30 jours" : wdacError),
			ExpectedValue = "Politique WDAC en mode blocage actif, aucun blocage inattendu",
			Status = ((wdacBlockCount > 0) ? SecurityStatus.Warning : SecurityStatus.OK),
			Description = wdacDescriptionBuilder.ToString().TrimEnd(),
			Recommendation = ((wdacBlockCount > 0) ? "La politique Code Integrity a bloqué des exécutables (EventID 3077). Vérifier la politique WDAC et les fichiers bloqués." : ((wdacAuditCount > 0) ? "Mode audit WDAC actif (EventID 3076). Envisager de passer en mode blocage pour une protection maximale." : "Aucun blocage WDAC détecté.")),
			Reference = "https://learn.microsoft.com/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control",
			CollectedAt = DateTime.Now
		});
		return new SectionResult
		{
			Results = results,
			EventCount = totalEventCount
		};
	}

	private SectionResult CollectRdpRemoteAccessEvents(CancellationToken ct)
	{
		string weekCutoff = LastWeek.ToString("yyyy-MM-ddTHH:mm:ss.000Z");
		List<SecurityResult> results = new List<SecurityResult>();
		int totalEventCount = 0;
		string xpathQuery = "*[System[(EventID=21 or EventID=23 or EventID=24 or EventID=25) and TimeCreated[@SystemTime>='" + weekCutoff + "']]]";
		(List<EventEntry> Events, string ErrorNote) sessionResult = ReadEvents("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", xpathQuery, 30, ct);
		List<EventEntry> sessionEvents = sessionResult.Events;
		string sessionError = sessionResult.ErrorNote;
		totalEventCount += sessionEvents.Count;
		int successCount = sessionEvents.FindAll((EventEntry e) => e.Id == 21).Count;
		int failureCount = sessionEvents.FindAll((EventEntry e) => e.Id == 23).Count;
		StringBuilder sessionDescriptionBuilder = FormatEventSection(sessionEvents, sessionError, "RDP — Sessions Locales TerminalServices (7 jours)", 30);
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "F1. RDP — Connexions Réussies/Échouées",
			CurrentValue = (string.IsNullOrEmpty(sessionError) ? $"{successCount} connexion(s) réussie(s) | {failureCount} échec(s) sur 7 jours" : sessionError),
			ExpectedValue = "Connexions RDP depuis des sources connues et autorisées uniquement",
			Status = ((failureCount > 5) ? SecurityStatus.Warning : ((successCount > 0) ? SecurityStatus.Info : SecurityStatus.OK)),
			Description = sessionDescriptionBuilder.ToString().TrimEnd(),
			Recommendation = ((failureCount > 5) ? $"{failureCount} échecs de connexion RDP sur 7 jours — Possible tentative de force brute. Vérifier les adresses IP sources." : ((successCount > 0) ? "Des connexions RDP ont eu lieu. Vérifier que les utilisateurs et les heures sont attendus." : "Aucune activité RDP récente.")),
			Reference = "https://learn.microsoft.com/windows-server/remote/remote-desktop-services/rds-plan-access-from-internet",
			CollectedAt = DateTime.Now
		});
		string xpathQuery2 = "*[System[EventID=1149 and TimeCreated[@SystemTime>='" + weekCutoff + "']]]";
		(List<EventEntry> Events, string ErrorNote) connectionResult = ReadEvents("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", xpathQuery2, 30, ct);
		List<EventEntry> connectionEvents = connectionResult.Events;
		string connectionError = connectionResult.ErrorNote;
		totalEventCount += connectionEvents.Count;
		StringBuilder connectionDescriptionBuilder = FormatEventSection(connectionEvents, connectionError, "RDP — Connexions Réseau Avant Authentification EventID 1149 (7 jours)", 30, (connectionEvents.Count > 10) ? $"[ALERTE] {connectionEvents.Count} connexions réseau RDP avant authentification — Possible scan de port ou reconnaissance." : null);
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "F2. RDP — Connexions Réseau Avant Auth (1149)",
			CurrentValue = (string.IsNullOrEmpty(connectionError) ? $"{connectionEvents.Count} connexion(s) réseau RDP sur 7 jours" : connectionError),
			ExpectedValue = "Connexions uniquement depuis des sources légitimes",
			Status = ((connectionEvents.Count > 10) ? SecurityStatus.Warning : ((connectionEvents.Count > 0) ? SecurityStatus.Info : SecurityStatus.OK)),
			Description = connectionDescriptionBuilder.ToString().TrimEnd(),
			Recommendation = ((connectionEvents.Count > 10) ? "Nombre élevé de connexions réseau RDP avant authentification (EventID 1149). Potentiel scan de port ou attaque. Activer le Network Level Authentication (NLA)." : "Activité réseau RDP normale."),
			Reference = "https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access",
			CollectedAt = DateTime.Now
		});
		return new SectionResult
		{
			Results = results,
			EventCount = totalEventCount
		};
	}

	private void AddSummaryStatistics(List<SecurityResult> results, int countSecurity, int countSystem, int countPowerShell, int countDefender, int countAppLocker, int countRdp, bool logClearedFound, bool activeThreatFound, int newServiceTaskCount)
	{
		int totalEvents = countSecurity + countSystem + countPowerShell + countDefender + countAppLocker + countRdp;
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.AppendLine("=== RÉSUMÉ FORENSIQUE — JOURNAUX WINDOWS (30 JOURS) ===");
		stringBuilder.AppendLine();
		StringBuilder stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder3 = stringBuilder2;
		StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(60, 1, stringBuilder2);
		handler.AppendLiteral("  Journal de Sécurité (événements critiques) : ");
		handler.AppendFormatted(countSecurity);
		handler.AppendLiteral(" événement(s)");
		stringBuilder3.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder4 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(61, 1, stringBuilder2);
		handler.AppendLiteral("  Journal Système (événements suspects)       : ");
		handler.AppendFormatted(countSystem);
		handler.AppendLiteral(" événement(s)");
		stringBuilder4.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder5 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(61, 1, stringBuilder2);
		handler.AppendLiteral("  PowerShell (scripts suspects)               : ");
		handler.AppendFormatted(countPowerShell);
		handler.AppendLiteral(" événement(s)");
		stringBuilder5.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder6 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(61, 1, stringBuilder2);
		handler.AppendLiteral("  Windows Defender (détections)               : ");
		handler.AppendFormatted(countDefender);
		handler.AppendLiteral(" événement(s)");
		stringBuilder6.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder7 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(61, 1, stringBuilder2);
		handler.AppendLiteral("  AppLocker / WDAC (blocages)                 : ");
		handler.AppendFormatted(countAppLocker);
		handler.AppendLiteral(" événement(s)");
		stringBuilder7.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder8 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(61, 1, stringBuilder2);
		handler.AppendLiteral("  RDP / Accès distants (7 jours)              : ");
		handler.AppendFormatted(countRdp);
		handler.AppendLiteral(" événement(s)");
		stringBuilder8.AppendLine(ref handler);
		stringBuilder.AppendLine("  ─────────────────────────────────────────────────────");
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder9 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(48, 1, stringBuilder2);
		handler.AppendLiteral("  TOTAL ÉVÉNEMENTS FORENSIQUES                : ");
		handler.AppendFormatted(totalEvents);
		stringBuilder9.AppendLine(ref handler);
		stringBuilder.AppendLine();
		if (logClearedFound)
		{
			stringBuilder.AppendLine("  [CRITIQUE] ⚠ Journal effacé détecté (EventID 1102 ou 104) — Possible tentative de dissimulation d'activité malveillante !");
		}
		if (activeThreatFound)
		{
			stringBuilder.AppendLine("  [CRITIQUE] ⚠ Menace active détectée par Windows Defender dans les 7 derniers jours !");
		}
		if (newServiceTaskCount > 0)
		{
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder10 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(88, 1, stringBuilder2);
			handler.AppendLiteral("  [AVERTISSEMENT] ");
			handler.AppendFormatted(newServiceTaskCount);
			handler.AppendLiteral(" nouveau(x) service(s)/tâche(s) planifiée(s) installé(s) sur 30 jours.");
			stringBuilder10.AppendLine(ref handler);
		}
		if (!logClearedFound && !activeThreatFound && newServiceTaskCount == 0)
		{
			stringBuilder.AppendLine("  [OK] Aucun indicateur critique de compromission détecté.");
		}
		SecurityStatus status = ((logClearedFound || activeThreatFound) ? SecurityStatus.Critical : ((newServiceTaskCount > 0 || totalEvents > 50) ? SecurityStatus.Warning : ((totalEvents > 0) ? SecurityStatus.Info : SecurityStatus.OK)));
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "G. Résumé Forensique Global",
			CurrentValue = $"{totalEvents} événement(s) forensique(s) au total sur 30 jours",
			ExpectedValue = "Aucun indicateur de compromission",
			Status = status,
			Description = stringBuilder.ToString().TrimEnd(),
			Recommendation = (logClearedFound ? "PRIORITÉ 1 : Journal effacé détecté. Lancer une investigation de sécurité complète immédiatement." : (activeThreatFound ? "PRIORITÉ 1 : Menace active détectée. Isoler la machine et contacter l'équipe sécurité." : "Consulter les détails de chaque section pour les actions correctives recommandées.")),
			Reference = "https://learn.microsoft.com/windows/security/threat-protection/auditing/security-monitoring-and-attack-detection",
			CollectedAt = DateTime.Now
		});
	}

	private static (List<EventEntry> Events, string ErrorNote) ReadEvents(string logName, string xpathQuery, int maxEvents, CancellationToken ct)
	{
		List<EventEntry> collectedEvents = new List<EventEntry>();
		string errorNote = string.Empty;
		try
		{
			using EventLogReader eventLogReader = new EventLogReader(new EventLogQuery(logName, PathType.LogName, xpathQuery)
			{
				ReverseDirection = true
			});
			for (int i = 0; i < maxEvents; i++)
			{
				ct.ThrowIfCancellationRequested();
				EventRecord eventRecord;
				try
				{
					eventRecord = eventLogReader.ReadEvent();
				}
				catch (EventLogException)
				{
					break;
				}
				if (eventRecord == null)
				{
					break;
				}
				using (eventRecord)
				{
					string formattedMessage;
					try
					{
						formattedMessage = eventRecord.FormatDescription() ?? string.Empty;
						if (formattedMessage.Length > 400)
						{
							formattedMessage = formattedMessage.Substring(0, 400) + "…";
						}
					}
					catch
					{
						formattedMessage = $"(Message non disponible — ID: {eventRecord.Id})";
					}
					collectedEvents.Add(new EventEntry
					{
						TimeCreated = (eventRecord.TimeCreated?.ToUniversalTime() ?? DateTime.MinValue),
						Id = eventRecord.Id,
						ProviderName = (eventRecord.ProviderName ?? string.Empty),
						Message = formattedMessage
					});
				}
			}
		}
		catch (EventLogNotFoundException)
		{
			errorNote = "Journal '" + logName + "' introuvable ou non disponible sur ce système.";
		}
		catch (UnauthorizedAccessException)
		{
			errorNote = "Accès refusé au journal '" + logName + "'. Exécution en tant qu'administrateur requise.";
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception readException)
		{
			errorNote = "Erreur lecture journal '" + logName + "' : " + readException.Message;
		}
		return (Events: collectedEvents, ErrorNote: errorNote);
	}

	private static StringBuilder FormatEventSection(List<EventEntry> events, string errorNote, string sectionTitle, int maxEvents, string? headerExtra = null)
	{
		StringBuilder stringBuilder = new StringBuilder();
		StringBuilder stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder3 = stringBuilder2;
		StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(8, 1, stringBuilder2);
		handler.AppendLiteral("=== ");
		handler.AppendFormatted(sectionTitle);
		handler.AppendLiteral(" ===");
		stringBuilder3.AppendLine(ref handler);
		if (!string.IsNullOrEmpty(errorNote))
		{
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(16, 1, stringBuilder2);
			handler.AppendLiteral("[AVERTISSEMENT] ");
			handler.AppendFormatted(errorNote);
			stringBuilder4.AppendLine(ref handler);
			return stringBuilder;
		}
		if (!string.IsNullOrEmpty(headerExtra))
		{
			stringBuilder.AppendLine(headerExtra);
		}
		if (events.Count == 0)
		{
			stringBuilder.AppendLine("Aucun événement correspondant trouvé dans la période analysée.");
			return stringBuilder;
		}
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder5 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(39, 2, stringBuilder2);
		handler.AppendLiteral("[RÉSUMÉ] ");
		handler.AppendFormatted(events.Count);
		handler.AppendLiteral(" événement(s) trouvé(s) (max ");
		handler.AppendFormatted(maxEvents);
		handler.AppendLiteral(")");
		stringBuilder5.AppendLine(ref handler);
		stringBuilder.AppendLine();
		foreach (EventEntry @event in events)
		{
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder6 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(27, 3, stringBuilder2);
			handler.AppendLiteral("[");
			handler.AppendFormatted(@event.TimeCreated, "yyyy-MM-dd HH:mm:ss");
			handler.AppendLiteral(" UTC] EventID: ");
			handler.AppendFormatted(@event.Id);
			handler.AppendLiteral(" | Source: ");
			handler.AppendFormatted(@event.ProviderName);
			stringBuilder6.AppendLine(ref handler);
			if (!string.IsNullOrWhiteSpace(@event.Message))
			{
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder7 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(2, 1, stringBuilder2);
				handler.AppendLiteral("  ");
				handler.AppendFormatted(@event.Message.TrimEnd());
				stringBuilder7.AppendLine(ref handler);
			}
			stringBuilder.AppendLine("  ──────────────────────────────────────────────────");
		}
		return stringBuilder;
	}

	private static string BuildIdXpath(int[] ids)
	{
		List<string> idFilters = new List<string>(ids.Length);
		foreach (int eventId in ids)
		{
			idFilters.Add($"EventID={eventId}");
		}
		return string.Join(" or ", idFilters);
	}

	private static SecurityStatus DetermineStatus(List<EventEntry> events, string errorNote, HashSet<int>? criticalIds = null)
	{
		if (!string.IsNullOrEmpty(errorNote))
		{
			return SecurityStatus.Error;
		}
		if (events.Count == 0)
		{
			return SecurityStatus.OK;
		}
		if (criticalIds != null && events.Exists((EventEntry e) => criticalIds.Contains(e.Id)))
		{
			return SecurityStatus.Critical;
		}
		return SecurityStatus.Warning;
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
				Category = "Forensics",
				CheckName = "Erreur de vérification",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les accès aux journaux d'événements (exécuter en tant qu'administrateur).",
				Reference = ""
			});
		}
	}
}
