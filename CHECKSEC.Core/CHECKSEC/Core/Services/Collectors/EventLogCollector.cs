using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Core.Services.Collectors;

public class EventLogCollector : ISecurityCollector
{
	private sealed class EventEntry
	{
		public DateTime TimeCreated { get; init; }

		public int Id { get; init; }

		public string LevelDisplayName { get; init; } = string.Empty;

		public string ProviderName { get; init; } = string.Empty;

		public string Message { get; init; } = string.Empty;
	}

	private const int MaxEventsPerLog = 50;

	private const int MaxMessageLength = 500;

	private static readonly HashSet<int> SecurityEventIds = new HashSet<int> { 4625, 4648, 4719, 4720, 4726, 4738, 4740, 4771, 4776 };

	private static readonly HashSet<int> DefenderEventIds = new HashSet<int> { 1006, 1007, 1116, 1117, 1119 };

	public string Name => "EventLogCollector";

	public string Category => "Journaux d'événements Windows";

	private static DateTime SevenDaysAgo => DateTime.UtcNow.AddDays(-7.0);

	public async Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		Stopwatch sw = Stopwatch.StartNew();
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		try
		{
			await Task.Run(delegate
			{
				ct.ThrowIfCancellationRequested();
				CollectSystemLog(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CollectApplicationLog(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CollectSecurityLog(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CollectPowerShellLog(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CollectDefenderLog(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CollectBitLockerLog(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CollectAppLockerLog(report.Results, ct);
			}, ct);
		}
		catch (OperationCanceledException)
		{
			report.ErrorMessage = "Collecte des journaux annulée.";
			throw;
		}
		catch (Exception ex2)
		{
			report.ErrorMessage = "Erreur EventLogCollector: " + ex2.Message;
		}
		finally
		{
			sw.Stop();
			report.Duration = sw.Elapsed;
		}
		return report;
	}

	private static void CollectSystemLog(List<SecurityResult> results, CancellationToken ct)
	{
		string xpathQuery = BuildLevelQuery("System", 3);
		CollectGenericLog(results, "System", xpathQuery, 50, ct);
	}

	private static void CollectApplicationLog(List<SecurityResult> results, CancellationToken ct)
	{
		string xpathQuery = BuildLevelQuery("Application", 3);
		CollectGenericLog(results, "Application", xpathQuery, 50, ct);
	}

	private static void CollectSecurityLog(List<SecurityResult> results, CancellationToken ct)
	{
		List<string> conditions = new List<string>();
		foreach (int securityEventId in SecurityEventIds)
		{
			conditions.Add($"EventID={securityEventId}");
		}
		string eventIdFilter = string.Join(" or ", conditions);
		string sinceTimestamp = SevenDaysAgo.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z");
		string xpathQuery = $"*[System[({eventIdFilter}) and TimeCreated[@SystemTime>='{sinceTimestamp}']]]";
		CollectGenericLog(results, "Security", xpathQuery, 50, ct, "Échecs d'authentification, modifications de comptes et d'audit détectés.");
	}

	private static void CollectPowerShellLog(List<SecurityResult> results, CancellationToken ct)
	{
		string xpathQuery = BuildLevelQuery("Microsoft-Windows-PowerShell/Operational", 3);
		CollectGenericLog(results, "Microsoft-Windows-PowerShell/Operational", xpathQuery, 50, ct);
	}

	private static void CollectDefenderLog(List<SecurityResult> results, CancellationToken ct)
	{
		List<string> conditions = new List<string>();
		foreach (int defenderEventId in DefenderEventIds)
		{
			conditions.Add($"EventID={defenderEventId}");
		}
		string eventIdFilter = string.Join(" or ", conditions);
		string sinceTimestamp = SevenDaysAgo.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z");
		string xpathQuery = $"*[System[({eventIdFilter}) and TimeCreated[@SystemTime>='{sinceTimestamp}']]]";
		CollectGenericLog(results, "Microsoft-Windows-Windows Defender/Operational", xpathQuery, 50, ct, "Détections et actions Windows Defender.");
	}

	private static void CollectBitLockerLog(List<SecurityResult> results, CancellationToken ct)
	{
		string xpathQuery = BuildLevelQuery("Microsoft-Windows-BitLocker/BitLocker Management", 3);
		CollectGenericLog(results, "Microsoft-Windows-BitLocker/BitLocker Management", xpathQuery, 50, ct);
	}

	private static void CollectAppLockerLog(List<SecurityResult> results, CancellationToken ct)
	{
		string sinceTimestamp = SevenDaysAgo.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z");
		string xpathQuery = "*[System[(EventID=8004 or EventID=8003 or EventID=8006 or EventID=8007) and TimeCreated[@SystemTime>='" + sinceTimestamp + "']]]";
		CollectGenericLog(results, "Microsoft-Windows-AppLocker/EXE and DLL", xpathQuery, 50, ct, "Exécutions bloquées par AppLocker.");
	}

	private static string BuildLevelQuery(string logPath, int maxLevel)
	{
		string sinceTimestamp = SevenDaysAgo.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z");
		return $"*[System[Level<={maxLevel} and TimeCreated[@SystemTime>='{sinceTimestamp}']]]";
	}

	private static void CollectGenericLog(List<SecurityResult> results, string logName, string xpathQuery, int maxEvents, CancellationToken ct, string additionalDescription = "")
	{
		List<EventEntry> entries = new List<EventEntry>();
		string errorMessage = string.Empty;
		try
		{
			using EventLogReader reader = new EventLogReader(new EventLogQuery(logName, PathType.LogName, xpathQuery)
			{
				ReverseDirection = true
			});
			for (int i = 0; i < maxEvents; i++)
			{
				ct.ThrowIfCancellationRequested();
				EventRecord eventRecord;
				try
				{
					eventRecord = reader.ReadEvent();
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
					string message;
					try
					{
						message = eventRecord.FormatDescription() ?? string.Empty;
						if (message.Length > 500)
						{
							message = message.Substring(0, 500) + "…";
						}
					}
					catch
					{
						message = $"(Message non disponible - ID: {eventRecord.Id})";
					}
					string levelDisplayName;
					try
					{
						levelDisplayName = eventRecord.LevelDisplayName ?? eventRecord.Level?.ToString() ?? "Unknown";
					}
					catch
					{
						levelDisplayName = eventRecord.Level?.ToString() ?? "Unknown";
					}
					entries.Add(new EventEntry
					{
						TimeCreated = (eventRecord.TimeCreated ?? DateTime.MinValue),
						Id = eventRecord.Id,
						LevelDisplayName = levelDisplayName,
						ProviderName = (eventRecord.ProviderName ?? string.Empty),
						Message = message
					});
				}
			}
		}
		catch (EventLogNotFoundException)
		{
			errorMessage = "Journal '" + logName + "' introuvable ou non disponible sur ce système.";
		}
		catch (UnauthorizedAccessException)
		{
			errorMessage = "Accès refusé au journal '" + logName + "'. Exécution en tant qu'administrateur requise.";
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex5)
		{
			errorMessage = "Erreur lors de la lecture du journal '" + logName + "': " + ex5.Message;
		}
		StringBuilder stringBuilder = new StringBuilder();
		if (!string.IsNullOrEmpty(errorMessage))
		{
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(16, 1, stringBuilder2);
			handler.AppendLiteral("[AVERTISSEMENT] ");
			handler.AppendFormatted(errorMessage);
			stringBuilder3.AppendLine(ref handler);
		}
		else if (entries.Count == 0)
		{
			stringBuilder.AppendLine("Aucun événement correspondant trouvé dans la période de 7 jours.");
		}
		else
		{
			int criticalCount = 0;
			int errorCount = 0;
			int warningCount = 0;
			foreach (EventEntry entry in entries)
			{
				string levelUpper = entry.LevelDisplayName.ToUpperInvariant();
				if (levelUpper.Contains("CRIT") || levelUpper == "1")
				{
					criticalCount++;
				}
				else if (levelUpper.Contains("ERR") || levelUpper == "2")
				{
					errorCount++;
				}
				else if (levelUpper.Contains("WARN") || levelUpper == "3")
				{
					warningCount++;
				}
			}
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(79, 4, stringBuilder2);
			handler.AppendLiteral("[RÉSUMÉ] ");
			handler.AppendFormatted(entries.Count);
			handler.AppendLiteral(" événement(s) sur 7 jours | ");
			handler.AppendLiteral("Critiques: ");
			handler.AppendFormatted(criticalCount);
			handler.AppendLiteral(" | Erreurs: ");
			handler.AppendFormatted(errorCount);
			handler.AppendLiteral(" | Avertissements: ");
			handler.AppendFormatted(warningCount);
			stringBuilder4.AppendLine(ref handler);
			if (!string.IsNullOrEmpty(additionalDescription))
			{
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder5 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(7, 1, stringBuilder2);
				handler.AppendLiteral("[INFO] ");
				handler.AppendFormatted(additionalDescription);
				stringBuilder5.AppendLine(ref handler);
			}
			stringBuilder.AppendLine();
			foreach (EventEntry entry in entries)
			{
				ct.ThrowIfCancellationRequested();
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder6 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(18, 4, stringBuilder2);
				handler.AppendLiteral("[");
				handler.AppendFormatted(entry.TimeCreated, "yyyy-MM-dd HH:mm:ss");
				handler.AppendLiteral("] [");
				handler.AppendFormatted(entry.LevelDisplayName);
				handler.AppendLiteral("] [");
				handler.AppendFormatted(entry.ProviderName);
				handler.AppendLiteral("] EventID: ");
				handler.AppendFormatted(entry.Id);
				stringBuilder6.AppendLine(ref handler);
				if (!string.IsNullOrWhiteSpace(entry.Message))
				{
					stringBuilder.AppendLine(entry.Message.TrimEnd());
				}
				stringBuilder.AppendLine("------");
			}
		}
		SecurityStatus status = ((!string.IsNullOrEmpty(errorMessage)) ? SecurityStatus.Error : ((entries.Count != 0) ? ((!entries.Exists((EventEntry e) => e.LevelDisplayName.Contains("Critical", StringComparison.OrdinalIgnoreCase) || e.LevelDisplayName == "1")) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK));
		string logDisplayName = (logName.Contains('/') ? logName.Split('/')[0] : logName);
		results.Add(new SecurityResult
		{
			Category = "Journaux d'événements Windows",
			CheckName = "Journal: " + logName,
			CurrentValue = (string.IsNullOrEmpty(errorMessage) ? $"{entries.Count} événement(s) détecté(s) (7 derniers jours, max {maxEvents})" : errorMessage),
			ExpectedValue = "Aucun événement critique ou erreur",
			Status = status,
			Description = stringBuilder.ToString().TrimEnd(),
			Recommendation = ((entries.Count > 0 && string.IsNullOrEmpty(errorMessage)) ? ("Analyser les événements dans le journal '" + logName + "' via l'Observateur d'événements. Corriger les erreurs récurrentes et investiguer les avertissements critiques.") : (string.IsNullOrEmpty(errorMessage) ? "Aucune action requise." : "Vérifier les permissions d'accès aux journaux (exécuter en tant qu'administrateur).")),
			Reference = "Observateur d'événements Windows > " + logDisplayName,
			CollectedAt = DateTime.Now
		});
	}
}
