using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services;
using CHECKSEC.Core.Services.Analysis;
using CHECKSEC.Core.Services.Helpers;
using EventLogEntry = CHECKSEC.Core.Models.EventLogEntry;

namespace CHECKSEC.Services;

/// <summary>
/// Source de vérité UNIQUE pour l'export JSON enrichi de CHECKSEC.
/// Réutilisée par l'UI (DashboardViewModel) et le mode headless (App.RunHeadlessAsync)
/// afin d'éliminer toute divergence de schéma entre les deux chemins d'export.
/// </summary>
public static class ReportJsonBuilder
{
	public static string Build(AnalysisService analysis, RemediationService remediation)
	{
		JsonSerializerOptions options = new JsonSerializerOptions
		{
			WriteIndented = true,
			Converters = { (JsonConverter)new JsonStringEnumConverter() }
		};

		// Dictionnaire ordonné : l'ordre d'insertion est préservé à la sérialisation.
		// Toutes les sections SAUF Integrity sont ajoutées ici, puis on calcule le
		// SHA-256 du JSON de ce corps, et on ajoute enfin le bloc Integrity.
		Dictionary<string, object?> report = new Dictionary<string, object?>();

		report["SchemaVersion"] = "1.0";

		report["Report"] = new
		{
			GeneratedUtc = DateTimeOffset.UtcNow.ToString("o"),
			GeneratedLocal = DateTimeOffset.Now.ToString("o"),
			TimeZone = TimeZoneInfo.Local.Id,
			Tool = new
			{
				Name = "CHECKSEC",
				Version = (typeof(ReportJsonBuilder).Assembly.GetName().Version?.ToString() ?? "6.0.0")
			}
		};

		report["Host"] = new
		{
			Machine = Environment.MachineName,
			Fqdn = TryGetFqdn(),
			Domain = Environment.UserDomainName,
			IsVM = WindowsInfo.IsVM,
			Os = Environment.OSVersion.ToString(),
			Edition = WindowsInfo.Edition,
			Build = WindowsInfo.BuildNumber,
			Is64BitOs = Environment.Is64BitOperatingSystem
		};

		report["Execution"] = new
		{
			User = Environment.UserName,
			UserDomain = Environment.UserDomainName,
			IsElevated = TryIsElevated(),
			StartedUtc = analysis.AnalysisStartUtc?.ToString("o"),
			EndedUtc = analysis.AnalysisEndUtc?.ToString("o"),
			DurationMs = analysis.AnalysisDuration.TotalMilliseconds,
			ProcessorCount = Environment.ProcessorCount,
			DotNetVersion = Environment.Version.ToString(),
			Culture = CultureInfo.CurrentCulture.Name
		};

		report["Metadata"] = new
		{
			ExportDate = DateTime.Now,
			Machine = Environment.MachineName,
			User = Environment.UserName,
			OS = Environment.OSVersion.ToString(),
			OSEdition = WindowsInfo.Edition,
			OSBuild = WindowsInfo.BuildNumber,
			AppVersion = (typeof(ReportJsonBuilder).Assembly.GetName().Version?.ToString() ?? "6.0.0")
		};

		report["Summary"] = new
		{
			GlobalScore = analysis.GlobalScore,
			GlobalGrade = analysis.GlobalGrade,
			// Correctif M10 : TotalChecks = total brut ; Evaluated = somme réconciliable des 4 statuts notés
			// (l'écart TotalChecks - Evaluated correspond aux Info/NotApplicable non notés)
			TotalChecks = analysis.AllResults.Count,
			Evaluated = analysis.TotalOK + analysis.TotalWarning + analysis.TotalCritical + analysis.TotalError,
			OK = analysis.TotalOK,
			Warning = analysis.TotalWarning,
			Critical = analysis.TotalCritical,
			Error = analysis.TotalError
		};

		report["CategoryScores"] = analysis.CategoryScores.Select((SecurityScore s) => new
		{
			s.Category,
			s.Grade,
			s.ScorePercent,
			s.TotalChecks,
			s.PassedChecks,
			s.WarningChecks,
			s.CriticalChecks,
			s.ErrorChecks,
			s.InfoChecks
		}).ToList();

		report["SecureCore"] = analysis.SecureCoreItems.Select((SecureCoreItem i) => new
		{
			Name = i.Name,
			Status = i.Status.ToString(),
			Value = i.Value,
			StatusLabel = i.StatusLabel,
			TechnicalDescription = i.TechnicalDescription,
			Impact = i.Impact,
			Remediation = i.Remediation,
			Reference = i.Reference
		}).ToList();

		report["CisBenchmarks"] = analysis.CisItems.Select((CisBenchmarkItem c) => new
		{
			c.CisId,
			c.Title,
			c.Level,
			c.Section,
			c.Status,
			c.IsCompliant,
			c.IsManualCheck,
			c.CurrentValue,
			c.ExpectedValue,
			c.Remediation
		}).ToList();

		report["MsctGaps"] = analysis.Gaps.Select((ComplianceGap g) => new
		{
			PolicyName = g.PolicyName,
			RegistryPath = g.RegistryPath,
			ValueName = g.ValueName,
			BaselineValue = g.BaselineValue,
			CurrentValue = g.CurrentValue,
			IsCompliant = g.IsCompliant,
			Severity = g.Severity.ToString(),
			GpoName = g.GpoName,
			Description = g.Description
		}).ToList();

		report["EventLogEntries"] = analysis.EventLogEntries.Select((EventLogEntry e) => new
		{
			Timestamp = e.Timestamp.ToString("o"),
			Level = e.Level,
			EventId = e.EventId,
			Source = e.Source,
			Message = e.Message
		}).ToList();

		report["Remediation"] = remediation.GeneratePlan(analysis)
			.Select(r => new { r.Priority, r.Severity, r.Category, r.Action, r.Detail, r.Effort, r.Command, r.Status })
			.ToList();

		report["Modules"] = analysis.Reports.Select((CollectorReport r) => new
		{
			CollectorName = r.CollectorName,
			Success = r.Success,
			ErrorMessage = r.ErrorMessage,
			DurationMs = r.Duration.TotalMilliseconds,
			ResultCount = r.Results.Count,
			Results = r.Results.Select((SecurityResult x) => new
			{
				Category = x.Category,
				CheckName = x.CheckName,
				Status = x.Status.ToString(),
				CurrentValue = x.CurrentValue,
				ExpectedValue = x.ExpectedValue,
				Description = x.Description,
				Recommendation = x.Recommendation,
				Reference = x.Reference,
				CollectedAt = x.CollectedAt.ToString("o"),
				// Mapping MITRE ATT&CK dérivé du nom du contrôle et de sa catégorie (0..n techniques).
				MitreTechniques = MitreMapper.Map(x.CheckName, x.Category)
					.Select(t => new { t.Id, t.Name, t.Tactic })
					.ToList()
			}).ToList()
		}).ToList();

		report["CollectedParameters"] = analysis.AllResults.Select((SecurityResult r) => new
		{
			Category = r.Category,
			Parameter = r.CheckName,
			Value = r.CurrentValue
		}).Concat(analysis.Gaps.Select((ComplianceGap g) => new
		{
			Category = (g.GpoName ?? "MSCT Policy"),
			Parameter = g.ValueName,
			Value = g.CurrentValue
		})).ToList();

		// Synthèse MITRE ATT&CK : agrège, pour tous les résultats NON-OK (Warning/Critical/Error),
		// le nombre de findings par technique. Alimente une vue « couverture ATT&CK » côté SOC.
		// Placée AVANT AnalysisLog/Diagnostics afin d'être couverte par le hash Integrity (calculé en dernier).
		report["MitreSummary"] = analysis.AllResults
			.Where((SecurityResult r) => r.Status == SecurityStatus.Warning
				|| r.Status == SecurityStatus.Critical
				|| r.Status == SecurityStatus.Error)
			.SelectMany((SecurityResult r) => MitreMapper.Map(r.CheckName, r.Category))
			.GroupBy((MitreTechnique t) => t.Id)
			.Select(g => new
			{
				Id = g.Key,
				Name = g.First().Name,
				Tactic = g.First().Tactic,
				FindingCount = g.Count()
			})
			.OrderByDescending(x => x.FindingCount)
			.ToList();

		// Journal d'analyse : trace lisible de l'exécution (statut/durée/nb résultats par collecteur,
		// collecteurs vides, diagnostics, totaux). Permet de vérifier, notamment en développement,
		// que TOUS les collecteurs ont bien fonctionné.
		report["AnalysisLog"] = BuildAnalysisLog(analysis);

		report["Diagnostics"] = ErrorLogger.GetErrors().ToList();

		// Bloc Integrity en DERNIER : SHA-256 hexadécimal de TOUTES les sections précédentes
		// (donc du JSON sérialisé SANS le bloc Integrity). Re-vérifiable en retirant Integrity
		// puis en re-sérialisant à l'identique.
		string bodyJson = JsonSerializer.Serialize(report, options);
		byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(bodyJson));
		string hex = Convert.ToHexString(hash).ToLowerInvariant();
		report["Integrity"] = new
		{
			Algorithm = "SHA-256",
			Hash = hex
		};

		return JsonSerializer.Serialize(report, options);
	}

	// Construit un journal d'analyse lisible pour vérifier que tous les collecteurs ont fonctionné.
	private static List<string> BuildAnalysisLog(AnalysisService analysis)
	{
		List<string> log = new List<string>();
		List<CollectorReport> reports = analysis.Reports;
		int ok = reports.Count(r => r.Success);
		int failed = reports.Count - ok;

		log.Add("===== JOURNAL D'ANALYSE CHECKSEC =====");
		log.Add("Début (UTC)   : " + (analysis.AnalysisStartUtc?.ToString("o") ?? "n/a"));
		log.Add("Fin (UTC)     : " + (analysis.AnalysisEndUtc?.ToString("o") ?? "n/a"));
		log.Add($"Durée totale  : {analysis.AnalysisDuration.TotalMilliseconds:F0} ms");
		log.Add($"Collecteurs   : {reports.Count} exécutés — {ok} OK, {failed} en échec");
		log.Add($"Écarts MSCT   : {analysis.Gaps.Count}");
		log.Add($"Vérifications : {analysis.AllResults.Count} (OK {analysis.TotalOK} / Warn {analysis.TotalWarning} / Crit {analysis.TotalCritical} / Err {analysis.TotalError})");
		log.Add($"Score global  : {analysis.GlobalScore}% (grade {analysis.GlobalGrade})");
		log.Add("----- Détail par collecteur -----");
		foreach (CollectorReport r in reports)
		{
			string mark = r.Success ? "[OK] " : "[ECHEC]";
			string line = $"{mark} {r.CollectorName,-42} | {r.Results.Count,4} résultats | {r.Duration.TotalMilliseconds,7:F0} ms";
			if (!r.Success && !string.IsNullOrEmpty(r.ErrorMessage))
			{
				line += " | ERREUR: " + r.ErrorMessage;
			}
			log.Add(line);
		}

		List<string> empty = reports.Where(r => r.Success && r.Results.Count == 0).Select(r => r.CollectorName).ToList();
		log.Add(empty.Count > 0
			? "⚠ Collecteurs SANS aucun résultat (à vérifier) : " + string.Join(", ", empty)
			: "Tous les collecteurs réussis ont produit au moins un résultat.");

		IReadOnlyList<string> diag = ErrorLogger.GetErrors();
		if (diag.Count > 0)
		{
			log.Add($"----- Diagnostics internes ({diag.Count}) -----");
			log.AddRange(diag);
		}
		else
		{
			log.Add("Diagnostics internes : aucun.");
		}

		log.Add(failed == 0 && empty.Count == 0
			? "RÉSULTAT : ✔ Analyse complète — tous les collecteurs ont fonctionné."
			: $"RÉSULTAT : ⚠ {failed} collecteur(s) en échec, {empty.Count} sans résultat — à examiner.");
		log.Add("===== FIN DU JOURNAL =====");
		return log;
	}

	private static string TryGetFqdn()
	{
		try
		{
			return System.Net.Dns.GetHostEntry("").HostName;
		}
		catch
		{
			return Environment.MachineName;
		}
	}

	private static bool TryIsElevated()
	{
		try
		{
			using WindowsIdentity identity = WindowsIdentity.GetCurrent();
			return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
		}
		catch
		{
			return false;
		}
	}
}
