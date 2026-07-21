using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Services;

public class HtmlReportService
{
	public string GenerateReport(AnalysisService analysis, RemediationService remediation, List<EventLogEntry>? eventLogEntries = null)
	{
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.AppendLine("<!DOCTYPE html>");
		stringBuilder.AppendLine("<html lang='fr'><head><meta charset='utf-8'/>");
		stringBuilder.AppendLine("<title>CHECKSEC — Rapport d'Audit</title>");
		stringBuilder.AppendLine("<style>");
		stringBuilder.AppendLine("\n:root { --bg: #ffffff; --fg: #1a1a1a; --card: #f8f9fa; --border: #e0e0e0; --accent: #0078D4; --green: #4CAF50; --orange: #FF9800; --red: #F44336; --grey: #78909C; }\n@media (prefers-color-scheme: dark) { :root { --bg: #1e1e1e; --fg: #e0e0e0; --card: #2d2d2d; --border: #404040; } }\nbody.dark { --bg: #1e1e1e; --fg: #e0e0e0; --card: #2d2d2d; --border: #404040; }\n* { margin: 0; padding: 0; box-sizing: border-box; }\nbody { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--fg); padding: 40px; max-width: 1200px; margin: 0 auto; }\nh1 { color: var(--accent); font-size: 2em; margin-bottom: 8px; }\nh2 { color: var(--accent); font-size: 1.3em; margin: 32px 0 16px; border-bottom: 2px solid var(--accent); padding-bottom: 8px; }\n.meta { opacity: 0.6; margin-bottom: 24px; }\n.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 16px 0; }\n.card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }\n.card .value { font-size: 2.5em; font-weight: bold; }\n.card .label { opacity: 0.6; font-size: 0.9em; }\n.score-badge { display: inline-block; font-size: 4em; font-weight: bold; color: var(--accent); border: 4px solid var(--accent); border-radius: 50%; width: 120px; height: 120px; line-height: 112px; text-align: center; margin: 16px auto; }\ntable { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 0.9em; }\nth { background: var(--accent); color: white; padding: 10px 12px; text-align: left; cursor: pointer; user-select: none; }\nth:hover { background: #005a9e; }\ntd { padding: 8px 12px; border-bottom: 1px solid var(--border); }\ntr:nth-child(even) { background: var(--card); }\n.ok { color: var(--green); } .warn { color: var(--orange); } .crit { color: var(--red); } .err { color: var(--grey); }\n.section { background: var(--card); border-radius: 12px; padding: 24px; margin: 16px 0; border: 1px solid var(--border); }\ndetails { margin: 8px 0; }\nsummary { cursor: pointer; font-weight: 600; padding: 8px; border-radius: 6px; }\nsummary:hover { background: var(--border); }\n.toggle-theme { position: fixed; top: 16px; right: 16px; padding: 8px 16px; border-radius: 8px; border: 1px solid var(--border); background: var(--card); cursor: pointer; color: var(--fg); }\n");
		stringBuilder.AppendLine("</style></head><body>");
		stringBuilder.AppendLine("<button class='toggle-theme' onclick='document.body.classList.toggle(\"dark\")'>Mode sombre</button>");
		stringBuilder.AppendLine("<h1>CHECKSEC — Rapport d'Audit de Sécurité</h1>");
		StringBuilder stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder3 = stringBuilder2;
		StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(57, 3, stringBuilder2);
		handler.AppendLiteral("<p class='meta'>Machine : ");
		handler.AppendFormatted(Environment.MachineName);
		handler.AppendLiteral(" | Date : ");
		handler.AppendFormatted(DateTime.Now, "dd/MM/yyyy HH:mm");
		handler.AppendLiteral(" | Utilisateur : ");
		handler.AppendFormatted(Environment.UserName);
		handler.AppendLiteral("</p>");
		stringBuilder3.AppendLine(ref handler);
		stringBuilder.AppendLine("<div style='text-align:center'>");
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder4 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(31, 1, stringBuilder2);
		handler.AppendLiteral("<div class='score-badge'>");
		handler.AppendFormatted(analysis.GlobalGrade);
		handler.AppendLiteral("</div>");
		stringBuilder4.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder5 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(32, 1, stringBuilder2);
		handler.AppendLiteral("<p style='font-size:1.2em'>");
		handler.AppendFormatted(analysis.GlobalScore);
		handler.AppendLiteral("%</p>");
		stringBuilder5.AppendLine(ref handler);
		stringBuilder.AppendLine("</div>");
		stringBuilder.AppendLine("<div class='cards'>");
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder6 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(79, 1, stringBuilder2);
		handler.AppendLiteral("<div class='card'><div class='value ok'>");
		handler.AppendFormatted(analysis.TotalOK);
		handler.AppendLiteral("</div><div class='label'>OK</div></div>");
		stringBuilder6.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder7 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(93, 1, stringBuilder2);
		handler.AppendLiteral("<div class='card'><div class='value warn'>");
		handler.AppendFormatted(analysis.TotalWarning);
		handler.AppendLiteral("</div><div class='label'>Avertissements</div></div>");
		stringBuilder7.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder8 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(88, 1, stringBuilder2);
		handler.AppendLiteral("<div class='card'><div class='value crit'>");
		handler.AppendFormatted(analysis.TotalCritical);
		handler.AppendLiteral("</div><div class='label'>Critiques</div></div>");
		stringBuilder8.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder9 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(85, 1, stringBuilder2);
		handler.AppendLiteral("<div class='card'><div class='value err'>");
		handler.AppendFormatted(analysis.TotalError);
		handler.AppendLiteral("</div><div class='label'>Erreurs</div></div>");
		stringBuilder9.AppendLine(ref handler);
		stringBuilder.AppendLine("</div>");
		stringBuilder.AppendLine("<h2>Scores par Catégorie</h2>");
		stringBuilder.AppendLine("<table><thead><tr><th>Catégorie</th><th>Grade</th><th>Score</th><th>OK</th><th>Warn</th><th>Crit</th></tr></thead><tbody>");
		foreach (SecurityScore categoryScore in analysis.CategoryScores)
		{
			string gradeClass;
			switch (categoryScore.Grade)
			{
			case "A":
			case "B":
				gradeClass = "ok";
				break;
			case "C":
				gradeClass = "warn";
				break;
			default:
				gradeClass = "crit";
				break;
			}
			string cssClass = gradeClass;
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder10 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(80, 7, stringBuilder2);
			handler.AppendLiteral("<tr><td>");
			handler.AppendFormatted(Esc(categoryScore.Category));
			handler.AppendLiteral("</td><td class='");
			handler.AppendFormatted(cssClass);
			handler.AppendLiteral("'><b>");
			handler.AppendFormatted(categoryScore.Grade);
			handler.AppendLiteral("</b></td><td>");
			handler.AppendFormatted(categoryScore.ScorePercent);
			handler.AppendLiteral("%</td><td>");
			handler.AppendFormatted(categoryScore.PassedChecks);
			handler.AppendLiteral("</td><td>");
			handler.AppendFormatted(categoryScore.WarningChecks);
			handler.AppendLiteral("</td><td>");
			handler.AppendFormatted(categoryScore.CriticalChecks);
			handler.AppendLiteral("</td></tr>");
			stringBuilder10.AppendLine(ref handler);
		}
		stringBuilder.AppendLine("</tbody></table>");
		stringBuilder.AppendLine("<h2>Secure Core</h2>");
		stringBuilder.AppendLine("<table><thead><tr><th>Composant</th><th>Statut</th><th>Valeur</th></tr></thead><tbody>");
		foreach (SecureCoreItem secureCoreItem in analysis.SecureCoreItems)
		{
			string coreStatusClass = ((secureCoreItem.Status == SecurityStatus.OK) ? "ok" : "crit");
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder11 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(45, 4, stringBuilder2);
			handler.AppendLiteral("<tr><td>");
			handler.AppendFormatted(Esc(secureCoreItem.Name));
			handler.AppendLiteral("</td><td class='");
			handler.AppendFormatted(coreStatusClass);
			handler.AppendLiteral("'>");
			handler.AppendFormatted(Esc(secureCoreItem.StatusLabel));
			handler.AppendLiteral("</td><td>");
			handler.AppendFormatted(Esc(secureCoreItem.Value));
			handler.AppendLiteral("</td></tr>");
			stringBuilder11.AppendLine(ref handler);
		}
		stringBuilder.AppendLine("</tbody></table>");
		if (analysis.Gaps.Count > 0)
		{
			// Correctif L8 : ComplianceGap ne possède pas de champ de remédiation ; en-tête renommé "Description" pour refléter le contenu réel
			stringBuilder.AppendLine("<h2>Écarts MSCT</h2>");
			stringBuilder.AppendLine("<table><thead><tr><th>Sévérité</th><th>Politique</th><th>Registre</th><th>Attendu</th><th>Actuel</th><th>Description</th></tr></thead><tbody>");
			foreach (ComplianceGap gap in from g in analysis.Gaps
				where !g.IsCompliant
				orderby g.Severity descending
				select g)
			{
				string gapSeverityClass = gap.Severity switch
				{
					GapSeverity.Critical => "crit", 
					GapSeverity.High => "warn", 
					_ => "", 
				};
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder12 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(96, 7, stringBuilder2);
				handler.AppendLiteral("<tr><td class='");
				handler.AppendFormatted(gapSeverityClass);
				handler.AppendLiteral("'>");
				handler.AppendFormatted(gap.Severity);
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(gap.PolicyName));
				handler.AppendLiteral("</td><td style='font-size:0.8em'>");
				handler.AppendFormatted(Esc(gap.RegistryPath));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(gap.BaselineValue));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(gap.CurrentValue));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(gap.Description));
				handler.AppendLiteral("</td></tr>");
				stringBuilder12.AppendLine(ref handler);
			}
			stringBuilder.AppendLine("</tbody></table>");
		}
		if (analysis.CisItems.Count > 0)
		{
			stringBuilder.AppendLine("<h2>Benchmark CIS</h2>");
			stringBuilder.AppendLine("<table><thead><tr><th>ID</th><th>Section</th><th>Description</th><th>Statut</th><th>Niveau</th><th>Actuel</th><th>Remédiation</th></tr></thead><tbody>");
			foreach (CisBenchmarkItem cisItem in analysis.CisItems)
			{
				string cisStatusClass = ((cisItem.Status == "Pass") ? "ok" : ((cisItem.Status == "Fail") ? "crit" : "warn"));
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder13 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(81, 8, stringBuilder2);
				handler.AppendLiteral("<tr><td>");
				handler.AppendFormatted(Esc(cisItem.CisId));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(cisItem.Section));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(cisItem.Title));
				handler.AppendLiteral("</td><td class='");
				handler.AppendFormatted(cisStatusClass);
				handler.AppendLiteral("'>");
				handler.AppendFormatted(cisItem.Status);
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(cisItem.Level));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(cisItem.CurrentValue));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(cisItem.Remediation));
				handler.AppendLiteral("</td></tr>");
				stringBuilder13.AppendLine(ref handler);
			}
			stringBuilder.AppendLine("</tbody></table>");
		}
		if (analysis.AllResults.Count > 0)
		{
			stringBuilder.AppendLine("<h2>Tous les Résultats</h2>");
			stringBuilder.AppendLine("<table><thead><tr><th>Statut</th><th>Catégorie</th><th>Vérification</th><th>Actuel</th><th>Attendu</th><th>Description</th><th>Recommandation</th></tr></thead><tbody>");
			foreach (SecurityResult allResult in analysis.AllResults)
			{
				string resultStatusClass = allResult.Status switch
				{
					SecurityStatus.OK => "ok", 
					SecurityStatus.Warning => "warn", 
					SecurityStatus.Critical => "crit", 
					SecurityStatus.Error => "err", 
					_ => "", 
				};
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder14 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(81, 8, stringBuilder2);
				handler.AppendLiteral("<tr><td class='");
				handler.AppendFormatted(resultStatusClass);
				handler.AppendLiteral("'>");
				handler.AppendFormatted(allResult.Status);
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(allResult.Category));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(allResult.CheckName));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(allResult.CurrentValue));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(allResult.ExpectedValue));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(allResult.Description));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(allResult.Recommendation));
				handler.AppendLiteral("</td></tr>");
				stringBuilder14.AppendLine(ref handler);
			}
			stringBuilder.AppendLine("</tbody></table>");
		}
		List<RemediationItem> remediationPlan = remediation.GeneratePlan(analysis);
		if (remediationPlan.Count > 0)
		{
			stringBuilder.AppendLine("<h2>Plan de Remédiation</h2>");
			stringBuilder.AppendLine("<table><thead><tr><th>#</th><th>Sévérité</th><th>Catégorie</th><th>Action</th><th>Détail</th><th>Effort</th><th>Commande</th></tr></thead><tbody>");
			foreach (RemediationItem remItem in remediationPlan)
			{
				string remSeverityClass = ((remItem.Severity == "Critical") ? "crit" : ((remItem.Severity == "High") ? "warn" : ""));
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder15 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(105, 8, stringBuilder2);
				handler.AppendLiteral("<tr><td>");
				handler.AppendFormatted(remItem.Priority);
				handler.AppendLiteral("</td><td class='");
				handler.AppendFormatted(remSeverityClass);
				handler.AppendLiteral("'>");
				handler.AppendFormatted(remItem.Severity);
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(remItem.Category));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(remItem.Action));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(remItem.Detail));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(remItem.Effort);
				handler.AppendLiteral("</td><td style='font-size:0.8em'>");
				handler.AppendFormatted(Esc(remItem.Command));
				handler.AppendLiteral("</td></tr>");
				stringBuilder15.AppendLine(ref handler);
			}
			stringBuilder.AppendLine("</tbody></table>");
		}
		List<EventLogEntry> logEntries = eventLogEntries ?? analysis.EventLogEntries;
		if (logEntries.Count > 0)
		{
			stringBuilder.AppendLine("<h2>Journaux d'Événements Sécurité</h2>");
			stringBuilder.AppendLine("<table><thead><tr><th>Date</th><th>Niveau</th><th>ID</th><th>Source</th><th>Message</th></tr></thead><tbody>");
			foreach (EventLogEntry entry in logEntries)
			{
				string level = entry.Level;
				bool isError = ((level == "Error" || level == "Critical") ? true : false);
				string levelClass = (isError ? "crit" : ((entry.Level == "Warning") ? "warn" : "ok"));
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder16 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(63, 6, stringBuilder2);
				handler.AppendLiteral("<tr><td>");
				handler.AppendFormatted(entry.Timestamp, "yyyy-MM-dd HH:mm:ss");
				handler.AppendLiteral("</td><td class='");
				handler.AppendFormatted(levelClass);
				handler.AppendLiteral("'>");
				handler.AppendFormatted(Esc(entry.Level));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(entry.EventId);
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(entry.Source));
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(Esc(entry.Message));
				handler.AppendLiteral("</td></tr>");
				stringBuilder16.AppendLine(ref handler);
			}
			stringBuilder.AppendLine("</tbody></table>");
		}
		stringBuilder.AppendLine("<script>\ndocument.querySelectorAll('th').forEach(th => {\n    th.addEventListener('click', () => {\n        const table = th.closest('table');\n        const tbody = table.querySelector('tbody');\n        const rows = Array.from(tbody.querySelectorAll('tr'));\n        const idx = Array.from(th.parentNode.children).indexOf(th);\n        const asc = th.dataset.sort !== 'asc';\n        th.dataset.sort = asc ? 'asc' : 'desc';\n        rows.sort((a, b) => {\n            const av = a.children[idx]?.textContent || '';\n            const bv = b.children[idx]?.textContent || '';\n            return asc ? av.localeCompare(bv, undefined, {numeric: true}) : bv.localeCompare(av, undefined, {numeric: true});\n        });\n        rows.forEach(r => tbody.appendChild(r));\n    });\n});\n</script>");
		stringBuilder.AppendLine("</body></html>");
		return stringBuilder.ToString();
	}

	private static string Esc(string? s)
	{
		return WebUtility.HtmlEncode(s ?? "");
	}
}
