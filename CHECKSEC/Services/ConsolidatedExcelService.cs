using System;
using System.Collections.Generic;
using System.Linq;
using CHECKSEC.Core.Models;
using ClosedXML.Excel;

namespace CHECKSEC.Services;

public class ConsolidatedExcelService
{
	public void GenerateReport(string path, AnalysisService analysis, RemediationService remediation)
	{
		using XLWorkbook workbook = new XLWorkbook();
		IXLWorksheet summarySheet = workbook.Worksheets.Add("Résumé");
		summarySheet.Cell(1, 1).Value = "WinCheckSec — Rapport d'Audit";
		summarySheet.Cell(1, 1).Style.Font.Bold = true;
		summarySheet.Cell(1, 1).Style.Font.FontSize = 16.0;
		summarySheet.Cell(3, 1).Value = "Machine :";
		summarySheet.Cell(3, 2).Value = Environment.MachineName;
		summarySheet.Cell(4, 1).Value = "Date :";
		summarySheet.Cell(4, 2).Value = DateTime.Now.ToString("dd/MM/yyyy HH:mm");
		summarySheet.Cell(5, 1).Value = "Score :";
		summarySheet.Cell(5, 2).Value = $"{analysis.GlobalScore}% ({analysis.GlobalGrade})";
		summarySheet.Cell(6, 1).Value = "OK :";
		summarySheet.Cell(6, 2).Value = analysis.TotalOK;
		summarySheet.Cell(7, 1).Value = "Warnings :";
		summarySheet.Cell(7, 2).Value = analysis.TotalWarning;
		summarySheet.Cell(8, 1).Value = "Critiques :";
		summarySheet.Cell(8, 2).Value = analysis.TotalCritical;
		summarySheet.Cell(9, 1).Value = "Erreurs :";
		summarySheet.Cell(9, 2).Value = analysis.TotalError;
		int summaryRow = 11;
		summarySheet.Cell(summaryRow, 1).Value = "Catégorie";
		summarySheet.Cell(summaryRow, 2).Value = "Grade";
		summarySheet.Cell(summaryRow, 3).Value = "Score";
		summarySheet.Cell(summaryRow, 4).Value = "OK";
		summarySheet.Cell(summaryRow, 5).Value = "Warn";
		summarySheet.Cell(summaryRow, 6).Value = "Crit";
		for (int i = 1; i <= 6; i++)
		{
			summarySheet.Cell(summaryRow, i).Style.Font.Bold = true;
			summarySheet.Cell(summaryRow, i).Style.Fill.BackgroundColor = XLColor.FromHtml("#0078D4");
			summarySheet.Cell(summaryRow, i).Style.Font.FontColor = XLColor.White;
		}
		summaryRow++;
		foreach (SecurityScore categoryScore in analysis.CategoryScores)
		{
			summarySheet.Cell(summaryRow, 1).Value = categoryScore.Category;
			summarySheet.Cell(summaryRow, 2).Value = categoryScore.Grade;
			summarySheet.Cell(summaryRow, 3).Value = categoryScore.ScorePercent;
			summarySheet.Cell(summaryRow, 4).Value = categoryScore.PassedChecks;
			summarySheet.Cell(summaryRow, 5).Value = categoryScore.WarningChecks;
			summarySheet.Cell(summaryRow, 6).Value = categoryScore.CriticalChecks;
			summaryRow++;
		}
		summarySheet.Columns().AdjustToContents();
		IXLWorksheet resultsSheet = workbook.Worksheets.Add("Résultats");
		WriteHeaders(resultsSheet, "Statut", "Catégorie", "Vérification", "Actuel", "Attendu", "Description", "Recommendation");
		int resultRow = 2;
		foreach (SecurityResult allResult in analysis.AllResults)
		{
			resultsSheet.Cell(resultRow, 1).Value = allResult.Status.ToString();
			resultsSheet.Cell(resultRow, 2).Value = allResult.Category;
			resultsSheet.Cell(resultRow, 3).Value = allResult.CheckName;
			resultsSheet.Cell(resultRow, 4).Value = allResult.CurrentValue;
			resultsSheet.Cell(resultRow, 5).Value = allResult.ExpectedValue;
			resultsSheet.Cell(resultRow, 6).Value = allResult.Description;
			resultsSheet.Cell(resultRow, 7).Value = allResult.Recommendation;
			ColorRow(resultsSheet, resultRow, 7, allResult.Status);
			resultRow++;
		}
		resultsSheet.Columns().AdjustToContents(1, 60);
		resultsSheet.SheetView.FreezeRows(1);
		IXLWorksheet gapsSheet = workbook.Worksheets.Add("Écarts MSCT");
		WriteHeaders(gapsSheet, "Sévérité", "Politique", "Registre", "Attendu", "Actuel", "GPO", "Description");
		int gapRow = 2;
		foreach (ComplianceGap gap in from g in analysis.Gaps
			where !g.IsCompliant
			orderby g.Severity descending
			select g)
		{
			gapsSheet.Cell(gapRow, 1).Value = gap.Severity.ToString();
			gapsSheet.Cell(gapRow, 2).Value = gap.PolicyName;
			gapsSheet.Cell(gapRow, 3).Value = gap.RegistryPath;
			gapsSheet.Cell(gapRow, 4).Value = gap.BaselineValue;
			gapsSheet.Cell(gapRow, 5).Value = gap.CurrentValue;
			gapsSheet.Cell(gapRow, 6).Value = gap.GpoName;
			gapsSheet.Cell(gapRow, 7).Value = gap.Description;
			string htmlColor = gap.Severity switch
			{
				GapSeverity.Critical => "#FFEBEE", 
				GapSeverity.High => "#FFF3E0", 
				GapSeverity.Medium => "#FFF8E1", 
				_ => "#F1F8E9", 
			};
			for (int j = 1; j <= 7; j++)
			{
				gapsSheet.Cell(gapRow, j).Style.Fill.BackgroundColor = XLColor.FromHtml(htmlColor);
			}
			gapRow++;
		}
		gapsSheet.Columns().AdjustToContents(1, 60);
		gapsSheet.SheetView.FreezeRows(1);
		IXLWorksheet cisSheet = workbook.Worksheets.Add("CIS Benchmark");
		WriteHeaders(cisSheet, "ID", "Section", "Description", "Statut", "Niveau", "Remédiation");
		int cisRow = 2;
		foreach (CisBenchmarkItem cisItem in analysis.CisItems)
		{
			cisSheet.Cell(cisRow, 1).Value = cisItem.CisId;
			cisSheet.Cell(cisRow, 2).Value = cisItem.Section;
			cisSheet.Cell(cisRow, 3).Value = cisItem.Title;
			cisSheet.Cell(cisRow, 4).Value = cisItem.Status;
			cisSheet.Cell(cisRow, 5).Value = cisItem.Level;
			cisSheet.Cell(cisRow, 6).Value = cisItem.Remediation;
			string status = cisItem.Status;
			string cisColor = ((status == "Pass") ? "#E8F5E9" : ((!(status == "Fail")) ? "#FFF8E1" : "#FFEBEE"));
			string htmlColor2 = cisColor;
			for (int k = 1; k <= 6; k++)
			{
				cisSheet.Cell(cisRow, k).Style.Fill.BackgroundColor = XLColor.FromHtml(htmlColor2);
			}
			cisRow++;
		}
		cisSheet.Columns().AdjustToContents(1, 60);
		cisSheet.SheetView.FreezeRows(1);
		IXLWorksheet secureCoreSheet = workbook.Worksheets.Add("Secure Core");
		WriteHeaders(secureCoreSheet, "Composant", "Statut", "Valeur", "Description", "Remédiation");
		int coreRow = 2;
		foreach (SecureCoreItem secureCoreItem in analysis.SecureCoreItems)
		{
			secureCoreSheet.Cell(coreRow, 1).Value = secureCoreItem.Name;
			secureCoreSheet.Cell(coreRow, 2).Value = secureCoreItem.StatusLabel;
			secureCoreSheet.Cell(coreRow, 3).Value = secureCoreItem.Value;
			secureCoreSheet.Cell(coreRow, 4).Value = secureCoreItem.TechnicalDescription;
			secureCoreSheet.Cell(coreRow, 5).Value = secureCoreItem.Remediation;
			string htmlColor3 = ((secureCoreItem.Status == SecurityStatus.OK) ? "#E8F5E9" : "#FFEBEE");
			for (int l = 1; l <= 5; l++)
			{
				secureCoreSheet.Cell(coreRow, l).Style.Fill.BackgroundColor = XLColor.FromHtml(htmlColor3);
			}
			coreRow++;
		}
		secureCoreSheet.Columns().AdjustToContents(1, 60);
		List<RemediationItem> remediationPlan = remediation.GeneratePlan(analysis);
		IXLWorksheet remediationSheet = workbook.Worksheets.Add("Remédiation");
		WriteHeaders(remediationSheet, "Priorité", "Sévérité", "Catégorie", "Action", "Détail", "Effort", "Commande", "Statut");
		int remRow = 2;
		foreach (RemediationItem remItem in remediationPlan)
		{
			remediationSheet.Cell(remRow, 1).Value = remItem.Priority;
			remediationSheet.Cell(remRow, 2).Value = remItem.Severity;
			remediationSheet.Cell(remRow, 3).Value = remItem.Category;
			remediationSheet.Cell(remRow, 4).Value = remItem.Action;
			remediationSheet.Cell(remRow, 5).Value = remItem.Detail;
			remediationSheet.Cell(remRow, 6).Value = remItem.Effort;
			remediationSheet.Cell(remRow, 7).Value = remItem.Command;
			remediationSheet.Cell(remRow, 8).Value = remItem.Status;
			string severity = remItem.Severity;
			string remColor = ((severity == "Critical") ? "#FFEBEE" : ((!(severity == "High")) ? "#F1F8E9" : "#FFF3E0"));
			string htmlColor4 = remColor;
			for (int m = 1; m <= 8; m++)
			{
				remediationSheet.Cell(remRow, m).Style.Fill.BackgroundColor = XLColor.FromHtml(htmlColor4);
			}
			remRow++;
		}
		remediationSheet.Columns().AdjustToContents(1, 60);
		remediationSheet.SheetView.FreezeRows(1);
		IXLWorksheet eventLogSheet = workbook.Worksheets.Add("Journaux Événements");
		WriteHeaders(eventLogSheet, "Date", "Niveau", "ID", "Source", "Message");
		int logRow = 2;
		foreach (EventLogEntry eventLogEntry in analysis.EventLogEntries)
		{
			eventLogSheet.Cell(logRow, 1).Value = eventLogEntry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
			eventLogSheet.Cell(logRow, 2).Value = eventLogEntry.Level;
			eventLogSheet.Cell(logRow, 3).Value = eventLogEntry.EventId;
			eventLogSheet.Cell(logRow, 4).Value = eventLogEntry.Source;
			eventLogSheet.Cell(logRow, 5).Value = eventLogEntry.Message;
			string logColor;
			switch (eventLogEntry.Level)
			{
			case "Error":
			case "Critical":
				logColor = "#FFEBEE";
				break;
			case "Warning":
				logColor = "#FFF3E0";
				break;
			default:
				logColor = "#E8F5E9";
				break;
			}
			string htmlColor5 = logColor;
			for (int n = 1; n <= 5; n++)
			{
				eventLogSheet.Cell(logRow, n).Style.Fill.BackgroundColor = XLColor.FromHtml(htmlColor5);
			}
			logRow++;
		}
		eventLogSheet.Columns().AdjustToContents(1, 60);
		eventLogSheet.SheetView.FreezeRows(1);
		workbook.SaveAs(path);
	}

	private static void WriteHeaders(IXLWorksheet ws, params string[] headers)
	{
		for (int i = 0; i < headers.Length; i++)
		{
			ws.Cell(1, i + 1).Value = headers[i];
			ws.Cell(1, i + 1).Style.Font.Bold = true;
			ws.Cell(1, i + 1).Style.Fill.BackgroundColor = XLColor.FromHtml("#0078D4");
			ws.Cell(1, i + 1).Style.Font.FontColor = XLColor.White;
		}
	}

	private static void ColorRow(IXLWorksheet ws, int row, int cols, SecurityStatus status)
	{
		string htmlColor = status switch
		{
			SecurityStatus.OK => "#E8F5E9", 
			SecurityStatus.Warning => "#FFF3E0", 
			SecurityStatus.Critical => "#FFEBEE", 
			SecurityStatus.Error => "#FFEBEE", 
			_ => "#F5F5F5", 
		};
		for (int i = 1; i <= cols; i++)
		{
			ws.Cell(row, i).Style.Fill.BackgroundColor = XLColor.FromHtml(htmlColor);
		}
	}
}
