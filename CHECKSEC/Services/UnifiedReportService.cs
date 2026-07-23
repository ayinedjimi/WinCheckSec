using System;
using System.Collections.Generic;
using System.Linq;
using CHECKSEC.Core.Models;
using QuestPDF;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace CHECKSEC.Services;

public class UnifiedReportService
{
	public void GenerateReport(string path, AnalysisService analysis, RemediationService remediation)
	{
		Settings.License = LicenseType.Community;
		Document.Create(delegate(IDocumentContainer container)
		{
			container.Page(delegate(PageDescriptor page)
			{
				page.Size(PageSizes.A4);
				page.Margin(40f);
				page.DefaultTextStyle((TextStyle x) => x.FontSize(11f));
				page.Content().Column(delegate(ColumnDescriptor col)
				{
					col.Item().PaddingTop(120f);
					col.Item().AlignCenter().Text("WinCheckSec")
						.FontSize(42f)
						.Bold()
						.FontColor(Colors.Blue.Darken2);
					col.Item().AlignCenter().Text("Rapport d'Audit de Sécurité")
						.FontSize(20f)
						.FontColor(Colors.Grey.Darken1);
					col.Item().PaddingTop(40f).AlignCenter()
						.LineHorizontal(2f)
						.LineColor(Colors.Blue.Darken2);
					col.Item().PaddingTop(30f);
					col.Item().AlignCenter().Text("Machine : " + Environment.MachineName)
						.FontSize(14f);
					col.Item().AlignCenter().Text($"Date : {DateTime.Now:dd MMMM yyyy à HH:mm}")
						.FontSize(14f);
					col.Item().AlignCenter().Text("Utilisateur : " + Environment.UserName)
						.FontSize(14f);
					col.Item().AlignCenter().Text($"OS : {Environment.OSVersion}")
						.FontSize(12f)
						.FontColor(Colors.Grey.Medium);
					col.Item().PaddingTop(60f);
					TextBlockDescriptor descriptor = col.Item().AlignCenter().Text($"Score Global : {analysis.GlobalScore}% — Grade {analysis.GlobalGrade}")
						.FontSize(24f)
						.Bold();
					descriptor.FontColor(analysis.GlobalGrade switch
					{
						"A" => Colors.Green.Darken2, 
						"B" => Colors.Green.Medium, 
						"C" => Colors.Orange.Medium, 
						_ => Colors.Red.Medium, 
					});
					col.Item().PaddingTop(20f);
					col.Item().AlignCenter().Text($"{analysis.TotalOK} OK | {analysis.TotalWarning} Avert. | {analysis.TotalCritical} Critiques | {analysis.TotalError} Erreurs")
						.FontSize(12f);
					col.Item().PaddingTop(100f);
					col.Item().AlignCenter().Text("WinCheckSec v6.0")
						.FontSize(10f)
						.FontColor(Colors.Grey.Medium);
					col.Item().AlignCenter().Text("Document confidentiel")
						.FontSize(9f)
						.Italic()
						.FontColor(Colors.Grey.Lighten1);
				});
			});
			container.Page(delegate(PageDescriptor page)
			{
				page.Size(PageSizes.A4);
				page.Margin(40f);
				page.DefaultTextStyle((TextStyle x) => x.FontSize(10f));
				page.Header().Column(delegate(ColumnDescriptor h)
				{
					h.Item().Row(delegate(RowDescriptor r)
					{
						r.RelativeItem().Text("WinCheckSec — Rapport d'Audit").FontSize(12f)
							.Bold()
							.FontColor(Colors.Blue.Darken2);
						r.ConstantItem(120f).AlignRight().Text(DateTime.Now.ToString("dd/MM/yyyy"))
							.FontSize(9f)
							.FontColor(Colors.Grey.Medium);
					});
					h.Item().PaddingBottom(8f).LineHorizontal(1f)
						.LineColor(Colors.Grey.Lighten2);
				});
				page.Content().Column(delegate(ColumnDescriptor col)
				{
					col.Item().Text("Résumé Exécutif").FontSize(18f)
						.Bold()
						.FontColor(Colors.Blue.Darken2);
					col.Item().PaddingTop(10f);
					col.Item().Text("Scores par Catégorie").FontSize(14f)
						.Bold();
					col.Item().PaddingTop(8f).Table(delegate(TableDescriptor table)
					{
						table.ColumnsDefinition(delegate(TableColumnsDefinitionDescriptor c)
						{
							c.RelativeColumn(3f);
							c.ConstantColumn(50f);
							c.ConstantColumn(55f);
							c.ConstantColumn(40f);
							c.ConstantColumn(40f);
							c.ConstantColumn(40f);
						});
						table.Header(delegate(TableCellDescriptor hdr)
						{
							string[] headers = new string[6] { "Catégorie", "Grade", "Score", "OK", "Warn", "Crit" };
							foreach (string header in headers)
							{
								hdr.Cell().Background(Colors.Blue.Darken2).Padding(5f)
									.Text(header)
									.FontColor(Colors.White)
									.Bold()
									.FontSize(9f);
							}
						});
						foreach (SecurityScore categoryScore in analysis.CategoryScores)
						{
							Color gradeColor = categoryScore.Grade switch
							{
								"A" => Colors.Green.Lighten5, 
								"B" => Colors.Green.Lighten4, 
								"C" => Colors.Orange.Lighten5, 
								_ => Colors.Red.Lighten5, 
							};
							table.Cell().Background(gradeColor).Padding(4f)
								.Text(categoryScore.Category)
								.FontSize(9f);
							table.Cell().Background(gradeColor).Padding(4f)
								.AlignCenter()
								.Text(categoryScore.Grade)
								.FontSize(9f)
								.Bold();
							table.Cell().Background(gradeColor).Padding(4f)
								.AlignCenter()
								.Text($"{categoryScore.ScorePercent}%")
								.FontSize(9f);
							table.Cell().Background(gradeColor).Padding(4f)
								.AlignCenter()
								.Text(categoryScore.PassedChecks.ToString())
								.FontSize(9f);
							table.Cell().Background(gradeColor).Padding(4f)
								.AlignCenter()
								.Text(categoryScore.WarningChecks.ToString())
								.FontSize(9f);
							table.Cell().Background(gradeColor).Padding(4f)
								.AlignCenter()
								.Text(categoryScore.CriticalChecks.ToString())
								.FontSize(9f);
						}
					});
					col.Item().PaddingTop(20f).Text("Secure Core")
						.FontSize(14f)
						.Bold();
					col.Item().PaddingTop(8f).Table(delegate(TableDescriptor table)
					{
						table.ColumnsDefinition(delegate(TableColumnsDefinitionDescriptor c)
						{
							c.RelativeColumn(2f);
							c.ConstantColumn(80f);
							c.RelativeColumn(3f);
						});
						table.Header(delegate(TableCellDescriptor hdr)
						{
							string[] headers = new string[3] { "Composant", "Statut", "Valeur" };
							foreach (string header in headers)
							{
								hdr.Cell().Background(Colors.Blue.Darken2).Padding(5f)
									.Text(header)
									.FontColor(Colors.White)
									.Bold()
									.FontSize(9f);
							}
						});
						foreach (SecureCoreItem secureCoreItem in analysis.SecureCoreItems)
						{
							Color statusColor = ((secureCoreItem.Status == SecurityStatus.OK) ? Colors.Green.Lighten5 : Colors.Red.Lighten5);
							table.Cell().Background(statusColor).Padding(4f)
								.Text(secureCoreItem.Name)
								.FontSize(9f);
							table.Cell().Background(statusColor).Padding(4f)
								.Text(secureCoreItem.StatusLabel)
								.FontSize(9f);
							table.Cell().Background(statusColor).Padding(4f)
								.Text(secureCoreItem.Value)
								.FontSize(8f);
						}
					});
				});
				page.Footer().AlignCenter().Text(delegate(TextDescriptor x)
				{
					x.Span("Page ");
					x.CurrentPageNumber();
					x.Span(" / ");
					x.TotalPages();
				});
			});
			if (analysis.Gaps.Count > 0)
			{
				container.Page(delegate(PageDescriptor page)
				{
					page.Size(PageSizes.A4.Landscape());
					page.Margin(30f);
					page.DefaultTextStyle((TextStyle x) => x.FontSize(9f));
					page.Header().Column(delegate(ColumnDescriptor h)
					{
						h.Item().Text("Écarts de Conformité MSCT").FontSize(16f)
							.Bold()
							.FontColor(Colors.Blue.Darken2);
						h.Item().Text($"{analysis.Gaps.Count} écarts identifiés").FontSize(10f)
							.FontColor(Colors.Grey.Darken1);
						h.Item().PaddingBottom(8f).LineHorizontal(1f)
							.LineColor(Colors.Grey.Lighten2);
					});
					page.Content().Table(delegate(TableDescriptor table)
					{
						table.ColumnsDefinition(delegate(TableColumnsDefinitionDescriptor c)
						{
							c.ConstantColumn(55f);
							c.RelativeColumn(2.5f);
							c.RelativeColumn(1.5f);
							c.ConstantColumn(60f);
							c.ConstantColumn(60f);
							c.RelativeColumn(1.2f);
							c.RelativeColumn(2f);
						});
						table.Header(delegate(TableCellDescriptor hdr)
						{
							string[] headers = new string[7] { "Sévérité", "Politique", "Registre", "Attendu", "Actuel", "GPO", "Remédiation" };
							foreach (string header in headers)
							{
								hdr.Cell().Background(Colors.Blue.Darken2).Padding(5f)
									.Text(header)
									.FontColor(Colors.White)
									.Bold()
									.FontSize(9f);
							}
						});
						foreach (ComplianceGap gap in from g in analysis.Gaps
							where !g.IsCompliant
							orderby g.Severity descending
							select g)
						{
							Color severityColor = gap.Severity switch
							{
								GapSeverity.Critical => Colors.Red.Lighten5, 
								GapSeverity.High => Colors.Orange.Lighten5, 
								GapSeverity.Medium => Colors.Yellow.Lighten5, 
								_ => Colors.Green.Lighten5, 
							};
							table.Cell().Background(severityColor).Padding(4f)
								.Text(gap.Severity.ToString())
								.FontSize(8f);
							table.Cell().Background(severityColor).Padding(4f)
								.Text(gap.PolicyName)
								.FontSize(8f);
							table.Cell().Background(severityColor).Padding(4f)
								.Text(gap.RegistryPath)
								.FontSize(7f);
							table.Cell().Background(severityColor).Padding(4f)
								.Text(gap.BaselineValue)
								.FontSize(8f);
							table.Cell().Background(severityColor).Padding(4f)
								.Text(gap.CurrentValue)
								.FontSize(8f);
							table.Cell().Background(severityColor).Padding(4f)
								.Text(gap.GpoName)
								.FontSize(8f);
							table.Cell().Background(severityColor).Padding(4f)
								.Text(gap.Description)
								.FontSize(7f);
						}
					});
					page.Footer().AlignCenter().Text(delegate(TextDescriptor x)
					{
						x.Span("Page ");
						x.CurrentPageNumber();
						x.Span(" / ");
						x.TotalPages();
					});
				});
			}
			if (analysis.CisItems.Count > 0)
			{
				container.Page(delegate(PageDescriptor page)
				{
					page.Size(PageSizes.A4.Landscape());
					page.Margin(30f);
					page.DefaultTextStyle((TextStyle x) => x.FontSize(9f));
					page.Header().Column(delegate(ColumnDescriptor h)
					{
						h.Item().Text("Benchmark CIS").FontSize(16f)
							.Bold()
							.FontColor(Colors.Blue.Darken2);
						h.Item().Text($"{analysis.CisItems.Count} contrôles évalués").FontSize(10f)
							.FontColor(Colors.Grey.Darken1);
						h.Item().PaddingBottom(8f).LineHorizontal(1f)
							.LineColor(Colors.Grey.Lighten2);
					});
					page.Content().Table(delegate(TableDescriptor table)
					{
						table.ColumnsDefinition(delegate(TableColumnsDefinitionDescriptor c)
						{
							c.ConstantColumn(70f);
							c.RelativeColumn(1.5f);
							c.RelativeColumn(3f);
							c.ConstantColumn(55f);
							c.ConstantColumn(55f);
							c.ConstantColumn(55f);
							c.RelativeColumn(2f);
						});
						table.Header(delegate(TableCellDescriptor hdr)
						{
							string[] headers = new string[7] { "ID", "Section", "Description", "Statut", "Niveau", "Actuel", "Remédiation" };
							foreach (string header in headers)
							{
								hdr.Cell().Background(Colors.Blue.Darken2).Padding(5f)
									.Text(header)
									.FontColor(Colors.White)
									.Bold()
									.FontSize(9f);
							}
						});
						foreach (CisBenchmarkItem cisItem in analysis.CisItems)
						{
							string status = cisItem.Status;
							Color statusColor = ((status == "Pass") ? Colors.Green.Lighten5 : ((!(status == "Fail")) ? Colors.Yellow.Lighten5 : Colors.Red.Lighten5));
							Color rowColor = statusColor;
							table.Cell().Background(rowColor).Padding(4f)
								.Text(cisItem.CisId)
								.FontSize(8f);
							table.Cell().Background(rowColor).Padding(4f)
								.Text(cisItem.Section)
								.FontSize(8f);
							table.Cell().Background(rowColor).Padding(4f)
								.Text(cisItem.Title)
								.FontSize(8f);
							table.Cell().Background(rowColor).Padding(4f)
								.Text(cisItem.Status)
								.FontSize(8f);
							table.Cell().Background(rowColor).Padding(4f)
								.Text(cisItem.Level)
								.FontSize(8f);
							table.Cell().Background(rowColor).Padding(4f)
								.Text(cisItem.CurrentValue)
								.FontSize(8f);
							table.Cell().Background(rowColor).Padding(4f)
								.Text(cisItem.Remediation)
								.FontSize(7f);
						}
					});
					page.Footer().AlignCenter().Text(delegate(TextDescriptor x)
					{
						x.Span("Page ");
						x.CurrentPageNumber();
						x.Span(" / ");
						x.TotalPages();
					});
				});
			}
			List<RemediationItem> remItems = remediation.GeneratePlan(analysis);
			if (remItems.Count > 0)
			{
				container.Page(delegate(PageDescriptor page)
				{
					page.Size(PageSizes.A4.Landscape());
					page.Margin(30f);
					page.DefaultTextStyle((TextStyle x) => x.FontSize(9f));
					page.Header().Column(delegate(ColumnDescriptor h)
					{
						h.Item().Text("Plan de Remédiation").FontSize(16f)
							.Bold()
							.FontColor(Colors.Blue.Darken2);
						h.Item().Text($"{remItems.Count} actions recommandées").FontSize(10f)
							.FontColor(Colors.Grey.Darken1);
						h.Item().PaddingBottom(8f).LineHorizontal(1f)
							.LineColor(Colors.Grey.Lighten2);
					});
					page.Content().Table(delegate(TableDescriptor table)
					{
						table.ColumnsDefinition(delegate(TableColumnsDefinitionDescriptor c)
						{
							c.ConstantColumn(25f);
							c.ConstantColumn(50f);
							c.RelativeColumn(1.2f);
							c.RelativeColumn(2f);
							c.RelativeColumn(2f);
							c.ConstantColumn(55f);
							c.RelativeColumn(2.5f);
						});
						table.Header(delegate(TableCellDescriptor hdr)
						{
							string[] headers = new string[7] { "#", "Sévérité", "Catégorie", "Action", "Détail", "Effort", "Commande" };
							foreach (string header in headers)
							{
								hdr.Cell().Background(Colors.Blue.Darken2).Padding(5f)
									.Text(header)
									.FontColor(Colors.White)
									.Bold()
									.FontSize(9f);
							}
						});
						foreach (RemediationItem remItem in remItems)
						{
							string severity = remItem.Severity;
							Color severityColor = ((severity == "Critical") ? Colors.Red.Lighten5 : ((!(severity == "High")) ? Colors.Green.Lighten5 : Colors.Orange.Lighten5));
							Color rowColor = severityColor;
							table.Cell().Background(rowColor).Padding(4f)
								.Text(remItem.Priority.ToString())
								.FontSize(8f);
							table.Cell().Background(rowColor).Padding(4f)
								.Text(remItem.Severity)
								.FontSize(8f);
							table.Cell().Background(rowColor).Padding(4f)
								.Text(remItem.Category)
								.FontSize(8f);
							table.Cell().Background(rowColor).Padding(4f)
								.Text(remItem.Action)
								.FontSize(8f);
							table.Cell().Background(rowColor).Padding(4f)
								.Text(remItem.Detail)
								.FontSize(7f);
							table.Cell().Background(rowColor).Padding(4f)
								.Text(remItem.Effort)
								.FontSize(8f);
							table.Cell().Background(rowColor).Padding(4f)
								.Text(remItem.Command)
								.FontSize(7f);
						}
					});
					page.Footer().AlignCenter().Text(delegate(TextDescriptor x)
					{
						x.Span("Page ");
						x.CurrentPageNumber();
						x.Span(" / ");
						x.TotalPages();
					});
				});
			}
		}).GeneratePdf(path);
	}
}
