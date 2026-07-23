using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using CHECKSEC.Core.Services;
using CHECKSEC.Services;
using CHECKSEC.ViewModels;
using ClosedXML.Excel;
using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Markup;
using QuestPDF;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using WinRT;
using WinRT.Interop;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;

namespace CHECKSEC.Pages;

public sealed partial class RemediationPage : Page
{







	public RemediationViewModel ViewModel { get; }

	public RemediationPage()
	{
		ViewModel = App.Services.GetRequiredService<RemediationViewModel>();
		InitializeComponent();
	}

	private void OnLoaded(object sender, RoutedEventArgs e)
	{
		ViewModel.LoadIfNeeded();
	}

	private void OnSorting(object sender, DataGridColumnEventArgs e)
	{
		if (!(sender is DataGrid dataGrid))
		{
			return;
		}
		DataGridSortDirection dataGridSortDirection = ((e.Column.SortDirection == DataGridSortDirection.Ascending) ? DataGridSortDirection.Descending : DataGridSortDirection.Ascending);
		foreach (DataGridColumn column in dataGrid.Columns)
		{
			column.SortDirection = null;
		}
		e.Column.SortDirection = dataGridSortDirection;
		string columnTag = e.Column.Tag?.ToString() ?? "";
		if (!string.IsNullOrEmpty(columnTag))
		{
			SortCollection(ViewModel.Items, columnTag, dataGridSortDirection == DataGridSortDirection.Ascending);
		}
	}

	private static void SortCollection<T>(ObservableCollection<T> source, string propertyName, bool ascending)
	{
		PropertyInfo prop = typeof(T).GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public);
		if (prop == null)
		{
			return;
		}
		List<T> sortedItems = (ascending ? source.OrderBy((T x) => prop.GetValue(x)).ToList() : source.OrderByDescending((T x) => prop.GetValue(x)).ToList());
		source.Clear();
		foreach (T item in sortedItems)
		{
			source.Add(item);
		}
	}

	private async void OnExportExcel(object sender, RoutedEventArgs e)
	{
		try
		{
			FileSavePicker fileSavePicker = new FileSavePicker();
			nint windowHandle = WindowNative.GetWindowHandle(App.MainAppWindow);
			InitializeWithWindow.Initialize(fileSavePicker, windowHandle);
			fileSavePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
			fileSavePicker.SuggestedFileName = $"Remediation_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("Excel", new string[1] { ".xlsx" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			ExportToExcel(storageFile.Path);
			await ShowStatus("Export Excel : " + storageFile.Path);
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Export remediation Excel: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"Remediation_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx");
			ExportToExcel(fallbackPath);
			await ShowStatus("Export Excel : " + fallbackPath);
		}
	}

	private async void OnExportPdf(object sender, RoutedEventArgs e)
	{
		try
		{
			FileSavePicker fileSavePicker = new FileSavePicker();
			nint windowHandle = WindowNative.GetWindowHandle(App.MainAppWindow);
			InitializeWithWindow.Initialize(fileSavePicker, windowHandle);
			fileSavePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
			fileSavePicker.SuggestedFileName = $"Remediation_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("PDF", new string[1] { ".pdf" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			ExportToPdf(storageFile.Path);
			await ShowStatus("Export PDF : " + storageFile.Path);
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Export remediation PDF: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"Remediation_{DateTime.Now:yyyyMMdd_HHmmss}.pdf");
			ExportToPdf(fallbackPath);
			await ShowStatus("Export PDF : " + fallbackPath);
		}
	}

	private void ExportToExcel(string path)
	{
		using XLWorkbook workbook = new XLWorkbook();
		IXLWorksheet worksheet = workbook.Worksheets.Add("Plan de Remédiation");
		string[] headers = new string[9] { "Priorité", "Sévérité", "Catégorie", "Action", "Détail", "Effort", "Commande", "Statut", "Responsable" };
		for (int i = 0; i < headers.Length; i++)
		{
			worksheet.Cell(1, i + 1).Value = headers[i];
			worksheet.Cell(1, i + 1).Style.Font.Bold = true;
			worksheet.Cell(1, i + 1).Style.Fill.BackgroundColor = XLColor.FromHtml("#0078D4");
			worksheet.Cell(1, i + 1).Style.Font.FontColor = XLColor.White;
		}
		int row = 2;
		foreach (RemediationItem item in ViewModel.Items)
		{
			worksheet.Cell(row, 1).Value = item.Priority;
			worksheet.Cell(row, 2).Value = item.Severity;
			worksheet.Cell(row, 3).Value = item.Category;
			worksheet.Cell(row, 4).Value = item.Action;
			worksheet.Cell(row, 5).Value = item.Detail;
			worksheet.Cell(row, 6).Value = item.Effort;
			worksheet.Cell(row, 7).Value = item.Command;
			worksheet.Cell(row, 8).Value = item.Status;
			worksheet.Cell(row, 9).Value = item.Responsible;
			string severity = item.Severity;
			string colorHex = ((severity == "Critical") ? "#FFEBEE" : ((!(severity == "High")) ? "#F1F8E9" : "#FFF3E0"));
			string htmlColor = colorHex;
			for (int j = 1; j <= headers.Length; j++)
			{
				worksheet.Cell(row, j).Style.Fill.BackgroundColor = XLColor.FromHtml(htmlColor);
			}
			row++;
		}
		worksheet.Columns().AdjustToContents(1, 60);
		worksheet.SheetView.FreezeRows(1);
		workbook.SaveAs(path);
	}

	private void ExportToPdf(string path)
	{
		Settings.License = LicenseType.Community;
		Document.Create(delegate(IDocumentContainer container)
		{
			container.Page(delegate(PageDescriptor page)
			{
				page.Size(PageSizes.A4.Landscape());
				page.Margin(30f);
				page.DefaultTextStyle((TextStyle x) => x.FontSize(9f));
				page.Header().Column(delegate(ColumnDescriptor col)
				{
					col.Item().Text("WinCheckSec — Plan de Remédiation").FontSize(18f)
						.Bold()
						.FontColor(Colors.Blue.Darken2);
					col.Item().Text($"{Environment.MachineName} — {DateTime.Now:dd/MM/yyyy HH:mm}").FontSize(10f)
						.FontColor(Colors.Grey.Darken1);
					col.Item().Text($"{ViewModel.TotalActions} actions — {ViewModel.CriticalActions} critiques — {ViewModel.QuickWins} quick wins").FontSize(10f)
						.FontColor(Colors.Grey.Medium);
					col.Item().PaddingBottom(10f).LineHorizontal(1f)
						.LineColor(Colors.Grey.Lighten2);
				});
				page.Content().Table(delegate(TableDescriptor table)
				{
					table.ColumnsDefinition(delegate(TableColumnsDefinitionDescriptor c)
					{
						c.ConstantColumn(30f);
						c.ConstantColumn(60f);
						c.RelativeColumn(1.5f);
						c.RelativeColumn(3f);
						c.ConstantColumn(70f);
						c.RelativeColumn(3f);
					});
					table.Header(delegate(TableCellDescriptor h)
					{
						string[] headers = new string[6] { "#", "Sévérité", "Catégorie", "Action", "Effort", "Remédiation" };
						foreach (string header in headers)
						{
							h.Cell().Background(Colors.Blue.Darken2).Padding(5f)
								.Text(header)
								.FontColor(Colors.White)
								.Bold()
								.FontSize(9f);
						}
					});
					foreach (RemediationItem item in ViewModel.Items)
					{
						string severity = item.Severity;
						Color severityColor = ((severity == "Critical") ? Colors.Red.Lighten5 : ((!(severity == "High")) ? Colors.Green.Lighten5 : Colors.Orange.Lighten5));
						Color rowColor = severityColor;
						table.Cell().Background(rowColor).Padding(4f)
							.Text(item.Priority.ToString())
							.FontSize(8f);
						table.Cell().Background(rowColor).Padding(4f)
							.Text(item.Severity)
							.FontSize(8f);
						table.Cell().Background(rowColor).Padding(4f)
							.Text(item.Category)
							.FontSize(8f);
						table.Cell().Background(rowColor).Padding(4f)
							.Text(item.Action)
							.FontSize(8f);
						table.Cell().Background(rowColor).Padding(4f)
							.Text(item.Effort)
							.FontSize(8f);
						table.Cell().Background(rowColor).Padding(4f)
							.Text(item.Command)
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
		}).GeneratePdf(path);
	}

	private async Task ShowStatus(string msg)
	{
		await new ContentDialog
		{
			Title = "Export terminé",
			Content = msg,
			CloseButtonText = "OK",
			XamlRoot = base.XamlRoot
		}.ShowAsync();
	}

	private void OnCopyAll(object sender, RoutedEventArgs e)
	{
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.AppendLine("Priorité\tSévérité\tCatégorie\tAction\tDétail\tEffort\tCommande\tStatut\tResponsable");
		foreach (RemediationItem item in ViewModel.Items)
		{
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(8, 9, stringBuilder2);
			handler.AppendFormatted(item.Priority);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(item.Severity);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(item.Category);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(item.Action);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(item.Detail);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(item.Effort);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(item.Command);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(item.Status);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(item.Responsible);
			stringBuilder2.AppendLine(ref handler);
		}
		DataPackage dataPackage = new DataPackage();
		dataPackage.SetText(stringBuilder.ToString());
		Clipboard.SetContent(dataPackage);
	}



}
