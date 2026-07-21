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
using System.Text.Json;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services;
using CHECKSEC.Services;
using CHECKSEC.ViewModels;
using ClosedXML.Excel;
using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Documents;
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

public sealed partial class GapsPage : Page
{




	private readonly DispatcherTimer _searchDebounce;






	public GapsViewModel ViewModel { get; }

	public GapsPage()
	{
		ViewModel = App.Services.GetRequiredService<GapsViewModel>();
		InitializeComponent();
		_searchDebounce = new DispatcherTimer
		{
			Interval = TimeSpan.FromMilliseconds(300L, 0L)
		};
		_searchDebounce.Tick += delegate
		{
			_searchDebounce.Stop();
			ViewModel.ApplyFilter();
		};
	}

	private void OnLoaded(object sender, RoutedEventArgs e)
	{
		ViewModel.LoadIfNeeded();
	}

	private void OnFilterChanged(object sender, SelectionChangedEventArgs e)
	{
		ViewModel.ApplyFilter();
	}

	private void OnSearchChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
	{
		ViewModel.SearchText = sender.Text;
		_searchDebounce.Stop();
		_searchDebounce.Start();
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
			SortCollection(ViewModel.Gaps, columnTag, dataGridSortDirection == DataGridSortDirection.Ascending);
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
			fileSavePicker.SuggestedFileName = $"MSCT_Gaps_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("Excel", new string[1] { ".xlsx" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			ViewModel.IsExporting = true;
			ExportGapsToExcel(storageFile.Path);
			ViewModel.IsExporting = false;
			await ShowStatus("Export Excel : " + storageFile.Path);
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Export Excel gaps: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"MSCT_Gaps_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx");
			ExportGapsToExcel(fallbackPath);
			ViewModel.IsExporting = false;
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
			fileSavePicker.SuggestedFileName = $"MSCT_Gaps_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("PDF", new string[1] { ".pdf" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			ViewModel.IsExporting = true;
			ExportGapsToPdf(storageFile.Path);
			ViewModel.IsExporting = false;
			await ShowStatus("Export PDF : " + storageFile.Path);
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Export PDF gaps: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"MSCT_Gaps_{DateTime.Now:yyyyMMdd_HHmmss}.pdf");
			ExportGapsToPdf(fallbackPath);
			ViewModel.IsExporting = false;
			await ShowStatus("Export PDF : " + fallbackPath);
		}
	}

	private async void OnExportCsv(object sender, RoutedEventArgs e)
	{
		try
		{
			FileSavePicker fileSavePicker = new FileSavePicker();
			nint windowHandle = WindowNative.GetWindowHandle(App.MainAppWindow);
			InitializeWithWindow.Initialize(fileSavePicker, windowHandle);
			fileSavePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
			fileSavePicker.SuggestedFileName = $"MSCT_Gaps_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("CSV", new string[1] { ".csv" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			ViewModel.IsExporting = true;
			ExportGapsToCsv(storageFile.Path);
			ViewModel.IsExporting = false;
			await ShowStatus("Export CSV : " + storageFile.Path);
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Export CSV gaps: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"MSCT_Gaps_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
			ExportGapsToCsv(fallbackPath);
			ViewModel.IsExporting = false;
			await ShowStatus("Export CSV : " + fallbackPath);
		}
	}

	private void ExportGapsToCsv(string path)
	{
		string csvSeparator = App.Services.GetRequiredService<SettingsService>().Current.CsvSeparator;
		StringBuilder stringBuilder = new StringBuilder();
		StringBuilder stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder3 = stringBuilder2;
		StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(59, 6, stringBuilder2);
		handler.AppendLiteral("Sévérité");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Politique");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Chemin registre");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Attendu");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Actuel");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("GPO");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Description");
		stringBuilder3.AppendLine(ref handler);
		foreach (ComplianceGap gap in ViewModel.Gaps)
		{
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(0, 13, stringBuilder2);
			handler.AppendFormatted(gap.Severity);
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(gap.PolicyName));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(gap.RegistryPath));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(gap.BaselineValue));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(gap.CurrentValue));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(gap.GpoName));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(gap.Description));
			stringBuilder4.AppendLine(ref handler);
		}
		File.WriteAllText(path, stringBuilder.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
	}

	private static string Esc(string? s)
	{
		if (s != null)
		{
			return "\"" + s.Replace("\"", "\"\"") + "\"";
		}
		return "";
	}

	private void ExportGapsToExcel(string path)
	{
		using XLWorkbook workbook = new XLWorkbook();
		IXLWorksheet worksheet = workbook.Worksheets.Add("Écarts MSCT");
		string[] headers = new string[7] { "Sévérité", "Politique", "Chemin registre", "Attendu", "Actuel", "GPO", "Description" };
		for (int i = 0; i < headers.Length; i++)
		{
			worksheet.Cell(1, i + 1).Value = headers[i];
			worksheet.Cell(1, i + 1).Style.Font.Bold = true;
			worksheet.Cell(1, i + 1).Style.Fill.BackgroundColor = XLColor.FromHtml("#0078D4");
			worksheet.Cell(1, i + 1).Style.Font.FontColor = XLColor.White;
		}
		int row = 2;
		foreach (ComplianceGap gap in ViewModel.Gaps)
		{
			worksheet.Cell(row, 1).Value = gap.Severity.ToString();
			worksheet.Cell(row, 2).Value = gap.PolicyName;
			worksheet.Cell(row, 3).Value = gap.RegistryPath;
			worksheet.Cell(row, 4).Value = gap.BaselineValue;
			worksheet.Cell(row, 5).Value = gap.CurrentValue;
			worksheet.Cell(row, 6).Value = gap.GpoName;
			worksheet.Cell(row, 7).Value = gap.Description;
			string htmlColor = gap.Severity switch
			{
				GapSeverity.Critical => "#FFEBEE",
				GapSeverity.High => "#FFF3E0",
				GapSeverity.Medium => "#FFF8E1",
				_ => "#F1F8E9",
			};
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

	private void ExportGapsToPdf(string path)
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
					col.Item().Text("CHECKSEC — Écarts MSCT").FontSize(18f)
						.Bold()
						.FontColor(Colors.Blue.Darken2);
					col.Item().Text($"{Environment.MachineName} — {DateTime.Now:dd/MM/yyyy HH:mm}").FontSize(10f)
						.FontColor(Colors.Grey.Darken1);
					col.Item().PaddingBottom(10f).LineHorizontal(1f)
						.LineColor(Colors.Grey.Lighten2);
				});
				page.Content().Table(delegate(TableDescriptor table)
				{
					table.ColumnsDefinition(delegate(TableColumnsDefinitionDescriptor c)
					{
						c.ConstantColumn(65f);
						c.RelativeColumn(3f);
						c.RelativeColumn(2f);
						c.ConstantColumn(75f);
						c.ConstantColumn(75f);
						c.RelativeColumn(1.5f);
					});
					table.Header(delegate(TableCellDescriptor h)
					{
						string[] headers = new string[6] { "Sévérité", "Politique", "Chemin registre", "Attendu", "Actuel", "GPO" };
						foreach (string header in headers)
						{
							h.Cell().Background(Colors.Blue.Darken2).Padding(5f)
								.Text(header)
								.FontColor(Colors.White)
								.Bold()
								.FontSize(9f);
						}
					});
					foreach (ComplianceGap gap in ViewModel.Gaps)
					{
						Color color = gap.Severity switch
						{
							GapSeverity.Critical => Colors.Red.Lighten5, 
							GapSeverity.High => Colors.Orange.Lighten5, 
							GapSeverity.Medium => Colors.Yellow.Lighten5, 
							_ => Colors.Green.Lighten5, 
						};
						table.Cell().Background(color).Padding(4f)
							.Text(gap.Severity.ToString())
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(gap.PolicyName)
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(gap.RegistryPath)
							.FontSize(7f);
						table.Cell().Background(color).Padding(4f)
							.Text(gap.BaselineValue)
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(gap.CurrentValue)
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(gap.GpoName)
							.FontSize(8f);
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

	private void OnCopyRow(object sender, RoutedEventArgs e)
	{
		if (GapsGrid.SelectedItem is ComplianceGap complianceGap)
		{
			string rowText = $"{complianceGap.Severity}\t{complianceGap.PolicyName}\t{complianceGap.RegistryPath}\t{complianceGap.BaselineValue}\t{complianceGap.CurrentValue}";
			DataPackage dataPackage = new DataPackage();
			dataPackage.SetText(rowText);
			Clipboard.SetContent(dataPackage);
		}
	}

	private void OnCopyRowJson(object sender, RoutedEventArgs e)
	{
		if (GapsGrid.SelectedItem is ComplianceGap selectedItem)
		{
			string json = JsonSerializer.Serialize(selectedItem, new JsonSerializerOptions
			{
				WriteIndented = true
			});
			DataPackage dataPackage = new DataPackage();
			dataPackage.SetText(json);
			Clipboard.SetContent(dataPackage);
		}
	}

	private async void OnViewDetails(object sender, RoutedEventArgs e)
	{
		if (GapsGrid.SelectedItem is ComplianceGap complianceGap)
		{
			await new ContentDialog
			{
				Title = complianceGap.PolicyName,
				Content = new StackPanel
				{
					Spacing = 8.0,
					Children = 
					{
						(UIElement)new TextBlock
						{
							Text = $"Sévérité : {complianceGap.Severity}",
							FontWeight = FontWeights.SemiBold
						},
						(UIElement)new TextBlock
						{
							Text = "Registre : " + complianceGap.RegistryPath,
							TextWrapping = TextWrapping.Wrap,
							Opacity = 0.7
						},
						(UIElement)new TextBlock
						{
							Text = "Attendu : " + complianceGap.BaselineValue
						},
						(UIElement)new TextBlock
						{
							Text = "Actuel : " + complianceGap.CurrentValue
						},
						(UIElement)new TextBlock
						{
							Text = "GPO : " + complianceGap.GpoName,
							Opacity = 0.7
						},
						(UIElement)new TextBlock
						{
							Text = complianceGap.Description,
							TextWrapping = TextWrapping.Wrap,
							Margin = new Thickness(0.0, 8.0, 0.0, 0.0)
						}
					}
				},
				CloseButtonText = "Fermer",
				XamlRoot = base.XamlRoot
			}.ShowAsync();
		}
	}

	private void OnCopyAll(object sender, RoutedEventArgs e)
	{
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.AppendLine("Sévérité\tPolitique\tChemin registre\tAttendu\tActuel\tGPO\tDescription");
		foreach (ComplianceGap gap in ViewModel.Gaps)
		{
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(6, 7, stringBuilder2);
			handler.AppendFormatted(gap.Severity);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(gap.PolicyName);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(gap.RegistryPath);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(gap.BaselineValue);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(gap.CurrentValue);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(gap.GpoName);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(gap.Description);
			stringBuilder2.AppendLine(ref handler);
		}
		DataPackage dataPackage = new DataPackage();
		dataPackage.SetText(stringBuilder.ToString());
		Clipboard.SetContent(dataPackage);
	}



}
