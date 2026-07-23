using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
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

public sealed partial class CisPage : Page
{
	private readonly DispatcherTimer _searchDebounce;

	public CisViewModel ViewModel { get; }

	public CisPage()
	{
		ViewModel = App.Services.GetRequiredService<CisViewModel>();
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
			SortCollection(ViewModel.CisResults, columnTag, dataGridSortDirection == DataGridSortDirection.Ascending);
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
			fileSavePicker.SuggestedFileName = $"CIS_Benchmark_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("Excel", new string[1] { ".xlsx" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			ViewModel.IsExporting = true;
			ExportCisToExcel(storageFile.Path);
			ViewModel.IsExporting = false;
			await ShowStatus("Export Excel : " + storageFile.Path);
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Export Excel CIS: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"CIS_Benchmark_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx");
			ExportCisToExcel(fallbackPath);
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
			fileSavePicker.SuggestedFileName = $"CIS_Benchmark_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("PDF", new string[1] { ".pdf" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			ViewModel.IsExporting = true;
			ExportCisToPdf(storageFile.Path);
			ViewModel.IsExporting = false;
			await ShowStatus("Export PDF : " + storageFile.Path);
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Export PDF CIS: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"CIS_Benchmark_{DateTime.Now:yyyyMMdd_HHmmss}.pdf");
			ExportCisToPdf(fallbackPath);
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
			fileSavePicker.SuggestedFileName = $"CIS_Benchmark_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("CSV", new string[1] { ".csv" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			ViewModel.IsExporting = true;
			ExportCisToCsv(storageFile.Path);
			ViewModel.IsExporting = false;
			await ShowStatus("Export CSV : " + storageFile.Path);
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Export CSV CIS: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"CIS_Benchmark_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
			ExportCisToCsv(fallbackPath);
			ViewModel.IsExporting = false;
			await ShowStatus("Export CSV : " + fallbackPath);
		}
	}

	private void ExportCisToCsv(string path)
	{
		string csvSeparator = App.Services.GetRequiredService<SettingsService>().Current.CsvSeparator;
		StringBuilder stringBuilder = new StringBuilder();
		StringBuilder stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder3 = stringBuilder2;
		StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(31, 4, stringBuilder2);
		handler.AppendLiteral("Section");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("ID");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Description");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Statut");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Level");
		stringBuilder3.AppendLine(ref handler);
		foreach (CisBenchmarkItem cisResult in ViewModel.CisResults)
		{
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(0, 9, stringBuilder2);
			handler.AppendFormatted(Esc(cisResult.Section));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(cisResult.CisId));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(cisResult.Title));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(cisResult.Status));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(cisResult.Level));
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

	private void ExportCisToExcel(string path)
	{
		using XLWorkbook workbook = new XLWorkbook();
		IXLWorksheet worksheet = workbook.Worksheets.Add("CIS Benchmark");
		string[] headers = new string[8] { "CIS ID", "Level", "Statut", "Section", "Titre", "Attendu", "Actuel", "Remédiation" };
		for (int i = 0; i < headers.Length; i++)
		{
			worksheet.Cell(1, i + 1).Value = headers[i];
			worksheet.Cell(1, i + 1).Style.Font.Bold = true;
			worksheet.Cell(1, i + 1).Style.Fill.BackgroundColor = XLColor.FromHtml("#0078D4");
			worksheet.Cell(1, i + 1).Style.Font.FontColor = XLColor.White;
		}
		int row = 2;
		foreach (CisBenchmarkItem cisResult in ViewModel.CisResults)
		{
			worksheet.Cell(row, 1).Value = cisResult.CisId;
			worksheet.Cell(row, 2).Value = cisResult.Level;
			worksheet.Cell(row, 3).Value = cisResult.Status;
			worksheet.Cell(row, 4).Value = cisResult.Section;
			worksheet.Cell(row, 5).Value = cisResult.Title;
			worksheet.Cell(row, 6).Value = cisResult.ExpectedValue;
			worksheet.Cell(row, 7).Value = cisResult.CurrentValue;
			worksheet.Cell(row, 8).Value = cisResult.Remediation;
			string htmlColor = cisResult.Status switch
			{
				"Pass" => "#E8F5E9",
				"Fail" => "#FFEBEE",
				"Manual" => "#FFF8E1",
				_ => "#ECEFF1",
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

	private void ExportCisToPdf(string path)
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
					col.Item().Text("WinCheckSec — Benchmark CIS").FontSize(18f)
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
						c.ConstantColumn(55f);
						c.ConstantColumn(35f);
						c.ConstantColumn(50f);
						c.RelativeColumn(1.5f);
						c.RelativeColumn(3f);
						c.ConstantColumn(75f);
						c.ConstantColumn(75f);
					});
					table.Header(delegate(TableCellDescriptor h)
					{
						string[] array = new string[7] { "CIS ID", "Lvl", "Statut", "Section", "Titre", "Attendu", "Actuel" };
						foreach (string text in array)
						{
							h.Cell().Background(Colors.Blue.Darken2).Padding(5f)
								.Text(text)
								.FontColor(Colors.White)
								.Bold()
								.FontSize(8f);
						}
					});
					foreach (CisBenchmarkItem cisResult in ViewModel.CisResults)
					{
						Color color = cisResult.Status switch
						{
							"Pass" => Colors.Green.Lighten5, 
							"Fail" => Colors.Red.Lighten5, 
							"Manual" => Colors.Yellow.Lighten5, 
							_ => Colors.Grey.Lighten5, 
						};
						table.Cell().Background(color).Padding(4f)
							.Text(cisResult.CisId)
							.FontSize(7f);
						table.Cell().Background(color).Padding(4f)
							.Text(cisResult.Level)
							.FontSize(7f);
						table.Cell().Background(color).Padding(4f)
							.Text(cisResult.Status)
							.FontSize(7f);
						table.Cell().Background(color).Padding(4f)
							.Text(cisResult.Section)
							.FontSize(7f);
						table.Cell().Background(color).Padding(4f)
							.Text(cisResult.Title)
							.FontSize(7f);
						table.Cell().Background(color).Padding(4f)
							.Text(cisResult.ExpectedValue)
							.FontSize(7f);
						table.Cell().Background(color).Padding(4f)
							.Text(cisResult.CurrentValue)
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

	private void OnCopyRow(object sender, RoutedEventArgs e)
	{
		if (CisGrid.SelectedItem is CisBenchmarkItem cisBenchmarkItem)
		{
			string rowText = $"{cisBenchmarkItem.CisId}\t{cisBenchmarkItem.Level}\t{cisBenchmarkItem.Status}\t{cisBenchmarkItem.Section}\t{cisBenchmarkItem.Title}\t{cisBenchmarkItem.ExpectedValue}\t{cisBenchmarkItem.CurrentValue}";
			DataPackage dataPackage = new DataPackage();
			dataPackage.SetText(rowText);
			Clipboard.SetContent(dataPackage);
		}
	}

	private void OnCopyRowJson(object sender, RoutedEventArgs e)
	{
		if (CisGrid.SelectedItem is CisBenchmarkItem selectedItem)
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
		if (CisGrid.SelectedItem is CisBenchmarkItem cisBenchmarkItem)
		{
			await new ContentDialog
			{
				Title = cisBenchmarkItem.Title,
				Content = new StackPanel
				{
					Spacing = 8.0,
					Children = 
					{
						(UIElement)new TextBlock
						{
							Text = "CIS ID : " + cisBenchmarkItem.CisId,
							FontWeight = FontWeights.SemiBold
						},
						(UIElement)new TextBlock
						{
							Text = "Level : " + cisBenchmarkItem.Level
						},
						(UIElement)new TextBlock
						{
							Text = "Statut : " + cisBenchmarkItem.Status,
							FontWeight = FontWeights.SemiBold
						},
						(UIElement)new TextBlock
						{
							Text = "Section : " + cisBenchmarkItem.Section,
							TextWrapping = TextWrapping.Wrap,
							Opacity = 0.7
						},
						(UIElement)new TextBlock
						{
							Text = "Attendu : " + cisBenchmarkItem.ExpectedValue
						},
						(UIElement)new TextBlock
						{
							Text = "Actuel : " + cisBenchmarkItem.CurrentValue
						},
						(UIElement)new TextBlock
						{
							Text = "Remédiation : " + cisBenchmarkItem.Remediation,
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
		stringBuilder.AppendLine("CIS ID\tLevel\tStatut\tSection\tTitre\tAttendu\tActuel\tRemédiation");
		foreach (CisBenchmarkItem cisResult in ViewModel.CisResults)
		{
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(7, 8, stringBuilder2);
			handler.AppendFormatted(cisResult.CisId);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(cisResult.Level);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(cisResult.Status);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(cisResult.Section);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(cisResult.Title);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(cisResult.ExpectedValue);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(cisResult.CurrentValue);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(cisResult.Remediation);
			stringBuilder2.AppendLine(ref handler);
		}
		DataPackage dataPackage = new DataPackage();
		dataPackage.SetText(stringBuilder.ToString());
		Clipboard.SetContent(dataPackage);
	}

}
