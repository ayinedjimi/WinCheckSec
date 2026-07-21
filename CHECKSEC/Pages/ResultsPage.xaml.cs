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

public sealed partial class ResultsPage : Page
{




	private readonly DispatcherTimer _searchDebounce;






	public ResultsViewModel ViewModel { get; }

	public ResultsPage()
	{
		ViewModel = App.Services.GetRequiredService<ResultsViewModel>();
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
		if (StatusFilter.SelectedItem is ComboBoxItem comboBoxItem)
		{
			ViewModel.FilterStatus = comboBoxItem.Content?.ToString() ?? "Tous";
			ViewModel.ApplyFilter();
		}
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
			SortCollection(ViewModel.FilteredResults, columnTag, dataGridSortDirection == DataGridSortDirection.Ascending);
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
			fileSavePicker.SuggestedFileName = $"Resultats_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("Excel", new string[1] { ".xlsx" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			ViewModel.IsExporting = true;
			ExportToExcel(storageFile.Path);
			ViewModel.IsExporting = false;
			await ShowStatus("Export Excel : " + storageFile.Path);
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Export Excel failed: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"Resultats_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx");
			ExportToExcel(fallbackPath);
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
			fileSavePicker.SuggestedFileName = $"Resultats_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("PDF", new string[1] { ".pdf" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			ViewModel.IsExporting = true;
			ExportToPdf(storageFile.Path);
			ViewModel.IsExporting = false;
			await ShowStatus("Export PDF : " + storageFile.Path);
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Export PDF failed: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"Resultats_{DateTime.Now:yyyyMMdd_HHmmss}.pdf");
			ExportToPdf(fallbackPath);
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
			fileSavePicker.SuggestedFileName = $"Resultats_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("CSV", new string[1] { ".csv" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			ViewModel.IsExporting = true;
			ExportToCsv(storageFile.Path);
			ViewModel.IsExporting = false;
			await ShowStatus("Export CSV : " + storageFile.Path);
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Export CSV failed: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"Resultats_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
			ExportToCsv(fallbackPath);
			ViewModel.IsExporting = false;
			await ShowStatus("Export CSV : " + fallbackPath);
		}
	}

	private void ExportToExcel(string path)
	{
		using XLWorkbook workbook = new XLWorkbook();
		IXLWorksheet worksheet = workbook.Worksheets.Add("Résultats Sécurité");
		string[] headers = new string[7] { "Statut", "Catégorie", "Vérification", "Actuel", "Attendu", "Description", "Recommendation" };
		for (int i = 0; i < headers.Length; i++)
		{
			worksheet.Cell(1, i + 1).Value = headers[i];
			worksheet.Cell(1, i + 1).Style.Font.Bold = true;
			worksheet.Cell(1, i + 1).Style.Fill.BackgroundColor = XLColor.FromHtml("#0078D4");
			worksheet.Cell(1, i + 1).Style.Font.FontColor = XLColor.White;
		}
		int row = 2;
		foreach (SecurityResult filteredResult in ViewModel.FilteredResults)
		{
			worksheet.Cell(row, 1).Value = filteredResult.Status.ToString();
			worksheet.Cell(row, 2).Value = filteredResult.Category;
			worksheet.Cell(row, 3).Value = filteredResult.CheckName;
			worksheet.Cell(row, 4).Value = filteredResult.CurrentValue;
			worksheet.Cell(row, 5).Value = filteredResult.ExpectedValue;
			worksheet.Cell(row, 6).Value = filteredResult.Description;
			worksheet.Cell(row, 7).Value = filteredResult.Recommendation;
			string htmlColor = filteredResult.Status switch
			{
				SecurityStatus.OK => "#E8F5E9",
				SecurityStatus.Warning => "#FFF3E0",
				SecurityStatus.Critical => "#FFEBEE",
				SecurityStatus.Error => "#FFEBEE",
				_ => "#F5F5F5",
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
					col.Item().Text("CHECKSEC — Résultats Sécurité").FontSize(18f)
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
						c.ConstantColumn(60f);
						c.RelativeColumn(2f);
						c.RelativeColumn(3f);
						c.RelativeColumn(1.5f);
						c.RelativeColumn(1.5f);
						c.RelativeColumn(3f);
					});
					table.Header(delegate(TableCellDescriptor h)
					{
						string[] headers = new string[6] { "Statut", "Catégorie", "Vérification", "Actuel", "Attendu", "Description" };
						foreach (string header in headers)
						{
							h.Cell().Background(Colors.Blue.Darken2).Padding(5f)
								.Text(header)
								.FontColor(Colors.White)
								.Bold()
								.FontSize(9f);
						}
					});
					foreach (SecurityResult filteredResult in ViewModel.FilteredResults)
					{
						Color color = filteredResult.Status switch
						{
							SecurityStatus.OK => Colors.Green.Lighten5, 
							SecurityStatus.Warning => Colors.Orange.Lighten5, 
							SecurityStatus.Critical => Colors.Red.Lighten5, 
							SecurityStatus.Error => Colors.Red.Lighten5, 
							_ => Colors.Grey.Lighten5, 
						};
						table.Cell().Background(color).Padding(4f)
							.Text(filteredResult.Status.ToString())
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(filteredResult.Category)
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(filteredResult.CheckName)
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(filteredResult.CurrentValue)
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(filteredResult.ExpectedValue)
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(filteredResult.Description)
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

	private void ExportToCsv(string path)
	{
		string csvSeparator = App.Services.GetRequiredService<SettingsService>().Current.CsvSeparator;
		StringBuilder stringBuilder = new StringBuilder();
		StringBuilder stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder3 = stringBuilder2;
		StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(65, 6, stringBuilder2);
		handler.AppendLiteral("Statut");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Catégorie");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Vérification");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Actuel");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Attendu");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Description");
		handler.AppendFormatted(csvSeparator);
		handler.AppendLiteral("Recommendation");
		stringBuilder3.AppendLine(ref handler);
		foreach (SecurityResult filteredResult in ViewModel.FilteredResults)
		{
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(0, 13, stringBuilder2);
			handler.AppendFormatted(filteredResult.Status);
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(filteredResult.Category));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(filteredResult.CheckName));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(filteredResult.CurrentValue));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(filteredResult.ExpectedValue));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(filteredResult.Description));
			handler.AppendFormatted(csvSeparator);
			handler.AppendFormatted(Esc(filteredResult.Recommendation));
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
		if (ResultsGrid.SelectedItem is SecurityResult securityResult)
		{
			string rowText = $"{securityResult.Status}\t{securityResult.Category}\t{securityResult.CheckName}\t{securityResult.CurrentValue}\t{securityResult.ExpectedValue}\t{securityResult.Description}";
			DataPackage dataPackage = new DataPackage();
			dataPackage.SetText(rowText);
			Clipboard.SetContent(dataPackage);
		}
	}

	private void OnCopyRowJson(object sender, RoutedEventArgs e)
	{
		if (ResultsGrid.SelectedItem is SecurityResult selectedItem)
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
		if (ResultsGrid.SelectedItem is SecurityResult securityResult)
		{
			await new ContentDialog
			{
				Title = securityResult.CheckName,
				Content = new StackPanel
				{
					Spacing = 8.0,
					Children = 
					{
						(UIElement)new TextBlock
						{
							Text = $"Statut : {securityResult.Status}",
							FontWeight = FontWeights.SemiBold
						},
						(UIElement)new TextBlock
						{
							Text = "Catégorie : " + securityResult.Category,
							Opacity = 0.7
						},
						(UIElement)new TextBlock
						{
							Text = "Attendu : " + securityResult.ExpectedValue
						},
						(UIElement)new TextBlock
						{
							Text = "Actuel : " + securityResult.CurrentValue
						},
						(UIElement)new TextBlock
						{
							Text = securityResult.Description,
							TextWrapping = TextWrapping.Wrap,
							Margin = new Thickness(0.0, 8.0, 0.0, 0.0)
						},
						(UIElement)new TextBlock
						{
							Text = "Recommandation : " + securityResult.Recommendation,
							TextWrapping = TextWrapping.Wrap,
							Opacity = 0.7
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
		stringBuilder.AppendLine("Statut\tCatégorie\tVérification\tActuel\tAttendu\tDescription\tRecommandation");
		foreach (SecurityResult filteredResult in ViewModel.FilteredResults)
		{
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(6, 7, stringBuilder2);
			handler.AppendFormatted(filteredResult.Status);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(filteredResult.Category);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(filteredResult.CheckName);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(filteredResult.CurrentValue);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(filteredResult.ExpectedValue);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(filteredResult.Description);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(filteredResult.Recommendation);
			stringBuilder2.AppendLine(ref handler);
		}
		DataPackage dataPackage = new DataPackage();
		dataPackage.SetText(stringBuilder.ToString());
		Clipboard.SetContent(dataPackage);
	}



}
