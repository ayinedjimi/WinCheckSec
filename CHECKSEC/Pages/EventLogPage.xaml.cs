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

public sealed partial class EventLogPage : Page
{
	private readonly DispatcherTimer _searchDebounce;

	public EventLogViewModel ViewModel { get; }

	public EventLogPage()
	{
		ViewModel = App.Services.GetRequiredService<EventLogViewModel>();
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
		if (LevelFilter.SelectedItem is ComboBoxItem comboBoxItem)
		{
			ViewModel.FilterLevel = comboBoxItem.Content?.ToString() ?? "Tous";
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
			SortCollection(ViewModel.FilteredEntries, columnTag, dataGridSortDirection == DataGridSortDirection.Ascending);
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
			fileSavePicker.SuggestedFileName = $"EventLog_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
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
			ErrorLogger.Log(LogLevel.Error, "Export Excel EventLog failed: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"EventLog_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx");
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
			fileSavePicker.SuggestedFileName = $"EventLog_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
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
			ErrorLogger.Log(LogLevel.Error, "Export PDF EventLog failed: " + ex.Message, ex);
			string fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"EventLog_{DateTime.Now:yyyyMMdd_HHmmss}.pdf");
			ExportToPdf(fallbackPath);
			ViewModel.IsExporting = false;
			await ShowStatus("Export PDF : " + fallbackPath);
		}
	}

	private void ExportToExcel(string path)
	{
		using XLWorkbook workbook = new XLWorkbook();
		IXLWorksheet worksheet = workbook.Worksheets.Add("Journaux");
		string[] headers = new string[5] { "Date/Heure", "Niveau", "Event ID", "Source", "Message" };
		for (int i = 0; i < headers.Length; i++)
		{
			worksheet.Cell(1, i + 1).Value = headers[i];
			worksheet.Cell(1, i + 1).Style.Font.Bold = true;
			worksheet.Cell(1, i + 1).Style.Fill.BackgroundColor = XLColor.FromHtml("#0078D4");
			worksheet.Cell(1, i + 1).Style.Font.FontColor = XLColor.White;
		}
		int row = 2;
		foreach (EventLogEntry filteredEntry in ViewModel.FilteredEntries)
		{
			worksheet.Cell(row, 1).Value = filteredEntry.Timestamp.ToString("dd/MM/yyyy HH:mm:ss");
			worksheet.Cell(row, 2).Value = filteredEntry.Level;
			worksheet.Cell(row, 3).Value = filteredEntry.EventId;
			worksheet.Cell(row, 4).Value = filteredEntry.Source;
			worksheet.Cell(row, 5).Value = filteredEntry.Message;
			string colorHex;
			switch (filteredEntry.Level)
			{
			case "Error":
			case "Critical":
				colorHex = "#FFEBEE";
				break;
			case "Warning":
				colorHex = "#FFF3E0";
				break;
			default:
				colorHex = "#E8F5E9";
				break;
			}
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
					col.Item().Text("WinCheckSec — Journaux d'événements").FontSize(18f)
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
						c.ConstantColumn(120f);
						c.ConstantColumn(70f);
						c.ConstantColumn(50f);
						c.RelativeColumn(2f);
						c.RelativeColumn(4f);
					});
					table.Header(delegate(TableCellDescriptor h)
					{
						string[] headers = new string[5] { "Date/Heure", "Niveau", "ID", "Source", "Message" };
						foreach (string header in headers)
						{
							h.Cell().Background(Colors.Blue.Darken2).Padding(5f)
								.Text(header)
								.FontColor(Colors.White)
								.Bold()
								.FontSize(9f);
						}
					});
					foreach (EventLogEntry filteredEntry in ViewModel.FilteredEntries)
					{
						Color rowColor;
						switch (filteredEntry.Level)
						{
						case "Error":
						case "Critical":
							rowColor = Colors.Red.Lighten5;
							break;
						case "Warning":
							rowColor = Colors.Orange.Lighten5;
							break;
						default:
							rowColor = Colors.Green.Lighten5;
							break;
						}
						Color color = rowColor;
						table.Cell().Background(color).Padding(4f)
							.Text(filteredEntry.Timestamp.ToString("dd/MM/yyyy HH:mm"))
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(filteredEntry.Level)
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(filteredEntry.EventId.ToString())
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(filteredEntry.Source)
							.FontSize(8f);
						table.Cell().Background(color).Padding(4f)
							.Text(filteredEntry.Message)
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
		if (EventLogGrid.SelectedItem is EventLogEntry eventLogEntry)
		{
			string rowText = $"{eventLogEntry.Timestamp:dd/MM/yyyy HH:mm:ss}\t{eventLogEntry.Level}\t{eventLogEntry.EventId}\t{eventLogEntry.Source}\t{eventLogEntry.Message}";
			DataPackage dataPackage = new DataPackage();
			dataPackage.SetText(rowText);
			Clipboard.SetContent(dataPackage);
		}
	}

	private void OnCopyRowJson(object sender, RoutedEventArgs e)
	{
		if (EventLogGrid.SelectedItem is EventLogEntry selectedItem)
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
		if (EventLogGrid.SelectedItem is EventLogEntry eventLogEntry)
		{
			await new ContentDialog
			{
				Title = $"Événement {eventLogEntry.EventId}",
				Content = new StackPanel
				{
					Spacing = 8.0,
					Children = 
					{
						(UIElement)new TextBlock
						{
							Text = "Niveau : " + eventLogEntry.Level,
							FontWeight = FontWeights.SemiBold
						},
						(UIElement)new TextBlock
						{
							Text = $"Date : {eventLogEntry.Timestamp:dd/MM/yyyy HH:mm:ss}",
							Opacity = 0.7
						},
						(UIElement)new TextBlock
						{
							Text = "Source : " + eventLogEntry.Source
						},
						(UIElement)new TextBlock
						{
							Text = $"ID : {eventLogEntry.EventId}"
						},
						(UIElement)new TextBlock
						{
							Text = eventLogEntry.Message,
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
		stringBuilder.AppendLine("Date/Heure\tNiveau\tID\tSource\tMessage");
		foreach (EventLogEntry filteredEntry in ViewModel.FilteredEntries)
		{
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(4, 5, stringBuilder2);
			handler.AppendFormatted(filteredEntry.Timestamp, "dd/MM/yyyy HH:mm:ss");
			handler.AppendLiteral("\t");
			handler.AppendFormatted(filteredEntry.Level);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(filteredEntry.EventId);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(filteredEntry.Source);
			handler.AppendLiteral("\t");
			handler.AppendFormatted(filteredEntry.Message);
			stringBuilder2.AppendLine(ref handler);
		}
		DataPackage dataPackage = new DataPackage();
		dataPackage.SetText(stringBuilder.ToString());
		Clipboard.SetContent(dataPackage);
	}

}
