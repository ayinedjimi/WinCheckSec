using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using CHECKSEC.Controls;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services;
using CHECKSEC.Services;
using CHECKSEC.ViewModels;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.UI.Xaml.Shapes;
using WinRT;
using WinRT.Interop;
using Windows.Foundation;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.UI;

namespace CHECKSEC.Pages;

public sealed partial class DashboardPage : Page
{
	public DashboardViewModel ViewModel { get; }

	public DashboardPage()
	{
		ViewModel = App.Services.GetRequiredService<DashboardViewModel>();
		InitializeComponent();
	}

	private async void OnKpiClick(object sender, RoutedEventArgs e)
	{
		if (sender is Button { Tag: string tag })
		{
			List<SecurityResult> resultsByStatus = ViewModel.GetResultsByStatus(tag switch
			{
				"OK" => SecurityStatus.OK, 
				"Warning" => SecurityStatus.Warning, 
				"Critical" => SecurityStatus.Critical, 
				"Error" => SecurityStatus.Error, 
				_ => SecurityStatus.Info, 
			});
			if (resultsByStatus.Count != 0)
			{
				await ShowResultsDialog(tag switch
				{
					"OK" => $"\ue73e  {resultsByStatus.Count} vérifications OK", 
					"Warning" => $"\ue7ba  {resultsByStatus.Count} avertissements", 
					"Critical" => $"\ue730  {resultsByStatus.Count} éléments critiques", 
					"Error" => $"\ue783  {resultsByStatus.Count} erreurs", 
					_ => "Détails", 
				}, resultsByStatus);
			}
		}
	}

	private async void OnCategoryTapped(object sender, TappedRoutedEventArgs e)
	{
		if (sender is FrameworkElement { DataContext: SecurityScore dataContext })
		{
			List<SecurityResult> resultsByCategory = ViewModel.GetResultsByCategory(dataContext.Category);
			if (resultsByCategory.Count != 0)
			{
				await ShowResultsDialog($"\ue8a5  {dataContext.Category} — {dataContext.ScorePercent}%", resultsByCategory);
			}
		}
	}

	protected override void OnNavigatedTo(NavigationEventArgs e)
	{
		base.OnNavigatedTo(e);
		if (base.Content is FrameworkElement frameworkElement)
		{
			Storyboard storyboard = new Storyboard();
			DoubleAnimation fadeAnimation = new DoubleAnimation
			{
				From = 0.0,
				To = 1.0,
				Duration = new Duration(TimeSpan.FromMilliseconds(400L, 0L)),
				EasingFunction = new CubicEase
				{
					EasingMode = EasingMode.EaseOut
				}
			};
			Storyboard.SetTarget(fadeAnimation, frameworkElement);
			Storyboard.SetTargetProperty(fadeAnimation, "Opacity");
			storyboard.Children.Add(fadeAnimation);
			DoubleAnimation slideAnimation = new DoubleAnimation
			{
				From = 20.0,
				To = 0.0,
				Duration = new Duration(TimeSpan.FromMilliseconds(400L, 0L)),
				EasingFunction = new CubicEase
				{
					EasingMode = EasingMode.EaseOut
				}
			};
			frameworkElement.RenderTransform = new TranslateTransform();
			Storyboard.SetTarget(slideAnimation, frameworkElement.RenderTransform);
			Storyboard.SetTargetProperty(slideAnimation, "Y");
			storyboard.Children.Add(slideAnimation);
			storyboard.Begin();
		}
	}

	private void OnCardPointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (sender is Border border)
		{
			Border hoverBorder = border;
			if ((object)hoverBorder.RenderTransform == null)
			{
				Transform newTransform = (hoverBorder.RenderTransform = new ScaleTransform());
			}
			if (border.RenderTransform is ScaleTransform scaleTransform)
			{
				border.RenderTransformOrigin = new Point(0.5, 0.5);
				scaleTransform.ScaleX = 1.02;
				scaleTransform.ScaleY = 1.02;
			}
		}
	}

	private void OnCardPointerExited(object sender, PointerRoutedEventArgs e)
	{
		if (sender is Border { RenderTransform: ScaleTransform renderTransform })
		{
			renderTransform.ScaleX = 1.0;
			renderTransform.ScaleY = 1.0;
		}
	}

	private async void OnGenerateFullReport(object sender, RoutedEventArgs e)
	{
		try
		{
			FileSavePicker fileSavePicker = new FileSavePicker();
			nint windowHandle = WindowNative.GetWindowHandle(App.MainAppWindow);
			InitializeWithWindow.Initialize(fileSavePicker, windowHandle);
			fileSavePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
			fileSavePicker.SuggestedFileName = $"CHECKSEC_Audit_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("PDF", new string[1] { ".pdf" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			App.Services.GetRequiredService<UnifiedReportService>().GenerateReport(analysis: App.Services.GetRequiredService<AnalysisService>(), remediation: App.Services.GetRequiredService<RemediationService>(), path: storageFile.Path);
			await new ContentDialog
			{
				Title = "Rapport généré",
				Content = "Rapport PDF complet exporté :\n" + storageFile.Path,
				CloseButtonText = "OK",
				XamlRoot = base.XamlRoot
			}.ShowAsync();
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Full report: " + ex.Message, ex);
			await ShowErrorDialog("Erreur lors de la génération du rapport PDF", "Le rapport n'a pas pu être généré. Vérifiez que le fichier n'est pas ouvert dans un autre programme.");
		}
	}

	private async void OnGenerateExcelReport(object sender, RoutedEventArgs e)
	{
		try
		{
			FileSavePicker fileSavePicker = new FileSavePicker();
			nint windowHandle = WindowNative.GetWindowHandle(App.MainAppWindow);
			InitializeWithWindow.Initialize(fileSavePicker, windowHandle);
			fileSavePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
			fileSavePicker.SuggestedFileName = $"CHECKSEC_Audit_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("Excel", new string[1] { ".xlsx" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			App.Services.GetRequiredService<ConsolidatedExcelService>().GenerateReport(analysis: App.Services.GetRequiredService<AnalysisService>(), remediation: App.Services.GetRequiredService<RemediationService>(), path: storageFile.Path);
			await new ContentDialog
			{
				Title = "Export Excel généré",
				Content = "Rapport Excel complet exporté :\n" + storageFile.Path,
				CloseButtonText = "OK",
				XamlRoot = base.XamlRoot
			}.ShowAsync();
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Excel report: " + ex.Message, ex);
			await ShowErrorDialog("Erreur lors de la génération du rapport Excel", "Le rapport n'a pas pu être généré. Vérifiez que le fichier n'est pas ouvert dans un autre programme.");
		}
	}

	private async Task ShowResultsDialog(string title, List<SecurityResult> results)
	{
		StackPanel stackPanel = new StackPanel
		{
			Spacing = 8.0
		};
		foreach (SecurityResult result in results.Take(100))
		{
			Border resultBorder = new Border
			{
				Background = (Brush)Application.Current.Resources["CardBackgroundFillColorSecondaryBrush"],
				CornerRadius = new CornerRadius(8.0),
				Padding = new Thickness(14.0, 10.0, 14.0, 10.0),
				Child = new Grid
				{
					ColumnDefinitions =
					{
						new ColumnDefinition
						{
							Width = new GridLength(16.0)
						},
						new ColumnDefinition
						{
							Width = new GridLength(1.0, GridUnitType.Star)
						}
					},
					Children =
					{
						(UIElement)CreateStatusDot(result),
						(UIElement)CreateResultContent(result)
					}
				}
			};
			stackPanel.Children.Add(resultBorder);
		}
		ScrollViewer content = new ScrollViewer
		{
			Content = stackPanel,
			MaxHeight = 500.0,
			HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
		};
		await new ContentDialog
		{
			Title = title,
			Content = content,
			CloseButtonText = "Fermer",
			XamlRoot = base.XamlRoot,
			DefaultButton = ContentDialogButton.Close
		}.ShowAsync();
	}

	private static Ellipse CreateStatusDot(SecurityResult r)
	{
		string statusColorHex = r.StatusColorHex;
		byte alpha = byte.MaxValue;
		byte red = 120;
		byte green = 144;
		byte blue = 156;
		if (statusColorHex.Length == 7)
		{
			red = Convert.ToByte(statusColorHex.Substring(1, 2), 16);
			green = Convert.ToByte(statusColorHex.Substring(3, 2), 16);
			blue = Convert.ToByte(statusColorHex.Substring(5, 2), 16);
		}
		Ellipse dot = new Ellipse
		{
			Width = 10.0,
			Height = 10.0,
			Fill = new SolidColorBrush(Color.FromArgb(alpha, red, green, blue)),
			VerticalAlignment = VerticalAlignment.Top,
			Margin = new Thickness(0.0, 5.0, 0.0, 0.0)
		};
		Grid.SetColumn(dot, 0);
		return dot;
	}

	private static StackPanel CreateResultContent(SecurityResult r)
	{
		StackPanel stackPanel = new StackPanel
		{
			Spacing = 2.0,
			Margin = new Thickness(10.0, 0.0, 0.0, 0.0)
		};
		stackPanel.Children.Add(new TextBlock
		{
			Text = r.CheckName,
			FontWeight = FontWeights.SemiBold,
			FontSize = 13.0,
			TextWrapping = TextWrapping.Wrap
		});
		if (!string.IsNullOrEmpty(r.Description))
		{
			stackPanel.Children.Add(new TextBlock
			{
				Text = r.Description,
				FontSize = 12.0,
				Opacity = 0.7,
				TextWrapping = TextWrapping.Wrap,
				MaxLines = 2
			});
		}
		if (!string.IsNullOrEmpty(r.CurrentValue) || !string.IsNullOrEmpty(r.ExpectedValue))
		{
			StackPanel valuePanel = new StackPanel
			{
				Orientation = Orientation.Horizontal,
				Spacing = 16.0,
				Margin = new Thickness(0.0, 4.0, 0.0, 0.0)
			};
			if (!string.IsNullOrEmpty(r.CurrentValue))
			{
				valuePanel.Children.Add(new TextBlock
				{
					Text = "Actuel : " + r.CurrentValue,
					FontSize = 11.0,
					Opacity = 0.5
				});
			}
			if (!string.IsNullOrEmpty(r.ExpectedValue))
			{
				valuePanel.Children.Add(new TextBlock
				{
					Text = "Attendu : " + r.ExpectedValue,
					FontSize = 11.0,
					Opacity = 0.5
				});
			}
			stackPanel.Children.Add(valuePanel);
		}
		if (!string.IsNullOrEmpty(r.Recommendation))
		{
			Border recommendationBorder = new Border
			{
				Background = new SolidColorBrush(Color.FromArgb(20, 0, 120, 212)),
				CornerRadius = new CornerRadius(4.0),
				Padding = new Thickness(8.0, 4.0, 8.0, 4.0),
				Margin = new Thickness(0.0, 4.0, 0.0, 0.0),
				Child = new TextBlock
				{
					Text = "\ue82f  " + r.Recommendation,
					FontSize = 11.0,
					TextWrapping = TextWrapping.Wrap,
					Opacity = 0.8
				}
			};
			stackPanel.Children.Add(recommendationBorder);
		}
		Grid.SetColumn(stackPanel, 1);
		return stackPanel;
	}

	private async Task ShowErrorDialog(string title, string message)
	{
		await new ContentDialog
		{
			Title = title,
			Content = message,
			CloseButtonText = "OK",
			XamlRoot = base.XamlRoot
		}.ShowAsync();
	}

	private async void OnGenerateHtmlReport(object sender, RoutedEventArgs e)
	{
		string targetPath;
		try
		{
			FileSavePicker fileSavePicker = new FileSavePicker();
			nint windowHandle = WindowNative.GetWindowHandle(App.MainAppWindow);
			InitializeWithWindow.Initialize(fileSavePicker, windowHandle);
			fileSavePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
			fileSavePicker.SuggestedFileName = $"CHECKSEC_Audit_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("HTML", new string[1] { ".html" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			targetPath = storageFile.Path;
		}
		catch
		{
			string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
			targetPath = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"CHECKSEC_Audit_{Environment.MachineName}_{timestamp}.html");
		}
		try
		{
			HtmlReportService htmlReportService = App.Services.GetRequiredService<HtmlReportService>();
			AnalysisService analysisService = App.Services.GetRequiredService<AnalysisService>();
			RemediationService remediationService = App.Services.GetRequiredService<RemediationService>();
			string contents = htmlReportService.GenerateReport(analysisService, remediationService);
			await File.WriteAllTextAsync(targetPath, contents, Encoding.UTF8);
			await new ContentDialog
			{
				Title = "Rapport HTML généré",
				Content = "Rapport HTML exporté :\n" + targetPath,
				CloseButtonText = "OK",
				XamlRoot = base.XamlRoot
			}.ShowAsync();
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "HTML report: " + ex.Message, ex);
			await ShowErrorDialog("Erreur lors de la génération du rapport HTML", "Le rapport n'a pas pu être généré.\nErreur : " + ex.Message);
		}
	}

	private async void OnExportCef(object sender, RoutedEventArgs e)
	{
		string targetPath;
		try
		{
			FileSavePicker fileSavePicker = new FileSavePicker();
			nint windowHandle = WindowNative.GetWindowHandle(App.MainAppWindow);
			InitializeWithWindow.Initialize(fileSavePicker, windowHandle);
			fileSavePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
			fileSavePicker.SuggestedFileName = $"CHECKSEC_CEF_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("CEF", new string[2] { ".cef", ".log" });
			StorageFile storageFile = await fileSavePicker.PickSaveFileAsync();
			if (storageFile == null)
			{
				return;
			}
			targetPath = storageFile.Path;
		}
		catch
		{
			string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
			targetPath = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"CHECKSEC_CEF_{Environment.MachineName}_{timestamp}.cef");
		}
		try
		{
			CefExportService cefExportService = App.Services.GetRequiredService<CefExportService>();
			AnalysisService analysisService = App.Services.GetRequiredService<AnalysisService>();
			string contents = cefExportService.GenerateCef(analysisService);
			await File.WriteAllTextAsync(targetPath, contents, Encoding.UTF8);
			await new ContentDialog
			{
				Title = "Export CEF",
				Content = "Export SIEM :\n" + targetPath,
				CloseButtonText = "OK",
				XamlRoot = base.XamlRoot
			}.ShowAsync();
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "CEF export: " + ex.Message, ex);
			await ShowErrorDialog("Erreur lors de l'export CEF", "L'export SIEM n'a pas pu être réalisé.\nErreur: " + ex.Message);
		}
	}

}
