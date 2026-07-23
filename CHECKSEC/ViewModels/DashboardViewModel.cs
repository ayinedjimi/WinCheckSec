using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services;
using CHECKSEC.Core.Services.Helpers;
using CHECKSEC.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using WinRT;
using WinRT.Interop;
using Windows.Storage;
using Windows.Storage.Pickers;

namespace CHECKSEC.ViewModels;

public partial class DashboardViewModel : ObservableObject, IDisposable
{
	private readonly AnalysisService _analysis;

	private readonly HistoryService _history;

	private readonly RemediationService _remediation;

	private readonly DispatcherQueue _dispatcher;

	private bool _disposed;

	[ObservableProperty]
	private bool _isAnalyzing;

	[ObservableProperty]
	private bool _hasResults;

	[ObservableProperty]
	private bool _showProgress;

	[ObservableProperty]
	private double _progressValue;

	[ObservableProperty]
	private double _progressMax = 1.0;

	[ObservableProperty]
	private string _statusText = "Prêt — Lancez une analyse pour commencer.";

	[ObservableProperty]
	private string _currentCollectorName = string.Empty;

	[ObservableProperty]
	private string _progressLabel = string.Empty;

	[ObservableProperty]
	private bool _isExporting;

	[ObservableProperty]
	private double _globalScore;

	[ObservableProperty]
	private string _globalGrade = "—";

	[ObservableProperty]
	private int _totalOK;

	[ObservableProperty]
	private int _totalWarning;

	[ObservableProperty]
	private int _totalCritical;

	[ObservableProperty]
	private int _totalError;

	public bool ShowEmptyState
	{
		get
		{
			if (!IsAnalyzing)
			{
				return !HasResults;
			}
			return false;
		}
	}

	public ObservableCollection<SecurityScore> CategoryScores { get; } = new ObservableCollection<SecurityScore>();

	public DashboardViewModel(AnalysisService analysis, HistoryService history, RemediationService remediation)
	{
		_analysis = analysis;
		_history = history;
		_remediation = remediation;
		_dispatcher = DispatcherQueue.GetForCurrentThread();
		_analysis.ProgressChanged += OnProgressChanged;
	}

	public void Dispose()
	{
		if (!_disposed)
		{
			_disposed = true;
			_analysis.ProgressChanged -= OnProgressChanged;
		}
	}

	private void OnProgressChanged(int done, int total, string status)
	{
		_dispatcher.TryEnqueue(delegate
		{
			ProgressValue = done;
			ProgressMax = total;
			StatusText = status;
			ProgressLabel = $"{done}/{total} collecteurs terminés";
			int dashIndex = status.IndexOf('—');
			if (dashIndex > 2)
			{
				CurrentCollectorName = status.Substring(2, dashIndex - 2).Trim();
			}
			else if (status.Contains("Initialisation") || status.Contains("MSCT") || status.Contains("Compilation"))
			{
				CurrentCollectorName = status;
			}
		});
	}

	[RelayCommand(CanExecute = "CanAnalyze")]
	private async Task AnalyzeAsync()
	{
		IsAnalyzing = true;
		ShowProgress = true;
		HasResults = false;
		ProgressValue = 0.0;
		CategoryScores.Clear();
		AnalyzeCommand.NotifyCanExecuteChanged();
		CancelCommand.NotifyCanExecuteChanged();
		try
		{
			await Task.Run(async delegate
			{
				await _analysis.RunAsync();
			});
			GlobalScore = _analysis.GlobalScore;
			GlobalGrade = _analysis.GlobalGrade;
			TotalOK = _analysis.TotalOK;
			TotalWarning = _analysis.TotalWarning;
			TotalCritical = _analysis.TotalCritical;
			TotalError = _analysis.TotalError;
			CategoryScores.Clear();
			foreach (SecurityScore categoryScore in _analysis.CategoryScores)
			{
				CategoryScores.Add(categoryScore);
			}
			HasResults = true;
			_history.SaveSnapshot(_analysis);
		}
		catch (Exception ex)
		{
			StatusText = "Erreur lors de l'analyse : " + ex.Message;
			ErrorLogger.Log(LogLevel.Error, "[Analyze] " + ex.Message, ex);
		}
		finally
		{
			IsAnalyzing = false;
			ShowProgress = false;
			AnalyzeCommand.NotifyCanExecuteChanged();
			CancelCommand.NotifyCanExecuteChanged();
			ExportCommand.NotifyCanExecuteChanged();
		}
	}

	private bool CanAnalyze()
	{
		return !IsAnalyzing;
	}

	[RelayCommand(CanExecute = "CanCancel")]
	private void Cancel()
	{
		_analysis.Cancel();
	}

	private bool CanCancel()
	{
		return IsAnalyzing;
	}

	[RelayCommand(CanExecute = "CanExport")]
	private async Task ExportAsync()
	{
		try
		{
			FileSavePicker fileSavePicker = new FileSavePicker();
			nint windowHandle = WindowNative.GetWindowHandle(App.MainAppWindow);
			InitializeWithWindow.Initialize(fileSavePicker, windowHandle);
			fileSavePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
			fileSavePicker.SuggestedFileName = $"CHECKSEC_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}";
			fileSavePicker.FileTypeChoices.Add("Rapport JSON complet", new string[1] { ".json" });
			fileSavePicker.FileTypeChoices.Add("Paramètres collectés (CSV brut)", new string[1] { ".csv" });
			fileSavePicker.FileTypeChoices.Add("Rapport texte", new string[2] { ".log", ".txt" });
			fileSavePicker.FileTypeChoices.Add("Rapport SARIF (CI/CD)", new string[1] { ".sarif" });
			StorageFile file = await fileSavePicker.PickSaveFileAsync();
			if (file == null)
			{
				return;
			}
			IsExporting = true;
			StatusText = "Exportation vers " + file.Name + "…";
			bool isJson = file.FileType.Equals(".json", StringComparison.OrdinalIgnoreCase);
			bool isSarif = file.FileType.Equals(".sarif", StringComparison.OrdinalIgnoreCase);
			string contents = (isSarif
				? App.Services.GetRequiredService<SarifExportService>().GenerateSarif(_analysis)
				: (file.FileType.Equals(".csv", StringComparison.OrdinalIgnoreCase) ? BuildCsvReport() : (isJson ? BuildJsonReport() : BuildTextReport())));
			await File.WriteAllTextAsync(file.Path, contents, Encoding.UTF8);
			IsExporting = false;
			StatusText = "Rapport exporté : " + file.Path;
			_dispatcher.TryEnqueue(async delegate
			{
				ContentDialog contentDialog = new ContentDialog
				{
					Title = "Export terminé",
					Content = "Rapport général exporté :\n" + file.Path,
					CloseButtonText = "OK",
					XamlRoot = App.MainAppWindow?.Content?.XamlRoot
				};
				if (contentDialog.XamlRoot != null)
				{
					await contentDialog.ShowAsync();
				}
			});
		}
		catch (Exception ex)
		{
			try
			{
				string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
				string path = $"CHECKSEC_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}.json";
				string fallbackPath = Path.Combine(folderPath, path);
				await File.WriteAllTextAsync(fallbackPath, BuildJsonReport(), Encoding.UTF8);
				StatusText = "Rapport exporté : " + fallbackPath;
				_dispatcher.TryEnqueue(async delegate
				{
					ContentDialog contentDialog2 = new ContentDialog
					{
						Title = "Export automatique",
						Content = "Rapport général exporté sur le Bureau :\n" + fallbackPath,
						CloseButtonText = "OK",
						XamlRoot = App.MainAppWindow?.Content?.XamlRoot
					};
					if (contentDialog2.XamlRoot != null)
					{
						await contentDialog2.ShowAsync();
					}
				});
			}
			catch (Exception ex2)
			{
				StatusText = "Erreur lors de l'export : impossible d'écrire le rapport.";
				ErrorLogger.AddError("[Export] Primary: " + ex.Message + " | Fallback: " + ex2.Message);
			}
			finally
			{
				IsExporting = false;
			}
		}
	}

	private bool CanExport()
	{
		if (HasResults)
		{
			return !IsAnalyzing;
		}
		return false;
	}

	public List<SecurityResult> GetResultsByStatus(SecurityStatus status)
	{
		return _analysis.AllResults.Where((SecurityResult r) => r.Status == status).ToList();
	}

	public List<SecurityResult> GetResultsByCategory(string category)
	{
		return _analysis.AllResults.Where((SecurityResult r) => r.Category == category).ToList();
	}

	private string BuildJsonReport()
	{
		return ReportJsonBuilder.Build(_analysis, _remediation);
	}

	private string BuildCsvReport()
	{
		StringBuilder stringBuilder = new StringBuilder();
		// En-tête : on garde le séparateur ';' et l'ordre des colonnes existant,
		// enrichi d'une colonne 'Statut'.
		stringBuilder.AppendLine("Catégorie;Paramètre;Valeur Collectée;Statut");
		foreach (SecurityResult allResult in _analysis.AllResults)
		{
			// Échappement RFC 4180 par champ (guillemets, séparateurs, sauts de ligne).
			stringBuilder.Append(CsvField(allResult.Category));
			stringBuilder.Append(';');
			stringBuilder.Append(CsvField(allResult.CheckName));
			stringBuilder.Append(';');
			stringBuilder.Append(CsvField(allResult.CurrentValue));
			stringBuilder.Append(';');
			stringBuilder.Append(CsvField(allResult.Status.ToString()));
			stringBuilder.AppendLine();
		}
		foreach (ComplianceGap gap in _analysis.Gaps)
		{
			stringBuilder.Append(CsvField(gap.GpoName ?? "MSCT Registry"));
			stringBuilder.Append(';');
			stringBuilder.Append(CsvField(gap.RegistryPath + "\\" + gap.ValueName));
			stringBuilder.Append(';');
			stringBuilder.Append(CsvField(gap.CurrentValue));
			stringBuilder.Append(';');
			stringBuilder.Append(CsvField(gap.IsCompliant ? "Conforme" : "Écart"));
			stringBuilder.AppendLine();
		}
		return stringBuilder.ToString();
	}

	// Échappement d'un champ CSV selon RFC 4180 :
	// si le champ contient un guillemet, un séparateur (';' ou ','),
	// un saut de ligne (\n) ou un retour chariot (\r), on l'entoure de
	// guillemets et on double les guillemets internes ('"' -> '""').
	private static string CsvField(string? value)
	{
		string field = value ?? string.Empty;
		if (field.IndexOfAny(new char[] { '"', ';', ',', '\n', '\r' }) >= 0)
		{
			return "\"" + field.Replace("\"", "\"\"") + "\"";
		}
		return field;
	}

	private string BuildTextReport()
	{
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.AppendLine("WinCheckSec — RAPPORT D'AUDIT DE SÉCURITÉ");
		stringBuilder.AppendLine(new string('=', 72));
		StringBuilder stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder3 = stringBuilder2;
		StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(7, 1, stringBuilder2);
		handler.AppendLiteral("Date : ");
		handler.AppendFormatted(DateTime.Now, "dddd dd MMMM yyyy à HH:mm:ss");
		stringBuilder3.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder4 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(10, 1, stringBuilder2);
		handler.AppendLiteral("Machine : ");
		handler.AppendFormatted(Environment.MachineName);
		stringBuilder4.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder5 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(19, 2, stringBuilder2);
		handler.AppendLiteral("Score : ");
		handler.AppendFormatted(_analysis.GlobalScore);
		handler.AppendLiteral("% (Grade: ");
		handler.AppendFormatted(_analysis.GlobalGrade);
		handler.AppendLiteral(")");
		stringBuilder5.AppendLine(ref handler);
		stringBuilder.AppendLine(new string('=', 72));
		stringBuilder.AppendLine();
		foreach (SecurityScore categoryScore in _analysis.CategoryScores)
		{
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder6 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(27, 6, stringBuilder2);
			handler.AppendLiteral("[");
			handler.AppendFormatted(categoryScore.Grade);
			handler.AppendLiteral("] ");
			handler.AppendFormatted(categoryScore.Category);
			handler.AppendLiteral(" — ");
			handler.AppendFormatted(categoryScore.ScorePercent);
			handler.AppendLiteral("% (");
			handler.AppendFormatted(categoryScore.PassedChecks);
			handler.AppendLiteral(" OK, ");
			handler.AppendFormatted(categoryScore.WarningChecks);
			handler.AppendLiteral(" Warn, ");
			handler.AppendFormatted(categoryScore.CriticalChecks);
			handler.AppendLiteral(" Crit)");
			stringBuilder6.AppendLine(ref handler);
		}
		stringBuilder.AppendLine();
		stringBuilder.Append(_analysis.ResultText);
		stringBuilder.AppendLine();
		stringBuilder.AppendLine(new string('=', 72));
		stringBuilder.AppendLine("ÉCARTS DE CONFORMITÉ MSCT");
		stringBuilder.AppendLine(new string('=', 72));
		foreach (ComplianceGap item in _analysis.Gaps.OrderByDescending((ComplianceGap g) => g.Severity))
		{
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder7 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(3, 2, stringBuilder2);
			handler.AppendLiteral("[");
			handler.AppendFormatted(item.Severity);
			handler.AppendLiteral("] ");
			handler.AppendFormatted(item.PolicyName);
			stringBuilder7.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder8 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(26, 2, stringBuilder2);
			handler.AppendLiteral("  Attendu : ");
			handler.AppendFormatted(item.BaselineValue);
			handler.AppendLiteral("  |  Actuel : ");
			handler.AppendFormatted(item.CurrentValue);
			stringBuilder8.AppendLine(ref handler);
		}
		stringBuilder.AppendLine();
		stringBuilder.Append(_analysis.EventLogText);
		return stringBuilder.ToString();
	}

	partial void OnIsAnalyzingChanged(bool value)
	{
		OnPropertyChanged("ShowEmptyState");
	}

	partial void OnHasResultsChanged(bool value)
	{
		OnPropertyChanged("ShowEmptyState");
	}
}
