using System.Diagnostics.CodeAnalysis;
using CHECKSEC.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinRT;

namespace CHECKSEC.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
	private readonly SettingsService _settings;

	[ObservableProperty]
	private string _msctToolkitPath = string.Empty;

	[ObservableProperty]
	private string _defaultExportPath = string.Empty;

	[ObservableProperty]
	private int _selectedThemeIndex;

	[ObservableProperty]
	private int _analysisTimeout = 5;

	[ObservableProperty]
	private string _csvSeparator = ";";

	[ObservableProperty]
	private int _selectedCsvSeparatorIndex;

	[ObservableProperty]
	private bool _autoExport;

	[ObservableProperty]
	private int _selectedTemplateIndex;

	[ObservableProperty]
	private string _companyName = "";

	[ObservableProperty]
	private string _reportWatermark = "CONFIDENTIEL";

	[ObservableProperty]
	private string _statusMessage = string.Empty;

	public SettingsViewModel(SettingsService settings)
	{
		_settings = settings;
		LoadFromSettings();
	}

	private void LoadFromSettings()
	{
		MsctToolkitPath = _settings.Current.MsctToolkitPath;
		DefaultExportPath = _settings.Current.DefaultExportPath;
		string settingValue = _settings.Current.Theme;
		int index = ((settingValue == "Light") ? 1 : ((settingValue == "Dark") ? 2 : 0));
		SelectedThemeIndex = index;
		AnalysisTimeout = _settings.Current.AnalysisTimeoutMinutes;
		CsvSeparator = _settings.Current.CsvSeparator;
		settingValue = _settings.Current.CsvSeparator;
		index = ((settingValue == ",") ? 1 : ((settingValue == "\t") ? 2 : 0));
		SelectedCsvSeparatorIndex = index;
		AutoExport = _settings.Current.AutoExportAfterAnalysis;
		settingValue = _settings.Current.ReportTemplate;
		index = ((settingValue == "Exécutif") ? 1 : ((settingValue == "Conformité") ? 2 : 0));
		SelectedTemplateIndex = index;
		CompanyName = _settings.Current.CompanyName;
		ReportWatermark = _settings.Current.ReportWatermark;
	}

	[RelayCommand]
	private void Save()
	{
		_settings.Current.MsctToolkitPath = MsctToolkitPath;
		_settings.Current.DefaultExportPath = DefaultExportPath;
		AppSettings current = _settings.Current;
		current.Theme = SelectedThemeIndex switch
		{
			1 => "Light",
			2 => "Dark",
			_ => "System",
		};
		_settings.Current.AnalysisTimeoutMinutes = AnalysisTimeout;
		_settings.Current.CsvSeparator = CsvSeparator;
		_settings.Current.AutoExportAfterAnalysis = AutoExport;
		current = _settings.Current;
		current.ReportTemplate = SelectedTemplateIndex switch
		{
			1 => "Exécutif",
			2 => "Conformité",
			_ => "Technique",
		};
		_settings.Current.CompanyName = CompanyName;
		_settings.Current.ReportWatermark = ReportWatermark;
		_settings.Save();
		StatusMessage = "Paramètres sauvegardés avec succès";
	}

	[RelayCommand]
	private void Reset()
	{
		_settings.Current = new AppSettings();
		_settings.Save();
		LoadFromSettings();
		StatusMessage = "Paramètres réinitialisés";
	}
}
