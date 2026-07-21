using System;
using System.IO;
using System.Text.Json;
using CHECKSEC.Core.Services;

namespace CHECKSEC.Services;

public class SettingsService
{
	private static readonly string SettingsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CHECKSEC");

	private static readonly string SettingsPath = Path.Combine(SettingsDir, "settings.json");

	private AppSettings _current = new AppSettings();

	private bool _loaded;

	public AppSettings Current
	{
		get
		{
			EnsureLoaded();
			return _current;
		}
		set
		{
			_current = value;
		}
	}

	private void EnsureLoaded()
	{
		if (!_loaded)
		{
			Load();
			_loaded = true;
		}
	}

	public void Load()
	{
		try
		{
			if (File.Exists(SettingsPath))
			{
				string json = File.ReadAllText(SettingsPath);
				_current = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
				ValidateSettings();
			}
		}
		catch (Exception ex)
		{
			_current = new AppSettings();
			ErrorLogger.Log(LogLevel.Warning, "Failed to load settings, using defaults: " + ex.Message);
		}
	}

	private void ValidateSettings()
	{
		if (_current.AnalysisTimeoutMinutes < 1 || _current.AnalysisTimeoutMinutes > 60)
		{
			_current.AnalysisTimeoutMinutes = 5;
		}
		if (string.IsNullOrEmpty(_current.CsvSeparator) || _current.CsvSeparator.Length > 1)
		{
			_current.CsvSeparator = ";";
		}
		if (string.IsNullOrWhiteSpace(_current.Theme) || (_current.Theme != "System" && _current.Theme != "Light" && _current.Theme != "Dark"))
		{
			_current.Theme = "System";
		}
		if (string.IsNullOrWhiteSpace(_current.Language))
		{
			_current.Language = "fr";
		}
	}

	public void Save()
	{
		try
		{
			Directory.CreateDirectory(SettingsDir);
			string contents = JsonSerializer.Serialize(Current, new JsonSerializerOptions
			{
				WriteIndented = true
			});
			File.WriteAllText(SettingsPath, contents);
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Failed to save settings: " + ex.Message, ex);
		}
	}
}
