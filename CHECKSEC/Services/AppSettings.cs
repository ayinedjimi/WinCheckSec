using System;

namespace CHECKSEC.Services;

public class AppSettings
{
	public string MsctToolkitPath { get; set; } = "C:\\MSCTOOLKIT";

	public string DefaultExportPath { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

	public string Theme { get; set; } = "System";

	public int AnalysisTimeoutMinutes { get; set; } = 5;

	public string CsvSeparator { get; set; } = ";";

	public bool AutoExportAfterAnalysis { get; set; }

	public string Language { get; set; } = "fr";

	public string ReportTemplate { get; set; } = "Technique";

	public string CompanyName { get; set; } = "";

	public string CompanyLogo { get; set; } = string.Empty;

	public string ReportWatermark { get; set; } = "CONFIDENTIEL";
}
