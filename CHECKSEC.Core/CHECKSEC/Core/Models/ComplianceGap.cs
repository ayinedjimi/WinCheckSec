namespace CHECKSEC.Core.Models;

public class ComplianceGap
{
	public string PolicyName { get; set; } = string.Empty;

	public string RegistryPath { get; set; } = string.Empty;

	public string ValueName { get; set; } = string.Empty;

	public string BaselineValue { get; set; } = string.Empty;

	public string CurrentValue { get; set; } = string.Empty;

	public bool IsCompliant { get; set; }

	public GapSeverity Severity { get; set; }

	public string GpoName { get; set; } = string.Empty;

	public string Description { get; set; } = string.Empty;

	public string SeverityColorHex => Severity switch
	{
		GapSeverity.Critical => "#F44336", 
		GapSeverity.High => "#FF5722", 
		GapSeverity.Medium => "#FF9800", 
		GapSeverity.Low => "#8BC34A", 
		_ => "#78909C", 
	};
}
