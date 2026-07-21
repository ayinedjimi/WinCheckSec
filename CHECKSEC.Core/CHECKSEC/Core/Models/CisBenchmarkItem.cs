namespace CHECKSEC.Core.Models;

public class CisBenchmarkItem
{
	public string CisId { get; set; } = string.Empty;

	public string Title { get; set; } = string.Empty;

	public string Level { get; set; } = string.Empty;

	public string Section { get; set; } = string.Empty;

	public bool IsCompliant { get; set; }

	public bool IsManualCheck { get; set; }

	public string CurrentValue { get; set; } = string.Empty;

	public string ExpectedValue { get; set; } = string.Empty;

	public string Status { get; set; } = "Not Checked";

	public string Remediation { get; set; } = string.Empty;

	public string StatusColorHex => Status switch
	{
		"Pass" => "#4CAF50", 
		"Fail" => "#F44336", 
		"Manual" => "#FF9800", 
		_ => "#78909C", 
	};
}
