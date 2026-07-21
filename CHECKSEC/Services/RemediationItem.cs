namespace CHECKSEC.Services;

public class RemediationItem
{
	public int Priority { get; set; }

	public string Category { get; set; } = string.Empty;

	public string Action { get; set; } = string.Empty;

	public string Detail { get; set; } = string.Empty;

	public string Effort { get; set; } = string.Empty;

	public string Command { get; set; } = string.Empty;

	public string Severity { get; set; } = string.Empty;

	public string Status { get; set; } = "À faire";

	public string Responsible { get; set; } = string.Empty;
}
