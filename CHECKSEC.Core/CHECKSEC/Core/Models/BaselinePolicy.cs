namespace CHECKSEC.Core.Models;

public class BaselinePolicy
{
	public string GpoName { get; set; } = string.Empty;

	public PolicyType Type { get; set; }

	public string KeyPath { get; set; } = string.Empty;

	public string ValueName { get; set; } = string.Empty;

	public string ExpectedValue { get; set; } = string.Empty;

	public string ValueType { get; set; } = "REG_DWORD";

	public string Section { get; set; } = string.Empty;
}
