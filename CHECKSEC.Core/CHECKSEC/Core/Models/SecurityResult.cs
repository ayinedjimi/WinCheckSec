using System;

namespace CHECKSEC.Core.Models;

public class SecurityResult
{
	public string Category { get; set; } = string.Empty;

	public string CheckName { get; set; } = string.Empty;

	public string CurrentValue { get; set; } = string.Empty;

	public string ExpectedValue { get; set; } = string.Empty;

	public SecurityStatus Status { get; set; } = SecurityStatus.Info;

	public string Description { get; set; } = string.Empty;

	public string Recommendation { get; set; } = string.Empty;

	public string Reference { get; set; } = string.Empty;

	public DateTime CollectedAt { get; set; } = DateTime.UtcNow;

	public string StatusColorHex => Status switch
	{
		SecurityStatus.OK => "#4CAF50", 
		SecurityStatus.Warning => "#FF9800", 
		SecurityStatus.Critical => "#F44336", 
		SecurityStatus.Error => "#E53935", 
		_ => "#78909C", 
	};
}
