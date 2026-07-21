namespace CHECKSEC.Core.Models;

public class SecureCoreItem
{
	public string Name { get; set; } = string.Empty;

	public string Icon { get; set; } = string.Empty;

	public string Value { get; set; } = string.Empty;

	public SecurityStatus Status { get; set; } = SecurityStatus.Info;

	public string StatusColorHex
	{
		get
		{
			switch (Status)
			{
			case SecurityStatus.OK:
				return "#4CAF50";
			case SecurityStatus.Warning:
				return "#FF9800";
			case SecurityStatus.Critical:
			case SecurityStatus.Error:
				return "#F44336";
			default:
				return "#78909C";
			}
		}
	}

	public string StatusLabel
	{
		get
		{
			switch (Status)
			{
			case SecurityStatus.OK:
				return "Activé";
			case SecurityStatus.Warning:
				return "Partiel";
			case SecurityStatus.Critical:
			case SecurityStatus.Error:
				return "Désactivé";
			default:
				return "Inconnu";
			}
		}
	}

	public string TechnicalDescription { get; set; } = string.Empty;

	public string Remediation { get; set; } = string.Empty;

	public string Impact { get; set; } = string.Empty;

	public string Reference { get; set; } = string.Empty;
}
