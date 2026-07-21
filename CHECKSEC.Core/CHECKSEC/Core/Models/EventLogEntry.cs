using System;

namespace CHECKSEC.Core.Models;

public class EventLogEntry
{
	public DateTime Timestamp { get; set; }

	public string Level { get; set; } = string.Empty;

	public int EventId { get; set; }

	public string Source { get; set; } = string.Empty;

	public string Message { get; set; } = string.Empty;

	public string LevelColorHex
	{
		get
		{
			switch (Level)
			{
			case "Error":
			case "Critical":
				return "#F44336";
			case "Warning":
				return "#FF9800";
			case "Information":
				return "#4CAF50";
			default:
				return "#78909C";
			}
		}
	}
}
