using System;

namespace CHECKSEC.Core.Services;

public class LogEntry
{
	public DateTime Timestamp { get; set; } = DateTime.Now;

	public LogLevel Level { get; set; } = LogLevel.Error;

	public string Message { get; set; } = string.Empty;

	public string? StackTrace { get; set; }

	public override string ToString()
	{
		return $"[{Timestamp:yyyy-MM-dd HH:mm:ss}] [{Level}] {Message}{((StackTrace != null) ? ("\n  " + StackTrace) : "")}";
	}
}
