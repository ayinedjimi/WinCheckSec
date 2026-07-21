using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CHECKSEC.Core.Services;

public static class ErrorLogger
{
	private static readonly List<LogEntry> _entries = new List<LogEntry>();

	private static readonly object _lock = new object();

	private static string? _logFilePath;

	public static event Action<LogEntry>? EntryAdded;

	public static void Initialize(string? logDirectory = null)
	{
		string? logDir = logDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CHECKSEC", "logs");
		Directory.CreateDirectory(logDir);
		_logFilePath = Path.Combine(logDir, $"checksec_{DateTime.Now:yyyyMMdd}.log");
	}

	public static void Log(LogLevel level, string message, Exception? ex = null)
	{
		try
		{
			LogEntry logEntry = new LogEntry
			{
				Timestamp = DateTime.Now,
				Level = level,
				Message = message,
				StackTrace = ex?.StackTrace
			};
			lock (_lock)
			{
				_entries.Add(logEntry);
				if (_entries.Count > 1000)
				{
					_entries.RemoveAt(0);
				}
			}
			if (_logFilePath != null)
			{
				lock (_lock)
				{
					File.AppendAllText(_logFilePath, logEntry.ToString() + Environment.NewLine);
				}
			}
			ErrorLogger.EntryAdded?.Invoke(logEntry);
		}
		catch
		{
		}
	}

	public static void AddError(string message)
	{
		Log(LogLevel.Error, message);
	}

	public static IReadOnlyList<LogEntry> GetEntries(LogLevel? minLevel = null)
	{
		lock (_lock)
		{
			if (!minLevel.HasValue)
			{
				return _entries.ToList().AsReadOnly();
			}
			LogLevel threshold = minLevel.Value;
			List<LogEntry> filtered = new List<LogEntry>();
			foreach (LogEntry entry in _entries)
			{
				if (entry.Level >= threshold)
				{
					filtered.Add(entry);
				}
			}
			return filtered.AsReadOnly();
		}
	}

	public static IReadOnlyList<string> GetErrors()
	{
		lock (_lock)
		{
			return (from e in _entries
				where e.Level >= LogLevel.Error
				select e.Message).ToList().AsReadOnly();
		}
	}

	public static void Clear()
	{
		lock (_lock)
		{
			_entries.Clear();
		}
	}
}
