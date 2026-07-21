using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Helpers;

public static class RegistryHelper
{
	private static readonly Dictionary<string, int> KnownDefaults = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
	{
		{ "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA", 1 },
		{ "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin", 5 },
		{ "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\FilterAdministratorToken", 0 },
		{ "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature", 0 }
	};

	public static RegistryKey? OpenHklm(string subKey)
	{
		using RegistryKey registryKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
		return registryKey.OpenSubKey(subKey);
	}

	public static int GetDword(string subKey, string valueName, int defaultValue = -1)
	{
		try
		{
			using RegistryKey registryKey = OpenHklm(subKey);
			object rawValue = registryKey?.GetValue(valueName);
			return (rawValue != null) ? Convert.ToInt32(rawValue) : defaultValue;
		}
		catch
		{
			return defaultValue;
		}
	}

	public static int GetValueOrDefault(string subKey, string valueName, int fallback = -1)
	{
		try
		{
			using RegistryKey registryKey = OpenHklm(subKey);
			object rawValue = registryKey?.GetValue(valueName);
			if (rawValue != null)
			{
				return Convert.ToInt32(rawValue);
			}
			string key = subKey + "\\" + valueName;
			if (KnownDefaults.TryGetValue(key, out var knownDefault))
			{
				return knownDefault;
			}
			return fallback;
		}
		catch
		{
			return fallback;
		}
	}

	public static string? GetString(string subKey, string valueName)
	{
		try
		{
			using RegistryKey registryKey = OpenHklm(subKey);
			return registryKey?.GetValue(valueName)?.ToString();
		}
		catch
		{
			return null;
		}
	}

	public static bool KeyExists(string subKey)
	{
		try
		{
			using RegistryKey registryKey = OpenHklm(subKey);
			return registryKey != null;
		}
		catch
		{
			return false;
		}
	}
}
