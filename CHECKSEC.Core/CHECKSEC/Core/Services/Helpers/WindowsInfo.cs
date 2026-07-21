using System;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Helpers;

public static class WindowsInfo
{
	private static string? _edition;

	private static int? _build;

	public static string Edition => _edition ?? (_edition = DetectEdition());

	public static int BuildNumber
	{
		get
		{
			int build = _build.GetValueOrDefault();
			if (!_build.HasValue)
			{
				build = DetectBuild();
				_build = build;
				return build;
			}
			return build;
		}
	}

	public static bool IsHome => Edition.Contains("Home", StringComparison.OrdinalIgnoreCase);

	public static bool IsPro
	{
		get
		{
			if (Edition.Contains("Pro", StringComparison.OrdinalIgnoreCase))
			{
				return !Edition.Contains("Education", StringComparison.OrdinalIgnoreCase);
			}
			return false;
		}
	}

	public static bool IsEnterprise
	{
		get
		{
			if (!Edition.Contains("Enterprise", StringComparison.OrdinalIgnoreCase))
			{
				return Edition.Contains("Education", StringComparison.OrdinalIgnoreCase);
			}
			return true;
		}
	}

	public static bool IsVM => DetectVM();

	public static bool Is22H2OrLater => BuildNumber >= 22621;

	public static bool Is23H2OrLater => BuildNumber >= 22631;

	public static bool Is24H2OrLater => BuildNumber >= 26100;

	private static string DetectEdition()
	{
		try
		{
			using RegistryKey registryKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey registryKey2 = registryKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
			return registryKey2?.GetValue("EditionID")?.ToString() ?? registryKey2?.GetValue("ProductName")?.ToString() ?? "Unknown";
		}
		catch
		{
			return "Unknown";
		}
	}

	private static int DetectBuild()
	{
		try
		{
			using RegistryKey registryKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey registryKey2 = registryKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
			string buildStr = registryKey2?.GetValue("CurrentBuildNumber")?.ToString();
			int parsed;
			return (buildStr != null && int.TryParse(buildStr, out parsed)) ? parsed : 0;
		}
		catch
		{
			return 0;
		}
	}

	private static bool DetectVM()
	{
		try
		{
			using RegistryKey registryKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey registryKey2 = registryKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\disk\\Enum");
			string diskEnum = registryKey2?.GetValue("0")?.ToString()?.ToLowerInvariant() ?? "";
			return diskEnum.Contains("vmware") || diskEnum.Contains("vbox") || diskEnum.Contains("virtual") || diskEnum.Contains("xen") || diskEnum.Contains("qemu") || diskEnum.Contains("hyper-v");
		}
		catch
		{
			return false;
		}
	}
}
