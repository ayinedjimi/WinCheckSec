using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Management;
using System.Threading;

namespace CHECKSEC.Core.Services.Helpers;

public static class WmiHelper
{
	private static readonly ConcurrentDictionary<string, ManagementScope> _scopes = new ConcurrentDictionary<string, ManagementScope>(StringComparer.OrdinalIgnoreCase);

	public static ManagementScope GetScope(string wmiNamespace = "\\\\.\\root\\cimv2")
	{
		return _scopes.GetOrAdd(wmiNamespace, delegate(string ns)
		{
			ManagementScope managementScope = new ManagementScope(ns)
			{
				Options = 
				{
					Timeout = TimeSpan.FromSeconds(15L)
				}
			};
			try
			{
				managementScope.Connect();
			}
			catch
			{
				Thread.Sleep(1000);
				managementScope.Connect();
			}
			return managementScope;
		});
	}

	public static List<ManagementObject> Query(string query, string wmiNamespace = "\\\\.\\root\\cimv2")
	{
		// Correctif L6: le ManagementObjectSearcher est désormais disposé (using).
		// L'énumération/collecte est matérialisée AVANT la libération (clones qui survivent au Dispose).
		using ManagementObjectSearcher searcher = new ManagementObjectSearcher(GetScope(wmiNamespace), new ObjectQuery(query))
		{
			Options =
			{
				Timeout = TimeSpan.FromSeconds(15L)
			}
		};
		List<ManagementObject> results = new List<ManagementObject>();
		using ManagementObjectCollection collection = searcher.Get();
		foreach (ManagementBaseObject item in collection)
		{
			results.Add((ManagementObject)item.Clone());
		}
		return results;
	}

	public static string? GetString(ManagementObject obj, string property)
	{
		try
		{
			return obj[property]?.ToString();
		}
		catch
		{
			return null;
		}
	}

	public static int GetInt(ManagementObject obj, string property, int defaultValue = -1)
	{
		try
		{
			object rawValue = obj[property];
			return (rawValue != null && !(rawValue is DBNull)) ? Convert.ToInt32(rawValue) : defaultValue;
		}
		catch
		{
			return defaultValue;
		}
	}

	public static bool GetBool(ManagementObject obj, string property, bool defaultValue = false)
	{
		try
		{
			object rawValue = obj[property];
			return (rawValue != null && !(rawValue is DBNull)) ? Convert.ToBoolean(rawValue) : defaultValue;
		}
		catch
		{
			return defaultValue;
		}
	}

	public static void ClearCache()
	{
		foreach (ManagementScope scope in _scopes.Values)
		{
			try
			{
				(scope as IDisposable)?.Dispose();
			}
			catch
			{
			}
		}
		_scopes.Clear();
	}
}
