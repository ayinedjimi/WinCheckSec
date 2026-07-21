using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services.Helpers;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class AutoRunsCollector : ISecurityCollector
{
	private static readonly HashSet<string> SuspiciousIfeoTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe", "taskhost.exe", "taskhostw.exe", "explorer.exe",
		"calc.exe", "notepad.exe", "mspaint.exe", "regedit.exe", "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe",
		"rundll32.exe", "msiexec.exe", "spoolsv.exe", "taskmgr.exe"
	};

	public string Name => "Autoruns & Persistance";

	public string Category => "Persistance";

	public Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport collectorReport = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch stopwatch = Stopwatch.StartNew();
		try
		{
			ct.ThrowIfCancellationRequested();
			CollectRegistryRunKeys(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectAppInitDlls(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectLsaAuthPackages(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectImageFileExecutionOptions(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectWmiSubscriptions(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectScheduledTasks(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectStartupFolders(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectBrowserHelperObjects(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			collectorReport.ErrorMessage = "AutoRunsCollector fatal error: " + ex2.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectRegistryRunKeys(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		(RegistryHive, string, string)[] runKeyLocations = new(RegistryHive, string, string)[6]
		{
			(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run"),
			(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM RunOnce"),
			(RegistryHive.CurrentUser, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU Run"),
			(RegistryHive.CurrentUser, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU RunOnce"),
			(RegistryHive.LocalMachine, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM WOW64 Run"),
			(RegistryHive.CurrentUser, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU WOW64 Run")
		};
		for (int i = 0; i < runKeyLocations.Length; i++)
		{
			var (hKey, name, label) = runKeyLocations[i];
			ct.ThrowIfCancellationRequested();
			try
			{
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
				using RegistryKey runKey = baseKey.OpenSubKey(name);
				if (runKey == null)
				{
					continue;
				}
				string[] valueNames = runKey.GetValueNames();
				if (valueNames.Length == 0)
				{
					TryAdd(results, () => new SecurityResult
					{
						Category = Category,
						CheckName = "Run Key: " + label,
						CurrentValue = "(empty)",
						ExpectedValue = "No unexpected entries",
						Status = SecurityStatus.OK,
						Description = "No autorun entries found in " + label + ".",
						Recommendation = "No action required.",
						Reference = "https://attack.mitre.org/techniques/T1547/001/"
					});
					continue;
				}
				string[] valueNamesArray = valueNames;
				foreach (string valueName in valueNamesArray)
				{
					string entryName = valueName;
					string entryValue = runKey.GetValue(valueName)?.ToString() ?? string.Empty;
					string location = label;
					TryAdd(results, delegate
					{
						SecurityStatus securityStatus = ClassifyRunEntryPath(entryValue);
						string description = $"Autorun entry in {location}: '{entryName}' → {entryValue}";
						string recommendation = securityStatus switch
						{
							SecurityStatus.Warning => "Entry '" + entryName + "' is in a user-writable location. Investigate whether it is legitimate.", 
							SecurityStatus.Info => "Entry appears to be in a standard location. Verify it is expected.", 
							_ => "Entry '" + entryName + "' is in a highly suspicious location (%TEMP%, AppData\\Roaming, etc.). Investigate immediately.", 
						};
						return new SecurityResult
						{
							Category = Category,
							CheckName = "Run Key: " + location + " → " + entryName,
							CurrentValue = entryValue,
							ExpectedValue = "Signed executable under Program Files or Windows",
							Status = securityStatus,
							Description = description,
							Recommendation = recommendation,
							Reference = "https://attack.mitre.org/techniques/T1547/001/"
						};
					});
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex2)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Run Key: " + label,
					CurrentValue = "Error: " + ex2.Message,
					Status = SecurityStatus.Error,
					Description = "Failed to read " + label + " registry key.",
					Recommendation = "Ensure the process is running with sufficient privileges.",
					Reference = ""
				});
			}
		}
		ct.ThrowIfCancellationRequested();
		CollectWinlogonPersistence(results, ct);
		ct.ThrowIfCancellationRequested();
		CollectWinlogonNotify(results, ct);
	}

	private void CollectWinlogonPersistence(List<SecurityResult> results, CancellationToken ct)
	{
		Dictionary<string, string> expectedValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
		{
			{ "Shell", "explorer.exe" },
			{ "Userinit", "C:\\Windows\\system32\\userinit.exe," },
			{ "AppSetup", "" }
		};
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			RegistryKey winlogonKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
			try
			{
				if (winlogonKey == null)
				{
					return;
				}
				foreach (KeyValuePair<string, string> entry in expectedValues)
				{
					entry.Deconstruct(out var entryKey, out var entryExpected);
					string name = entryKey;
					string expectedVal = entryExpected;
					string vn = name;
					string ev = expectedVal;
					TryAdd(results, delegate
					{
						string currentVal = winlogonKey.GetValue(vn)?.ToString() ?? string.Empty;
						bool matches = (string.IsNullOrEmpty(ev) ? string.IsNullOrEmpty(currentVal) : (currentVal.Equals(ev, StringComparison.OrdinalIgnoreCase) || currentVal.StartsWith(ev, StringComparison.OrdinalIgnoreCase)));
						return new SecurityResult
						{
							Category = Category,
							CheckName = "Winlogon: " + vn,
							CurrentValue = (string.IsNullOrEmpty(currentVal) ? "(not set)" : currentVal),
							ExpectedValue = (string.IsNullOrEmpty(ev) ? "(empty / not set)" : ev),
							Status = ((!matches) ? SecurityStatus.Critical : SecurityStatus.OK),
							Description = "Winlogon value '" + vn + "' controls shell/initialization. Unexpected values indicate persistence or compromise.",
							Recommendation = (matches ? "Value is as expected." : $"Winlogon '{vn}' has been modified. Expected: '{ev}', found: '{currentVal}'. Investigate immediately."),
							Reference = "https://attack.mitre.org/techniques/T1547/004/"
						};
					});
				}
			}
			finally
			{
				if (winlogonKey != null)
				{
					((IDisposable)winlogonKey).Dispose();
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Winlogon Persistence Check",
				CurrentValue = "Error: " + ex2.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to read Winlogon registry values.",
				Recommendation = "Run as Administrator.",
				Reference = ""
			});
		}
	}

	private void CollectWinlogonNotify(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey notifyKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify");
			if (notifyKey == null)
			{
				return;
			}
			string[] subKeyNames = notifyKey.GetSubKeyNames();
			if (subKeyNames.Length == 0)
			{
				return;
			}
			string[] subKeys = subKeyNames;
			foreach (string subKeyName in subKeys)
			{
				string skName = subKeyName;
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Winlogon Notify: " + skName,
					CurrentValue = skName,
					ExpectedValue = "(no subkeys expected)",
					Status = SecurityStatus.Warning,
					Description = "Winlogon Notify subkey '" + skName + "' found. This mechanism is used for DLL injection at logon. Legitimate use is extremely rare on modern Windows.",
					Recommendation = "Investigate the DLL registered under Winlogon\\Notify\\" + skName + ". Remove if not authorized.",
					Reference = "https://attack.mitre.org/techniques/T1547/004/"
				});
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Winlogon Notify Subkeys",
				CurrentValue = "Error: " + ex2.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to enumerate Winlogon\\Notify subkeys.",
				Recommendation = "Run as Administrator.",
				Reference = ""
			});
		}
	}

	private void CollectAppInitDlls(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey windowsKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
			string appInitDlls = windowsKey?.GetValue("AppInit_DLLs")?.ToString() ?? string.Empty;
			object loadValue = windowsKey?.GetValue("LoadAppInit_DLLs");
			int loadAppInitDlls = ((loadValue != null && !(loadValue is DBNull)) ? Convert.ToInt32(loadValue) : 0);
			bool isActive = loadAppInitDlls == 1 && !string.IsNullOrWhiteSpace(appInitDlls);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "AppInit_DLLs",
				CurrentValue = $"LoadAppInit_DLLs={loadAppInitDlls}, AppInit_DLLs=\"{appInitDlls}\"",
				ExpectedValue = "LoadAppInit_DLLs=0 and AppInit_DLLs empty",
				Status = (isActive ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "AppInit_DLLs causes listed DLLs to be loaded into every process that loads User32.dll. This is a classic DLL injection/persistence mechanism exploited by malware.",
				Recommendation = (isActive ? ("AppInit_DLLs is active with DLLs: \"" + appInitDlls + "\". This is a severe persistence indicator. Set LoadAppInit_DLLs=0 and clear AppInit_DLLs unless intentionally configured.") : "AppInit_DLLs mechanism is not active."),
				Reference = "https://attack.mitre.org/techniques/T1546/010/"
			};
		});
	}

	private void CollectLsaAuthPackages(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		(string, HashSet<string>, string)[] packageChecks = new(string, HashSet<string>, string)[3]
		{
			("Authentication Packages", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "msv1_0" }, "LSA: Authentication Packages"),
			("Security Packages", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u" }, "LSA: Security Packages"),
			("Notification Packages", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "scecli" }, "LSA: Notification Packages")
		};
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			try
			{
				(string, HashSet<string>, string)[] checks = packageChecks;
				for (int i = 0; i < checks.Length; i++)
				{
					(string, HashSet<string>, string) check = checks[i];
					string valueName = check.Item1;
					HashSet<string> defaults = check.Item2;
					string checkName = check.Item3;
					string vn = valueName;
					HashSet<string> defaultSet = defaults;
					string cn = checkName;
					TryAdd(results, delegate
					{
						string[] configuredPackages = Array.Empty<string>();
						if (lsaKey != null)
						{
							object rawValue = lsaKey.GetValue(vn);
							if (rawValue is string[] strArray)
							{
								configuredPackages = strArray;
							}
							else if (rawValue != null)
							{
								configuredPackages = rawValue.ToString().Split(new char[3] { '\0', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
							}
						}
						List<string> unexpected = (from p in configuredPackages
							where !string.IsNullOrWhiteSpace(p) && !defaultSet.Contains(p.Trim())
							select p.Trim()).ToList();
						string currentValue = ((configuredPackages.Length == 0) ? "(none)" : string.Join(", ", configuredPackages));
						bool hasUnexpected = unexpected.Count > 0;
						return new SecurityResult
						{
							Category = Category,
							CheckName = cn,
							CurrentValue = currentValue,
							ExpectedValue = string.Join(", ", defaultSet),
							Status = (hasUnexpected ? SecurityStatus.Warning : SecurityStatus.OK),
							Description = "LSA " + vn + " controls which authentication packages are loaded by LSASS. Extra packages may be credential-theft DLLs (e.g. mimikatz SSP).",
							Recommendation = (hasUnexpected ? ("Unexpected packages found: " + string.Join(", ", unexpected) + ". Verify these are authorized security packages.") : "All packages are within expected defaults."),
							Reference = "https://attack.mitre.org/techniques/T1547/005/"
						};
					});
				}
			}
			finally
			{
				if (lsaKey != null)
				{
					((IDisposable)lsaKey).Dispose();
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "LSA Authentication Packages",
				CurrentValue = "Error: " + ex2.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to read LSA authentication package registry keys.",
				Recommendation = "Run as Administrator.",
				Reference = ""
			});
		}
	}

	private void CollectImageFileExecutionOptions(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			RegistryKey ifeoKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options");
			try
			{
				if (ifeoKey == null)
				{
					return;
				}
				string[] subKeyNames = ifeoKey.GetSubKeyNames();
				foreach (string imageName in subKeyNames)
				{
					ct.ThrowIfCancellationRequested();
					string skName = imageName;
					TryAdd(results, delegate
					{
						using RegistryKey optionsKey = ifeoKey.OpenSubKey(skName);
						string debugger = optionsKey?.GetValue("Debugger")?.ToString();
						if (string.IsNullOrEmpty(debugger))
						{
							return (SecurityResult)null;
						}
						bool isSuspicious = SuspiciousIfeoTargets.Contains(skName);
						return new SecurityResult
						{
							Category = Category,
							CheckName = "IFEO Debugger: " + skName,
							CurrentValue = debugger,
							ExpectedValue = "(no Debugger value set for system processes)",
							Status = (isSuspicious ? SecurityStatus.Warning : SecurityStatus.Info),
							Description = $"Image File Execution Options 'Debugger' for '{skName}' is set to '{debugger}'. " + (isSuspicious ? "This is a critical system process — a Debugger entry can redirect execution or block the process." : "Legitimate for debugging tools (WinDbg, ProcMon). Verify this is intentional."),
							Recommendation = (isSuspicious ? ("Remove the Debugger value under IFEO\\" + skName + " unless explicitly set for authorized debugging.") : "Verify that this IFEO Debugger entry was set intentionally by a legitimate debugging tool."),
							Reference = "https://attack.mitre.org/techniques/T1546/012/"
						};
					});
				}
			}
			finally
			{
				if (ifeoKey != null)
				{
					((IDisposable)ifeoKey).Dispose();
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Image File Execution Options",
				CurrentValue = "Error: " + ex2.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to enumerate IFEO registry keys.",
				Recommendation = "Run as Administrator.",
				Reference = ""
			});
		}
	}

	private void CollectWmiSubscriptions(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		(string, string)[] subscriptionClasses = new(string, string)[3]
		{
			("__EventFilter", "WMI EventFilter"),
			("__EventConsumer", "WMI EventConsumer"),
			("__FilterToConsumerBinding", "WMI FilterToConsumerBinding")
		};
		int count = 0;
		(string, string)[] classes = subscriptionClasses;
		for (int i = 0; i < classes.Length; i++)
		{
			var (rawClass, rawLabel) = classes[i];
			ct.ThrowIfCancellationRequested();
			string wmiClass = rawClass;
			string wmiLabel = rawLabel;
			try
			{
				ManagementObjectSearcher searcher = new ManagementObjectSearcher(WmiHelper.GetScope("\\\\.\\root\\subscription"), new ObjectQuery("SELECT * FROM " + wmiClass));
				try
				{
					using ManagementObjectCollection subscriptions = searcher.Get();
					foreach (ManagementObject subscription in subscriptions)
					{
						ManagementObject mo = subscription;
						try
						{
							ct.ThrowIfCancellationRequested();
							count++;
							string name = subscription["Name"]?.ToString() ?? "(unnamed)";
							string query = string.Empty;
							try
							{
								query = subscription["Query"]?.ToString() ?? string.Empty;
							}
							catch (Exception)
							{
							}
							string capturedName = name;
							string capturedQuery = query;
							string capturedClass = wmiClass;
							string capturedLabel = wmiLabel;
							TryAdd(results, () => new SecurityResult
							{
								Category = Category,
								CheckName = capturedLabel + ": " + capturedName,
								CurrentValue = (string.IsNullOrEmpty(capturedQuery) ? capturedName : (capturedName + " | Query: " + capturedQuery)),
								ExpectedValue = "(no WMI permanent subscriptions expected)",
								Status = SecurityStatus.Warning,
								Description = $"Permanent WMI {capturedClass} subscription '{capturedName}' found. Legitimate software rarely uses WMI permanent subscriptions. APT groups use this for fileless persistence.",
								Recommendation = $"Investigate WMI subscription '{capturedName}'. Remove with: Get-WMIObject -Namespace root\\subscription -Class {capturedClass} -Filter \"Name='{capturedName}'\" | Remove-WmiObject",
								Reference = "https://attack.mitre.org/techniques/T1546/003/"
							});
						}
						finally
						{
							((IDisposable)mo)?.Dispose();
						}
					}
				}
				finally
				{
					((IDisposable)searcher)?.Dispose();
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex3)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = wmiLabel + " Query",
					CurrentValue = "Error: " + ex3.Message,
					Status = SecurityStatus.Error,
					Description = "Failed to query WMI " + wmiClass + " subscriptions.",
					Recommendation = "Run as Administrator. Verify WMI service is running.",
					Reference = ""
				});
			}
		}
		if (count == 0)
		{
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "WMI Permanent Subscriptions",
				CurrentValue = "None found",
				ExpectedValue = "No subscriptions",
				Status = SecurityStatus.OK,
				Description = "No WMI permanent event subscriptions detected in root\\subscription namespace.",
				Recommendation = "No action required.",
				Reference = "https://attack.mitre.org/techniques/T1546/003/"
			});
		}
	}

	private void CollectScheduledTasks(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			// Correctif H1 : schtasks.exe émet en code page OEM, pas en UTF8. On sélectionne
			// l'encodage OEM de la locale installée (fallback UTF8) pour éviter les caractères corrompus.
			Encoding schtasksEncoding;
			try
			{
				schtasksEncoding = Encoding.GetEncoding(CultureInfo.InstalledUICulture.TextInfo.OEMCodePage);
			}
			catch
			{
				schtasksEncoding = Encoding.UTF8;
			}
			using Process process = Process.Start(new ProcessStartInfo("schtasks.exe", "/query /fo CSV /v")
			{
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true,
				StandardOutputEncoding = schtasksEncoding
			});
			if (process == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Scheduled Tasks",
					CurrentValue = "Process start failed",
					Status = SecurityStatus.Error,
					Description = "Failed to start schtasks.exe.",
					Recommendation = "Ensure schtasks.exe is available.",
					Reference = ""
				});
				return;
			}
			string stderr = "";
			process.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e)
			{
				if (e.Data != null)
				{
					stderr += e.Data;
				}
			};
			process.BeginErrorReadLine();
			string output = process.StandardOutput.ReadToEnd();
			if (!process.WaitForExit(30000))
			{
				try
				{
					process.Kill();
				}
				catch
				{
				}
			}
			ct.ThrowIfCancellationRequested();
			string[] lines = output.Split('\n');
			if (lines.Length < 2)
			{
				return;
			}
			string[] headers = ParseCsvLine(lines[0]);
			int index = FindHeader(headers, "TaskName");
			int index2 = FindHeader(headers, "Author", "Run As User");
			int index3 = FindHeader(headers, "Task To Run");
			int index4 = FindHeader(headers, "Status");
			int index5 = FindHeader(headers, "Last Run Time");
			int suspicious = 0;
			int total = 0;
			for (int i = 1; i < lines.Length; i++)
			{
				ct.ThrowIfCancellationRequested();
				string trimmedLine = lines[i].Trim();
				if (string.IsNullOrEmpty(trimmedLine))
				{
					continue;
				}
				string[] fields = ParseCsvLine(trimmedLine);
				if (fields.Length < 2)
				{
					continue;
				}
				string taskName = SafeField(fields, index);
				string author = SafeField(fields, index2);
				string taskToRun = SafeField(fields, index3);
				string status = SafeField(fields, index4);
				string lastRun = SafeField(fields, index5);
				// Correctif H1 : ne plus filtrer sur status == "Ready"/"Running" (libellés localisés).
				// On rapporte TOUTE tâche non-Microsoft, quel que soit son statut, et on inclut la
				// valeur de statut brute (informative) pour ne jamais ignorer une tâche à cause de la langue.
				if (author.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) < 0)
				{
					int counter = total;
					total = counter + 1;
					bool isSuspiciousPath = ContainsSuspiciousPath(taskToRun);
					if (isSuspiciousPath)
					{
						counter = suspicious;
						suspicious = counter + 1;
					}
					string tn = taskName;
					string auth = author;
					string ttr = taskToRun;
					string lr = lastRun;
					string st = status;
					TryAdd(results, () => new SecurityResult
					{
						Category = Category,
						CheckName = "Scheduled Task: " + tn,
						CurrentValue = $"Author={auth}, Cmd={ttr}, Status={st}, LastRun={lr}",
						ExpectedValue = "Known-good software under Program Files",
						Status = (isSuspiciousPath ? SecurityStatus.Warning : SecurityStatus.Info),
						Description = $"Non-Microsoft scheduled task '{tn}' found (status: '{st}'). Author: '{auth}'. Command: '{ttr}'.",
						Recommendation = (isSuspiciousPath ? $"Task '{tn}' runs from a suspicious location ({ttr}). Investigate and remove if unauthorized." : ("Verify that task '" + tn + "' is intentionally created by installed software.")),
						Reference = "https://attack.mitre.org/techniques/T1053/005/"
					});
				}
			}
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Scheduled Tasks: Summary",
				CurrentValue = $"{total} non-Microsoft tasks, {suspicious} in suspicious paths",
				ExpectedValue = "0 tasks in suspicious paths",
				Status = ((suspicious > 0) ? SecurityStatus.Warning : SecurityStatus.Info),
				Description = $"Found {total} non-Microsoft scheduled tasks (all statuses, locale-independent). {suspicious} are in suspicious locations (AppData, Temp, ProgramData non-Microsoft).",
				Recommendation = ((suspicious > 0) ? "Review the tasks flagged as Warning and remove unauthorized entries." : "Review active non-Microsoft tasks and verify they correspond to installed software."),
				Reference = "https://attack.mitre.org/techniques/T1053/005/"
			});
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Scheduled Tasks",
				CurrentValue = "Error: " + ex2.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to enumerate scheduled tasks via schtasks.exe.",
				Recommendation = "Run as Administrator and verify schtasks.exe is accessible.",
				Reference = ""
			});
		}
	}

	private void CollectStartupFolders(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		string userStartup = Environment.ExpandEnvironmentVariables("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
		string commonStartup = Environment.ExpandEnvironmentVariables("%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
		(string, string)[] startupFolders = new(string, string)[2]
		{
			(userStartup, "User Startup Folder"),
			(commonStartup, "Common Startup Folder")
		};
		bool foundAny = false;
		(string, string)[] folders = startupFolders;
		for (int i = 0; i < folders.Length; i++)
		{
			var (folderPath, label) = folders[i];
			ct.ThrowIfCancellationRequested();
			if (!Directory.Exists(folderPath))
			{
				continue;
			}
			try
			{
				string[] files = Directory.GetFiles(folderPath).Where(delegate(string f)
				{
					string ext = Path.GetExtension(f).ToLowerInvariant();
					if (ext != null)
					{
						int length = ext.Length;
						if (length != 3)
						{
							if (length == 4)
							{
								switch (ext[1])
								{
								case 'e':
									break;
								case 'b':
									goto IL_006f;
								case 'p':
									goto IL_007e;
								case 'v':
									goto IL_008d;
								case 'l':
									goto IL_009c;
								case 'c':
									goto IL_00ab;
								default:
									goto IL_00cb;
								}
								if (ext == ".exe")
								{
									goto IL_00c7;
								}
							}
						}
						else if (ext == ".js")
						{
							goto IL_00c7;
						}
					}
					goto IL_00cb;
					IL_00ab:
					if (ext == ".cmd")
					{
						goto IL_00c7;
					}
					goto IL_00cb;
					IL_009c:
					if (ext == ".lnk")
					{
						goto IL_00c7;
					}
					goto IL_00cb;
					IL_00cb:
					return false;
					IL_00c7:
					return true;
					IL_007e:
					if (ext == ".ps1")
					{
						goto IL_00c7;
					}
					goto IL_00cb;
					IL_008d:
					if (ext == ".vbs")
					{
						goto IL_00c7;
					}
					goto IL_00cb;
					IL_006f:
					if (ext == ".bat")
					{
						goto IL_00c7;
					}
					goto IL_00cb;
				}).ToArray();
				foreach (string filePath in files)
				{
					ct.ThrowIfCancellationRequested();
					foundAny = true;
					string fp = filePath;
					string lbl = label;
					TryAdd(results, delegate
					{
						FileInfo fileInfo = new FileInfo(fp);
						bool isSuspicious = ContainsSuspiciousPath(fp);
						return new SecurityResult
						{
							Category = Category,
							CheckName = "Startup Folder: " + fileInfo.Name,
							CurrentValue = $"{fp} (Modified: {fileInfo.LastWriteTime:yyyy-MM-dd HH:mm:ss})",
							ExpectedValue = "Known-good shortcut or executable",
							Status = (isSuspicious ? SecurityStatus.Warning : SecurityStatus.Info),
							Description = $"File '{fileInfo.Name}' found in {lbl} ({fp}). Last modified: {fileInfo.LastWriteTime:yyyy-MM-dd HH:mm:ss}.",
							Recommendation = (isSuspicious ? ("File '" + fileInfo.Name + "' is in a suspicious location. Verify it is legitimate startup software.") : ("Verify that '" + fileInfo.Name + "' corresponds to intentionally installed startup software.")),
							Reference = "https://attack.mitre.org/techniques/T1547/001/"
						};
					});
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex2)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Startup Folder: " + label,
					CurrentValue = "Error: " + ex2.Message,
					Status = SecurityStatus.Error,
					Description = $"Failed to enumerate {label} at '{folderPath}'.",
					Recommendation = "Verify path permissions.",
					Reference = ""
				});
			}
		}
		if (!foundAny)
		{
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Startup Folders",
				CurrentValue = "Empty",
				ExpectedValue = "No unexpected files",
				Status = SecurityStatus.OK,
				Description = "No startup items found in User or Common startup folders.",
				Recommendation = "No action required.",
				Reference = "https://attack.mitre.org/techniques/T1547/001/"
			});
		}
	}

	private void CollectBrowserHelperObjects(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		(RegistryHive, string, string)[] bhoLocations = new(RegistryHive, string, string)[2]
		{
			(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", "HKLM BHO"),
			(RegistryHive.LocalMachine, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", "HKLM BHO (WOW64)")
		};
		bool foundAny = false;
		(RegistryHive, string, string)[] locations = bhoLocations;
		for (int i = 0; i < locations.Length; i++)
		{
			var (hive, subKeyPath, label) = locations[i];
			ct.ThrowIfCancellationRequested();
			try
			{
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
				using RegistryKey bhoKey = baseKey.OpenSubKey(subKeyPath);
				if (bhoKey == null)
				{
					continue;
				}
				string[] subKeyNames = bhoKey.GetSubKeyNames();
				foreach (string clsid in subKeyNames)
				{
					ct.ThrowIfCancellationRequested();
					foundAny = true;
					string guid = clsid;
					string lbl = label;
					TryAdd(results, delegate
					{
						string dllPath = string.Empty;
						string friendlyName = string.Empty;
						try
						{
							using RegistryKey inprocKey = Registry.ClassesRoot.OpenSubKey("CLSID\\" + guid + "\\InprocServer32");
							dllPath = inprocKey?.GetValue(null)?.ToString() ?? string.Empty;
						}
						catch (Exception)
						{
						}
						try
						{
							using RegistryKey clsidKey = Registry.ClassesRoot.OpenSubKey("CLSID\\" + guid);
							friendlyName = clsidKey?.GetValue(null)?.ToString() ?? string.Empty;
						}
						catch (Exception)
						{
						}
						string display = (string.IsNullOrEmpty(friendlyName) ? guid : (friendlyName + " (" + guid + ")"));
						if (!string.IsNullOrEmpty(dllPath))
						{
							display = display + " → " + dllPath;
						}
						return new SecurityResult
						{
							Category = Category,
							CheckName = "BHO (" + lbl + "): " + (string.IsNullOrEmpty(friendlyName) ? guid : friendlyName),
							CurrentValue = display,
							ExpectedValue = "(no BHOs expected — most are malware or adware)",
							Status = SecurityStatus.Warning,
							Description = $"Browser Helper Object found in {lbl}: GUID={guid}. " + (string.IsNullOrEmpty(dllPath) ? "Could not resolve DLL path." : ("DLL: " + dllPath)),
							Recommendation = "Investigate BHO with GUID " + guid + ". BHOs are commonly used by adware and browser hijackers. Remove if not explicitly authorized.",
							Reference = "https://attack.mitre.org/techniques/T1176/"
						};
					});
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex4)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Browser Helper Objects: " + label,
					CurrentValue = "Error: " + ex4.Message,
					Status = SecurityStatus.Error,
					Description = "Failed to enumerate BHOs from " + label + ".",
					Recommendation = "Run as Administrator.",
					Reference = ""
				});
			}
		}
		if (!foundAny)
		{
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Browser Helper Objects",
				CurrentValue = "None found",
				ExpectedValue = "No BHOs",
				Status = SecurityStatus.OK,
				Description = "No Browser Helper Objects found in HKLM or WOW64 BHO registry keys.",
				Recommendation = "No action required.",
				Reference = "https://attack.mitre.org/techniques/T1176/"
			});
		}
	}

	private static SecurityStatus ClassifyRunEntryPath(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return SecurityStatus.Critical;
		}
		string lowerPath = path.ToLowerInvariant();
		if (lowerPath.Contains("\\temp\\") || lowerPath.Contains("/temp/") || lowerPath.Contains("%temp%") || lowerPath.Contains("%tmp%"))
		{
			return SecurityStatus.Critical;
		}
		if (lowerPath.Contains("\\appdata\\") || lowerPath.Contains("\\users\\") || (lowerPath.Contains("\\programdata\\") && !lowerPath.Contains("\\programdata\\microsoft\\")))
		{
			return SecurityStatus.Warning;
		}
		if (lowerPath.Contains("\\program files\\") || lowerPath.Contains("\\program files (x86)\\") || lowerPath.Contains("\\windows\\") || lowerPath.Contains("\\system32\\") || lowerPath.Contains("\\syswow64\\"))
		{
			return SecurityStatus.Info;
		}
		return SecurityStatus.Warning;
	}

	private static bool ContainsSuspiciousPath(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return false;
		}
		string lowerPath = path.ToLowerInvariant();
		if (!lowerPath.Contains("\\appdata\\") && !lowerPath.Contains("\\temp\\") && !lowerPath.Contains("%temp%") && !lowerPath.Contains("%tmp%"))
		{
			if (lowerPath.Contains("\\programdata\\"))
			{
				return !lowerPath.Contains("\\programdata\\microsoft\\");
			}
			return false;
		}
		return true;
	}

	private static int FindHeader(string[] headers, params string[] candidates)
	{
		foreach (string candidate in candidates)
		{
			for (int j = 0; j < headers.Length; j++)
			{
				if (headers[j].Trim('"').Trim().Equals(candidate, StringComparison.OrdinalIgnoreCase))
				{
					return j;
				}
			}
		}
		return -1;
	}

	private static string SafeField(string[] fields, int index)
	{
		if (index < 0 || index >= fields.Length)
		{
			return string.Empty;
		}
		return fields[index].Trim('"').Trim();
	}

	private static string[] ParseCsvLine(string line)
	{
		List<string> fields = new List<string>();
		bool inQuotes = false;
		StringBuilder currentField = new StringBuilder();
		foreach (char c in line)
		{
			switch (c)
			{
			case '"':
				inQuotes = !inQuotes;
				continue;
			case ',':
				if (!inQuotes)
				{
					fields.Add(currentField.ToString());
					currentField.Clear();
					continue;
				}
				break;
			}
			currentField.Append(c);
		}
		fields.Add(currentField.ToString());
		return fields.ToArray();
	}

	private static int WmiInt(ManagementObject obj, string prop, int def = -1)
	{
		object value = obj[prop];
		if (value == null || value is DBNull)
		{
			return def;
		}
		return Convert.ToInt32(value);
	}

	private void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			SecurityResult securityResult = factory();
			if (securityResult != null)
			{
				results.Add(securityResult);
			}
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Check failed: " + ex.Message,
				Recommendation = "Review registry and WMI access permissions.",
				Reference = ""
			});
		}
	}
}
