using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Core.Services.Collectors;

public class ProcessDriverCollector : ISecurityCollector
{
	private static readonly HashSet<string> KnownVulnerableDrivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		"AsrDrv101.sys", "AsrDrv102.sys", "AsrDrv103.sys", "gdrv.sys", "MsIo64.sys", "MsIo32.sys", "NalDrv.sys", "rtcore64.sys", "dbutil_2_3.sys", "TrUeSight.sys",
		"procexp152.sys", "WinRing0.sys", "WinRing0x64.sys", "cpuz141_x64.sys", "cpuz143_x64.sys", "HWiNFO64A.sys", "kprocesshacker.sys", "openlibsys.sys", "NCHGBIOS2x64.sys", "ene.sys",
		"nvflash.sys", "amifldrv64.sys", "BS_Flash64.sys", "sandra.sys"
	};

	private static readonly HashSet<string> KnownSystemProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe", "taskhost.exe", "taskhostw.exe", "explorer.exe" };

	private static readonly HashSet<string> NullPathWhitelistedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		"System Idle Process", "System", "Secure System", "Registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "LsaIso.exe",
		"MsMpEng.exe", "MpDefenderCoreService.exe", "SecurityHealthService.exe", "svchost.exe", "vmmemWSL", "fontdrvhost.exe", "dwm.exe"
	};

	public string Name => "Processus & Drivers";

	public string Category => "Intégrité Système";

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
			(int, int) tuple = CollectProcesses(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			(int, int) tuple2 = CollectServices(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			var (totalDrv, vulnDrv, _) = CollectDrivers(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			AddSummary(collectorReport.Results, tuple.Item1, tuple.Item2, totalDrv, vulnDrv, tuple2.Item1, tuple2.Item2);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "ProcessDriverCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private (int total, int suspicious) CollectProcesses(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		int totalProcesses = 0;
		int suspiciousCount = 0;
		try
		{
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT Name, ExecutablePath, CommandLine, ProcessId, ParentProcessId, CreationDate FROM Win32_Process");
			try
			{
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				List<(int score, string name, string execPath, string cmdLine, string pid, string ppid, string creationDate)> interesting = new List<(int, string, string, string, string, string, string)>();
				foreach (ManagementObject processObject in managementObjectCollection)
				{
					ManagementObject disposableWmiObject = processObject;
					try
					{
						ct.ThrowIfCancellationRequested();
						totalProcesses++;
						string processName = processObject["Name"]?.ToString() ?? string.Empty;
						string executablePath = processObject["ExecutablePath"]?.ToString() ?? string.Empty;
						int score = ScoreProcess(processName, executablePath);
						if (score > 0)
						{
							interesting.Add((score, processName, executablePath, processObject["CommandLine"]?.ToString() ?? string.Empty, processObject["ProcessId"]?.ToString() ?? "?", processObject["ParentProcessId"]?.ToString() ?? "?", processObject["CreationDate"]?.ToString() ?? string.Empty));
						}
					}
					finally
					{
						((IDisposable)disposableWmiObject)?.Dispose();
					}
				}
				foreach (var topProcess in interesting.OrderByDescending<(int, string, string, string, string, string, string), int>(((int score, string name, string execPath, string cmdLine, string pid, string ppid, string creationDate) t) => t.score).Take(50).ToList())
				{
					int topScore = topProcess.Item1;
					string topName = topProcess.Item2;
					string topPath = topProcess.Item3;
					string topCmd = topProcess.Item4;
					string topPid = topProcess.Item5;
					string topPpid = topProcess.Item6;
					string topDate = topProcess.Item7;
					ct.ThrowIfCancellationRequested();
					int pScore = topScore;
					string capName = topName;
					string capPath = topPath;
					string capCmd = topCmd;
					string capPid = topPid;
					string capPpid = topPpid;
					string capDate = topDate;
					TryAdd(results, delegate
					{
						(SecurityStatus status, string reason) classification = ClassifyProcess(capName, capPath, pScore);
						SecurityStatus status = classification.status;
						string reason = classification.reason;
						string displayValue = (string.IsNullOrEmpty(capPath) ? "(no path — possible hollow process)" : capPath);
						if (!string.IsNullOrEmpty(capCmd) && capCmd.Length <= 300)
						{
							displayValue = displayValue + " | CMD: " + capCmd;
						}
						return new SecurityResult
						{
							Category = Category,
							CheckName = $"Process: {capName} (PID {capPid})",
							CurrentValue = displayValue,
							ExpectedValue = (IsKnownSystemProcess(capName) ? "C:\\Windows\\System32\\ or SysWOW64\\" : "Signed executable under Program Files or Windows"),
							Status = status,
							Description = $"Process '{capName}' PID={capPid} PPID={capPpid} Started={capDate}. {reason}",
							Recommendation = status switch
							{
								SecurityStatus.Warning => "Process '" + capName + "' runs from a suspicious location. Verify it is a legitimate application.", 
								SecurityStatus.Critical => $"Process '{capName}' is masquerading — it runs from '{capPath}' instead of System32. Investigate immediately.", 
								_ => "Review process if unexpected.", 
							},
							Reference = "https://attack.mitre.org/techniques/T1036/005/"
						};
					});
					SecurityStatus topStatus = ClassifyProcess(topName, topPath, topScore).status;
					if (topStatus == SecurityStatus.Critical || topStatus == SecurityStatus.Warning)
					{
						suspiciousCount++;
					}
				}
				foreach (var emptyPathProcess in interesting.Where<(int, string, string, string, string, string, string)>(((int score, string name, string execPath, string cmdLine, string pid, string ppid, string creationDate) t) => string.IsNullOrEmpty(t.execPath)).Take(10))
				{
					_ = emptyPathProcess;
					ct.ThrowIfCancellationRequested();
				}
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Processes: Enumeration Coverage",
					CurrentValue = $"{totalProcesses} total, showing top {Math.Min(50, interesting.Count)} non-standard processes",
					ExpectedValue = "All system processes running from expected paths",
					Status = SecurityStatus.Info,
					Description = $"Total processes running: {totalProcesses}. Showing {Math.Min(50, interesting.Count)} processes with non-standard or suspicious paths.",
					Recommendation = "Review any processes flagged as Warning or Critical.",
					Reference = ""
				});
			}
			finally
			{
				((IDisposable)managementObjectSearcher)?.Dispose();
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Process Enumeration",
				CurrentValue = "Error: " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to enumerate running processes via WMI Win32_Process.",
				Recommendation = "Run as Administrator and verify WMI is functioning.",
				Reference = ""
			});
		}
		return (total: totalProcesses, suspicious: suspiciousCount);
	}

	private static int ScoreProcess(string name, string execPath)
	{
		int score = 0;
		if (string.IsNullOrEmpty(execPath))
		{
			if (NullPathWhitelistedProcesses.Contains(name))
			{
				return 0;
			}
			score += 50;
		}
		string lowerPath = execPath.ToLowerInvariant();
		if (IsKnownSystemProcess(name))
		{
			if (!string.IsNullOrEmpty(execPath) && !lowerPath.Contains("\\system32\\") && !lowerPath.Contains("\\syswow64\\"))
			{
				score += 100;
			}
			else if (!string.IsNullOrEmpty(execPath))
			{
				return 0;
			}
		}
		if (lowerPath.Contains("\\appdata\\"))
		{
			score += 30;
		}
		if (lowerPath.Contains("\\temp\\"))
		{
			score += 40;
		}
		if (lowerPath.Contains("%temp%"))
		{
			score += 40;
		}
		if (lowerPath.Contains("\\programdata\\") && !lowerPath.Contains("\\programdata\\microsoft\\"))
		{
			score += 20;
		}
		if (lowerPath.Contains("\\windows\\") || lowerPath.Contains("\\program files\\") || lowerPath.Contains("\\program files (x86)\\"))
		{
			return 0;
		}
		if (score == 0 && !string.IsNullOrEmpty(execPath))
		{
			score = 1;
		}
		return score;
	}

	private static bool IsKnownSystemProcess(string name)
	{
		return KnownSystemProcesses.Contains(name);
	}

	private static (SecurityStatus status, string reason) ClassifyProcess(string name, string execPath, int score)
	{
		if (string.IsNullOrEmpty(execPath))
		{
			return (status: SecurityStatus.Warning, reason: "ExecutablePath is null/empty — possible process hollowing or very early system process.");
		}
		string lowerPath = execPath.ToLowerInvariant();
		if (IsKnownSystemProcess(name) && !lowerPath.Contains("\\system32\\") && !lowerPath.Contains("\\syswow64\\"))
		{
			return (status: SecurityStatus.Critical, reason: "Known system process '" + name + "' is NOT running from System32/SysWOW64. This strongly indicates process masquerading.");
		}
		if (lowerPath.Contains("\\temp\\") || lowerPath.Contains("%temp%"))
		{
			return (status: SecurityStatus.Warning, reason: "Process runs from a %TEMP% or temporary directory.");
		}
		if (lowerPath.Contains("\\appdata\\"))
		{
			return (status: SecurityStatus.Warning, reason: "Process runs from AppData directory.");
		}
		if (lowerPath.Contains("\\programdata\\") && !lowerPath.Contains("\\programdata\\microsoft\\"))
		{
			return (status: SecurityStatus.Warning, reason: "Process runs from ProgramData (non-Microsoft subdirectory).");
		}
		return (status: SecurityStatus.Info, reason: "Process path is non-standard but not immediately critical.");
	}

	private (int total, int suspicious) CollectServices(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		int totalServices = 0;
		int runningServices = 0;
		int suspiciousServices = 0;
		try
		{
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT Name, DisplayName, PathName, StartMode, State, StartName FROM Win32_Service");
			try
			{
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				foreach (ManagementObject item in managementObjectCollection)
				{
					ManagementObject disposableWmiObject = item;
					try
					{
						ct.ThrowIfCancellationRequested();
						totalServices++;
						string name = item["Name"]?.ToString() ?? string.Empty;
						string displayName = item["DisplayName"]?.ToString() ?? string.Empty;
						string pathName = item["PathName"]?.ToString() ?? string.Empty;
						string startMode = item["StartMode"]?.ToString() ?? string.Empty;
						string state = item["State"]?.ToString() ?? string.Empty;
						string startName = item["StartName"]?.ToString() ?? string.Empty;
						if (state.Equals("Running", StringComparison.OrdinalIgnoreCase))
						{
							runningServices++;
						}
						var (securityStatus, reason) = ClassifyService(pathName, state, startName);
						if (securityStatus == SecurityStatus.Critical || securityStatus == SecurityStatus.Warning)
						{
							int prevCount = suspiciousServices;
							suspiciousServices = prevCount + 1;
							string capName = name;
							string capDisplay = displayName;
							string capPath = pathName;
							string capStartMode = startMode;
							string capState = state;
							string capStartName = startName;
							string capReason = reason;
							SecurityStatus capStatus = securityStatus;
							TryAdd(results, () => new SecurityResult
							{
								Category = Category,
								CheckName = "Service: " + capName,
								CurrentValue = $"State={capState}, StartMode={capStartMode}, Account={capStartName}, Path={capPath}",
								ExpectedValue = "Path under C:\\Windows or C:\\Program Files",
								Status = capStatus,
								Description = $"Service '{capDisplay}' ({capName}): {capReason}",
								Recommendation = ((capStatus == SecurityStatus.Critical) ? ("Service '" + capName + "' runs from a critical suspicious location. Stop and investigate immediately.") : ("Verify that service '" + capName + "' is a legitimate installed service.")),
								Reference = "https://attack.mitre.org/techniques/T1543/003/"
							});
						}
					}
					finally
					{
						((IDisposable)disposableWmiObject)?.Dispose();
					}
				}
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Services: Summary",
					CurrentValue = $"Total={totalServices}, Running={runningServices}, Suspicious={suspiciousServices}",
					ExpectedValue = "0 suspicious services",
					Status = ((suspiciousServices > 0) ? SecurityStatus.Warning : SecurityStatus.Info),
					Description = $"Windows service enumeration: {totalServices} total, {runningServices} running, {suspiciousServices} with suspicious paths or configurations.",
					Recommendation = ((suspiciousServices > 0) ? "Investigate services flagged as Warning or Critical. Use 'sc query' and 'sigcheck' to verify service binaries." : "No suspicious services detected."),
					Reference = "https://attack.mitre.org/techniques/T1543/003/"
				});
			}
			finally
			{
				((IDisposable)managementObjectSearcher)?.Dispose();
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Service Enumeration",
				CurrentValue = "Error: " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to enumerate services via WMI Win32_Service.",
				Recommendation = "Run as Administrator and verify WMI is functioning.",
				Reference = ""
			});
			totalServices = 0;
		}
		return (total: totalServices, suspicious: suspiciousServices);
	}

	private static (SecurityStatus status, string reason) ClassifyService(string pathName, string state, string startName)
	{
		if (string.IsNullOrEmpty(pathName))
		{
			return (status: SecurityStatus.Warning, reason: "Service has no executable path configured.");
		}
		string binaryPath = pathName;
		int dashKIndex = pathName.IndexOf("-k ", StringComparison.OrdinalIgnoreCase);
		if (dashKIndex > 0)
		{
			binaryPath = pathName.Substring(0, dashKIndex).Trim().Trim('"');
		}
		string lowerPath = binaryPath.ToLowerInvariant();
		bool isRunning = state.Equals("Running", StringComparison.OrdinalIgnoreCase);
		bool isSystemAccount = startName.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase) || startName.Equals("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase);
		if (isRunning && (lowerPath.Contains("\\temp\\") || lowerPath.Contains("%temp%")))
		{
			return (status: SecurityStatus.Critical, reason: "Service is RUNNING from %TEMP%: '" + pathName + "'. This is a strong malware indicator.");
		}
		if (isRunning && lowerPath.Contains("\\appdata\\"))
		{
			return (status: SecurityStatus.Critical, reason: "Service is RUNNING from AppData: '" + pathName + "'. Services should not run from user profile directories.");
		}
		bool isStandardPath = lowerPath.Contains("c:\\windows\\") || lowerPath.Contains("c:\\program files\\") || lowerPath.Contains("c:\\program files (x86)\\");
		if (!isStandardPath && isSystemAccount)
		{
			return (status: SecurityStatus.Warning, reason: "SYSTEM-account service runs from non-standard path: '" + pathName + "'.");
		}
		if (!isStandardPath)
		{
			return (status: SecurityStatus.Warning, reason: "Service runs from a non-standard path: '" + pathName + "'. Verify it is from installed software.");
		}
		return (status: SecurityStatus.OK, reason: "Path appears standard.");
	}

	private (int totalDrivers, int vulnDrivers, int suspDrivers) CollectDrivers(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		int totalDrivers = 0;
		int vulnDrivers = 0;
		int suspDrivers = 0;
		try
		{
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT Name, DisplayName, PathName, Started, StartMode, Status FROM Win32_SystemDriver");
			try
			{
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				foreach (ManagementObject item in managementObjectCollection)
				{
					ManagementObject disposableWmiObject = item;
					try
					{
						ct.ThrowIfCancellationRequested();
						totalDrivers++;
						string name = item["Name"]?.ToString() ?? string.Empty;
						string displayName = item["DisplayName"]?.ToString() ?? string.Empty;
						string pathName = item["PathName"]?.ToString() ?? string.Empty;
						bool started = WmiBool(item, "Started");
						if (item["StartMode"]?.ToString() == null)
						{
							_ = string.Empty;
						}
						if (item["Status"]?.ToString() == null)
						{
							_ = string.Empty;
						}
						string fileName = Path.GetFileName(pathName);
						if (KnownVulnerableDrivers.Contains(fileName) || KnownVulnerableDrivers.Contains(name + ".sys"))
						{
							int prevVuln = vulnDrivers;
							vulnDrivers = prevVuln + 1;
							string capDisplay = displayName;
							string capPath = pathName;
							bool capStarted = started;
							string capFileName = fileName;
							TryAdd(results, () => new SecurityResult
							{
								Category = Category,
								CheckName = "Vulnerable Driver: " + capFileName,
								CurrentValue = $"Path={capPath}, Started={capStarted}",
								ExpectedValue = "Driver should not be loaded",
								Status = SecurityStatus.Critical,
								Description = $"Known vulnerable driver '{capFileName}' ('{capDisplay}') is present on this system. " + "This driver has known exploitable vulnerabilities and is frequently abused by ransomware and APTs to escalate privileges and disable security tools (Bring Your Own Vulnerable Driver - BYOVD).",
								Recommendation = "Uninstall the software that installs '" + capFileName + "', or block it via Windows Defender Application Control (WDAC). See the LoLDrivers project for details: https://www.loldrivers.io/",
								Reference = "https://www.loldrivers.io/"
							});
							continue;
						}
						var (securityStatus, reason) = ClassifyDriver(pathName, started);
						if (securityStatus == SecurityStatus.Critical || securityStatus == SecurityStatus.Warning)
						{
							int prevSusp = suspDrivers;
							suspDrivers = prevSusp + 1;
							string capName2 = name;
							string capDisplay2 = displayName;
							string capPath2 = pathName;
							bool capStarted2 = started;
							string capReason2 = reason;
							SecurityStatus capStatus2 = securityStatus;
							TryAdd(results, () => new SecurityResult
							{
								Category = Category,
								CheckName = "Driver (Suspicious Path): " + capName2,
								CurrentValue = $"Path={capPath2}, Started={capStarted2}",
								ExpectedValue = "C:\\Windows\\System32\\drivers\\ or SysWOW64\\",
								Status = capStatus2,
								Description = $"Kernel driver '{capName2}' ('{capDisplay2}'): {capReason2}",
								Recommendation = ((capStatus2 == SecurityStatus.Critical) ? ("Driver '" + capName2 + "' is loaded from a suspicious path. Investigate immediately — a malicious driver gives full kernel-level access.") : ("Verify that driver '" + capName2 + "' is from legitimate installed software.")),
								Reference = "https://attack.mitre.org/techniques/T1014/"
							});
						}
					}
					finally
					{
						((IDisposable)disposableWmiObject)?.Dispose();
					}
				}
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Drivers: Summary",
					CurrentValue = $"Total={totalDrivers}, Vulnerable={vulnDrivers}, Suspicious path={suspDrivers}",
					ExpectedValue = "0 vulnerable or suspicious drivers",
					Status = ((vulnDrivers > 0) ? SecurityStatus.Critical : ((suspDrivers > 0) ? SecurityStatus.Warning : SecurityStatus.OK)),
					Description = $"Kernel driver enumeration: {totalDrivers} total. {vulnDrivers} match known vulnerable driver signatures (LoLDrivers). {suspDrivers} have suspicious load paths.",
					Recommendation = ((vulnDrivers > 0) ? "Remove or block all known vulnerable drivers immediately. They are a primary attack vector for privilege escalation." : ((suspDrivers > 0) ? "Investigate drivers with suspicious paths." : "No known vulnerable or suspicious drivers found.")),
					Reference = "https://www.loldrivers.io/"
				});
			}
			finally
			{
				((IDisposable)managementObjectSearcher)?.Dispose();
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Driver Enumeration",
				CurrentValue = "Error: " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to enumerate kernel drivers via WMI Win32_SystemDriver.",
				Recommendation = "Run as Administrator and verify WMI is functioning.",
				Reference = ""
			});
		}
		return (totalDrivers: totalDrivers, vulnDrivers: vulnDrivers, suspDrivers: suspDrivers);
	}

	private static (SecurityStatus status, string reason) ClassifyDriver(string pathName, bool started)
	{
		if (string.IsNullOrEmpty(pathName))
		{
			return (status: SecurityStatus.Warning, reason: "Driver has no path configured.");
		}
		string lowerPath = pathName.ToLowerInvariant();
		bool isStandardDriverPath = lowerPath.Contains("\\system32\\drivers\\") || lowerPath.Contains("\\system32\\driverstore\\filerepository\\") || lowerPath.Contains("\\syswow64\\") || lowerPath.Contains("\\windows\\inf\\");
		bool isWindowsPath = lowerPath.StartsWith("c:\\windows\\") || lowerPath.StartsWith("\\systemroot\\") || lowerPath.StartsWith("system32\\");
		bool isDefenderPath = lowerPath.Contains("\\programdata\\microsoft\\windows defender\\");
		if (!isStandardDriverPath && !isWindowsPath && !isDefenderPath)
		{
			if (started && (lowerPath.Contains("\\temp\\") || lowerPath.Contains("\\appdata\\") || lowerPath.Contains("%temp%")))
			{
				return (status: SecurityStatus.Critical, reason: "Driver is LOADED from a user/temp directory: '" + pathName + "'. This is a critical malware indicator.");
			}
			return (status: SecurityStatus.Warning, reason: "Driver path is outside System32\\drivers: '" + pathName + "'. Verify it is from legitimate software.");
		}
		return (status: SecurityStatus.OK, reason: "Path is within expected driver directories.");
	}

	private void AddSummary(List<SecurityResult> results, int totalProc, int suspProc, int totalDrv, int vulnDrv, int totalSvc, int suspSvc)
	{
		TryAdd(results, delegate
		{
			SecurityStatus securityStatus = SecurityStatus.OK;
			if (vulnDrv > 0)
			{
				securityStatus = SecurityStatus.Critical;
			}
			else if (suspProc > 0 || suspSvc > 0)
			{
				securityStatus = SecurityStatus.Warning;
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "System Integrity: Overall Summary",
				CurrentValue = $"Processes: {totalProc} total / {suspProc} suspicious | Drivers: {totalDrv} total / {vulnDrv} vulnerable | Services: {totalSvc} total / {suspSvc} suspicious",
				ExpectedValue = "0 suspicious processes, 0 vulnerable drivers, 0 suspicious services",
				Status = securityStatus,
				Description = "Aggregate summary of process, driver, and service integrity checks. " + $"Suspicious processes: {suspProc}. Vulnerable/suspicious drivers: {vulnDrv}. Suspicious services: {suspSvc}.",
				Recommendation = securityStatus switch
				{
					SecurityStatus.Warning => "Review all items flagged as Warning. Investigate suspicious processes and services.", 
					SecurityStatus.Critical => "CRITICAL: Known vulnerable drivers detected. These must be addressed immediately as they allow full kernel privilege escalation.", 
					_ => "No critical or warning issues detected in process and driver integrity.", 
				},
				Reference = "https://attack.mitre.org/techniques/T1014/"
			};
		});
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

	private static bool WmiBool(ManagementObject obj, string prop, bool def = false)
	{
		object value = obj[prop];
		if (value == null || value is DBNull)
		{
			return def;
		}
		return Convert.ToBoolean(value);
	}

	private void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			SecurityResult result = factory();
			if (result != null)
			{
				results.Add(result);
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
				Recommendation = "Review WMI access and run as Administrator.",
				Reference = ""
			});
		}
	}
}
