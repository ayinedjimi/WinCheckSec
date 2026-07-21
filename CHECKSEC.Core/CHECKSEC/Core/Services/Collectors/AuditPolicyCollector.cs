using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class AuditPolicyCollector : ISecurityCollector
{
	private static readonly Dictionary<string, string> s_guidToSubcategory = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
	{
		["{0CCE9210-69AE-11D9-BED3-505054503030}"] = "Security State Change",
		["{0CCE9211-69AE-11D9-BED3-505054503030}"] = "Security System Extension",
		["{0CCE9212-69AE-11D9-BED3-505054503030}"] = "System Integrity",
		["{0CCE9213-69AE-11D9-BED3-505054503030}"] = "IPsec Driver",
		["{0CCE9214-69AE-11D9-BED3-505054503030}"] = "Other System Events",
		["{0CCE9215-69AE-11D9-BED3-505054503030}"] = "Logon",
		["{0CCE9216-69AE-11D9-BED3-505054503030}"] = "Logoff",
		["{0CCE9217-69AE-11D9-BED3-505054503030}"] = "Account Lockout",
		["{0CCE921B-69AE-11D9-BED3-505054503030}"] = "Special Logon",
		["{0CCE921C-69AE-11D9-BED3-505054503030}"] = "Other Logon/Logoff Events",
		["{0CCE921D-69AE-11D9-BED3-505054503030}"] = "File System",
		["{0CCE921E-69AE-11D9-BED3-505054503030}"] = "Registry",
		["{0CCE921F-69AE-11D9-BED3-505054503030}"] = "Kernel Object",
		["{0CCE9220-69AE-11D9-BED3-505054503030}"] = "SAM",
		["{0CCE9224-69AE-11D9-BED3-505054503030}"] = "File Share",
		["{0CCE9227-69AE-11D9-BED3-505054503030}"] = "Other Object Access Events",
		["{0CCE9244-69AE-11D9-BED3-505054503030}"] = "Detailed File Share",
		["{0CCE9245-69AE-11D9-BED3-505054503030}"] = "Removable Storage",
		["{0CCE9228-69AE-11D9-BED3-505054503030}"] = "Sensitive Privilege Use",
		["{0CCE9229-69AE-11D9-BED3-505054503030}"] = "Non Sensitive Privilege Use",
		["{0CCE922B-69AE-11D9-BED3-505054503030}"] = "Process Creation",
		["{0CCE922C-69AE-11D9-BED3-505054503030}"] = "Process Termination",
		["{0CCE922D-69AE-11D9-BED3-505054503030}"] = "DPAPI Activity",
		["{0CCE922E-69AE-11D9-BED3-505054503030}"] = "RPC Events",
		["{0CCE9248-69AE-11D9-BED3-505054503030}"] = "Plug and Play Events",
		["{0CCE922F-69AE-11D9-BED3-505054503030}"] = "Audit Policy Change",
		["{0CCE9230-69AE-11D9-BED3-505054503030}"] = "Authentication Policy Change",
		["{0CCE9231-69AE-11D9-BED3-505054503030}"] = "Authorization Policy Change",
		["{0CCE9232-69AE-11D9-BED3-505054503030}"] = "MPSSVC Rule-Level Policy Change",
		["{0CCE9233-69AE-11D9-BED3-505054503030}"] = "Filtering Platform Policy Change",
		["{0CCE9235-69AE-11D9-BED3-505054503030}"] = "User Account Management",
		["{0CCE9236-69AE-11D9-BED3-505054503030}"] = "Computer Account Management",
		["{0CCE9237-69AE-11D9-BED3-505054503030}"] = "Security Group Management",
		["{0CCE9238-69AE-11D9-BED3-505054503030}"] = "Distribution Group Management",
		["{0CCE9239-69AE-11D9-BED3-505054503030}"] = "Application Group Management",
		["{0CCE923A-69AE-11D9-BED3-505054503030}"] = "Other Account Management Events",
		["{0CCE923B-69AE-11D9-BED3-505054503030}"] = "Directory Service Access",
		["{0CCE923C-69AE-11D9-BED3-505054503030}"] = "Directory Service Changes",
		["{0CCE923D-69AE-11D9-BED3-505054503030}"] = "Directory Service Replication",
		["{0CCE923E-69AE-11D9-BED3-505054503030}"] = "Detailed Directory Service Replication",
		["{0CCE923F-69AE-11D9-BED3-505054503030}"] = "Credential Validation",
		["{0CCE9240-69AE-11D9-BED3-505054503030}"] = "Kerberos Service Ticket Operations",
		["{0CCE9241-69AE-11D9-BED3-505054503030}"] = "Other Account Logon Events",
		["{0CCE9242-69AE-11D9-BED3-505054503030}"] = "Kerberos Authentication Service"
	};

	public string Name => "Audit Policy";

	public string Category => "Audit & Logging";

	public async Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch sw = Stopwatch.StartNew();
		try
		{
			using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
			timeoutCts.CancelAfter(TimeSpan.FromSeconds(20L));
			CancellationToken internalCt = timeoutCts.Token;
			internalCt.ThrowIfCancellationRequested();
			Dictionary<string, string> auditMap = await RunAuditPolAsync(internalCt);
			internalCt.ThrowIfCancellationRequested();
			CheckAuditSettings(report.Results, auditMap, internalCt);
			internalCt.ThrowIfCancellationRequested();
			CollectLsaAuditSettings(report.Results, internalCt);
			internalCt.ThrowIfCancellationRequested();
			CollectEventLogSizes(report.Results, internalCt);
			internalCt.ThrowIfCancellationRequested();
			CollectEventLogRetention(report.Results, internalCt);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			report.ErrorMessage = "AuditPolicyCollector fatal error: " + ex2.Message;
		}
		finally
		{
			sw.Stop();
			report.Duration = sw.Elapsed;
		}
		return await Task.FromResult(report);
	}

	private async Task<Dictionary<string, string>> RunAuditPolAsync(CancellationToken ct)
	{
		Dictionary<string, string> parsedSettings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		try
		{
			ProcessStartInfo startInfo = new ProcessStartInfo("auditpol.exe", "/get /category:* /r")
			{
				RedirectStandardOutput = true,
				UseShellExecute = false,
				CreateNoWindow = true,
				StandardOutputEncoding = GetSafeOemEncoding()
			};
			using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
			timeoutCts.CancelAfter(TimeSpan.FromSeconds(15L));
			using Process proc = Process.Start(startInfo);
			if (proc == null)
			{
				return parsedSettings;
			}
			string output;
			try
			{
				output = await proc.StandardOutput.ReadToEndAsync(timeoutCts.Token);
				await proc.WaitForExitAsync(timeoutCts.Token);
			}
			catch (OperationCanceledException)
			{
				proc.Kill();
				throw;
			}
			if (proc.ExitCode != 0)
			{
				parsedSettings["__error__"] = $"auditpol.exe exited with code {proc.ExitCode}";
				return parsedSettings;
			}
			bool isHeaderLine = true;
			string[] lines = output.Split(new char[2] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
			foreach (string line in lines)
			{
				if (isHeaderLine)
				{
					isHeaderLine = false;
					continue;
				}
				string[] fields = SplitCsvLine(line);
				if (fields.Length >= 5)
				{
					string guid = fields[3].Trim().Trim('"');
					string settingRaw = fields[4].Trim().Trim('"');
					string settingValue = ((fields.Length < 7) ? NormalizeInclusionSetting(settingRaw) : (fields[6].Trim().Trim('"') switch
					{
						"0" => "No Auditing",
						"1" => "Success",
						"2" => "Failure",
						"3" => "Success and Failure",
						_ => NormalizeInclusionSetting(settingRaw),
					}));
					string mappedName;
					string subcategory = (s_guidToSubcategory.TryGetValue(guid, out mappedName) ? mappedName : fields[2].Trim().Trim('"'));
					if (!string.IsNullOrEmpty(subcategory))
					{
						parsedSettings[subcategory] = settingValue;
					}
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex3)
		{
			parsedSettings["__error__"] = ex3.Message;
		}
		return parsedSettings;
	}

	private static string NormalizeInclusionSetting(string value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return "No Auditing";
		}
		string normalized = value.Trim();
		if (normalized.Equals("Success and Failure", StringComparison.OrdinalIgnoreCase))
		{
			return "Success and Failure";
		}
		if (normalized.Equals("Success", StringComparison.OrdinalIgnoreCase))
		{
			return "Success";
		}
		if (normalized.Equals("Failure", StringComparison.OrdinalIgnoreCase))
		{
			return "Failure";
		}
		if (normalized.Equals("No Auditing", StringComparison.OrdinalIgnoreCase))
		{
			return "No Auditing";
		}
		if (normalized.IndexOf("succ", StringComparison.OrdinalIgnoreCase) >= 0 && normalized.IndexOf("chec", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Success and Failure";
		}
		if (normalized.IndexOf("ussite", StringComparison.OrdinalIgnoreCase) >= 0 && normalized.IndexOf("chec", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Success and Failure";
		}
		if (normalized.IndexOf("succ", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Success";
		}
		if (normalized.IndexOf("ussite", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Success";
		}
		if (normalized.IndexOf("chec", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Failure";
		}
		if (normalized.IndexOf("Pas d", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "No Auditing";
		}
		if (normalized.IndexOf("Aucun", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "No Auditing";
		}
		if (normalized.IndexOf("Erfolg", StringComparison.OrdinalIgnoreCase) >= 0 && normalized.IndexOf("Fehler", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Success and Failure";
		}
		if (normalized.IndexOf("Erfolg", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Success";
		}
		if (normalized.IndexOf("Fehler", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Failure";
		}
		if (normalized.IndexOf("Keine", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "No Auditing";
		}
		if (normalized.IndexOf("Acierto", StringComparison.OrdinalIgnoreCase) >= 0 && normalized.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Success and Failure";
		}
		if (normalized.IndexOf("xito", StringComparison.OrdinalIgnoreCase) >= 0 && normalized.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Success and Failure";
		}
		if (normalized.IndexOf("Acierto", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Success";
		}
		if (normalized.IndexOf("xito", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Success";
		}
		if (normalized.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "Failure";
		}
		if (normalized.IndexOf("Sin audit", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return "No Auditing";
		}
		return normalized;
	}

	private static string[] SplitCsvLine(string line)
	{
		List<string> fields = new List<string>();
		bool inQuotes = false;
		StringBuilder currentField = new StringBuilder();
		for (int i = 0; i < line.Length; i++)
		{
			char c = line[i];
			switch (c)
			{
			case '"':
				if (i + 1 < line.Length && line[i + 1] == '"' && inQuotes)
				{
					currentField.Append('"');
					i++;
				}
				else
				{
					inQuotes = !inQuotes;
				}
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

	private void CheckAuditSettings(List<SecurityResult> results, Dictionary<string, string> auditMap, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		if (auditMap.ContainsKey("__error__"))
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Audit Policy Collection",
				CurrentValue = "Error: " + auditMap["__error__"],
				Status = SecurityStatus.Error,
				Description = "auditpol.exe execution failed. Cannot determine audit policy settings.",
				Recommendation = "Ensure auditpol.exe is accessible and run CHECKSEC as Administrator.",
				Reference = ""
			});
			return;
		}
		if (auditMap.Count == 0)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Audit Policy Collection",
				CurrentValue = "No data returned from auditpol",
				Status = SecurityStatus.Error,
				Description = "auditpol returned no parseable output.",
				Recommendation = "Run 'auditpol /get /category:*' manually to verify output.",
				Reference = ""
			});
			return;
		}
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "Audit Policy Collection",
			CurrentValue = $"{auditMap.Count} subcategories parsed",
			Status = SecurityStatus.OK,
			Description = "Successfully retrieved and parsed audit policy settings from auditpol.exe.",
			Recommendation = "",
			Reference = ""
		});
		ct.ThrowIfCancellationRequested();
		(string, string, string, string)[] checks = new(string, string, string, string)[27]
		{
			("Credential Validation", "Success and Failure", "Account Logon", "Credential Validation auditing logs authentication attempts. Success+Failure is needed to detect password spraying, brute-force, and failed logon patterns."),
			("Kerberos Authentication Service", "Success and Failure", "Account Logon", "Kerberos authentication service auditing detects Kerberos-based attacks such as AS-REP roasting and Kerberoasting."),
			("Kerberos Service Ticket Operations", "Success and Failure", "Account Logon", "Kerberos service ticket auditing helps detect Pass-the-Ticket and Golden/Silver Ticket attacks."),
			("Security Group Management", "Success", "Account Management", "Security Group Management auditing records changes to security groups, detecting privilege escalation via group membership changes."),
			("User Account Management", "Success and Failure", "Account Management", "User Account Management auditing tracks account creation, deletion, and modification — critical for detecting unauthorized account changes."),
			("Computer Account Management", "Success", "Account Management", "Tracks computer account changes in Active Directory."),
			("Distribution Group Management", "Success", "Account Management", "Tracks changes to distribution groups."),
			("Application Group Management", "Success", "Account Management", "Tracks application group changes."),
			("Process Creation", "Success", "Detailed Tracking", "Process Creation auditing (Event ID 4688) records every new process with command-line arguments. Essential for detecting malware execution, living-off-the-land attacks, and lateral movement."),
			("Process Termination", "Success", "Detailed Tracking", "Process Termination auditing helps correlate process lifecycle for forensic analysis."),
			("Logon", "Success and Failure", "Logon/Logoff", "Logon auditing (Event IDs 4624/4625) is fundamental for detecting unauthorized access, failed logon attempts, and lateral movement via interactive and network logons."),
			("Logoff", "Success", "Logon/Logoff", "Logoff auditing records session end times for activity correlation."),
			("Account Lockout", "Failure", "Logon/Logoff", "Account Lockout auditing detects brute-force attacks that cause account lockouts."),
			("Special Logon", "Success", "Logon/Logoff", "Special Logon auditing detects logons with administrative or special privileges (Event ID 4964)."),
			("Other Logon/Logoff Events", "Success and Failure", "Logon/Logoff", "Covers Remote Desktop, terminal server, and other session types."),
			("Audit Policy Change", "Success", "Policy Change", "Audit Policy Change auditing detects modifications to the audit policy itself, which attackers often disable to cover tracks."),
			("Authentication Policy Change", "Success", "Policy Change", "Detects changes to Kerberos, trust, and logon policies."),
			("Authorization Policy Change", "Success", "Policy Change", "Detects changes to user rights assignments."),
			("MPSSVC Rule-Level Policy Change", "Success and Failure", "Policy Change", "Tracks Windows Firewall rule changes."),
			("Sensitive Privilege Use", "Failure", "Privilege Use", "Sensitive Privilege Use records use of sensitive privileges like SeDebugPrivilege, SeTcbPrivilege. Failures detect privilege abuse attempts."),
			("Security State Change", "Success", "System", "Security State Change auditing records system security state changes (startup, shutdown, authentication changes)."),
			("Security System Extension", "Success", "System", "Security System Extension auditing detects loading of authentication packages, LSA secrets, and security DLLs — often used by rootkits."),
			("System Integrity", "Success and Failure", "System", "System Integrity auditing detects violations of the audit subsystem and tampering with audit logs."),
			("IPsec Driver", "Success and Failure", "System", "IPsec driver events for network security monitoring."),
			("Other System Events", "Success and Failure", "System", "Covers Firewall service startup/shutdown events."),
			("Removable Storage", "Success and Failure", "Object Access", "Removable Storage auditing detects access to USB drives and removable media, important for data exfiltration detection."),
			("SAM", "Failure", "Object Access", "SAM object access failure auditing detects unauthorized attempts to read the SAM database (credential theft).")
		};
		for (int i = 0; i < checks.Length; i++)
		{
			(string, string, string, string) check = checks[i];
			string subName = check.Item1;
			string expectedName = check.Item2;
			string categoryName = check.Item3;
			string descText = check.Item4;
			ct.ThrowIfCancellationRequested();
			string sub = subName;
			string expected = expectedName;
			string auditCat = categoryName;
			string desc = descText;
			TryAdd(results, delegate
			{
				string currentSetting = "No Auditing";
				string mappedSetting;
				bool found = auditMap.TryGetValue(sub, out mappedSetting);
				if (found && mappedSetting != null)
				{
					currentSetting = mappedSetting;
				}
				// Correctif M1 : "Success and Failure" satisfait et dépasse une exigence "Success" ou "Failure".
				// On ne réclame plus l'égalité stricte : une valeur couvrant tous les composants attendus est conforme.
				bool matchesExpected = currentSetting.Equals(expected, StringComparison.OrdinalIgnoreCase) || (currentSetting.Equals("Success and Failure", StringComparison.OrdinalIgnoreCase) && (expected.Equals("Success", StringComparison.OrdinalIgnoreCase) || expected.Equals("Failure", StringComparison.OrdinalIgnoreCase)));
				bool partialMatch = !matchesExpected && expected == "Success and Failure" && (currentSetting == "Success" || currentSetting == "Failure");
				SecurityStatus status = ((!matchesExpected) ? (partialMatch ? SecurityStatus.Warning : ((found && !(currentSetting == "No Auditing")) ? SecurityStatus.Warning : SecurityStatus.Critical)) : SecurityStatus.OK);
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Audit: " + auditCat + " > " + sub,
					CurrentValue = currentSetting,
					ExpectedValue = expected,
					Status = status,
					Description = desc,
					Recommendation = (matchesExpected ? ("'" + sub + "' auditing is correctly configured.") : ($"Set '{sub}' to '{expected}'. Run: auditpol /set /subcategory:\"{sub}\" " + ((expected == "Success and Failure") ? "/success:enable /failure:enable" : ((expected == "Success") ? "/success:enable" : "/failure:enable")))),
					Reference = "https://docs.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations"
				};
			});
		}
	}

	private void CollectLsaAuditSettings(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object rawValue = lsaKey?.GetValue("AuditBaseObjects");
			int auditBaseObjects = ((rawValue != null) ? Convert.ToInt32(rawValue) : 0);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA: AuditBaseObjects",
				CurrentValue = ((auditBaseObjects == 1) ? "Enabled (1)" : "Disabled (0)"),
				ExpectedValue = "0 (Disabled, default)",
				Status = SecurityStatus.Info,
				Description = "AuditBaseObjects enables auditing of base system objects. Generally not needed unless troubleshooting; can generate excessive events.",
				Recommendation = "Keep at default (0) unless specifically required.",
				Reference = ""
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object rawValue = lsaKey?.GetValue("CrashOnAuditFail");
			int crashOnAuditFail = ((rawValue != null) ? Convert.ToInt32(rawValue) : 0);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA: CrashOnAuditFail",
				CurrentValue = crashOnAuditFail switch
				{
					1 => "Enabled (1) - Crash on audit failure",
					0 => "Disabled (0)",
					_ => $"{crashOnAuditFail}",
				},
				ExpectedValue = "0 (Disabled) for workstations; 1 for high-security servers",
				Status = SecurityStatus.Info,
				Description = "CrashOnAuditFail causes the system to halt (BSOD) if the security audit log cannot be written. Prevents security events from being lost on high-security systems.",
				Recommendation = "Enable on high-security servers where audit log integrity is critical. For workstations, leave disabled.",
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/auditing/basic-audit-system-events"
			};
		});
	}

	private void CollectEventLogSizes(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		(string, string, int, string)[] logDefinitions = new(string, string, int, string)[3]
		{
			("Application", "SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application", 32768, "Application event log. Should hold enough events for forensic investigation."),
			("Security", "SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security", 196608, "Security event log. Must be large enough to retain audit events. 196608 KB (192 MB) is Microsoft's recommended minimum."),
			("System", "SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System", 32768, "System event log. Should retain system-level events for troubleshooting and forensics.")
		};
		for (int i = 0; i < logDefinitions.Length; i++)
		{
			(string, string, int, string) logDef = logDefinitions[i];
			string logName = logDef.Item1;
			string regPath = logDef.Item2;
			int minSizeKb = logDef.Item3;
			string descText = logDef.Item4;
			ct.ThrowIfCancellationRequested();
			string ln = logName;
			string rp = regPath;
			int minKb = minSizeKb;
			string description = descText;
			TryAdd(results, delegate
			{
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey policyKey = baseKey.OpenSubKey(rp);
				object maxSizeValue = policyKey?.GetValue("MaxSize");
				int sizeKb = ((maxSizeValue != null) ? Convert.ToInt32(maxSizeValue) : (-1));
				bool configured = sizeKb > 0;
				bool adequate = configured && sizeKb >= minKb;
				if (!configured)
				{
					try
					{
						ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NTEventlogFile WHERE LogfileName='" + ln + "'");
						try
						{
							using ManagementObjectCollection logFiles = searcher.Get();
							foreach (ManagementObject logFile in logFiles)
							{
								ManagementObject mo = logFile;
								try
								{
									object maxFileSize = logFile["MaxFileSize"];
									if (maxFileSize != null)
									{
										sizeKb = (int)(Convert.ToInt64(maxFileSize) / 1024);
										configured = true;
										adequate = sizeKb >= minKb;
									}
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
					catch (ManagementException)
					{
					}
					catch (Exception)
					{
					}
				}
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Event Log Size: " + ln,
					CurrentValue = (configured ? $"{sizeKb} KB ({sizeKb / 1024} MB)" : "Not configured via policy"),
					ExpectedValue = $">= {minKb} KB ({minKb / 1024} MB)",
					Status = ((!adequate) ? (configured ? SecurityStatus.Warning : SecurityStatus.Warning) : SecurityStatus.OK),
					Description = description,
					Recommendation = (adequate ? (ln + " log size is adequate.") : $"Set {ln} log MaxSize to at least {minKb} KB via Group Policy: Computer Configuration > Windows Settings > Security Settings > Event Log."),
					Reference = "https://docs.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations"
				};
			});
		}
	}

	private void CollectEventLogRetention(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		string[] logNames = new string[3] { "Application", "Security", "System" };
		foreach (string logName in logNames)
		{
			ct.ThrowIfCancellationRequested();
			string ln = logName;
			TryAdd(results, delegate
			{
				string overwritePolicy = "Unknown";
				try
				{
					ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NTEventlogFile WHERE LogfileName='" + ln + "'");
					try
					{
						using ManagementObjectCollection logFiles = searcher.Get();
						foreach (ManagementObject logFile in logFiles)
						{
							ManagementObject mo = logFile;
							try
							{
								overwritePolicy = logFile["OverwritePolicy"]?.ToString() ?? "Unknown";
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
				catch (ManagementException)
				{
					overwritePolicy = "WMI unavailable";
				}
				catch (UnauthorizedAccessException)
				{
					overwritePolicy = "Access denied";
				}
				catch (Exception ex3)
				{
					overwritePolicy = "Error: " + ex3.Message;
				}
				bool isWhenNeeded = overwritePolicy.Equals("WhenNeeded", StringComparison.OrdinalIgnoreCase);
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Event Log Retention: " + ln,
					CurrentValue = overwritePolicy,
					ExpectedValue = "WhenNeeded (overwrite as needed, rely on log size)",
					Status = ((!isWhenNeeded) ? SecurityStatus.Info : SecurityStatus.OK),
					Description = "Retention policy for " + ln + " event log. 'WhenNeeded' relies on log size limit. 'Never' may stop logging when full. Ensure log size is large enough.",
					Recommendation = (isWhenNeeded ? (ln + " log uses overwrite-as-needed policy.") : ("Set " + ln + " log retention to 'Overwrite as needed' and ensure adequate log size.")),
					Reference = ""
				};
			});
		}
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object rawValue = lsaKey?.GetValue("SCENoApplyLegacyAuditPolicy");
			int scenoApply = ((rawValue == null) ? 1 : Convert.ToInt32(rawValue));
			bool subcategoryOverride = scenoApply == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Advanced Audit: Subcategory Override",
				CurrentValue = ((scenoApply == 1) ? "Enabled (1) - Subcategory settings take precedence" : "Disabled (0)"),
				ExpectedValue = "1 (Subcategory settings override category settings)",
				Status = ((!subcategoryOverride) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "SCENoApplyLegacyAuditPolicy ensures advanced audit policy subcategory settings override legacy category settings, providing more granular audit control.",
				Recommendation = (subcategoryOverride ? "Advanced audit subcategory override is active." : "Set SCENoApplyLegacyAuditPolicy = 1 to enable precise subcategory audit control."),
				Reference = "https://docs.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations"
			};
		});
	}

	private static void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			results.Add(factory());
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = "Audit & Logging",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Check failed: " + ex.Message,
				Recommendation = "Review registry and WMI access.",
				Reference = ""
			});
		}
	}

	private static Encoding GetSafeOemEncoding()
	{
		try
		{
			return Encoding.GetEncoding(CultureInfo.InstalledUICulture.TextInfo.OEMCodePage);
		}
		catch
		{
			return Encoding.UTF8;
		}
	}
}
