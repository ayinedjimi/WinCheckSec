using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class FirewallCollector : ISecurityCollector
{
	private const string FwBase = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy";

	private const string FwPolicyBase = "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall";

	public string Name => "Windows Firewall";

	public string Category => "Firewall";

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
			CollectServiceStatus(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectProfileRegistry(collectorReport.Results, "Domain", "DomainProfile", ct);
			ct.ThrowIfCancellationRequested();
			CollectProfileRegistry(collectorReport.Results, "Public", "PublicProfile", ct);
			ct.ThrowIfCancellationRequested();
			CollectProfileRegistry(collectorReport.Results, "Private (Standard)", "StandardProfile", ct);
			ct.ThrowIfCancellationRequested();
			CollectPolicyOverrides(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectFirewallCom(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "FirewallCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectServiceStatus(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			bool isRunning = false;
			string state = "Unknown";
			try
			{
				ManagementObjectSearcher serviceSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service WHERE Name='MpsSvc'");
				try
				{
					foreach (ManagementObject service in serviceSearcher.Get())
					{
						ManagementObject disposableService = service;
						try
						{
							state = service["State"]?.ToString() ?? "Unknown";
							isRunning = state.Equals("Running", StringComparison.OrdinalIgnoreCase);
						}
						finally
						{
							((IDisposable)disposableService)?.Dispose();
						}
					}
				}
				finally
				{
					((IDisposable)serviceSearcher)?.Dispose();
				}
			}
			catch
			{
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows Firewall Service (MpsSvc)",
				CurrentValue = state,
				ExpectedValue = "Running",
				Status = ((!isRunning) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "The Windows Firewall service (MpsSvc) must be running for any firewall profile to be active. If stopped, all firewall rules are ineffective.",
				Recommendation = (isRunning ? "Windows Firewall service is running." : "Start MpsSvc service and set to Automatic startup."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security"
			};
		});
	}

	private void CollectProfileRegistry(List<SecurityResult> results, string profileLabel, string profileKey, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		string regPath = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\" + profileKey;
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey profileRegKey = baseKey.OpenSubKey(regPath);
			object enableValue = profileRegKey?.GetValue("EnableFirewall");
			int enableFirewall = ((enableValue == null) ? 1 : Convert.ToInt32(enableValue));
			bool isEnabled = enableFirewall == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = profileLabel + " Profile: Firewall Enabled",
				CurrentValue = ((enableFirewall == 1) ? "Enabled (1)" : $"Disabled ({enableFirewall})"),
				ExpectedValue = "1 (Enabled)",
				Status = ((!isEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Windows Firewall enabled state for the " + profileLabel + " network profile. Disabling the firewall on any profile exposes the system to network attacks.",
				Recommendation = (isEnabled ? (profileLabel + " profile firewall is enabled.") : ("Enable the firewall for the " + profileLabel + " profile immediately.")),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-firewall/"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey profileRegKey = baseKey.OpenSubKey(regPath);
			object inboundValue = profileRegKey?.GetValue("DefaultInboundAction");
			int inboundAction = ((inboundValue != null) ? Convert.ToInt32(inboundValue) : (-1));
			bool isBlock = inboundAction == 1;
			string currentValue = inboundAction switch
			{
				0 => "0 - Allow",
				1 => "1 - Block",
				-1 => "Not configured (-1)",
				_ => $"Unknown ({inboundAction})",
			};
			SecurityStatus status = inboundAction switch
			{
				1 => SecurityStatus.OK,
				-1 => SecurityStatus.Warning,
				_ => SecurityStatus.Critical,
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = profileLabel + " Profile: Default Inbound Action",
				CurrentValue = currentValue,
				ExpectedValue = "1 (Block)",
				Status = status,
				Description = "Default action for inbound connections with no matching rule on the " + profileLabel + " profile. Should always be Block to apply deny-by-default.",
				Recommendation = (isBlock ? "Default inbound is Block." : ((inboundAction == -1) ? ("DefaultInboundAction is not explicitly configured for the " + profileLabel + " profile. Set it to 1 (Block) explicitly.") : ("Set DefaultInboundAction = 1 (Block) for the " + profileLabel + " profile."))),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-firewall/"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey profileRegKey = baseKey.OpenSubKey(regPath);
			object outboundValue = profileRegKey?.GetValue("DefaultOutboundAction");
			string outboundText = ((outboundValue != null) ? Convert.ToInt32(outboundValue) : (-1)) switch
			{
				0 => "0 - Allow",
				1 => "1 - Block",
				_ => "Not configured (default: Allow)",
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = profileLabel + " Profile: Default Outbound Action",
				CurrentValue = outboundText,
				ExpectedValue = "0 (Allow) or 1 (Block for high-security)",
				Status = SecurityStatus.Info,
				Description = "Default action for outbound connections with no matching rule on the " + profileLabel + " profile. Allowing by default is common; blocking requires explicit rules for each application.",
				Recommendation = "For high-security environments, set outbound to Block and create explicit allow rules.",
				Reference = ""
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey profileRegKey = baseKey.OpenSubKey(regPath);
			object notificationsValue = profileRegKey?.GetValue("DisableNotifications");
			bool notificationsDisabled = ((notificationsValue != null) ? Convert.ToInt32(notificationsValue) : 0) == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = profileLabel + " Profile: Notifications Disabled",
				CurrentValue = (notificationsDisabled ? "Disabled (1)" : "Enabled (0)"),
				ExpectedValue = "0 (Notifications enabled)",
				Status = (notificationsDisabled ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Firewall block notifications for the " + profileLabel + " profile. Disabling notifications prevents users from being alerted when connections are blocked.",
				Recommendation = (notificationsDisabled ? "Consider enabling notifications so users and admins are informed of blocked connections." : "Notifications are enabled."),
				Reference = ""
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey profileRegKey = baseKey.OpenSubKey(regPath);
			object logDroppedValue = profileRegKey?.GetValue("LogDroppedPackets");
			bool logDropped = ((logDroppedValue != null) ? Convert.ToInt32(logDroppedValue) : 0) == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = profileLabel + " Profile: Log Dropped Packets",
				CurrentValue = (logDropped ? "Enabled (1)" : "Disabled (0)"),
				ExpectedValue = "1 (Enabled)",
				Status = ((!logDropped) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Logs dropped packets for the " + profileLabel + " profile. Logging is essential for detecting port scans and attack attempts.",
				Recommendation = (logDropped ? "Dropped packet logging is enabled." : ("Enable dropped packet logging for the " + profileLabel + " profile.")),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-firewall/configure-the-windows-firewall-log"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey profileRegKey = baseKey.OpenSubKey(regPath);
			object logSuccessValue = profileRegKey?.GetValue("LogSuccessfulConnections");
			int logSuccess = ((logSuccessValue != null) ? Convert.ToInt32(logSuccessValue) : 0);
			return new SecurityResult
			{
				Category = Category,
				CheckName = profileLabel + " Profile: Log Successful Connections",
				CurrentValue = ((logSuccess == 1) ? "Enabled (1)" : "Disabled (0)"),
				ExpectedValue = "1 (Enabled)",
				Status = ((logSuccess != 1) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "Logs allowed connections for the " + profileLabel + " profile. Useful for forensic analysis and detecting lateral movement.",
				Recommendation = "Enable connection logging for forensic and incident response capability.",
				Reference = ""
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey profileRegKey = baseKey.OpenSubKey(regPath);
			string logPath = Environment.ExpandEnvironmentVariables(profileRegKey?.GetValue("LogFilePath")?.ToString() ?? "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log");
			object logSizeValue = profileRegKey?.GetValue("LogFileSize");
			int logSize = ((logSizeValue != null) ? Convert.ToInt32(logSizeValue) : 4096);
			bool sizeAdequate = logSize >= 16384;
			return new SecurityResult
			{
				Category = Category,
				CheckName = profileLabel + " Profile: Log File",
				CurrentValue = $"Path: {logPath}, Size: {logSize} KB",
				ExpectedValue = "Size >= 16384 KB",
				Status = ((!sizeAdequate) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Firewall log file path and maximum size for the " + profileLabel + " profile. Small log files may be overwritten quickly during attacks.",
				Recommendation = (sizeAdequate ? "Log file size is adequate." : ("Increase log file size to at least 16384 KB for the " + profileLabel + " profile.")),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-firewall/configure-the-windows-firewall-log"
			};
		});
	}

	private void CollectPolicyOverrides(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		(string, string)[] profiles = new(string, string)[3]
		{
			("Domain", "DomainProfile"),
			("Public", "PublicProfile"),
			("Private (Standard)", "StandardProfile")
		};
		for (int i = 0; i < profiles.Length; i++)
		{
			(string, string) profile = profiles[i];
			string profileLabel = profile.Item1;
			string profileKeyName = profile.Item2;
			string policyPath = "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\" + profileKeyName;
			TryAdd(results, delegate
			{
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey policyRegKey = baseKey.OpenSubKey(policyPath);
				if (policyRegKey == null)
				{
					return new SecurityResult
					{
						Category = Category,
						CheckName = "GPO Override: " + profileLabel + " Firewall",
						CurrentValue = "No policy override",
						ExpectedValue = "No policy or policy enables firewall",
						Status = SecurityStatus.OK,
						Description = "No Group Policy firewall override exists for the " + profileLabel + " profile.",
						Recommendation = "No override present; local settings apply.",
						Reference = ""
					};
				}
				object enableValue = policyRegKey.GetValue("EnableFirewall");
				int enableFirewall = ((enableValue == null) ? 1 : Convert.ToInt32(enableValue));
				bool isDisabled = enableFirewall == 0;
				return new SecurityResult
				{
					Category = Category,
					CheckName = "GPO Override: " + profileLabel + " Firewall",
					CurrentValue = ((enableFirewall == 1) ? "Enabled (1)" : $"Disabled ({enableFirewall})"),
					ExpectedValue = "1 (Enabled) or not configured",
					Status = (isDisabled ? SecurityStatus.Critical : SecurityStatus.OK),
					Description = "Group Policy is overriding the " + profileLabel + " firewall setting. A GPO disabling the firewall is a serious security misconfiguration.",
					Recommendation = (isDisabled ? ("Correct the Group Policy that disables the " + profileLabel + " firewall immediately.") : "GPO firewall policy is correctly configured."),
					Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-firewall/"
				};
			});
		}
	}

	private void CollectFirewallCom(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		Type typeFromProgID = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
		if (typeFromProgID == null)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "COM Firewall API",
				CurrentValue = "HNetCfg.FwPolicy2 not available",
				Status = SecurityStatus.Error,
				Description = "Could not resolve Windows Firewall COM ProgID. Firewall components may not be installed.",
				Recommendation = "Ensure Windows Firewall components are installed.",
				Reference = ""
			});
			return;
		}
		dynamic fwPolicy = null;
		try
		{
			fwPolicy = Activator.CreateInstance(typeFromProgID);
			if (fwPolicy == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "COM Firewall API",
					CurrentValue = "COM instantiation returned null",
					Status = SecurityStatus.Error,
					Description = "Activator.CreateInstance returned null for HNetCfg.FwPolicy2.",
					Recommendation = "Ensure Windows Firewall components are installed and COM registration is intact.",
					Reference = ""
				});
				return;
			}
			int[] profileTypes = new int[3] { 1, 2, 4 };
			string[] profileLabels = new string[3] { "Domain (COM)", "Private (COM)", "Public (COM)" };
			for (int i = 0; i < profileTypes.Length; i++)
			{
				ct.ThrowIfCancellationRequested();
				int profileType = profileTypes[i];
				string profileLabel = profileLabels[i];
				TryAdd(results, delegate
				{
					bool isEnabled = (bool)fwPolicy.FirewallEnabled[profileType];
					return new SecurityResult
					{
						Category = Category,
						CheckName = "COM: " + profileLabel + " Firewall Enabled",
						CurrentValue = (isEnabled ? "True" : "False"),
						ExpectedValue = "True",
						Status = ((!isEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
						Description = "Firewall enabled status for " + profileLabel + " profile via COM API (NetFwTypeLib). This reflects the effective runtime state.",
						Recommendation = (isEnabled ? (profileLabel + " firewall is enabled.") : ("Enable the " + profileLabel + " profile firewall.")),
						Reference = "https://docs.microsoft.com/windows/win32/api/netfw/"
					};
				});
				TryAdd(results, delegate
				{
					int inboundAction = (int)fwPolicy.DefaultInboundAction[profileType];
					bool isBlock = inboundAction == 1;
					return new SecurityResult
					{
						Category = Category,
						CheckName = "COM: " + profileLabel + " Default Inbound Action",
						CurrentValue = ((inboundAction == 1) ? "Block (1)" : $"Allow (0) or Unknown ({inboundAction})"),
						ExpectedValue = "1 (Block)",
						Status = ((!isBlock) ? SecurityStatus.Critical : SecurityStatus.OK),
						Description = "Runtime default inbound action for " + profileLabel + " profile as reported by COM API.",
						Recommendation = (isBlock ? "Default inbound is Block." : "Set default inbound to Block for all profiles."),
						Reference = ""
					};
				});
				TryAdd(results, delegate
				{
					int outboundAction = (int)fwPolicy.DefaultOutboundAction[profileType];
					return new SecurityResult
					{
						Category = Category,
						CheckName = "COM: " + profileLabel + " Default Outbound Action",
						CurrentValue = ((outboundAction == 0) ? "Allow (0)" : $"Block (1) or Unknown ({outboundAction})"),
						ExpectedValue = "0 (Allow) or 1 (Block)",
						Status = SecurityStatus.Info,
						Description = "Runtime default outbound action for " + profileLabel + " profile.",
						Recommendation = "For high-security environments, consider blocking outbound by default.",
						Reference = ""
					};
				});
			}
			ct.ThrowIfCancellationRequested();
			TryAdd(results, delegate
			{
				dynamic rules = fwPolicy.Rules;
				int totalCount = 0;
				int activeInbound = 0;
				int activeOutbound = 0;
				int suspiciousInbound = 0;
				foreach (dynamic rule in rules)
				{
					totalCount++;
					if ((bool)rule.Enabled)
					{
						int direction = (int)rule.Direction;
						int action = (int)rule.Action;
						string remoteAddresses = rule.RemoteAddresses?.ToString() ?? "";
						string localPorts = rule.LocalPorts?.ToString();
						if (direction == 1)
						{
							activeInbound++;
						}
						if (direction == 2)
						{
							activeOutbound++;
						}
						if (direction == 1 && action == 1 && (remoteAddresses == "*" || remoteAddresses.Contains("*")))
						{
							switch (localPorts)
							{
							case null:
							case "*":
							case "":
								suspiciousInbound++;
								break;
							}
						}
					}
				}
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Firewall Rules Summary",
					CurrentValue = $"Total: {totalCount}, Active Inbound: {activeInbound}, Active Outbound: {activeOutbound}, Suspicious Inbound (Allow All): {suspiciousInbound}",
					ExpectedValue = "Suspicious Inbound = 0",
					Status = ((suspiciousInbound > 0) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = "Count of active firewall rules. Rules that allow all inbound traffic from any address are potentially dangerous.",
					Recommendation = ((suspiciousInbound > 0) ? $"Review {suspiciousInbound} inbound rules that allow all traffic from any source. Remove or restrict unnecessary rules." : "No obviously suspicious inbound rules found."),
					Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-firewall/create-an-inbound-port-rule"
				};
			});
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
				CheckName = "COM Firewall API",
				CurrentValue = "Error: " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to query firewall rules via COM API. Registry-based checks above are still valid.",
				Recommendation = "Ensure Windows Firewall components are intact.",
				Reference = ""
			});
		}
		finally
		{
			if (fwPolicy != null)
			{
				try
				{
					Marshal.ReleaseComObject(fwPolicy);
				}
				catch
				{
				}
			}
		}
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
				Category = "Firewall",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Check failed: " + ex.Message,
				Recommendation = "Review registry and COM access.",
				Reference = ""
			});
		}
	}
}
