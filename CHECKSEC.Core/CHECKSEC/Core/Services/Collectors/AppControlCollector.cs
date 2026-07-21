using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services.Helpers;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class AppControlCollector : ISecurityCollector
{
	private const string CiConfigKey = "SYSTEM\\CurrentControlSet\\Control\\CI\\Config";

	private const string CiPolicyKey = "SYSTEM\\CurrentControlSet\\Control\\CI\\Policy";

	private const string DeviceGuardPoliciesKey = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard";

	private const string SrpV2Key = "SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2";

	private const string UacKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

	public string Name => "Application Control";

	public string Category => "Application Control";

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
			CollectWdac(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectAppLocker(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectSmartAppControl(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectUac(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			collectorReport.ErrorMessage = "AppControlCollector fatal error: " + ex2.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectWdac(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey ciConfigKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\CI\\Config");
			bool keyPresent = ciConfigKey != null;
			string[] valueNames = ciConfigKey?.GetValueNames() ?? Array.Empty<string>();
			return new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC: CI Config Registry Key",
				CurrentValue = (keyPresent ? $"Present ({valueNames.Length} values)" : "Not present"),
				ExpectedValue = "Present with configuration",
				Status = ((!keyPresent) ? SecurityStatus.Warning : SecurityStatus.Info),
				Description = "Windows Defender Application Control (WDAC) Code Integrity configuration registry key. Presence indicates CI policy is configured.",
				Recommendation = (keyPresent ? "WDAC CI Config key is present. Review policy details." : "Configure WDAC code integrity policies for application control."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey ciPolicyKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\CI\\Policy");
			if (ciPolicyKey == null)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "WDAC: CI Policy Registry Key",
					CurrentValue = "Not present",
					ExpectedValue = "Present",
					Status = SecurityStatus.Warning,
					Description = "WDAC Code Integrity Policy registry key is absent. No enforced WDAC policy detected.",
					Recommendation = "Deploy a WDAC policy to enforce application control.",
					Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/"
				};
			}
			object velocityId = ciPolicyKey.GetValue("VelocityId");
			return new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC: CI Policy VelocityId",
				CurrentValue = (velocityId?.ToString() ?? "Not set"),
				ExpectedValue = "Set (policy active)",
				Status = ((velocityId == null) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "WDAC policy VelocityId indicates an active Code Integrity policy is loaded.",
				Recommendation = ((velocityId != null) ? "WDAC policy is active." : "Deploy a WDAC policy to set this value."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey deviceGuardKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard");
			object policiesActive = deviceGuardKey?.GetValue("CodeIntegrityPoliciesActive");
			return new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC: CodeIntegrityPoliciesActive",
				CurrentValue = (policiesActive?.ToString() ?? "Not configured"),
				ExpectedValue = "1 (Active)",
				Status = ((policiesActive == null) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "DeviceGuard policy key indicating active code integrity policies.",
				Recommendation = ((policiesActive != null) ? "Code integrity policies are active." : "Deploy WDAC policies via Group Policy or SCCM."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/"
			};
		});
		TryAdd(results, delegate
		{
			bool activeDirExists = Directory.Exists("C:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active");
			int policyFileCount = 0;
			if (activeDirExists)
			{
				try
				{
					policyFileCount = Directory.GetFiles("C:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active", "*.p7b").Length;
				}
				catch
				{
				}
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC: Active CI Policy Files",
				CurrentValue = (activeDirExists ? $"{policyFileCount} .p7b policy file(s) in CiPolicies\\Active" : "Directory not found"),
				ExpectedValue = ">= 1 policy file",
				Status = ((policyFileCount <= 0) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "WDAC enforced policy files in C:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active. Each .p7b file is an active code integrity policy.",
				Recommendation = ((policyFileCount > 0) ? $"{policyFileCount} WDAC policy file(s) active." : "No active WDAC policy files found. Deploy a WDAC policy."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/deploy-windows-defender-application-control-policies-using-group-policy"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey ciPolicyKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\CI\\Policy");
			object ciPolicyActive = ciPolicyKey?.GetValue("CIPolicyActive");
			return new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC: CIPolicyActive Key",
				CurrentValue = (ciPolicyActive?.ToString() ?? "Not set"),
				ExpectedValue = "Set",
				Status = ((ciPolicyActive == null) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "CIPolicyActive registry value indicates the active WDAC policy.",
				Recommendation = ((ciPolicyActive != null) ? "CIPolicyActive is set." : "Deploy a WDAC policy to populate this value."),
				Reference = ""
			};
		});
	}

	private void CollectAppLocker(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			bool isRunning = false;
			string serviceState = "Unknown";
			try
			{
				ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service WHERE Name='AppIDSvc'");
				try
				{
					foreach (ManagementObject serviceObject in searcher.Get())
					{
						ManagementObject mo = serviceObject;
						try
						{
							serviceState = serviceObject["State"]?.ToString() ?? "Unknown";
							isRunning = serviceState.Equals("Running", StringComparison.OrdinalIgnoreCase);
						}
						finally
						{
							((IDisposable)mo)?.Dispose();
						}
					}
					if (serviceState == "Unknown")
					{
						serviceState = "Service not found";
					}
				}
				finally
				{
					((IDisposable)searcher)?.Dispose();
				}
			}
			catch
			{
				serviceState = "Service not found";
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "AppLocker: AppID Service (AppIDSvc)",
				CurrentValue = serviceState,
				ExpectedValue = "Running",
				Status = ((!isRunning) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "The Application Identity Service (AppIDSvc) is required for AppLocker to evaluate and enforce application control rules.",
				Recommendation = (isRunning ? "AppID service is running." : "Start AppIDSvc and set to Automatic to enable AppLocker enforcement."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview"
			};
		});
		(string, string)[] ruleCategories = new(string, string)[5]
		{
			("Exe", "Executable Rules"),
			("Dll", "DLL Rules"),
			("Script", "Script Rules"),
			("Msi", "MSI/Installer Rules"),
			("Appx", "Packaged App Rules")
		};
		for (int i = 0; i < ruleCategories.Length; i++)
		{
			(string, string) ruleCategory = ruleCategories[i];
			string ruleType = ruleCategory.Item1;
			string ruleLabel = ruleCategory.Item2;
			ct.ThrowIfCancellationRequested();
			string label2 = ruleLabel;
			string regSub = ruleType;
			TryAdd(results, delegate
			{
				string ruleKeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\" + regSub;
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey rulesKey = baseKey.OpenSubKey(ruleKeyPath);
				if (rulesKey == null)
				{
					return new SecurityResult
					{
						Category = Category,
						CheckName = "AppLocker: " + label2,
						CurrentValue = "No rules configured",
						ExpectedValue = ">= 1 rule",
						Status = SecurityStatus.Info,
						Description = "AppLocker " + label2 + " registry key is absent. No rules are configured for this category.",
						Recommendation = "Consider configuring AppLocker " + label2 + " to restrict unauthorized application execution.",
						Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/applocker/create-applocker-default-rules"
					};
				}
				string[] ruleNames = rulesKey.GetSubKeyNames();
				int allowCount = 0;
				int denyCount = 0;
				string[] ruleSubKeys = ruleNames;
				foreach (string ruleName in ruleSubKeys)
				{
					try
					{
						using RegistryKey ruleKey = rulesKey.OpenSubKey(ruleName);
						string action = ruleKey?.GetValue("Action")?.ToString() ?? "";
						if (action.Equals("Allow", StringComparison.OrdinalIgnoreCase))
						{
							allowCount++;
						}
						else if (action.Equals("Deny", StringComparison.OrdinalIgnoreCase))
						{
							denyCount++;
						}
					}
					catch
					{
					}
				}
				bool hasRules = ruleNames.Length != 0;
				return new SecurityResult
				{
					Category = Category,
					CheckName = "AppLocker: " + label2,
					CurrentValue = $"{ruleNames.Length} rules ({allowCount} Allow, {denyCount} Deny)",
					ExpectedValue = ">= 1 rule configured",
					Status = ((!hasRules) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = "AppLocker " + label2 + " count. Rules restrict which applications users can run, reducing attack surface.",
					Recommendation = (hasRules ? $"{ruleNames.Length} AppLocker {label2} are configured." : ("Configure AppLocker " + label2 + ".")),
					Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/applocker/"
				};
			});
		}
		TryAdd(results, delegate
		{
			string exeRuleKeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Exe";
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey exeRulesKey = baseKey.OpenSubKey(exeRuleKeyPath);
			object enforcementValue = exeRulesKey?.GetValue("EnforcementMode");
			string enforcementText = enforcementValue?.ToString() ?? "Not configured";
			int enforcementMode = ((enforcementValue != null) ? Convert.ToInt32(enforcementValue) : (-1));
			string currentValue = enforcementMode switch
			{
				0 => "0 - Not configured", 
				1 => "1 - Audit only", 
				2 => "2 - Enforce", 
				_ => enforcementText,
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "AppLocker: Exe Enforcement Mode",
				CurrentValue = currentValue,
				ExpectedValue = "2 (Enforce)",
				Status = enforcementMode switch
				{
					1 => SecurityStatus.Warning,
					2 => SecurityStatus.OK,
					_ => SecurityStatus.Info,
				},
				Description = "AppLocker executable rule enforcement mode. Audit mode logs violations without blocking; Enforce mode actively blocks unauthorized executables.",
				Recommendation = ((enforcementMode == 2) ? "AppLocker is in Enforce mode." : "Switch AppLocker to Enforce mode after testing in Audit mode."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/applocker/configure-an-applocker-policy-for-enforce-rules"
			};
		});
	}

	private void CollectSmartAppControl(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		if (!WindowsInfo.Is22H2OrLater)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Smart App Control (SAC) State",
				CurrentValue = $"N/A (Build {WindowsInfo.BuildNumber})",
				ExpectedValue = "Windows 11 22H2+ (Build 22621+)",
				Status = SecurityStatus.Info,
				Description = "Smart App Control is only available on Windows 11 22H2 and later. This system's build predates that feature.",
				Recommendation = "Upgrade to Windows 11 22H2 or later to access Smart App Control.",
				Reference = "https://support.microsoft.com/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003"
			});
			return;
		}
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey ciPolicyKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\CI\\Policy");
			object sacValue = ciPolicyKey?.GetValue("VerifiedAndReputablePolicyState");
			int sacState = ((sacValue != null) ? Convert.ToInt32(sacValue) : (-1));
			string stateText;
			object stateLabel;
			switch (sacState)
			{
			case 0:
				stateText = "0 - Off";
				break;
			case 1:
				stateText = "1 - Evaluation mode";
				break;
			case 2:
				stateText = "2 - On (enforcing)";
				break;
			default:
				stateLabel = $"{sacState} - Unknown";
				goto IL_009a;
			case -1:
				{
					stateLabel = "Not configured / Key missing";
					goto IL_009a;
				}
				IL_009a:
				stateText = (string)stateLabel;
				break;
			}
			string currentValue = stateText;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Smart App Control (SAC) State",
				CurrentValue = currentValue,
				ExpectedValue = "2 (On) or 1 (Evaluation)",
				Status = sacState switch
				{
					1 => SecurityStatus.Warning,
					2 => SecurityStatus.OK,
					_ => SecurityStatus.Warning,
				},
				Description = "Smart App Control (Windows 11 22H2+) uses cloud intelligence to block untrusted or unsigned applications before they run, providing an additional layer of application control.",
				Recommendation = sacState switch
				{
					1 => "Smart App Control is in evaluation mode. Review and switch to On if appropriate.",
					2 => "Smart App Control is active.", 
					_ => "Enable Smart App Control via Windows Security > App & Browser Control > Smart App Control.", 
				},
				Reference = "https://support.microsoft.com/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003"
			};
		});
	}

	private void CollectUac(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemPolicyKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
			object luaValue = systemPolicyKey?.GetValue("EnableLUA");
			int enableLua = ((luaValue == null) ? 1 : Convert.ToInt32(luaValue));
			bool isEnabled = enableLua == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "UAC: EnableLUA",
				CurrentValue = ((enableLua == 1) ? "Enabled (1)" : $"Disabled ({enableLua})"),
				ExpectedValue = "1 (Enabled)",
				Status = ((!isEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "User Account Control (UAC) limits administrative privileges. Disabling UAC allows all processes to run with full admin rights, making malware escalation trivial.",
				Recommendation = (isEnabled ? "UAC is enabled." : "Enable UAC immediately. Disabling UAC is a critical security misconfiguration."),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/user-account-control/user-account-control-overview"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemPolicyKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
			object consentValue = systemPolicyKey?.GetValue("ConsentPromptBehaviorAdmin");
			int consentAdmin = ((consentValue != null) ? Convert.ToInt32(consentValue) : 5);
			string currentValue = consentAdmin switch
			{
				0 => "0 - Elevate without prompting (dangerous)", 
				1 => "1 - Prompt for credentials on secure desktop", 
				2 => "2 - Prompt for consent on secure desktop (recommended)", 
				3 => "3 - Prompt for credentials", 
				4 => "4 - Prompt for consent", 
				5 => "5 - Prompt for consent for non-Windows binaries (default)",
				_ => $"{consentAdmin} - Unknown",
			};
			bool isSecureDesktop = consentAdmin == 1 || consentAdmin == 2;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "UAC: ConsentPromptBehaviorAdmin",
				CurrentValue = currentValue,
				ExpectedValue = "2 (Prompt for consent on secure desktop)",
				Status = ((consentAdmin == 0) ? SecurityStatus.Critical : ((!isSecureDesktop) ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = "Determines UAC behavior when admins request elevation. Value 0 silently elevates (very dangerous). Secure desktop prevents UI spoofing attacks.",
				Recommendation = ((consentAdmin == 0) ? "Set ConsentPromptBehaviorAdmin to at least 2 to prevent silent elevation." : (isSecureDesktop ? "UAC admin prompt is using secure desktop." : "Consider setting to 2 (secure desktop) for stronger protection.")),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemPolicyKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
			object consentValue = systemPolicyKey?.GetValue("ConsentPromptBehaviorUser");
			int consentUser = ((consentValue != null) ? Convert.ToInt32(consentValue) : 3);
			string userConsentText = consentUser switch
			{
				0 => "0 - Automatically deny elevation requests (recommended)", 
				1 => "1 - Prompt for credentials on secure desktop", 
				3 => "3 - Prompt for credentials (default)",
				_ => $"{consentUser} - Unknown",
			};
			bool deniesElevation = consentUser == 0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "UAC: ConsentPromptBehaviorUser",
				CurrentValue = userConsentText,
				ExpectedValue = "0 (Deny elevation)",
				Status = ((!deniesElevation) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "UAC behavior for standard users requesting elevation. Denying elevation prevents unprivileged users from installing software or making system changes.",
				Recommendation = (deniesElevation ? "Standard users cannot elevate." : "Set ConsentPromptBehaviorUser = 0 to automatically deny elevation for standard users."),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemPolicyKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
			object secureDesktopValue = systemPolicyKey?.GetValue("PromptOnSecureDesktop");
			int promptOnSecureDesktop = ((secureDesktopValue == null) ? 1 : Convert.ToInt32(secureDesktopValue));
			bool isEnabled = promptOnSecureDesktop == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "UAC: PromptOnSecureDesktop",
				CurrentValue = (isEnabled ? "Enabled (1)" : $"Disabled ({promptOnSecureDesktop})"),
				ExpectedValue = "1 (Enabled)",
				Status = ((!isEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Secure Desktop prevents other applications from intercepting UAC prompts. Disabling it allows UI spoofing attacks against UAC dialogs.",
				Recommendation = (isEnabled ? "UAC prompts on secure desktop." : "Enable PromptOnSecureDesktop to prevent UAC prompt spoofing."),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/user-account-control/"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemPolicyKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
			object virtualizationValue = systemPolicyKey?.GetValue("EnableVirtualization");
			int enableVirtualization = ((virtualizationValue == null) ? 1 : Convert.ToInt32(virtualizationValue));
			bool isEnabled = enableVirtualization == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "UAC: EnableVirtualization",
				CurrentValue = (isEnabled ? "Enabled (1)" : $"Disabled ({enableVirtualization})"),
				ExpectedValue = "1 (Enabled)",
				Status = ((!isEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "UAC file and registry virtualization redirects legacy app writes to protected locations to per-user virtual stores, enabling non-admin operation.",
				Recommendation = (isEnabled ? "UAC virtualization is enabled." : "Enable UAC virtualization for application compatibility."),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/user-account-control/"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemPolicyKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
			object installerDetectionValue = systemPolicyKey?.GetValue("EnableInstallerDetection");
			int enableInstallerDetection = ((installerDetectionValue == null) ? 1 : Convert.ToInt32(installerDetectionValue));
			bool isEnabled = enableInstallerDetection == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "UAC: EnableInstallerDetection",
				CurrentValue = (isEnabled ? "Enabled (1)" : $"Disabled ({enableInstallerDetection})"),
				ExpectedValue = "1 (Enabled)",
				Status = ((!isEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Detects installation packages and prompts for elevation, preventing silent software installation by standard users.",
				Recommendation = (isEnabled ? "Installer detection is enabled." : "Enable installer detection to prompt for elevation during software installation."),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/user-account-control/"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemPolicyKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
			object signatureValue = systemPolicyKey?.GetValue("ValidateAdminCodeSignatures");
			bool validatesSignatures = ((signatureValue != null) ? Convert.ToInt32(signatureValue) : 0) == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "UAC: ValidateAdminCodeSignatures",
				CurrentValue = (validatesSignatures ? "Enabled (1)" : "Disabled (0)"),
				ExpectedValue = "1 (Enabled for high-security)",
				Status = ((!validatesSignatures) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "Requires that elevated applications be signed by a trusted publisher. Provides stronger assurance that elevated code is legitimate.",
				Recommendation = (validatesSignatures ? "Admin code signature validation is enabled." : "Consider enabling ValidateAdminCodeSignatures for high-security environments."),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemPolicyKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
			object filterTokenValue = systemPolicyKey?.GetValue("FilterAdministratorToken");
			bool filtersAdminToken = ((filterTokenValue != null) ? Convert.ToInt32(filterTokenValue) : 0) == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "UAC: FilterAdministratorToken (Admin Approval Mode for Built-in Admin)",
				CurrentValue = (filtersAdminToken ? "Enabled (1)" : "Disabled (0)"),
				ExpectedValue = "1 (Enabled)",
				Status = ((!filtersAdminToken) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Applies UAC Admin Approval Mode to the built-in Administrator account. When disabled, the built-in Administrator bypasses all UAC prompts.",
				Recommendation = (filtersAdminToken ? "Built-in Administrator is subject to UAC." : "Enable FilterAdministratorToken to apply UAC to the built-in Administrator account."),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings"
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
				Category = "Application Control",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Check failed: " + ex.Message,
				Recommendation = "Review registry and file system access.",
				Reference = ""
			});
		}
	}
}
