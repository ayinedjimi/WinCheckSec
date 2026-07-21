using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class AzureAdCollector : ISecurityCollector
{
	private Dictionary<string, string> _dsregMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

	public string Name => "Azure AD & Conformité Cloud";

	public string Category => "Identité Cloud";

	public Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport collectorReport = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch stopwatch = Stopwatch.StartNew();
		try
		{
			_dsregMap = RunDsregCmd(ct);
			ct.ThrowIfCancellationRequested();
			CollectJoinStatus(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectIntuneEnrollment(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectConditionalAccessCompliance(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectWindowsHello(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectMsaStatus(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectOneDriveKfm(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			collectorReport.ErrorMessage = "AzureAdCollector fatal error: " + ex2.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private static Dictionary<string, string> RunDsregCmd(CancellationToken ct)
	{
		Dictionary<string, string> dsregValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		try
		{
			using Process process = Process.Start(new ProcessStartInfo("dsregcmd.exe", "/status")
			{
				RedirectStandardOutput = true,
				UseShellExecute = false,
				CreateNoWindow = true
			});
			if (process == null)
			{
				return dsregValues;
			}
			string output = process.StandardOutput.ReadToEnd();
			if (!process.WaitForExit(15000))
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
			for (int i = 0; i < lines.Length; i++)
			{
				Match match = Regex.Match(lines[i], "^\\s*([^:]+?)\\s*:\\s*(.+?)\\s*$");
				if (match.Success)
				{
					dsregValues[match.Groups[1].Value.Trim()] = match.Groups[2].Value.Trim();
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception)
		{
		}
		return dsregValues;
	}

	private string DsregValue(string key)
	{
		if (!_dsregMap.TryGetValue(key, out string value))
		{
			return string.Empty;
		}
		return value;
	}

	private bool DsregYes(string key)
	{
		return DsregValue(key).Equals("YES", StringComparison.OrdinalIgnoreCase);
	}

	private void CollectJoinStatus(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		bool dsregAvailable = _dsregMap.Count > 0;
		bool isAzureAdJoined = DsregYes("AzureAdJoined");
		bool isDomainJoined = DsregYes("DomainJoined");
		bool isHybridJoined = DsregYes("HybridAzureAdJoined");
		bool isWorkplaceJoined = DsregYes("WorkplaceJoined");
		string deviceId = DsregValue("DeviceId");
		string tenantId = DsregValue("TenantId");
		string tenantName = DsregValue("TenantName");
		string registryTenantId = string.Empty;
		if (!dsregAvailable || string.IsNullOrWhiteSpace(tenantId))
		{
			try
			{
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey cdjKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CDJ\\AAD");
				registryTenantId = cdjKey?.GetValue("TenantId")?.ToString() ?? string.Empty;
			}
			catch (Exception)
			{
			}
			if (string.IsNullOrWhiteSpace(registryTenantId))
			{
				try
				{
					using RegistryKey baseKey2 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
					using RegistryKey joinInfoKey = baseKey2.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo");
					if (joinInfoKey != null)
					{
						string[] subKeyNames = joinInfoKey.GetSubKeyNames();
						foreach (string name in subKeyNames)
						{
							using RegistryKey joinSubKey = joinInfoKey.OpenSubKey(name);
							string regTenantId = joinSubKey?.GetValue("TenantId")?.ToString();
							if (!string.IsNullOrWhiteSpace(regTenantId))
							{
								registryTenantId = regTenantId;
								break;
							}
						}
					}
				}
				catch (Exception)
				{
				}
			}
			if (!string.IsNullOrWhiteSpace(registryTenantId))
			{
				isAzureAdJoined = true;
			}
		}
		string effectiveTenantId = (string.IsNullOrWhiteSpace(tenantId) ? registryTenantId : tenantId);
		SecurityStatus joinStatus;
		string joinDescription;
		string joinRecommendation;
		if (isHybridJoined)
		{
			joinStatus = SecurityStatus.OK;
			joinDescription = "Device is Hybrid Azure AD Joined (domain + AAD). MDE, Intune, and Conditional Access policies are all available.";
			joinRecommendation = "Hybrid join is the recommended configuration for on-premises domain members.";
		}
		else if (isAzureAdJoined)
		{
			joinStatus = SecurityStatus.OK;
			joinDescription = "Device is Azure AD Joined. MDE, Intune, and Conditional Access policies are available.";
			joinRecommendation = "Azure AD Join is the recommended configuration for cloud-first devices.";
		}
		else if (isDomainJoined)
		{
			joinStatus = SecurityStatus.Info;
			joinDescription = "Device is domain-joined only (traditional Active Directory). Cloud benefits such as Intune/MDE/Conditional Access are not available.";
			joinRecommendation = "Consider Hybrid Azure AD Join to gain cloud security capabilities while keeping domain membership.";
		}
		else if (isWorkplaceJoined)
		{
			joinStatus = SecurityStatus.Info;
			joinDescription = "Device is Azure AD Registered (Workplace Joined) — personal device BYOD scenario. Full Conditional Access enforcement may not apply.";
			joinRecommendation = "For corporate devices, prefer Azure AD Join or Hybrid Join over Workplace registration.";
		}
		else
		{
			joinStatus = SecurityStatus.Warning;
			joinDescription = "Device is not joined to Azure AD or any domain — unmanaged device. Conditional Access and Intune policies cannot be enforced.";
			joinRecommendation = "Join device to Azure AD (or Hybrid) to enable cloud security management.";
		}
		string joinState = (isHybridJoined ? "HybridAzureAdJoined" : (isAzureAdJoined ? "AzureAdJoined" : (isDomainJoined ? "DomainJoined only" : (isWorkplaceJoined ? "WorkplaceJoined (AAD Registered)" : "Not joined"))));
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Azure AD / Domain Join Status",
			CurrentValue = joinState + (string.IsNullOrWhiteSpace(effectiveTenantId) ? "" : (" | TenantId=" + effectiveTenantId)) + (string.IsNullOrWhiteSpace(tenantName) ? "" : (" | Tenant=" + tenantName)) + (string.IsNullOrWhiteSpace(deviceId) ? "" : (" | DeviceId=" + deviceId)),
			ExpectedValue = "AzureAdJoined or HybridAzureAdJoined",
			Status = joinStatus,
			Description = joinDescription + (dsregAvailable ? "" : " (Registry fallback — dsregcmd unavailable)"),
			Recommendation = joinRecommendation,
			Reference = "https://docs.microsoft.com/azure/active-directory/devices/overview"
		});
	}

	private void CollectIntuneEnrollment(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		bool intuneFound = false;
		int mdmPolicies = 0;
		List<string> enrollments = new List<string>();
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey enrollmentsKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Enrollments");
			if (enrollmentsKey != null)
			{
				string[] subKeyNames = enrollmentsKey.GetSubKeyNames();
				foreach (string name in subKeyNames)
				{
					ct.ThrowIfCancellationRequested();
					using RegistryKey enrollmentKey = enrollmentsKey.OpenSubKey(name);
					if (enrollmentKey != null)
					{
						string providerId = enrollmentKey.GetValue("ProviderID")?.ToString() ?? string.Empty;
						string upn = enrollmentKey.GetValue("UPN")?.ToString() ?? string.Empty;
						string enrollmentState = enrollmentKey.GetValue("EnrollmentState")?.ToString() ?? string.Empty;
						string syncServerUrl = enrollmentKey.GetValue("SyncServerUrl")?.ToString() ?? string.Empty;
						string enrollmentType = enrollmentKey.GetValue("EnrollmentType")?.ToString() ?? string.Empty;
						if ((providerId.IndexOf("MS DM Server", StringComparison.OrdinalIgnoreCase) >= 0 || providerId.IndexOf("WS-MDM", StringComparison.OrdinalIgnoreCase) >= 0 || enrollmentType == "6" || enrollmentType == "13") && enrollmentState == "1")
						{
							intuneFound = true;
							enrollments.Add($"Provider={providerId} UPN={upn} Type={enrollmentType} URL={syncServerUrl}");
						}
					}
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception)
		{
		}
		ct.ThrowIfCancellationRequested();
		try
		{
			using RegistryKey baseKey2 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey policyKey = baseKey2.OpenSubKey("SOFTWARE\\Microsoft\\PolicyManager\\current\\device");
			if (policyKey != null)
			{
				mdmPolicies = policyKey.SubKeyCount;
			}
		}
		catch (Exception)
		{
		}
		string enrollmentSummary = (intuneFound ? string.Join(" | ", enrollments) : "No Intune enrollment found");
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Intune MDM Enrollment",
			CurrentValue = $"Enrolled={intuneFound} | MDM Policies applied={mdmPolicies} | {enrollmentSummary}",
			ExpectedValue = "Enrolled=True, MDM policies applied",
			Status = ((!intuneFound) ? SecurityStatus.Warning : SecurityStatus.OK),
			Description = (intuneFound ? $"Device is enrolled in Intune MDM. {mdmPolicies} MDM policies are currently applied." : "Device is NOT enrolled in any MDM solution. Device compliance cannot be enforced and corporate policies are not applied."),
			Recommendation = (intuneFound ? "Intune enrollment is active. Verify compliance policies are assigned." : "Enroll device in Microsoft Intune to enforce compliance and security policies."),
			Reference = "https://docs.microsoft.com/mem/intune/enrollment/windows-enrollment-methods"
		});
	}

	private void CollectConditionalAccessCompliance(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		bool compliant = DsregYes("Compliant");
		bool dsregHasIt = _dsregMap.ContainsKey("Compliant");
		string mdmUrl = DsregValue("MdmUrl");
		string accessCtrl = DsregValue("Access Control");
		string regMdmStatus = string.Empty;
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey mdmKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MDM");
			regMdmStatus = mdmKey?.GetValue("Status")?.ToString() ?? string.Empty;
		}
		catch (Exception)
		{
		}
		SecurityStatus complianceStatus;
		string complianceDesc;
		string complianceRec;
		if (!dsregHasIt)
		{
			complianceStatus = SecurityStatus.Info;
			complianceDesc = "Compliance status not available from dsregcmd (device may not be AAD joined or Intune enrolled).";
			complianceRec = "Enroll device in Intune and join Azure AD to get compliance status.";
		}
		else if (!compliant)
		{
			complianceStatus = SecurityStatus.Critical;
			complianceDesc = "Device is marked NON-COMPLIANT by Intune. Access to corporate resources protected by Conditional Access may be blocked or at risk.";
			complianceRec = "Review Intune compliance policies in the Company Portal or MEM admin center. Remediate compliance issues immediately.";
		}
		else
		{
			complianceStatus = SecurityStatus.OK;
			complianceDesc = "Device is Intune-compliant. Conditional Access policies allow access to corporate resources.";
			complianceRec = "Device compliance is confirmed. Continue monitoring for policy changes.";
		}
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Conditional Access Compliance",
			CurrentValue = ((!dsregHasIt) ? "N/A" : (compliant ? "Compliant" : "NON-COMPLIANT")) + (string.IsNullOrWhiteSpace(mdmUrl) ? "" : (" | MDM URL=" + mdmUrl)) + (string.IsNullOrWhiteSpace(accessCtrl) ? "" : (" | Access Control=" + accessCtrl)) + (string.IsNullOrWhiteSpace(regMdmStatus) ? "" : (" | MDM Reg Status=" + regMdmStatus)),
			ExpectedValue = "Compliant=YES",
			Status = complianceStatus,
			Description = complianceDesc,
			Recommendation = complianceRec,
			Reference = "https://docs.microsoft.com/azure/active-directory/conditional-access/overview"
		});
	}

	private void CollectWindowsHello(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		bool whfbPolicyDeployed = false;
		bool whfbAllowed = true;
		bool ngcSet = DsregYes("NgcSet");
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey passportKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\PassportForWork");
			object enabledValue = passportKey?.GetValue("Enabled");
			if (enabledValue != null)
			{
				whfbPolicyDeployed = Convert.ToInt32(enabledValue) == 1;
			}
		}
		catch (Exception)
		{
		}
		ct.ThrowIfCancellationRequested();
		try
		{
			using RegistryKey baseKey2 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey authKey = baseKey2.OpenSubKey("SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Authentication");
			object allowValue = authKey?.GetValue("AllowWindowsHello");
			if (allowValue != null)
			{
				whfbAllowed = Convert.ToInt32(allowValue) != 0;
			}
		}
		catch (Exception)
		{
		}
		ct.ThrowIfCancellationRequested();
		bool hkuEnrolled = false;
		try
		{
			using RegistryKey userBaseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
			using RegistryKey intentKey = userBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CloudExperienceHost\\Intent");
			hkuEnrolled = intentKey != null;
		}
		catch (Exception)
		{
		}
		bool whfbActive = ngcSet || hkuEnrolled;
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Windows Hello for Business",
			CurrentValue = $"PolicyDeployed={whfbPolicyDeployed} | AllowedByMDM={whfbAllowed} | NgcSet={ngcSet} | UserEnrolled={hkuEnrolled}",
			ExpectedValue = "Policy deployed, NgcSet=YES (WHfB enrolled)",
			Status = ((!whfbAllowed) ? SecurityStatus.Warning : ((!whfbActive) ? ((!whfbPolicyDeployed) ? SecurityStatus.Warning : SecurityStatus.Info) : SecurityStatus.OK)),
			Description = (whfbActive ? "Windows Hello for Business credentials are provisioned (NgcSet=YES). Phishing-resistant passwordless authentication is active." : (whfbPolicyDeployed ? "WHfB policy is deployed but user has not yet enrolled. Password-based authentication is still in use." : "Windows Hello for Business is not configured. Only password-based authentication is available, which is vulnerable to phishing.")),
			Recommendation = ((!whfbActive) ? "Deploy Windows Hello for Business policy and enroll users to enable phishing-resistant authentication." : "WHfB is active. Ensure FIDO2 or PIN complexity requirements are set in policy."),
			Reference = "https://docs.microsoft.com/windows/security/identity-protection/hello-for-business/hello-overview"
		});
	}

	private void CollectMsaStatus(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		int msaOptional = -1;
		int disableMsaAssistant = -1;
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\System");
			object msaOptionalValue = systemKey?.GetValue("MSAOptional");
			if (msaOptionalValue != null)
			{
				msaOptional = Convert.ToInt32(msaOptionalValue);
			}
		}
		catch (Exception)
		{
		}
		ct.ThrowIfCancellationRequested();
		try
		{
			using RegistryKey baseKey2 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey accountKey = baseKey2.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Account");
			object disableValue = accountKey?.GetValue("DisableMicrosoftAccountSignInAssistant");
			if (disableValue != null)
			{
				disableMsaAssistant = Convert.ToInt32(disableValue);
			}
		}
		catch (Exception)
		{
		}
		// Correctif L1 : le blocage réel des comptes MSA repose sur NoConnectedUser (=3), pas sur MSAOptional
		int noConnectedUser = -1;
		try
		{
			using RegistryKey baseKey3 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey policiesSystemKey = baseKey3.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
			object noConnectedUserValue = policiesSystemKey?.GetValue("NoConnectedUser");
			if (noConnectedUserValue != null)
			{
				noConnectedUser = Convert.ToInt32(noConnectedUserValue);
			}
		}
		catch (Exception)
		{
		}
		// MSAOptional=0 ne restreint PAS : seuls NoConnectedUser==3 ou DisableMSASignInAssistant==1 bloquent réellement les comptes MSA
		bool msaRestricted = noConnectedUser == 3 || disableMsaAssistant == 1;
		string msaStr = ((msaOptional == -1 && disableMsaAssistant == -1 && noConnectedUser == -1) ? "No MSA restriction policy configured" : $"NoConnectedUser={noConnectedUser} | MSAOptional={msaOptional} | DisableMSASignInAssistant={disableMsaAssistant}");
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Microsoft Account (MSA) Restriction",
			CurrentValue = msaStr,
			ExpectedValue = "MSA restricted on corporate devices (NoConnectedUser=3 or DisableMSASignInAssistant=1)",
			Status = ((!msaRestricted) ? SecurityStatus.Warning : SecurityStatus.OK),
			Description = (msaRestricted ? "Microsoft accounts are blocked by policy (NoConnectedUser=3 or MSA Sign-in Assistant disabled). Personal accounts cannot be mixed with corporate work accounts." : "No effective MSA blocking policy is configured. Personal Microsoft accounts may be used on this device, mixing personal and corporate identities. Note: MSAOptional=0 does NOT restrict MSA."),
			Recommendation = ((!msaRestricted) ? "Set NoConnectedUser=3 (Accounts: Block Microsoft accounts) and/or DisableMicrosoftAccountSignInAssistant=1 via GPO to block personal MSA on corporate devices." : "MSA is appropriately restricted."),
			Reference = "https://docs.microsoft.com/windows/security/identity-protection/access-control/microsoft-accounts"
		});
	}

	private void CollectOneDriveKfm(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		string kfmTenantId = string.Empty;
		int disablePersonalSync = -1;
		bool businessConfigured = false;
		string kfmFoldersProtected = string.Empty;
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey oneDriveKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\OneDrive");
			if (oneDriveKey != null)
			{
				kfmTenantId = oneDriveKey.GetValue("KFMSilentOptIn")?.ToString() ?? string.Empty;
				object syncValue = oneDriveKey.GetValue("DisablePersonalSync");
				if (syncValue != null)
				{
					disablePersonalSync = Convert.ToInt32(syncValue);
				}
			}
		}
		catch (Exception)
		{
		}
		ct.ThrowIfCancellationRequested();
		try
		{
			using RegistryKey userBaseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
			using RegistryKey businessKey = userBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\OneDrive\\Accounts\\Business1");
			businessConfigured = businessKey != null;
			if (businessKey != null)
			{
				kfmFoldersProtected = businessKey.GetValue("KfmFoldersProtectedByPolicy")?.ToString() ?? string.Empty;
			}
		}
		catch (Exception)
		{
		}
		bool kfmConfigured = !string.IsNullOrWhiteSpace(kfmTenantId);
		bool personalBlocked = disablePersonalSync == 1;
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "OneDrive KFM (Known Folder Move)",
			CurrentValue = $"KFMConfigured={kfmConfigured}" + (kfmConfigured ? (" TenantId=" + kfmTenantId) : "") + $" | PersonalSyncDisabled={personalBlocked}" + $" | BusinessAccountConfigured={businessConfigured}" + (string.IsNullOrWhiteSpace(kfmFoldersProtected) ? "" : (" | ProtectedFolders=" + kfmFoldersProtected)),
			ExpectedValue = "KFM configured (backup), PersonalSync disabled on corporate device",
			Status = ((!personalBlocked && businessConfigured) ? SecurityStatus.Warning : (kfmConfigured ? SecurityStatus.Info : SecurityStatus.Info)),
			Description = (kfmConfigured ? ("OneDrive Known Folder Move is configured for tenant " + kfmTenantId + ". Desktop, Documents and Pictures are backed up to OneDrive Business.") : "OneDrive KFM is not configured. User data in known folders is not automatically backed up to the cloud."),
			Recommendation = ((!personalBlocked && businessConfigured) ? "Disable personal OneDrive sync on corporate devices (DisablePersonalSync=1) to prevent data leakage to personal accounts." : (kfmConfigured ? "KFM is active. Ensure DisablePersonalSync=1 to block personal account sync." : "Consider enabling KFM to protect user data in known folders with automatic cloud backup.")),
			Reference = "https://docs.microsoft.com/onedrive/redirect-known-folders"
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
				Category = "Identité Cloud",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Check failed: " + ex.Message,
				Recommendation = "Verify dsregcmd availability and registry access. Run as Administrator.",
				Reference = ""
			});
		}
	}
}
