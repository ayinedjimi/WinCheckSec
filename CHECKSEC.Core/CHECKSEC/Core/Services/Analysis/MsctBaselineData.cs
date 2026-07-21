using System.Collections.Generic;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Core.Services.Analysis;

public static class MsctBaselineData
{
	public static List<BaselinePolicy> GetBaselinePolicies()
	{
		List<BaselinePolicy> policies = new List<BaselinePolicy>(600);
		AddDomainSecurityPolicies(policies);
		AddComputerGptTmplPolicies(policies);
		AddComputerRegistryPolPolicies(policies);
		AddComputerAuditPolicies(policies);
		AddDefenderAntivirusPolicies(policies);
		AddBitLockerPolicies(policies);
		AddCredentialGuardPolicies(policies);
		AddIE11ComputerPolicies(policies);
		AddIE11UserPolicies(policies);
		AddUserPolicies(policies);
		return policies;
	}

	private static void AddDomainSecurityPolicies(List<BaselinePolicy> p)
	{
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Domain Security",
			Type = PolicyType.PasswordPolicy,
			KeyPath = "System Access",
			ValueName = "MinimumPasswordLength",
			ExpectedValue = "14",
			ValueType = "REG_DWORD",
			Section = "System Access"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Domain Security",
			Type = PolicyType.PasswordPolicy,
			KeyPath = "System Access",
			ValueName = "PasswordComplexity",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "System Access"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Domain Security",
			Type = PolicyType.PasswordPolicy,
			KeyPath = "System Access",
			ValueName = "PasswordHistorySize",
			ExpectedValue = "24",
			ValueType = "REG_DWORD",
			Section = "System Access"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Domain Security",
			Type = PolicyType.PasswordPolicy,
			KeyPath = "System Access",
			ValueName = "ClearTextPassword",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "System Access"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Domain Security",
			Type = PolicyType.AccountLockout,
			KeyPath = "System Access",
			ValueName = "LockoutBadCount",
			ExpectedValue = "10",
			ValueType = "REG_DWORD",
			Section = "System Access"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Domain Security",
			Type = PolicyType.AccountLockout,
			KeyPath = "System Access",
			ValueName = "ResetLockoutCount",
			ExpectedValue = "10",
			ValueType = "REG_DWORD",
			Section = "System Access"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Domain Security",
			Type = PolicyType.AccountLockout,
			KeyPath = "System Access",
			ValueName = "LockoutDuration",
			ExpectedValue = "10",
			ValueType = "REG_DWORD",
			Section = "System Access"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Domain Security",
			Type = PolicyType.SecurityOption,
			KeyPath = "System Access",
			ValueName = "AllowAdministratorLockout",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "System Access"
		});
	}

	private static void AddComputerGptTmplPolicies(List<BaselinePolicy> p)
	{
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.SecurityOption,
			KeyPath = "System Access",
			ValueName = "LSAAnonymousNameLookup",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "System Access"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "ConsentPromptBehaviorEnhancedAdmin",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "TypeOfAdminApprovalMode",
			ExpectedValue = "2",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
			ValueName = "ScRemoveOption",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "InactivityTimeoutSecs",
			ExpectedValue = "900",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
			ValueName = "EnablePlainTextPassword",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Control\\Lsa",
			ValueName = "LimitBlankPasswordUse",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Control\\Lsa",
			ValueName = "RestrictAnonymousSAM",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Control\\Lsa",
			ValueName = "RestrictAnonymous",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters",
			ValueName = "RestrictNullSessAccess",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Control\\Lsa",
			ValueName = "SCENoApplyLegacyAuditPolicy",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
			ValueName = "NTLMMinClientSec",
			ExpectedValue = "537395200",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Control\\Lsa",
			ValueName = "LmCompatibilityLevel",
			ExpectedValue = "5",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
			ValueName = "allownullsessionfallback",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
			ValueName = "NTLMMinServerSec",
			ExpectedValue = "537395200",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
			ValueName = "requirestrongkey",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
			ValueName = "RequireSecuritySignature",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
			ValueName = "sealsecurechannel",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
			ValueName = "requiresignorseal",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
			ValueName = "signsecurechannel",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters",
			ValueName = "requiresecuritysignature",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Control\\Session Manager",
			ValueName = "ProtectionMode",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "ConsentPromptBehaviorAdmin",
			ExpectedValue = "2",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "EnableSecureUIAPaths",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "EnableLUA",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "ConsentPromptBehaviorUser",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "EnableInstallerDetection",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "FilterAdministratorToken",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "EnableVirtualization",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Services\\LDAP",
			ValueName = "LDAPClientIntegrity",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Control\\Lsa",
			ValueName = "RestrictRemoteSAM",
			ExpectedValue = "O:BAG:BAD:(A;;RC;;;BA)",
			ValueType = "REG_SZ",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
			ValueName = "DisablePasswordChange",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Values"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeSecurityPrivilege",
			ExpectedValue = "*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeRestorePrivilege",
			ExpectedValue = "*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeTakeOwnershipPrivilege",
			ExpectedValue = "*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeBackupPrivilege",
			ExpectedValue = "*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeDenyRemoteInteractiveLogonRight",
			ExpectedValue = "*S-1-5-113",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeCreatePermanentPrivilege",
			ExpectedValue = "",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeManageVolumePrivilege",
			ExpectedValue = "*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeLoadDriverPrivilege",
			ExpectedValue = "*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeLockMemoryPrivilege",
			ExpectedValue = "",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeDenyNetworkLogonRight",
			ExpectedValue = "*S-1-5-113",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeNetworkLogonRight",
			ExpectedValue = "*S-1-5-32-555,*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeImpersonatePrivilege",
			ExpectedValue = "*S-1-5-6,*S-1-5-99-216390572-1995538116-3857911515-2404958512-2623887229,*S-1-5-20,*S-1-5-19,*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeCreateTokenPrivilege",
			ExpectedValue = "",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeCreateGlobalPrivilege",
			ExpectedValue = "*S-1-5-20,*S-1-5-19,*S-1-5-6,*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeSystemEnvironmentPrivilege",
			ExpectedValue = "*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeCreatePagefilePrivilege",
			ExpectedValue = "*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeInteractiveLogonRight",
			ExpectedValue = "*S-1-5-32-545,*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeRemoteShutdownPrivilege",
			ExpectedValue = "*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeDebugPrivilege",
			ExpectedValue = "*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeTrustedCredManAccessPrivilege",
			ExpectedValue = "",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeProfileSingleProcessPrivilege",
			ExpectedValue = "*S-1-5-32-544",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeTcbPrivilege",
			ExpectedValue = "",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.UserRightsAssignment,
			KeyPath = "Privilege Rights",
			ValueName = "SeEnableDelegationPrivilege",
			ExpectedValue = "",
			ValueType = "REG_SZ",
			Section = "Privilege Rights"
		});
	}

	private static void AddComputerRegistryPolPolicies(List<BaselinePolicy> p)
	{
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\WcmSvc\\wifinetworkmanager\\config",
			ValueName = "AutoConnectAllowedOEM",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI",
			ValueName = "EnumerateAdministrators",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
			ValueName = "NoDriveTypeAutoRun",
			ExpectedValue = "255",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
			ValueName = "NoWebServices",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
			ValueName = "NoAutorun",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS",
			ValueName = "BackupDirectory",
			ExpectedValue = "2",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS",
			ValueName = "ADPasswordEncryptionEnabled",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS",
			ValueName = "ADBackupDSRMPassword",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "MSAOptional",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "DisableAutomaticRestartSignOn",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "LocalAccountTokenFilterPolicy",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName = "EnableMPR",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
			ValueName = "ProcessCreationIncludeCmdLine_Enabled",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters",
			ValueName = "AllowEncryptionOracle",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\KDC\\Parameters",
			ValueName = "PKINITHashAlgorithmConfigurationEnabled",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\KDC\\Parameters",
			ValueName = "PKINITSHA1",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\KDC\\Parameters",
			ValueName = "PKINITSHA256",
			ExpectedValue = "3",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\KDC\\Parameters",
			ValueName = "PKINITSHA384",
			ExpectedValue = "3",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\KDC\\Parameters",
			ValueName = "PKINITSHA512",
			ExpectedValue = "3",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
			ValueName = "PKInitHashAlgorithmConfigurationEnabled",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
			ValueName = "PKInitSHA1",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
			ValueName = "PKInitSHA256",
			ExpectedValue = "3",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
			ValueName = "PKInitSHA384",
			ExpectedValue = "3",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
			ValueName = "PKInitSHA512",
			ExpectedValue = "3",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Biometrics\\FacialFeatures",
			ValueName = "EnhancedAntiSpoofing",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Feeds",
			ValueName = "DisableEnclosureDownload",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51",
			ValueName = "DCSettingIndex",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51",
			ValueName = "ACSettingIndex",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\AppPrivacy",
			ValueName = "LetAppsActivateWithVoiceAboveLock",
			ExpectedValue = "2",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\Bowser",
			ValueName = "EnableMailslots",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CloudContent",
			ValueName = "DisableWindowsConsumerFeatures",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CredentialsDelegation",
			ValueName = "AllowProtectedCreds",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\EventLog\\Application",
			ValueName = "MaxSize",
			ExpectedValue = "32768",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\EventLog\\Security",
			ValueName = "MaxSize",
			ExpectedValue = "196608",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\EventLog\\System",
			ValueName = "MaxSize",
			ExpectedValue = "32768",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\Explorer",
			ValueName = "NoAutoplayfornonVolume",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\Explorer",
			ValueName = "DisableMotWOnInsecurePathCopy",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\GameDVR",
			ValueName = "AllowGameDVR",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\Installer",
			ValueName = "AlwaysInstallElevated",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\Installer",
			ValueName = "EnableUserControl",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\Kernel DMA Protection",
			ValueName = "DeviceEnumerationPolicy",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanServer",
			ValueName = "AuditClientDoesNotSupportEncryption",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanServer",
			ValueName = "AuditClientDoesNotSupportSigning",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanServer",
			ValueName = "AuditInsecureGuestLogon",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanServer",
			ValueName = "EnableAuthRateLimiter",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanServer",
			ValueName = "MaxSmb2Dialect",
			ExpectedValue = "785",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanServer",
			ValueName = "MinSmb2Dialect",
			ExpectedValue = "768",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanServer",
			ValueName = "InvalidAuthenticationDelayTimeInMs",
			ExpectedValue = "2000",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanWorkstation",
			ValueName = "AllowInsecureGuestAuth",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanWorkstation",
			ValueName = "AuditInsecureGuestLogon",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanWorkstation",
			ValueName = "AuditServerDoesNotSupportEncryption",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanWorkstation",
			ValueName = "AuditServerDoesNotSupportSigning",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanWorkstation",
			ValueName = "MaxSmb2Dialect",
			ExpectedValue = "785",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanWorkstation",
			ValueName = "MinSmb2Dialect",
			ExpectedValue = "768",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\LanmanWorkstation",
			ValueName = "RequireEncryption",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\Network Connections",
			ValueName = "NC_ShowSharedAccessUI",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\NetworkProvider",
			ValueName = "EnableMailslots",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths",
			ValueName = "\\\\*\\SYSVOL",
			ExpectedValue = "RequireMutualAuthentication=1,RequireIntegrity=1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths",
			ValueName = "\\\\*\\NETLOGON",
			ExpectedValue = "RequireMutualAuthentication=1,RequireIntegrity=1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\Personalization",
			ValueName = "NoLockScreenCamera",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\Personalization",
			ValueName = "NoLockScreenSlideshow",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
			ValueName = "EnableScriptBlockLogging",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\Sudo",
			ValueName = "Enabled",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\System",
			ValueName = "AllowDomainPINLogon",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\System",
			ValueName = "EnumerateLocalUsers",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\System",
			ValueName = "EnableSmartScreen",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\System",
			ValueName = "ShellSmartScreenLevel",
			ExpectedValue = "Block",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\System",
			ValueName = "AllowCustomSSPsAPs",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\System",
			ValueName = "RunAsPPL",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy",
			ValueName = "fBlockNonDomain",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\Windows Search",
			ValueName = "AllowIndexingEncryptedStoresOrItems",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\WinRM\\Client",
			ValueName = "AllowDigest",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\WinRM\\Client",
			ValueName = "AllowUnencryptedTraffic",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\WinRM\\Client",
			ValueName = "AllowBasic",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\WinRM\\Service",
			ValueName = "AllowUnencryptedTraffic",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\WinRM\\Service",
			ValueName = "DisableRunAs",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\WinRM\\Service",
			ValueName = "AllowBasic",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\WTDS\\Components",
			ValueName = "NotifyMalicious",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\WTDS\\Components",
			ValueName = "NotifyPasswordReuse",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\WTDS\\Components",
			ValueName = "NotifyUnsafeApp",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\WTDS\\Components",
			ValueName = "ServiceEnabled",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\DNSClient",
			ValueName = "EnableMulticast",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\DNSClient",
			ValueName = "EnableNetbios",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Printers",
			ValueName = "DisableWebPnPDownload",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Printers",
			ValueName = "RedirectionGuardPolicy",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Printers",
			ValueName = "CopyFilesPolicy",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint",
			ValueName = "RestrictDriverInstallationToAdministrators",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
			ValueName = "RpcUseNamedPipeProtocol",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
			ValueName = "RpcAuthentication",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
			ValueName = "RpcProtocols",
			ExpectedValue = "5",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
			ValueName = "ForceKerberosForRpc",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
			ValueName = "RpcTcpPort",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Rpc",
			ValueName = "RestrictRemoteClients",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services",
			ValueName = "fAllowToGetHelp",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services",
			ValueName = "MinEncryptionLevel",
			ExpectedValue = "3",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services",
			ValueName = "fPromptForPassword",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services",
			ValueName = "fDisableCdm",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services",
			ValueName = "DisablePasswordSaving",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services",
			ValueName = "fEncryptRPCTraffic",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall",
			ValueName = "PolicyVersion",
			ExpectedValue = "538",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile",
			ValueName = "DefaultOutboundAction",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile",
			ValueName = "DisableNotifications",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile",
			ValueName = "EnableFirewall",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile",
			ValueName = "DefaultInboundAction",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging",
			ValueName = "LogDroppedPackets",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging",
			ValueName = "LogFileSize",
			ExpectedValue = "16384",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging",
			ValueName = "LogSuccessfulConnections",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile",
			ValueName = "EnableFirewall",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile",
			ValueName = "DisableNotifications",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile",
			ValueName = "DefaultInboundAction",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile",
			ValueName = "DefaultOutboundAction",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging",
			ValueName = "LogSuccessfulConnections",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging",
			ValueName = "LogDroppedPackets",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging",
			ValueName = "LogFileSize",
			ExpectedValue = "16384",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile",
			ValueName = "DefaultOutboundAction",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile",
			ValueName = "EnableFirewall",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile",
			ValueName = "DisableNotifications",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile",
			ValueName = "AllowLocalIPsecPolicyMerge",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile",
			ValueName = "AllowLocalPolicyMerge",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile",
			ValueName = "DefaultInboundAction",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging",
			ValueName = "LogFileSize",
			ExpectedValue = "16384",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging",
			ValueName = "LogDroppedPackets",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging",
			ValueName = "LogSuccessfulConnections",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\WindowsInkWorkspace",
			ValueName = "AllowWindowsInkWorkspace",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "SYSTEM\\CurrentControlSet\\Control\\Lsa",
			ValueName = "RunAsPPL",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "SYSTEM\\CurrentControlSet\\Control\\Print",
			ValueName = "RpcAuthnLevelPrivacyEnabled",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
			ValueName = "DisableExceptionChainValidation",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch",
			ValueName = "DriverLoadPolicy",
			ExpectedValue = "3",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
			ValueName = "SMB1",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "SYSTEM\\CurrentControlSet\\Services\\MrxSmb10",
			ValueName = "Start",
			ExpectedValue = "4",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters",
			ValueName = "NoNameReleaseOnDemand",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters",
			ValueName = "NodeType",
			ExpectedValue = "2",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
			ValueName = "EnableICMPRedirect",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
			ValueName = "DisableIPSourceRouting",
			ExpectedValue = "2",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
			ValueName = "DisableIPSourceRouting",
			ExpectedValue = "2",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
	}

	private static void AddComputerAuditPolicies(List<BaselinePolicy> p)
	{
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce923f-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success and Failure",
			ValueType = "REG_SZ",
			Section = "Audit Credential Validation"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9237-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success",
			ValueType = "REG_SZ",
			Section = "Audit Security Group Management"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9235-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success and Failure",
			ValueType = "REG_SZ",
			Section = "Audit User Account Management"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9248-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success",
			ValueType = "REG_SZ",
			Section = "Audit PNP Activity"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce922b-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success",
			ValueType = "REG_SZ",
			Section = "Audit Process Creation"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9217-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Failure",
			ValueType = "REG_SZ",
			Section = "Audit Account Lockout"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9249-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success",
			ValueType = "REG_SZ",
			Section = "Audit Group Membership"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9215-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success and Failure",
			ValueType = "REG_SZ",
			Section = "Audit Logon"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce921c-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success and Failure",
			ValueType = "REG_SZ",
			Section = "Audit Other Logon/Logoff Events"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce921b-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success",
			ValueType = "REG_SZ",
			Section = "Audit Special Logon"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9244-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Failure",
			ValueType = "REG_SZ",
			Section = "Audit Detailed File Share"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9224-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success and Failure",
			ValueType = "REG_SZ",
			Section = "Audit File Share"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9227-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success and Failure",
			ValueType = "REG_SZ",
			Section = "Audit Other Object Access Events"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9245-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success and Failure",
			ValueType = "REG_SZ",
			Section = "Audit Removable Storage"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce922f-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success",
			ValueType = "REG_SZ",
			Section = "Audit Audit Policy Change"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9230-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success",
			ValueType = "REG_SZ",
			Section = "Audit Authentication Policy Change"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9232-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success and Failure",
			ValueType = "REG_SZ",
			Section = "Audit MPSSVC Rule-Level Policy Change"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9234-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Failure",
			ValueType = "REG_SZ",
			Section = "Audit Other Policy Change Events"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9228-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success",
			ValueType = "REG_SZ",
			Section = "Audit Sensitive Privilege Use"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9214-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success and Failure",
			ValueType = "REG_SZ",
			Section = "Audit Other System Events"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9210-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success",
			ValueType = "REG_SZ",
			Section = "Audit Security State Change"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9211-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success",
			ValueType = "REG_SZ",
			Section = "Audit Security System Extension"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Computer",
			Type = PolicyType.AuditPolicy,
			KeyPath = "Audit Policy",
			ValueName = "{0cce9212-69ae-11d9-bed3-505054503030}",
			ExpectedValue = "Success and Failure",
			ValueType = "REG_SZ",
			Section = "Audit System Integrity"
		});
	}

	private static void AddDefenderAntivirusPolicies(List<BaselinePolicy> p)
	{
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender",
			ValueName = "PUAProtection",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender",
			ValueName = "DisableLocalAdminMerge",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender",
			ValueName = "HideExclusionsFromLocalAdmins",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender",
			ValueName = "DisableRoutinelyTakingAction",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Features",
			ValueName = "PassiveRemediation",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\MpEngine",
			ValueName = "MpCloudBlockLevel",
			ExpectedValue = "2",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\MpEngine",
			ValueName = "MpBafsExtendedTimeout",
			ExpectedValue = "50",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\NIS",
			ValueName = "EnableConvertWarnToBlock",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
			ValueName = "DisableIOAVProtection",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
			ValueName = "DisableRealtimeMonitoring",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
			ValueName = "DisableScriptScanning",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
			ValueName = "DisableBehaviorMonitoring",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
			ValueName = "RealtimeScanDirection",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
			ValueName = "DisableOnAccessProtection",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
			ValueName = "DisableScanOnRealtimeEnable",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
			ValueName = "OobeEnableRtpAndSigUpdate",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Reporting",
			ValueName = "EnableDynamicSignatureDroppedEventReporting",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Scan",
			ValueName = "DisableRemovableDriveScanning",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Scan",
			ValueName = "QuickScanIncludeExclusions",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Spynet",
			ValueName = "SpynetReporting",
			ExpectedValue = "2",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Spynet",
			ValueName = "DisableBlockAtFirstSeen",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Spynet",
			ValueName = "SubmitSamplesConsent",
			ExpectedValue = "3",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR",
			ValueName = "ExploitGuard_ASR_Rules",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "3b576869-a4ec-4529-8536-b80a7769e899",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "d3e037e1-3eb8-44c8-a917-57927947596d",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "26190899-1602-49e8-8b27-eb1d0a1ce869",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "c1db55ab-c21a-4637-bb3f-a12568109d35",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "e6db77e5-3df2-4cf1-b95a-636979351e5b",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "56a863a9-875e-4185-98a7-b882c64b5ce5",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules",
			ValueName = "d1e49aac-8f56-4280-b9ba-993a6d77406c",
			ExpectedValue = "2",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Defender Antivirus",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection",
			ValueName = "EnableNetworkProtection",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
	}

	private static void AddBitLockerPolicies(List<BaselinePolicy> p)
	{
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - BitLocker",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\FVE",
			ValueName = "UseEnhancedPin",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - BitLocker",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\FVE",
			ValueName = "RDVDenyCrossOrg",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - BitLocker",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\FVE",
			ValueName = "DisableExternalDMAUnderLock",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - BitLocker",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\abfc2519-3608-4c2a-94ea-171b0ed546ab",
			ValueName = "DCSettingIndex",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - BitLocker",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\abfc2519-3608-4c2a-94ea-171b0ed546ab",
			ValueName = "ACSettingIndex",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - BitLocker",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions",
			ValueName = "DenyDeviceClasses",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - BitLocker",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions",
			ValueName = "DenyDeviceClassesRetroactive",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - BitLocker",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions\\DenyDeviceClasses",
			ValueName = "1",
			ExpectedValue = "{d48179be-ec20-11d1-b6b8-00c04fa372a7}",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - BitLocker",
			Type = PolicyType.Registry,
			KeyPath = "System\\CurrentControlSet\\Policies\\Microsoft\\FVE",
			ValueName = "RDVDenyWriteAccess",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
	}

	private static void AddCredentialGuardPolicies(List<BaselinePolicy> p)
	{
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Credential Guard",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
			ValueName = "EnableVirtualizationBasedSecurity",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Credential Guard",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
			ValueName = "RequirePlatformSecurityFeatures",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Credential Guard",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
			ValueName = "HypervisorEnforcedCodeIntegrity",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Credential Guard",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
			ValueName = "HVCIMATRequired",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Credential Guard",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
			ValueName = "LsaCfgFlags",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Credential Guard",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
			ValueName = "MachineIdentityIsolation",
			ExpectedValue = "3",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Credential Guard",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
			ValueName = "ConfigureSystemGuardLaunch",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - Credential Guard",
			Type = PolicyType.Registry,
			KeyPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
			ValueName = "ConfigureKernelShadowStacksLaunch",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
	}

	private static void AddIE11ComputerPolicies(List<BaselinePolicy> p)
	{
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext",
			ValueName = "RunThisTimeEnabled",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext",
			ValueName = "VersionCheckEnabled",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Download",
			ValueName = "RunInvalidSignatures",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Download",
			ValueName = "CheckExeSignatures",
			ExpectedValue = "yes",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main",
			ValueName = "Isolation64Bit",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main",
			ValueName = "DisableEPMCompat",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main",
			ValueName = "Isolation",
			ExpectedValue = "PMEM",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main",
			ValueName = "DisableInternetExplorerLaunchViaCOM",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_DISABLE_MK_PROTOCOL",
			ValueName = "(Reserved)",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_DISABLE_MK_PROTOCOL",
			ValueName = "iexplore.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_DISABLE_MK_PROTOCOL",
			ValueName = "explorer.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_MIME_HANDLING",
			ValueName = "explorer.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_MIME_HANDLING",
			ValueName = "iexplore.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_MIME_HANDLING",
			ValueName = "(Reserved)",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_MIME_SNIFFING",
			ValueName = "explorer.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_MIME_SNIFFING",
			ValueName = "iexplore.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_MIME_SNIFFING",
			ValueName = "(Reserved)",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_ACTIVEXINSTALL",
			ValueName = "(Reserved)",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_ACTIVEXINSTALL",
			ValueName = "explorer.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_ACTIVEXINSTALL",
			ValueName = "iexplore.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_FILEDOWNLOAD",
			ValueName = "(Reserved)",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_FILEDOWNLOAD",
			ValueName = "iexplore.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_FILEDOWNLOAD",
			ValueName = "explorer.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_SECURITYBAND",
			ValueName = "(Reserved)",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_SECURITYBAND",
			ValueName = "iexplore.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_SECURITYBAND",
			ValueName = "explorer.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_WINDOW_RESTRICTIONS",
			ValueName = "iexplore.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_WINDOW_RESTRICTIONS",
			ValueName = "(Reserved)",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_WINDOW_RESTRICTIONS",
			ValueName = "explorer.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_ZONE_ELEVATION",
			ValueName = "(Reserved)",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_ZONE_ELEVATION",
			ValueName = "explorer.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_ZONE_ELEVATION",
			ValueName = "iexplore.exe",
			ExpectedValue = "1",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\PhishingFilter",
			ValueName = "PreventOverrideAppRepUnknown",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\PhishingFilter",
			ValueName = "PreventOverride",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\PhishingFilter",
			ValueName = "EnabledV9",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Restrictions",
			ValueName = "NoCrashDetection",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Security",
			ValueName = "DisableSecuritySettingsCheck",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Security\\ActiveX",
			ValueName = "BlockNonAdminActiveXInstall",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\AxInstaller",
			ValueName = "OnlyUseAXISForActiveXInstall",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			ValueName = "Security_zones_map_edit",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			ValueName = "Security_options_edit",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			ValueName = "Security_HKLM_only",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			ValueName = "CertificateRevocation",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			ValueName = "PreventIgnoreCertErrors",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			ValueName = "WarnOnBadCertRecving",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			ValueName = "EnableSSL3Fallback",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			ValueName = "SecureProtocols",
			ExpectedValue = "2560",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - Computer",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap",
			ValueName = "UNCAsIntranet",
			ExpectedValue = "0",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
	}

	private static void AddIE11UserPolicies(List<BaselinePolicy> p)
	{
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - User",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel",
			ValueName = "FormSuggest Passwords",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - User",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main",
			ValueName = "FormSuggest PW Ask",
			ExpectedValue = "no",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Internet Explorer 11 - User",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Internet Explorer\\Main",
			ValueName = "FormSuggest Passwords",
			ExpectedValue = "no",
			ValueType = "REG_SZ",
			Section = "Registry Policy"
		});
	}

	private static void AddUserPolicies(List<BaselinePolicy> p)
	{
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - User",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CloudContent",
			ValueName = "DisableThirdPartySuggestions",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
		p.Add(new BaselinePolicy
		{
			GpoName = "MSFT Windows 11 25H2 - User",
			Type = PolicyType.Registry,
			KeyPath = "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
			ValueName = "NoToastApplicationNotificationOnLockScreen",
			ExpectedValue = "1",
			ValueType = "REG_DWORD",
			Section = "Registry Policy"
		});
	}
}
