using System;
using System.Collections.Generic;
using System.Linq;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Core.Services.Analysis;

public class CisBenchmarkMapper
{
	public class CisMapping
	{
		public string CisId { get; set; } = string.Empty;

		public string Title { get; set; } = string.Empty;

		public string Level { get; set; } = "L1";

		public string Section { get; set; } = string.Empty;

		public string ExpectedValue { get; set; } = string.Empty;

		public string Remediation { get; set; } = string.Empty;

		public string[]? CheckNameContains { get; set; }
	}

	public static readonly List<CisMapping> Mappings = new List<CisMapping>
	{
		new CisMapping
		{
			CisId = "1.1.1",
			Title = "Ensure 'Enforce password history' is set to '24 or more password(s)'",
			Level = "L1",
			Section = "Account Policies",
			ExpectedValue = "24 or more",
			CheckNameContains = new string[1] { "Password History" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Enforce password history → 24 or more password(s)"
		},
		new CisMapping
		{
			CisId = "1.1.2",
			Title = "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'",
			Level = "L1",
			Section = "Account Policies",
			ExpectedValue = "365 or fewer (not 0)",
			CheckNameContains = new string[1] { "Maximum Password Age" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Maximum password age → 365 or fewer days, but not 0"
		},
		new CisMapping
		{
			CisId = "1.1.3",
			Title = "Ensure 'Minimum password age' is set to '1 or more day(s)'",
			Level = "L1",
			Section = "Account Policies",
			ExpectedValue = "1 or more day(s)",
			CheckNameContains = new string[1] { "Minimum Password Age" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Minimum password age → 1 or more day(s)"
		},
		new CisMapping
		{
			CisId = "1.1.4",
			Title = "Ensure 'Minimum password length' is set to '14 or more character(s)'",
			Level = "L1",
			Section = "Account Policies",
			ExpectedValue = "14 or more",
			CheckNameContains = new string[1] { "Minimum Length" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Minimum password length → 14 or more character(s)"
		},
		new CisMapping
		{
			CisId = "1.1.5",
			Title = "Ensure 'Password must meet complexity requirements' is set to 'Enabled'",
			Level = "L1",
			Section = "Account Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "Password Policy" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Password must meet complexity requirements → Enabled"
		},
		new CisMapping
		{
			CisId = "1.1.6",
			Title = "Ensure 'Relax minimum password length limits' is set to 'Enabled'",
			Level = "L1",
			Section = "Account Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[2] { "Password Policy", "Minimum Length" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Relax minimum password length limits → Enabled"
		},
		new CisMapping
		{
			CisId = "1.1.7",
			Title = "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'",
			Level = "L1",
			Section = "Account Policies",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "Password Policy" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Store passwords using reversible encryption → Disabled"
		},
		new CisMapping
		{
			CisId = "1.2.1",
			Title = "Ensure 'Account lockout duration' is set to '15 or more minute(s)'",
			Level = "L1",
			Section = "Account Policies",
			ExpectedValue = "15 or more minute(s)",
			CheckNameContains = new string[1] { "Lockout Duration" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Account Lockout Policy\\Account lockout duration → 15 or more minute(s)"
		},
		new CisMapping
		{
			CisId = "1.2.2",
			Title = "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'",
			Level = "L1",
			Section = "Account Policies",
			ExpectedValue = "5 or fewer (not 0)",
			CheckNameContains = new string[1] { "Lockout Threshold" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Account Lockout Policy\\Account lockout threshold → 5 or fewer invalid logon attempt(s), but not 0"
		},
		new CisMapping
		{
			CisId = "1.2.3",
			Title = "Ensure 'Allow Administrator account lockout' is set to 'Enabled'",
			Level = "L1",
			Section = "Account Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "Lockout Threshold" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Account Lockout Policy\\Allow Administrator account lockout → Enabled"
		},
		new CisMapping
		{
			CisId = "1.2.4",
			Title = "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'",
			Level = "L1",
			Section = "Account Policies",
			ExpectedValue = "15 or more minute(s)",
			CheckNameContains = new string[1] { "Lockout Observation Window" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Account Lockout Policy\\Reset account lockout counter after → 15 or more minute(s)"
		},
		new CisMapping
		{
			CisId = "2.3.1.1",
			Title = "Ensure 'Accounts: Administrator account status' is set to 'Disabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[2] { "Built-in Administrator", "Active" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Accounts: Administrator account status → Disabled"
		},
		new CisMapping
		{
			CisId = "2.3.1.2",
			Title = "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Users can't add or log on with Microsoft accounts",
			CheckNameContains = new string[2] { "MSA", "Microsoft Account" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Accounts: Block Microsoft accounts → Users can't add or log on with Microsoft accounts"
		},
		new CisMapping
		{
			CisId = "2.3.1.3",
			Title = "Ensure 'Accounts: Guest account status' is set to 'Disabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "Guest Account" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Accounts: Guest account status → Disabled"
		},
		new CisMapping
		{
			CisId = "2.3.1.5",
			Title = "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "LimitBlankPasswordUse" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Accounts: Limit local account use of blank passwords to console logon only → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.2.1",
			Title = "Ensure 'Audit: Force audit policy subcategory settings to override audit policy category settings' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "Subcategory Override" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.4.1",
			Title = "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[2] { "Point and Print", "PrintNightmare" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Devices: Prevent users from installing printer drivers → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.7.1",
			Title = "Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[2] { "Économiseur d'écran", "Ouverture de session" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Don't display last signed-in → Enabled. Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName = 1"
		},
		new CisMapping
		{
			CisId = "2.3.7.2",
			Title = "Ensure 'Interactive logon: Don't display username at sign-in' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[2] { "Ouverture de session", "AutoAdminLogon" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Don't display username at sign-in → Enabled. Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayUserName = 1"
		},
		new CisMapping
		{
			CisId = "2.3.7.3",
			Title = "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "900 or fewer (not 0)",
			CheckNameContains = new string[1] { "InactivityTimeout" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Machine inactivity limit → 900 or fewer second(s), but not 0"
		},
		new CisMapping
		{
			CisId = "2.3.7.4",
			Title = "Ensure 'Interactive logon: Message text for users attempting to log on' is configured",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Configured (non-empty)",
			CheckNameContains = new string[1] { "Legal Banner" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Message text for users attempting to log on → Configure a legal notice message"
		},
		new CisMapping
		{
			CisId = "2.3.7.5",
			Title = "Ensure 'Interactive logon: Message title for users attempting to log on' is configured",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Configured (non-empty)",
			CheckNameContains = new string[1] { "Legal Banner" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Message title for users attempting to log on → Configure a legal notice title"
		},
		new CisMapping
		{
			CisId = "2.3.7.7",
			Title = "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[2] { "Ouverture de session", "AutoAdminLogon" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Do not require CTRL+ALT+DEL → Disabled. Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD = 0"
		},
		new CisMapping
		{
			CisId = "2.3.8.1",
			Title = "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "SMB: Client Signing" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Microsoft network client: Digitally sign communications (always) → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.8.2",
			Title = "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[2] { "SMB Encryption", "SMB: Server Encryption" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Microsoft network client: Send unencrypted password to third-party SMB servers → Disabled"
		},
		new CisMapping
		{
			CisId = "2.3.9.1",
			Title = "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "SMB: Server Signing" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Microsoft network server: Digitally sign communications (always) → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.9.2",
			Title = "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "SMB: Server Signing" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Microsoft network server: Digitally sign communications (if client agrees) → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.10.1",
			Title = "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "RestrictAnonymous" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network access: Allow anonymous SID/Name translation → Disabled"
		},
		new CisMapping
		{
			CisId = "2.3.10.2",
			Title = "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "RestrictAnonymousSAM" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network access: Do not allow anonymous enumeration of SAM accounts → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.10.4",
			Title = "Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "DisableDomainCreds" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network access: Do not allow storage of passwords and credentials for network authentication → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.10.5",
			Title = "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "EveryoneIncludesAnonymous" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network access: Let Everyone permissions apply to anonymous users → Disabled"
		},
		new CisMapping
		{
			CisId = "2.3.10.7",
			Title = "Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "None",
			CheckNameContains = new string[1] { "NullSessionPipes" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network access: Named Pipes that can be accessed anonymously → (blank)"
		},
		new CisMapping
		{
			CisId = "2.3.10.9",
			Title = "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "RestrictNullSessAccess" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network access: Restrict anonymous access to Named Pipes and Shares → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.10.10",
			Title = "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is configured",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "O:BAG:BAD:(A;;RC;;;BA)",
			CheckNameContains = new string[1] { "RestrictRemoteSAM" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network access: Restrict clients allowed to make remote calls to SAM → O:BAG:BAD:(A;;RC;;;BA)"
		},
		new CisMapping
		{
			CisId = "2.3.11.1",
			Title = "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "NTLM" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: Allow Local System to use computer identity for NTLM → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.11.2",
			Title = "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[2] { "Session Nulle", "NullSession" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: Allow LocalSystem NULL session fallback → Disabled. Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\AllowNullSessionFallback = 0"
		},
		new CisMapping
		{
			CisId = "2.3.11.3",
			Title = "Ensure 'Network security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[2] { "Kerberos", "chiffrement" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: Allow PKU2U authentication requests → Disabled. Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\pku2u\\AllowOnlineID = 0"
		},
		new CisMapping
		{
			CisId = "2.3.11.4",
			Title = "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set appropriately",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types",
			CheckNameContains = new string[2] { "Kerberos", "chiffrement" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: Configure encryption types allowed for Kerberos → AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types"
		},
		new CisMapping
		{
			CisId = "2.3.11.7",
			Title = "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "NTLMv2 only (level 5)",
			CheckNameContains = new string[1] { "LmCompatibilityLevel" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: LAN Manager authentication level → Send NTLMv2 response only. Refuse LM & NTLM"
		},
		new CisMapping
		{
			CisId = "2.3.11.8",
			Title = "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Negotiate signing or Require signing",
			CheckNameContains = new string[2] { "Netlogon", "RequireSignOrSeal" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: LDAP client signing requirements → Negotiate signing or Require signing. Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity = 1 or 2"
		},
		new CisMapping
		{
			CisId = "2.3.11.9",
			Title = "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Require NTLMv2 + 128-bit (537395200)",
			CheckNameContains = new string[1] { "NTLM" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: Minimum session security for NTLM SSP based clients → Require NTLMv2 session security, Require 128-bit encryption"
		},
		new CisMapping
		{
			CisId = "2.3.11.10",
			Title = "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Require NTLMv2 + 128-bit (537395200)",
			CheckNameContains = new string[1] { "NTLM" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network security: Minimum session security for NTLM SSP based servers → Require NTLMv2 session security, Require 128-bit encryption"
		},
		new CisMapping
		{
			CisId = "2.3.17.1",
			Title = "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "FilterAdministratorToken" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\User Account Control: Admin Approval Mode for the Built-in Administrator account → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.17.2",
			Title = "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' or higher",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Prompt for consent on secure desktop (2)",
			CheckNameContains = new string[1] { "ConsentPromptBehaviorAdmin" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\User Account Control: Behavior of the elevation prompt for administrators → Prompt for consent on the secure desktop"
		},
		new CisMapping
		{
			CisId = "2.3.17.3",
			Title = "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Automatically deny (0)",
			CheckNameContains = new string[1] { "ConsentPromptBehaviorUser" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\User Account Control: Behavior of the elevation prompt for standard users → Automatically deny elevation requests"
		},
		new CisMapping
		{
			CisId = "2.3.17.4",
			Title = "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "EnableInstallerDetection" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\User Account Control: Detect application installations and prompt for elevation → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.17.5",
			Title = "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "ValidateAdminCodeSignatures" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\User Account Control: Only elevate UIAccess applications that are installed in secure locations → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.17.6",
			Title = "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "EnableLUA" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\User Account Control: Run all administrators in Admin Approval Mode → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.17.7",
			Title = "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "PromptOnSecureDesktop" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\User Account Control: Switch to the secure desktop when prompting for elevation → Enabled"
		},
		new CisMapping
		{
			CisId = "2.3.17.8",
			Title = "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'",
			Level = "L1",
			Section = "Local Policies",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "UAC: EnableVirtualization" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\User Account Control: Virtualize file and registry write failures to per-user locations → Enabled"
		},
		new CisMapping
		{
			CisId = "5.1",
			Title = "Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled'",
			Level = "L1",
			Section = "System Services",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[2] { "Bluetooth", "Service" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\System Services\\Bluetooth Audio Gateway Service → Disabled. Run: Set-Service BTAGService -StartupType Disabled"
		},
		new CisMapping
		{
			CisId = "5.2",
			Title = "Ensure 'Bluetooth Support Service (bthserv)' is set to 'Disabled'",
			Level = "L1",
			Section = "System Services",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[2] { "Bluetooth", "BTHPORT" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\System Services\\Bluetooth Support Service → Disabled. Run: Set-Service bthserv -StartupType Disabled"
		},
		new CisMapping
		{
			CisId = "5.6",
			Title = "Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'",
			Level = "L1",
			Section = "System Services",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_1.1.1" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\System Services\\Computer Browser → Disabled. Run: Set-Service Browser -StartupType Disabled"
		},
		new CisMapping
		{
			CisId = "5.9",
			Title = "Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled'",
			Level = "L1",
			Section = "System Services",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_5.9" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\System Services\\Downloaded Maps Manager → Disabled. Run: Set-Service MapsBroker -StartupType Disabled"
		},
		new CisMapping
		{
			CisId = "5.20",
			Title = "Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled'",
			Level = "L2",
			Section = "System Services",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_5.20" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\System Services\\Link-Layer Topology Discovery Mapper → Disabled. Run: Set-Service lltdsvc -StartupType Disabled"
		},
		new CisMapping
		{
			CisId = "5.29",
			Title = "Ensure 'Print Spooler (Spooler)' is set to 'Disabled' or 'Not Installed'",
			Level = "L1",
			Section = "System Services",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "Print Spooler" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\System Services\\Print Spooler → Disabled"
		},
		new CisMapping
		{
			CisId = "5.36",
			Title = "Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled'",
			Level = "L2",
			Section = "System Services",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[2] { "RDP", "État" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\System Services\\Remote Desktop Services → Disabled. Run: Set-Service TermService -StartupType Disabled"
		},
		new CisMapping
		{
			CisId = "5.38",
			Title = "Ensure 'Remote Procedure Call Locator (RpcLocator)' is set to 'Disabled'",
			Level = "L2",
			Section = "System Services",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_5.29" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\System Services\\Remote Procedure Call Locator → Disabled. Run: Set-Service RpcLocator -StartupType Disabled"
		},
		new CisMapping
		{
			CisId = "5.42",
			Title = "Ensure 'Server (LanmanServer)' is set to 'Disabled'",
			Level = "L2",
			Section = "System Services",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_5.42" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\System Services\\Server (LanmanServer) → Disabled. Run: Set-Service LanmanServer -StartupType Disabled"
		},
		new CisMapping
		{
			CisId = "5.48",
			Title = "Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Disabled'",
			Level = "L2",
			Section = "System Services",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "WinRM" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\System Services\\Windows Remote Management (WS-Management) → Disabled"
		},
		new CisMapping
		{
			CisId = "9.1.1",
			Title = "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = "On",
			CheckNameContains = new string[1] { "Domain Profile: Firewall Enabled" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Domain Profile\\Firewall state → On (recommended)"
		},
		new CisMapping
		{
			CisId = "9.1.2",
			Title = "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = "Block",
			CheckNameContains = new string[1] { "Domain Profile: Default Inbound" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Domain Profile\\Inbound connections → Block (default)"
		},
		new CisMapping
		{
			CisId = "9.1.3",
			Title = "Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = "Allow",
			CheckNameContains = new string[1] { "Domain Profile: Default Outbound" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Domain Profile\\Outbound connections → Allow (default)"
		},
		new CisMapping
		{
			CisId = "9.1.4",
			Title = "Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = "Yes",
			CheckNameContains = new string[1] { "Domain Profile: Log Dropped" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Domain Profile\\Logging\\Log dropped packets → Yes"
		},
		new CisMapping
		{
			CisId = "9.1.5",
			Title = "Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = ">= 16384 KB",
			CheckNameContains = new string[1] { "Domain Profile: Log File" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Domain Profile\\Logging\\Size limit (KB) → 16384 or greater"
		},
		new CisMapping
		{
			CisId = "9.2.1",
			Title = "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = "On",
			CheckNameContains = new string[1] { "Private Profile: Firewall Enabled" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Private Profile\\Firewall state → On (recommended)"
		},
		new CisMapping
		{
			CisId = "9.2.2",
			Title = "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = "Block",
			CheckNameContains = new string[1] { "Private Profile: Default Inbound" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Private Profile\\Inbound connections → Block (default)"
		},
		new CisMapping
		{
			CisId = "9.2.3",
			Title = "Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = "Allow",
			CheckNameContains = new string[1] { "Private Profile: Default Outbound" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Private Profile\\Outbound connections → Allow (default)"
		},
		new CisMapping
		{
			CisId = "9.2.4",
			Title = "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = "Yes",
			CheckNameContains = new string[1] { "Private Profile: Log Dropped" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Private Profile\\Logging\\Log dropped packets → Yes"
		},
		new CisMapping
		{
			CisId = "9.2.5",
			Title = "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = ">= 16384 KB",
			CheckNameContains = new string[1] { "Private Profile: Log File" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Private Profile\\Logging\\Size limit (KB) → 16384 or greater"
		},
		new CisMapping
		{
			CisId = "9.3.1",
			Title = "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = "On",
			CheckNameContains = new string[1] { "Public Profile: Firewall Enabled" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Public Profile\\Firewall state → On (recommended)"
		},
		new CisMapping
		{
			CisId = "9.3.2",
			Title = "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = "Block",
			CheckNameContains = new string[1] { "Public Profile: Default Inbound" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Public Profile\\Inbound connections → Block (default)"
		},
		new CisMapping
		{
			CisId = "9.3.3",
			Title = "Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = "Allow",
			CheckNameContains = new string[1] { "Public Profile: Default Outbound" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Public Profile\\Outbound connections → Allow (default)"
		},
		new CisMapping
		{
			CisId = "9.3.4",
			Title = "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = "Yes",
			CheckNameContains = new string[1] { "Public Profile: Log Dropped" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Public Profile\\Logging\\Log dropped packets → Yes"
		},
		new CisMapping
		{
			CisId = "9.3.5",
			Title = "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'",
			Level = "L1",
			Section = "Windows Firewall",
			ExpectedValue = ">= 16384 KB",
			CheckNameContains = new string[1] { "Public Profile: Log File" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall with Advanced Security\\Public Profile\\Logging\\Size limit (KB) → 16384 or greater"
		},
		new CisMapping
		{
			CisId = "17.1.1",
			Title = "Ensure 'Audit Credential Validation' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[1] { "Credential Validation" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Account Logon\\Audit Credential Validation → Success and Failure"
		},
		new CisMapping
		{
			CisId = "17.2.1",
			Title = "Ensure 'Audit Application Group Management' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[1] { "Application Group Management" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Account Management\\Audit Application Group Management → Success and Failure"
		},
		new CisMapping
		{
			CisId = "17.2.5",
			Title = "Ensure 'Audit Security Group Management' is set to include 'Success'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success",
			CheckNameContains = new string[1] { "Security Group Management" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Account Management\\Audit Security Group Management → Success"
		},
		new CisMapping
		{
			CisId = "17.2.6",
			Title = "Ensure 'Audit User Account Management' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[1] { "User Account Management" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Account Management\\Audit User Account Management → Success and Failure"
		},
		new CisMapping
		{
			CisId = "17.3.1",
			Title = "Ensure 'Audit PNP Activity' is set to include 'Success'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success",
			CheckNameContains = new string[1] { "Plug and Play" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Detailed Tracking\\Audit PNP Activity → Success"
		},
		new CisMapping
		{
			CisId = "17.3.2",
			Title = "Ensure 'Audit Process Creation' is set to include 'Success'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success",
			CheckNameContains = new string[2] { "Audit:", "Process Creation" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Detailed Tracking\\Audit Process Creation → Success"
		},
		new CisMapping
		{
			CisId = "17.5.1",
			Title = "Ensure 'Audit Account Lockout' is set to include 'Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Failure",
			CheckNameContains = new string[2] { "Audit:", "Account Lockout" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Logon/Logoff\\Audit Account Lockout → include Failure"
		},
		new CisMapping
		{
			CisId = "17.5.2",
			Title = "Ensure 'Audit Group Membership' is set to include 'Success'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success",
			CheckNameContains = new string[1] { "Group Membership" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Logon/Logoff\\Audit Group Membership → Success"
		},
		new CisMapping
		{
			CisId = "17.5.3",
			Title = "Ensure 'Audit Logoff' is set to include 'Success'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success",
			CheckNameContains = new string[2] { "Audit:", "Logoff" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Logon/Logoff\\Audit Logoff → Success"
		},
		new CisMapping
		{
			CisId = "17.5.4",
			Title = "Ensure 'Audit Logon' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[2] { "Audit:", "> Logon" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Logon/Logoff\\Audit Logon → Success and Failure"
		},
		new CisMapping
		{
			CisId = "17.5.5",
			Title = "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[1] { "Other Logon/Logoff" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Logon/Logoff\\Audit Other Logon/Logoff Events → Success and Failure"
		},
		new CisMapping
		{
			CisId = "17.5.6",
			Title = "Ensure 'Audit Special Logon' is set to include 'Success'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success",
			CheckNameContains = new string[1] { "Special Logon" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Logon/Logoff\\Audit Special Logon → Success"
		},
		new CisMapping
		{
			CisId = "17.6.1",
			Title = "Ensure 'Audit Detailed File Share' is set to include 'Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Failure",
			CheckNameContains = new string[1] { "Detailed File Share" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Object Access\\Audit Detailed File Share → include Failure"
		},
		new CisMapping
		{
			CisId = "17.6.2",
			Title = "Ensure 'Audit File Share' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[1] { "> File Share" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Object Access\\Audit File Share → Success and Failure"
		},
		new CisMapping
		{
			CisId = "17.6.3",
			Title = "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[1] { "Other Object Access" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Object Access\\Audit Other Object Access Events → Success and Failure"
		},
		new CisMapping
		{
			CisId = "17.6.4",
			Title = "Ensure 'Audit Removable Storage' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[1] { "Removable Storage" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Object Access\\Audit Removable Storage → Success and Failure"
		},
		new CisMapping
		{
			CisId = "17.7.1",
			Title = "Ensure 'Audit Audit Policy Change' is set to include 'Success'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success",
			CheckNameContains = new string[1] { "Audit Policy Change" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Policy Change\\Audit Audit Policy Change → Success"
		},
		new CisMapping
		{
			CisId = "17.7.2",
			Title = "Ensure 'Audit Authentication Policy Change' is set to include 'Success'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success",
			CheckNameContains = new string[1] { "Authentication Policy Change" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Policy Change\\Audit Authentication Policy Change → Success"
		},
		new CisMapping
		{
			CisId = "17.7.3",
			Title = "Ensure 'Audit Authorization Policy Change' is set to include 'Success'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success",
			CheckNameContains = new string[1] { "Authorization Policy Change" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Policy Change\\Audit Authorization Policy Change → Success"
		},
		new CisMapping
		{
			CisId = "17.7.4",
			Title = "Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[1] { "MPSSVC Rule-Level" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Policy Change\\Audit MPSSVC Rule-Level Policy Change → Success and Failure"
		},
		new CisMapping
		{
			CisId = "17.8.1",
			Title = "Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[1] { "Sensitive Privilege Use" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Privilege Use\\Audit Sensitive Privilege Use → Success and Failure"
		},
		new CisMapping
		{
			CisId = "17.9.1",
			Title = "Ensure 'Audit IPsec Driver' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[1] { "IPsec Driver" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\System\\Audit IPsec Driver → Success and Failure"
		},
		new CisMapping
		{
			CisId = "17.9.2",
			Title = "Ensure 'Audit Other System Events' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[1] { "Other System Events" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\System\\Audit Other System Events → Success and Failure"
		},
		new CisMapping
		{
			CisId = "17.9.3",
			Title = "Ensure 'Audit Security State Change' is set to include 'Success'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success",
			CheckNameContains = new string[1] { "Security State Change" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\System\\Audit Security State Change → Success"
		},
		new CisMapping
		{
			CisId = "17.9.4",
			Title = "Ensure 'Audit Security System Extension' is set to include 'Success'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success",
			CheckNameContains = new string[1] { "Security System Extension" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\System\\Audit Security System Extension → Success"
		},
		new CisMapping
		{
			CisId = "17.9.5",
			Title = "Ensure 'Audit System Integrity' is set to 'Success and Failure'",
			Level = "L1",
			Section = "Advanced Audit Policy",
			ExpectedValue = "Success and Failure",
			CheckNameContains = new string[1] { "System Integrity" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\System\\Audit System Integrity → Success and Failure"
		},
		new CisMapping
		{
			CisId = "18.1.1.1",
			Title = "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_5.48" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Control Panel\\Personalization\\Prevent enabling lock screen camera → Enabled"
		},
		new CisMapping
		{
			CisId = "18.1.1.2",
			Title = "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_18.1.1.2" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Control Panel\\Personalization\\Prevent enabling lock screen slide show → Enabled"
		},
		new CisMapping
		{
			CisId = "18.4.1",
			Title = "Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "AutoAdminLogon" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\MSS (Legacy)\\MSS: (AutoAdminLogon) Enable Automatic Logon → Disabled"
		},
		new CisMapping
		{
			CisId = "18.4.4",
			Title = "Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Highest protection, source routing is completely disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Highest protection (2)",
			CheckNameContains = new string[1] { "CISFallback_18.4.1" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\MSS (Legacy)\\MSS: (DisableIPSourceRouting IPv6) → Highest protection, source routing is completely disabled. Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\DisableIPSourceRouting = 2"
		},
		new CisMapping
		{
			CisId = "18.4.5",
			Title = "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Highest protection, source routing is completely disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Highest protection (2)",
			CheckNameContains = new string[1] { "CISFallback_18.4.5" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\MSS (Legacy)\\MSS: (DisableIPSourceRouting) → Highest protection, source routing is completely disabled. Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\DisableIPSourceRouting = 2"
		},
		new CisMapping
		{
			CisId = "18.4.7",
			Title = "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_18.4.7" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\MSS (Legacy)\\MSS: (EnableICMPRedirect) Allow ICMP redirects → Disabled. Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\EnableICMPRedirect = 0"
		},
		new CisMapping
		{
			CisId = "18.4.9",
			Title = "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_18.4.9" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\MSS (Legacy)\\MSS: (NoNameReleaseOnDemand) → Enabled. Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\NoNameReleaseOnDemand = 1"
		},
		new CisMapping
		{
			CisId = "18.4.11",
			Title = "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_18.4.11" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\MSS (Legacy)\\MSS: (SafeDllSearchMode) → Enabled. Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SafeDllSearchMode = 1"
		},
		new CisMapping
		{
			CisId = "18.4.12",
			Title = "Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to '5 or fewer seconds'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "5 or fewer seconds",
			CheckNameContains = new string[2] { "Économiseur d'écran", "Délai" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\MSS (Legacy)\\MSS: (ScreenSaverGracePeriod) → 5 or fewer seconds. Set HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ScreenSaverGracePeriod = 5"
		},
		new CisMapping
		{
			CisId = "18.5.4.2",
			Title = "Ensure 'Turn off multicast name resolution' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "LLMNR" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Network\\DNS Client\\Turn off multicast name resolution → Enabled"
		},
		new CisMapping
		{
			CisId = "18.5.8",
			Title = "Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_18.4.12" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Network\\Microsoft Peer-to-Peer Networking Services\\Turn off Microsoft Peer-to-Peer Networking Services → Enabled"
		},
		new CisMapping
		{
			CisId = "18.5.11.2",
			Title = "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_18.5.11.2" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Network\\Network Connections\\Prohibit installation and configuration of Network Bridge on your DNS domain network → Enabled"
		},
		new CisMapping
		{
			CisId = "18.5.14.1",
			Title = "Ensure 'Hardened UNC Paths' is set to 'Enabled, with Require Mutual Authentication and Require Integrity set for all NETLOGON and SYSVOL shares'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled with RequireMutualAuthentication=1, RequireIntegrity=1",
			CheckNameContains = new string[1] { "CISFallback_18.5.14.1" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Network\\Network Provider\\Hardened UNC Paths → Enabled. \\\\*\\NETLOGON RequireMutualAuthentication=1,RequireIntegrity=1 and \\\\*\\SYSVOL RequireMutualAuthentication=1,RequireIntegrity=1"
		},
		new CisMapping
		{
			CisId = "18.5.21.1",
			Title = "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled: 3",
			CheckNameContains = new string[1] { "CISFallback_18.5.21.1" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Network\\Windows Connection Manager\\Minimize the number of simultaneous connections to the Internet or a Windows Domain → Enabled: 3 = Prevent Wi-Fi when on Ethernet"
		},
		new CisMapping
		{
			CisId = "18.6.1",
			Title = "Ensure 'Apply layered order of evaluation for Allow and Prevent device installation policies across all device match criteria' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "USB" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Device Installation\\Device Installation Restrictions\\Apply layered order of evaluation for Allow and Prevent device installation policies → Enabled"
		},
		new CisMapping
		{
			CisId = "18.8.3.1",
			Title = "Ensure 'Include command line in process creation events' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[2] { "ligne de commande", "ProcessCreation" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Audit Process Creation\\Include command line in process creation events → Enabled"
		},
		new CisMapping
		{
			CisId = "18.8.4.1",
			Title = "Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[2] { "AllowDefaultCredentials", "CredSSP" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Credentials Delegation\\Remote host allows delegation of non-exportable credentials → Enabled"
		},
		new CisMapping
		{
			CisId = "18.8.5.1",
			Title = "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[2] { "VBS", "EnableVirtualizationBasedSecurity" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Device Guard\\Turn On Virtualization Based Security → Enabled"
		},
		new CisMapping
		{
			CisId = "18.8.5.2",
			Title = "Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Secure Boot or higher",
			CheckNameContains = new string[1] { "RequirePlatformSecurity" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Device Guard\\Turn On Virtualization Based Security: Select Platform Security Level → Secure Boot or Secure Boot and DMA Protection"
		},
		new CisMapping
		{
			CisId = "18.8.5.3",
			Title = "Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled with UEFI lock",
			CheckNameContains = new string[1] { "HVCI" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Device Guard\\Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity → Enabled with UEFI lock"
		},
		new CisMapping
		{
			CisId = "18.8.5.4",
			Title = "Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled with UEFI lock",
			CheckNameContains = new string[2] { "Credential Guard", "LsaCfg" },
			Remediation = "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Turn On Virtualization Based Security: Credential Guard Configuration → Enabled with UEFI lock"
		},
		new CisMapping
		{
			CisId = "18.8.5.7",
			Title = "Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[2] { "System Guard", "Secure Launch" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Device Guard\\Turn On Virtualization Based Security: Secure Launch Configuration → Enabled"
		},
		new CisMapping
		{
			CisId = "18.8.22.1.1",
			Title = "Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[2] { "Windows Hello", "PIN" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Logon\\Turn on convenience PIN sign-in → Disabled"
		},
		new CisMapping
		{
			CisId = "18.8.22.1.2",
			Title = "Ensure 'Turn off picture password sign-in' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_18.6.1" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Logon\\Turn off picture password sign-in → Enabled"
		},
		new CisMapping
		{
			CisId = "18.8.22.1.5",
			Title = "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled: Good, unknown and bad but critical (3)",
			CheckNameContains = new string[2] { "ELAM", "Driver Load" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Early Launch Antimalware\\Boot-Start Driver Initialization Policy → Enabled: Good, unknown and bad but critical"
		},
		new CisMapping
		{
			CisId = "18.9.5.1",
			Title = "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[2] { "VBS", "EnableVirtualization" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Device Guard\\Turn On Virtualization Based Security → Enabled"
		},
		new CisMapping
		{
			CisId = "18.9.25.1",
			Title = "Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_18.8.22.1.5" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Logon\\Block user from showing account details on sign-in → Enabled"
		},
		new CisMapping
		{
			CisId = "18.9.28.2",
			Title = "Ensure 'Do not display network selection UI' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_18.9.28.2" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\System\\Logon\\Do not display network selection UI → Enabled. Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\DontDisplayNetworkSelectionUI = 1"
		},
		new CisMapping
		{
			CisId = "18.10.7.1",
			Title = "Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_18.10.7.1" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Biometrics\\Facial Features\\Configure enhanced anti-spoofing → Enabled"
		},
		new CisMapping
		{
			CisId = "18.10.9.1.1",
			Title = "Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "ASR Rules" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Microsoft Defender Antivirus\\Microsoft Defender Exploit Guard\\Attack Surface Reduction\\Configure Attack Surface Reduction rules → Enabled"
		},
		new CisMapping
		{
			CisId = "18.10.9.2.1",
			Title = "Ensure 'Block Office applications from creating child processes' ASR rule is configured",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Block (d4f940ab-401b-4efc-aadc-ad5f3c50688a = 1)",
			CheckNameContains = new string[1] { "ASR Rules" },
			Remediation = "Configure ASR rule GUID d4f940ab-401b-4efc-aadc-ad5f3c50688a = 1 (Block). See Microsoft Defender Exploit Guard ASR documentation."
		},
		new CisMapping
		{
			CisId = "18.10.9.3.1",
			Title = "Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled: Block",
			CheckNameContains = new string[1] { "Network Protection" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Microsoft Defender Antivirus\\Microsoft Defender Exploit Guard\\Network Protection\\Prevent users and apps from accessing dangerous websites → Enabled: Block"
		},
		new CisMapping
		{
			CisId = "18.10.9.4",
			Title = "Ensure 'Configure Controlled folder access' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "Controlled Folder Access" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Microsoft Defender Antivirus\\Microsoft Defender Exploit Guard\\Controlled Folder Access\\Configure Controlled folder access → Enabled"
		},
		new CisMapping
		{
			CisId = "18.10.12.1",
			Title = "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "SmartScreen" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows Defender SmartScreen\\Explorer\\Configure Windows Defender SmartScreen → Enabled"
		},
		new CisMapping
		{
			CisId = "18.10.43.5.1",
			Title = "Ensure 'Configure Windows Defender SmartScreen' (Edge) is set to 'Enabled: Warn and prevent bypass'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled: Warn and prevent bypass",
			CheckNameContains = new string[1] { "SmartScreen" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\File Explorer\\Configure Windows Defender SmartScreen → Enabled: Warn and prevent bypass"
		},
		new CisMapping
		{
			CisId = "18.10.50.1",
			Title = "Ensure 'Prevent users from modifying settings' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "Tamper Protection" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Microsoft Defender Antivirus\\Client Interface\\Prevent users from modifying settings → Enabled"
		},
		new CisMapping
		{
			CisId = "18.10.57.1",
			Title = "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled: All drives",
			CheckNameContains = new string[2] { "AutoRun", "AutoPlay" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\AutoPlay Policies\\Turn off Autoplay → Enabled: All drives"
		},
		new CisMapping
		{
			CisId = "18.10.76.3.1",
			Title = "Ensure 'Configure Windows Spotlight on lock screen' is set to 'Disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_18.10.9.1.1" },
			Remediation = "User Configuration\\Policies\\Administrative Templates\\Windows Components\\Cloud Content\\Configure Windows Spotlight on lock screen → Disabled"
		},
		new CisMapping
		{
			CisId = "18.10.80.1",
			Title = "Ensure 'Allow Cortana' is set to 'Disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_18.10.80.1" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Search\\Allow Cortana → Disabled. Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\AllowCortana = 0"
		},
		new CisMapping
		{
			CisId = "18.10.89.1",
			Title = "Ensure 'Turn off Windows Game Recording and Broadcasting' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_18.10.89.1" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows Game Recording and Broadcasting\\Turn off Windows Game Recording and Broadcasting → Enabled. Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\\AllowGameDVR = 0"
		},
		new CisMapping
		{
			CisId = "18.10.92.1",
			Title = "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "ScriptBlock" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows PowerShell\\Turn on PowerShell Script Block Logging → Enabled"
		},
		new CisMapping
		{
			CisId = "18.10.92.2",
			Title = "Ensure 'Turn on PowerShell Transcription' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "Transcription" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows PowerShell\\Turn on PowerShell Transcription → Enabled"
		},
		new CisMapping
		{
			CisId = "18.10.93.1",
			Title = "Ensure 'Allow Basic authentication' (WinRM Client) is set to 'Disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_18.10.92.1" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows Remote Management (WinRM)\\WinRM Client\\Allow Basic authentication → Disabled. Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\AllowBasic = 0"
		},
		new CisMapping
		{
			CisId = "18.10.93.2",
			Title = "Ensure 'Allow unencrypted traffic' (WinRM Client) is set to 'Disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_18.10.93.2" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows Remote Management (WinRM)\\WinRM Client\\Allow unencrypted traffic → Disabled. Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\AllowUnencryptedTraffic = 0"
		},
		new CisMapping
		{
			CisId = "18.10.93.3",
			Title = "Ensure 'Disallow Digest authentication' (WinRM Client) is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_18.10.93.3" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows Remote Management (WinRM)\\WinRM Client\\Disallow Digest authentication → Enabled. Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\AllowDigest = 0"
		},
		new CisMapping
		{
			CisId = "18.10.93.4",
			Title = "Ensure 'Allow Basic authentication' (WinRM Service) is set to 'Disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_18.10.93.4" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows Remote Management (WinRM)\\WinRM Service\\Allow Basic authentication → Disabled. Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\AllowBasic = 0"
		},
		new CisMapping
		{
			CisId = "18.10.93.5",
			Title = "Ensure 'Allow unencrypted traffic' (WinRM Service) is set to 'Disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_18.10.93.5" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows Remote Management (WinRM)\\WinRM Service\\Allow unencrypted traffic → Disabled. Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\AllowUnencryptedTraffic = 0"
		},
		new CisMapping
		{
			CisId = "18.10.93.6",
			Title = "Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[1] { "CISFallback_18.10.93.6" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows Remote Management (WinRM)\\WinRM Service\\Disallow WinRM from storing RunAs credentials → Enabled. Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\DisableRunAs = 1"
		},
		new CisMapping
		{
			CisId = "18.10.95.1",
			Title = "Ensure 'Allow Remote Shell Access' is set to 'Disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[1] { "CISFallback_18.10.95.1" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows Remote Shell\\Allow Remote Shell Access → Disabled. Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\WinRS\\AllowRemoteShellAccess = 0"
		},
		new CisMapping
		{
			CisId = "18.10.97.1",
			Title = "Ensure 'Configure Automatic Updates' is set to 'Enabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Enabled",
			CheckNameContains = new string[2] { "Windows Update", "automatique" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows Update\\Manage end user experience\\Configure Automatic Updates → Enabled"
		},
		new CisMapping
		{
			CisId = "18.10.97.2",
			Title = "Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'",
			Level = "L1",
			Section = "Administrative Templates",
			ExpectedValue = "Disabled",
			CheckNameContains = new string[2] { "Windows Update", "Redémarrages" },
			Remediation = "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows Update\\Manage end user experience\\No auto-restart with logged on users for scheduled automatic updates installations → Disabled"
		}
	};

	public List<CisBenchmarkItem> MapResults(List<SecurityResult>? allResults)
	{
		List<CisBenchmarkItem> items = new List<CisBenchmarkItem>(Mappings.Count);
		if (allResults == null)
		{
			allResults = new List<SecurityResult>();
		}
		foreach (CisMapping mapping in Mappings)
		{
			CisBenchmarkItem cisBenchmarkItem = new CisBenchmarkItem
			{
				CisId = mapping.CisId,
				Title = mapping.Title,
				Level = mapping.Level,
				Section = mapping.Section,
				ExpectedValue = mapping.ExpectedValue,
				Remediation = mapping.Remediation
			};
			if (mapping.CheckNameContains == null || mapping.CheckNameContains.Length == 0)
			{
				cisBenchmarkItem.Status = "Manual";
				cisBenchmarkItem.CurrentValue = "Non vérifié automatiquement";
				cisBenchmarkItem.IsCompliant = false;
				cisBenchmarkItem.IsManualCheck = true;
				items.Add(cisBenchmarkItem);
				continue;
			}
			SecurityResult match = FindMatchingResult(allResults, mapping.CheckNameContains);
			if (match == null)
			{
				cisBenchmarkItem.Status = "Not Checked";
				cisBenchmarkItem.CurrentValue = "N/A";
				cisBenchmarkItem.IsCompliant = false;
			}
			else
			{
				cisBenchmarkItem.CurrentValue = match.CurrentValue;
				switch (match.Status)
				{
				case SecurityStatus.OK:
					cisBenchmarkItem.Status = "Pass";
					cisBenchmarkItem.IsCompliant = true;
					break;
				case SecurityStatus.Warning:
					cisBenchmarkItem.Status = "Fail";
					cisBenchmarkItem.IsCompliant = false;
					break;
				case SecurityStatus.Critical:
					cisBenchmarkItem.Status = "Fail";
					cisBenchmarkItem.IsCompliant = false;
					break;
				default:
					cisBenchmarkItem.Status = "Manual";
					cisBenchmarkItem.IsCompliant = false;
					break;
				}
			}
			items.Add(cisBenchmarkItem);
		}
		return items;
	}

	private static SecurityResult? FindMatchingResult(List<SecurityResult> allResults, string[] terms)
	{
		// Correctif M7: uniquement le match strict (terms.All). Le fallback terms.Any est supprimé
		// car il attachait le statut d'un résultat sans rapport (mot générique) → faux Pass.
		// Aucun match strict → null → le contrôle CIS est traité comme « Not Checked » / non conforme.
		return allResults.FirstOrDefault((SecurityResult result) => terms.All((string term) => result.CheckName.Contains(term, StringComparison.OrdinalIgnoreCase)));
	}
}
