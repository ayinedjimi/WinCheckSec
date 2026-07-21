using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class UserAccountsCollector : ISecurityCollector
{
	public string Name => "User Accounts";

	public string Category => "User & Account Security";

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
			CollectLocalUsers(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectPasswordPolicy(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectLsaSecuritySettings(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "UserAccountsCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectLocalUsers(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			bool guestEnabled = false;
			bool defaultAdminEnabled = false;
			bool defaultAdminRenamed = true;
			int totalUsers = 0;
			int enabledUsers = 0;
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_UserAccount WHERE LocalAccount=True");
			try
			{
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				foreach (ManagementObject userAccount in managementObjectCollection)
				{
					ManagementObject userAccountToDispose = userAccount;
					try
					{
						ct.ThrowIfCancellationRequested();
						int counter = totalUsers;
						totalUsers = counter + 1;
						string name = userAccount["Name"]?.ToString() ?? "Unknown";
						string sid = userAccount["SID"]?.ToString() ?? "";
						bool disabled = Convert.ToBoolean(userAccount["Disabled"] ?? ((object)true));
						bool lockedOut = Convert.ToBoolean(userAccount["Lockout"] ?? ((object)false));
						bool passwordRequired = Convert.ToBoolean(userAccount["PasswordRequired"] ?? ((object)false));
						Convert.ToBoolean(userAccount["PasswordChangeable"] ?? ((object)false));
						bool passwordExpires = Convert.ToBoolean(userAccount["PasswordExpires"] ?? ((object)false));
						if (!disabled)
						{
							counter = enabledUsers;
							enabledUsers = counter + 1;
						}
						bool isBuiltinAdmin = sid.EndsWith("-500");
						bool isGuest = sid.EndsWith("-501");
						if (isGuest && !disabled)
						{
							guestEnabled = true;
						}
						if (isBuiltinAdmin)
						{
							if (!disabled)
							{
								defaultAdminEnabled = true;
							}
							if (new string[5] { "Administrator", "Administrateur", "Administrador", "Amministratore", "Beheerder" }.Any((string knownAdminName) => name.Equals(knownAdminName, StringComparison.OrdinalIgnoreCase)))
							{
								defaultAdminRenamed = false;
							}
						}
						string userCapture = name;
						bool disabledCapture = disabled;
						bool lockoutCapture = lockedOut;
						bool pwdReqCapture = passwordRequired;
						bool pwdExpCapture = passwordExpires;
						bool isAdminCapture = isBuiltinAdmin;
						bool isGuestCapture = isGuest;
						string sidCapture = sid;
						TryAdd(results, delegate
						{
							List<string> statusFlags = new List<string>();
							if (disabledCapture)
							{
								statusFlags.Add("Disabled");
							}
							else
							{
								statusFlags.Add("Enabled");
							}
							if (lockoutCapture)
							{
								statusFlags.Add("Locked out");
							}
							if (!pwdReqCapture)
							{
								statusFlags.Add("No password required");
							}
							if (!pwdExpCapture)
							{
								statusFlags.Add("Password never expires");
							}
							SecurityStatus status = ((isGuestCapture && !disabledCapture) ? SecurityStatus.Critical : ((!pwdReqCapture && !disabledCapture) ? SecurityStatus.Critical : ((isAdminCapture && !disabledCapture) ? SecurityStatus.Warning : SecurityStatus.Info)));
							return new SecurityResult
							{
								Category = Category,
								CheckName = "Local User: " + userCapture,
								CurrentValue = string.Join(", ", statusFlags),
								ExpectedValue = (isGuestCapture ? "Disabled" : (isAdminCapture ? "Disabled or renamed" : "Enabled with password")),
								Status = status,
								Description = $"Local user account '{userCapture}' (SID: {sidCapture}). " + (isGuestCapture ? "Guest account should always be disabled." : (isAdminCapture ? "Built-in Administrator should be disabled or renamed." : "Review account necessity and password settings.")),
								Recommendation = ((isGuestCapture && !disabledCapture) ? "Disable the Guest account immediately." : ((!pwdReqCapture && !disabledCapture) ? ("Require a password for account '" + userCapture + "'.") : ((isAdminCapture && !disabledCapture) ? "Disable the built-in Administrator account and use a renamed admin account." : "Account configuration acceptable."))),
								Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status"
							};
						});
					}
					finally
					{
						((IDisposable)userAccountToDispose)?.Dispose();
					}
				}
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Local Accounts: Total / Enabled",
					CurrentValue = $"{totalUsers} total, {enabledUsers} enabled",
					ExpectedValue = "Minimum necessary enabled accounts",
					Status = SecurityStatus.Info,
					Description = "Total number of local user accounts and how many are enabled. Reducing enabled accounts reduces the attack surface.",
					Recommendation = "Disable or remove any local accounts that are no longer needed.",
					Reference = ""
				});
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Guest Account Status",
					CurrentValue = (guestEnabled ? "Enabled" : "Disabled"),
					ExpectedValue = "Disabled",
					Status = (guestEnabled ? SecurityStatus.Critical : SecurityStatus.OK),
					Description = "The built-in Guest account provides unauthenticated access to the system. It must be disabled.",
					Recommendation = (guestEnabled ? "Disable the Guest account via: net user guest /active:no" : "Guest account is disabled."),
					Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status"
				});
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Built-in Administrator: Active",
					CurrentValue = (defaultAdminEnabled ? "Enabled" : "Disabled"),
					ExpectedValue = "Disabled",
					Status = (defaultAdminEnabled ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = "The built-in Administrator account (SID-500) is well-known and frequently targeted by attackers. It should be disabled.",
					Recommendation = (defaultAdminEnabled ? "Disable the built-in Administrator account and use a different named admin account." : "Built-in Administrator is disabled."),
					Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/accounts-administrator-account-status"
				});
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Built-in Administrator: Renamed",
					CurrentValue = (defaultAdminRenamed ? "Renamed" : "Default name 'Administrator'"),
					ExpectedValue = "Renamed",
					Status = ((!defaultAdminRenamed) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = "Renaming the built-in Administrator account reduces the risk from brute-force attacks that target the well-known 'Administrator' username.",
					Recommendation = (defaultAdminRenamed ? "Administrator account has been renamed." : "Rename the built-in Administrator account to a non-obvious name."),
					Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/accounts-rename-administrator-account"
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
				CheckName = "Local User Enumeration",
				CurrentValue = "Error: " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to enumerate local user accounts via WMI.",
				Recommendation = "Run as Administrator and verify WMI is functioning.",
				Reference = ""
			});
		}
	}

	private void CollectPasswordPolicy(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		Dictionary<string, string> seceditPolicy = GetPasswordPolicyViaSecedit(ct);
		Dictionary<string, string> netAccountsMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		try
		{
			using Process process = Process.Start(new ProcessStartInfo("net.exe", "accounts")
			{
				RedirectStandardOutput = true,
				UseShellExecute = false,
				CreateNoWindow = true
			});
			if (process != null)
			{
				string netAccountsOutput = process.StandardOutput.ReadToEnd();
				if (!process.WaitForExit(10000))
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
				if (process.ExitCode == 0)
				{
					string[] outputLines = netAccountsOutput.Split('\n');
					for (int i = 0; i < outputLines.Length; i++)
					{
						Match match = Regex.Match(outputLines[i], "^(.+?)\\s{2,}(.+)$");
						if (match.Success)
						{
							netAccountsMap[match.Groups[1].Value.Trim()] = match.Groups[2].Value.Trim();
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
		bool seceditAvailable = seceditPolicy.Count > 0;
		if (!seceditAvailable && netAccountsMap.Count == 0)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Password Policy",
				CurrentValue = "Both secedit and net accounts failed",
				Status = SecurityStatus.Error,
				Description = "Unable to retrieve password policy via secedit or net accounts. Both methods failed.",
				Recommendation = "Run CHECKSEC as Administrator and ensure secedit.exe is available.",
				Reference = ""
			});
			return;
		}
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Password Policy: Source",
			CurrentValue = (seceditAvailable ? "secedit /export (locale-independent)" : "net accounts (locale-dependent, may fail on non-English Windows)"),
			ExpectedValue = "secedit (preferred)",
			Status = ((!seceditAvailable) ? SecurityStatus.Warning : SecurityStatus.OK),
			Description = "Password policy data source. secedit exports locale-independent INF key names and is the preferred source. net accounts outputs localized text which may fail to parse on non-English Windows.",
			Recommendation = (seceditAvailable ? "Policy data retrieved via secedit (reliable)." : "secedit failed; using net accounts which may have locale issues on French/other Windows."),
			Reference = ""
		});
		TryAdd(results, delegate
		{
			string minLengthRaw = ResolveValue("MinimumPasswordLength", new string[2] { "Minimum password length", "Longueur minimale du mot de passe" });
			int parsedMinLength;
			int minLength = (int.TryParse(minLengthRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsedMinLength) ? parsedMinLength : 0);
			bool meetsLength = minLength >= 14;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Password Policy: Minimum Length",
				CurrentValue = minLengthRaw,
				ExpectedValue = ">= 14 characters (MSCT recommendation)",
				Status = ((!meetsLength) ? ((minLength >= 8) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
				Description = "Minimum password length. MSCT recommends at least 14 characters. Short passwords are vulnerable to brute-force attacks.",
				Recommendation = (meetsLength ? "Password minimum length meets recommendations." : "Set minimum password length to at least 14 characters."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/minimum-password-length"
			};
		});
		TryAdd(results, delegate
		{
			string maxAgeRaw = ResolveValue("MaximumPasswordAge", new string[3] { "Maximum password age (days)", "Durée de validité maximale du mot de passe (jours)", "Durée de validité maximale du mot de passe (jours)" });
			int parsedMaxAge;
			int maxAge = (int.TryParse(maxAgeRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsedMaxAge) ? parsedMaxAge : (-1));
			bool withinRange = maxAge > 0 && maxAge <= 365;
			bool unlimited = maxAgeRaw.Equals("Unlimited", StringComparison.OrdinalIgnoreCase) || maxAge == 0 || maxAge == -1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Password Policy: Maximum Password Age",
				CurrentValue = maxAgeRaw,
				ExpectedValue = "60-365 days (or per policy)",
				Status = ((unlimited || !withinRange) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Maximum number of days before a password must be changed. Passwords that never expire increase the risk from compromised credentials.",
				Recommendation = (withinRange ? "Maximum password age is configured." : (unlimited ? "Configure a maximum password age to force periodic password changes." : "Adjust maximum password age to organizational policy.")),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/maximum-password-age"
			};
		});
		TryAdd(results, delegate
		{
			string minAgeRaw = ResolveValue("MinimumPasswordAge", new string[2] { "Minimum password age (days)", "Durée de validité minimale du mot de passe (jours)" });
			int parsedMinAge;
			bool meetsMinAge = (int.TryParse(minAgeRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsedMinAge) ? parsedMinAge : 0) >= 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Password Policy: Minimum Password Age",
				CurrentValue = minAgeRaw,
				ExpectedValue = ">= 1 day",
				Status = ((!meetsMinAge) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Minimum days before a password can be changed again. Prevents users from immediately cycling back to a previous password to defeat history requirements.",
				Recommendation = (meetsMinAge ? "Minimum password age is configured." : "Set minimum password age to at least 1 day."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/minimum-password-age"
			};
		});
		TryAdd(results, delegate
		{
			string historyRaw = ResolveValue("PasswordHistorySize", new string[2] { "Length of password history maintained", "Longueur de l'historique des mots de passe" });
			int parsedHistory;
			int historySize = (int.TryParse(historyRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsedHistory) ? parsedHistory : 0);
			bool meetsHistory = historySize >= 24;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Password Policy: Password History Size",
				CurrentValue = historyRaw,
				ExpectedValue = ">= 24",
				Status = ((!meetsHistory) ? ((historySize >= 12) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
				Description = "Number of previous passwords remembered. A higher value prevents reuse of recent passwords.",
				Recommendation = (meetsHistory ? "Password history meets recommendations." : "Set password history to at least 24 passwords."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/enforce-password-history"
			};
		});
		TryAdd(results, delegate
		{
			string thresholdRaw = ResolveValue("LockoutBadCount", new string[2] { "Lockout threshold", "Seuil de verrouillage des comptes" });
			int parsedThreshold;
			int threshold = (int.TryParse(thresholdRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsedThreshold) ? parsedThreshold : (-1));
			bool noLockout = thresholdRaw.Equals("Never", StringComparison.OrdinalIgnoreCase) || threshold == 0;
			bool withinThreshold = !noLockout && threshold <= 10;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Password Policy: Account Lockout Threshold",
				CurrentValue = thresholdRaw,
				ExpectedValue = "<= 10 attempts (5 recommended)",
				Status = (noLockout ? SecurityStatus.Critical : ((!withinThreshold) ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = "Number of failed logon attempts before the account is locked. No lockout allows unlimited brute-force attempts.",
				Recommendation = (noLockout ? "Configure account lockout threshold immediately. Recommend 5 attempts." : (withinThreshold ? "Lockout threshold is configured." : "Reduce lockout threshold to 10 or fewer attempts.")),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/account-lockout-threshold"
			};
		});
		TryAdd(results, delegate
		{
			string durationRaw = ResolveValue("LockoutDuration", new string[2] { "Lockout duration (minutes)", "Durée de verrouillage des comptes (minutes)" });
			int parsedDuration;
			int duration = (int.TryParse(durationRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsedDuration) ? parsedDuration : 0);
			bool meetsDuration = duration >= 15;
			durationRaw.Equals("Unlimited", StringComparison.OrdinalIgnoreCase);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Password Policy: Lockout Duration",
				CurrentValue = durationRaw,
				ExpectedValue = ">= 15 minutes",
				Status = ((duration == 0) ? SecurityStatus.Info : ((!meetsDuration) ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = "Time an account stays locked after reaching the lockout threshold. 0 = administrator must unlock. Longer duration slows attackers.",
				Recommendation = ((meetsDuration || duration == 0) ? "Lockout duration is adequate." : "Increase lockout duration to at least 15 minutes."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/account-lockout-duration"
			};
		});
		TryAdd(results, delegate
		{
			string windowRaw = ResolveValue("ResetLockoutCount", new string[2] { "Lockout observation window (minutes)", "Durée d'observation du verrouillage des comptes (minutes)" });
			int parsedWindow;
			bool meetsWindow = (int.TryParse(windowRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsedWindow) ? parsedWindow : 0) >= 15;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Password Policy: Lockout Observation Window",
				CurrentValue = windowRaw,
				ExpectedValue = ">= 15 minutes",
				Status = ((!meetsWindow) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Time window within which failed logon attempts are counted toward the lockout threshold.",
				Recommendation = (meetsWindow ? "Observation window is adequate." : "Set lockout observation window to at least 15 minutes."),
				Reference = ""
			};
		});
		string ResolveValue(string seceditKey, string[] netAccountsKeys)
		{
			if (seceditAvailable && seceditPolicy.TryGetValue(seceditKey, out string seceditVal) && seceditVal != null)
			{
				return seceditVal;
			}
			foreach (string netKey in netAccountsKeys)
			{
				if (netAccountsMap.TryGetValue(netKey, out string netVal) && netVal != null)
				{
					return netVal;
				}
			}
			return "Unknown";
		}
	}

	private static Dictionary<string, string> GetPasswordPolicyViaSecedit(CancellationToken ct)
	{
		Dictionary<string, string> policy = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		string infPath = Path.Combine(Path.GetTempPath(), $"checksec_secedit_{Guid.NewGuid():N}.inf");
		try
		{
			using Process process = Process.Start(new ProcessStartInfo("secedit.exe", "/export /cfg \"" + infPath + "\" /areas SECURITYPOLICY /quiet")
			{
				UseShellExecute = false,
				CreateNoWindow = true,
				RedirectStandardOutput = false,
				RedirectStandardError = false
			});
			if (process == null)
			{
				return policy;
			}
			if (!process.WaitForExit(10000))
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
			if (process.ExitCode != 0)
			{
				return policy;
			}
			if (!File.Exists(infPath))
			{
				return policy;
			}
			bool inSystemAccessSection = false;
			string[] lines = File.ReadAllLines(infPath);
			for (int i = 0; i < lines.Length; i++)
			{
				string trimmedLine = lines[i].Trim();
				if (trimmedLine.Equals("[System Access]", StringComparison.OrdinalIgnoreCase))
				{
					inSystemAccessSection = true;
					continue;
				}
				if (trimmedLine.StartsWith("[") && inSystemAccessSection)
				{
					break;
				}
				if (inSystemAccessSection && !trimmedLine.StartsWith(";") && trimmedLine.Length != 0)
				{
					int separatorIndex = trimmedLine.IndexOf('=');
					if (separatorIndex > 0)
					{
						string key = trimmedLine.Substring(0, separatorIndex).Trim();
						string valueLine = trimmedLine;
						int valueStart = separatorIndex + 1;
						string entryValue = valueLine.Substring(valueStart, valueLine.Length - valueStart).Trim();
						policy[key] = entryValue;
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
		finally
		{
			try
			{
				if (File.Exists(infPath))
				{
					File.Delete(infPath);
				}
			}
			catch (Exception)
			{
			}
		}
		return policy;
	}

	private void CollectLsaSecuritySettings(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object limitBlankRaw = lsaKey?.GetValue("LimitBlankPasswordUse");
			int limitBlank = ((limitBlankRaw == null) ? 1 : Convert.ToInt32(limitBlankRaw));
			bool restricted = limitBlank == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA: LimitBlankPasswordUse",
				CurrentValue = (restricted ? "Enabled (1)" : $"Disabled ({limitBlank})"),
				ExpectedValue = "1 (Enabled)",
				Status = ((!restricted) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Limits accounts with blank passwords to console logon only, preventing network logon with empty passwords.",
				Recommendation = (restricted ? "Blank password network logon is restricted." : "Enable LimitBlankPasswordUse to prevent blank password network access."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/accounts-limit-local-account-use-of-blank-passwords-to-console-logon-only"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object noLmHashRaw = lsaKey?.GetValue("NoLMHash");
			int noLmHash = ((noLmHashRaw == null) ? 1 : Convert.ToInt32(noLmHashRaw));
			bool lmHashDisabled = noLmHash == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA: NoLMHash (No LAN Manager Hash)",
				CurrentValue = (lmHashDisabled ? "Enabled (1) - LM hash not stored" : $"Disabled ({noLmHash}) - LM hash stored"),
				ExpectedValue = "1 (LM hash disabled)",
				Status = ((!lmHashDisabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Prevents Windows from storing the weak LAN Manager (LM) hash of passwords. LM hashes can be cracked in seconds and enable Pass-the-Hash attacks.",
				Recommendation = (lmHashDisabled ? "LM hash storage is disabled." : "Enable NoLMHash to prevent storage of weak LM password hashes."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object lmCompatRaw = lsaKey?.GetValue("LmCompatibilityLevel");
			int lmCompatLevel = ((lmCompatRaw != null) ? Convert.ToInt32(lmCompatRaw) : 3);
			string currentValue = lmCompatLevel switch
			{
				0 => "0 - LM and NTLM (very weak)",
				1 => "1 - LM and NTLM, NTLMv2 session if negotiated",
				2 => "2 - NTLM only",
				3 => "3 - NTLMv2 only (client)",
				4 => "4 - NTLMv2 only, refuse LM (server)",
				5 => "5 - NTLMv2 only, refuse LM and NTLM (recommended)",
				_ => $"{lmCompatLevel} - Unknown",
			};
			bool enforcesNtlmv2 = lmCompatLevel >= 5;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA: LmCompatibilityLevel",
				CurrentValue = currentValue,
				ExpectedValue = "5 (NTLMv2 only, refuse LM and NTLM)",
				Status = ((!enforcesNtlmv2) ? ((lmCompatLevel >= 3) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
				Description = "Controls NTLM authentication protocol level. Level 5 enforces NTLMv2 and refuses weak LM and NTLMv1 authentication, preventing relay and downgrade attacks.",
				Recommendation = (enforcesNtlmv2 ? "NTLMv2 is enforced." : "Set LmCompatibilityLevel = 5 to enforce NTLMv2 and refuse LM/NTLM."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object restrictAnonRaw = lsaKey?.GetValue("RestrictAnonymous");
			int restrictAnon = ((restrictAnonRaw != null) ? Convert.ToInt32(restrictAnonRaw) : 0);
			string currentValue = restrictAnon switch
			{
				0 => "0 - No restrictions (anonymous access allowed)",
				1 => "1 - No enumeration of SAM accounts/shares",
				2 => "2 - No access without explicit anonymous permissions",
				_ => $"{restrictAnon} - Unknown",
			};
			bool restricted = restrictAnon >= 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA: RestrictAnonymous",
				CurrentValue = currentValue,
				ExpectedValue = "1 or 2",
				Status = ((!restricted) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Restricts anonymous access to the system. Value 0 allows anonymous enumeration of SAM accounts and shares, a serious information disclosure.",
				Recommendation = (restricted ? "Anonymous access is restricted." : "Set RestrictAnonymous to 1 to prevent anonymous SAM enumeration."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object restrictSamRaw = lsaKey?.GetValue("RestrictAnonymousSAM");
			int restrictSam = ((restrictSamRaw == null) ? 1 : Convert.ToInt32(restrictSamRaw));
			bool samRestricted = restrictSam == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA: RestrictAnonymousSAM",
				CurrentValue = (samRestricted ? "Enabled (1)" : $"Disabled ({restrictSam})"),
				ExpectedValue = "1 (Restrict anonymous SAM enumeration)",
				Status = ((!samRestricted) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Prevents anonymous users from enumerating SAM account names, stopping reconnaissance of local user accounts.",
				Recommendation = (samRestricted ? "Anonymous SAM enumeration is restricted." : "Enable RestrictAnonymousSAM to prevent anonymous account discovery."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object everyoneAnonRaw = lsaKey?.GetValue("EveryoneIncludesAnonymous");
			int everyoneAnon = ((everyoneAnonRaw != null) ? Convert.ToInt32(everyoneAnonRaw) : 0);
			bool anonExcluded = everyoneAnon == 0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA: EveryoneIncludesAnonymous",
				CurrentValue = ((everyoneAnon == 0) ? "Disabled (0) - Everyone does not include Anonymous" : $"Enabled ({everyoneAnon}) - Anonymous included in Everyone"),
				ExpectedValue = "0 (Disabled)",
				Status = ((!anonExcluded) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Controls whether the Everyone group includes anonymous users. Including anonymous users in Everyone grants broad unauthenticated access.",
				Recommendation = (anonExcluded ? "Anonymous users are not included in Everyone group." : "Set EveryoneIncludesAnonymous = 0 to exclude anonymous from Everyone."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access-let-everyone-permissions-apply-to-anonymous-users"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object forceGuestRaw = lsaKey?.GetValue("ForceGuest");
			int forceGuest = ((forceGuestRaw != null) ? Convert.ToInt32(forceGuestRaw) : 0);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA: ForceGuest (Sharing and Security Model)",
				CurrentValue = ((forceGuest == 0) ? "0 - Classic (recommended)" : "1 - Guest only"),
				ExpectedValue = "0 (Classic)",
				Status = SecurityStatus.Info,
				Description = "Determines the sharing and security model for local accounts. Classic mode uses actual credentials; Guest only mode maps all local logons to Guest.",
				Recommendation = "Classic mode (0) is recommended for enterprise environments.",
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access-sharing-and-security-model-for-local-accounts"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object disableDomainCredsRaw = lsaKey?.GetValue("DisableDomainCreds");
			int disableDomainCreds = ((disableDomainCredsRaw != null) ? Convert.ToInt32(disableDomainCredsRaw) : 0);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA: DisableDomainCreds",
				CurrentValue = ((disableDomainCreds == 1) ? "Enabled (1) - Domain credentials storage disabled" : "Disabled (0)"),
				ExpectedValue = "Context-dependent",
				Status = SecurityStatus.Info,
				Description = "Disabling domain credential storage prevents saving domain passwords in Credential Manager, reducing credential theft surface.",
				Recommendation = "Consider enabling on sensitive systems to prevent credential caching.",
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication"
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
				Category = "User & Account Security",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Check failed: " + ex.Message,
				Recommendation = "Review WMI and registry access.",
				Reference = ""
			});
		}
	}
}
