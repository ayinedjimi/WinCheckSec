using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Analysis;

public class GapAnalyzer
{
	private static readonly HashSet<string> CriticalKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		"LmCompatibilityLevel", "NTLMMinClientSec", "NTLMMinServerSec", "RestrictSendingNTLMTraffic", "EnableVirtualizationBasedSecurity", "HypervisorEnforcedCodeIntegrity", "CredentialGuard", "RequireSecuritySignature", "SMB1", "EnableFirewall",
		"DoRequireValidation", "WDigest", "AllowProtectedCreds", "LSACfgFlags", "RunAsPPL"
	};

	private static readonly HashSet<string> HighKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		"MinimumPasswordLength", "MaximumPasswordAge", "PasswordComplexity", "LockoutBadCount", "LockoutDuration", "AuditLogonEvents", "AuditObjectAccess", "AuditPolicyChange", "AuditPrivilegeUse", "MinEncryptionLevel",
		"SecurityLayer", "UserAuthentication", "SchUseStrongCrypto", "SystemCryptography", "TLS", "SSL", "AllowUnencryptedTraffic", "EnableAutoDoh", "DOHPolicy"
	};

	private static readonly HashSet<string> MediumKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop", "FilterAdministratorToken", "MaxSize", "Retention", "DisablePasswordReveal", "EnableSmartScreen", "BlockAtFirstSeen" };

	private static Dictionary<string, string>? _auditPolicies;

	private static readonly object _auditLock = new object();

	private static Dictionary<string, string>? _accountPolicies;

	private static readonly object _accountLock = new object();

	private static readonly Dictionary<string, (string Hive, string SubKey, string Value)> SecurityOptionMap = new Dictionary<string, (string, string, string)>(StringComparer.OrdinalIgnoreCase)
	{
		["EnableAdminAccount"] = ("HKLM", "SAM\\SAM\\Domains\\Account\\Users\\000001F4", ""),
		["NewAdministratorName"] = ("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Lsa", ""),
		["NewGuestName"] = ("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Lsa", "")
	};

	public List<ComplianceGap> Analyze(List<BaselinePolicy> policies, CancellationToken ct = default(CancellationToken))
	{
		List<ComplianceGap> gaps = new List<ComplianceGap>();
		foreach (BaselinePolicy policy in policies)
		{
			ct.ThrowIfCancellationRequested();
			try
			{
				ComplianceGap complianceGap = policy.Type switch
				{
					PolicyType.Registry => AnalyzeRegistryPolicy(policy), 
					PolicyType.AuditPolicy => AnalyzeAuditPolicy(policy), 
					PolicyType.PasswordPolicy => AnalyzePasswordPolicy(policy), 
					PolicyType.AccountLockout => AnalyzeAccountLockoutPolicy(policy), 
					PolicyType.SecurityOption => AnalyzeSecurityOption(policy), 
					PolicyType.UserRightsAssignment => AnalyzeUserRights(policy), 
					_ => AnalyzeRegistryPolicy(policy), 
				};
				if (complianceGap != null)
				{
					gaps.Add(complianceGap);
				}
			}
			catch (Exception ex)
			{
				gaps.Add(new ComplianceGap
				{
					PolicyName = policy.ValueName,
					RegistryPath = policy.KeyPath,
					ValueName = policy.ValueName,
					BaselineValue = policy.ExpectedValue,
					CurrentValue = "(Erreur d'analyse: " + ex.Message + ")",
					IsCompliant = false,
					Severity = GapSeverity.Low,
					GpoName = policy.GpoName,
					Description = "Impossible d'évaluer la politique: " + ex.Message
				});
			}
		}
		gaps.Sort(delegate(ComplianceGap a, ComplianceGap b)
		{
			int severityCompare = b.Severity.CompareTo(a.Severity);
			return (severityCompare != 0) ? severityCompare : string.Compare(a.GpoName, b.GpoName, StringComparison.OrdinalIgnoreCase);
		});
		return gaps;
	}

	public int CountCompliant(List<ComplianceGap> gaps)
	{
		return gaps.Count((ComplianceGap g) => g.IsCompliant);
	}

	public int CountNonCompliant(List<ComplianceGap> gaps)
	{
		return gaps.Count((ComplianceGap g) => !g.IsCompliant);
	}

	public Dictionary<GapSeverity, int> GetSeveritySummary(List<ComplianceGap> gaps)
	{
		Dictionary<GapSeverity, int> dictionary = new Dictionary<GapSeverity, int>
		{
			[GapSeverity.Critical] = 0,
			[GapSeverity.High] = 0,
			[GapSeverity.Medium] = 0,
			[GapSeverity.Low] = 0
		};
		foreach (ComplianceGap gap in gaps)
		{
			if (!gap.IsCompliant)
			{
				dictionary[gap.Severity]++;
			}
		}
		return dictionary;
	}

	private ComplianceGap AnalyzeRegistryPolicy(BaselinePolicy policy)
	{
		(RegistryHive hive, string subKey) splitPath = SplitRegistryPath(policy.KeyPath);
		RegistryHive hive = splitPath.hive;
		string subKey = splitPath.subKey;
		object rawValue = ReadRegistryValue(hive, subKey, policy.ValueName);
		string formattedValue = FormatRegistryValue(rawValue, policy.ValueType);
		bool isCompliant = CompareValues(formattedValue, policy.ExpectedValue, policy.ValueType);
		return new ComplianceGap
		{
			PolicyName = policy.GpoName + ": " + policy.ValueName,
			RegistryPath = policy.KeyPath,
			ValueName = policy.ValueName,
			BaselineValue = policy.ExpectedValue,
			CurrentValue = ((rawValue == null) ? "(non défini)" : formattedValue),
			IsCompliant = isCompliant,
			Severity = DetermineSeverity(policy),
			GpoName = policy.GpoName,
			Description = BuildRegistryDescription(policy, formattedValue, isCompliant)
		};
	}

	private static (RegistryHive hive, string subKey) SplitRegistryPath(string keyPath)
	{
		string normalizedPath = keyPath.ToUpperInvariant().Replace("HKEY_LOCAL_MACHINE\\", "HKLM\\").Replace("HKEY_CURRENT_USER\\", "HKCU\\")
			.Replace("HKEY_CURRENT_CONFIG\\", "HKCC\\")
			.Replace("HKEY_USERS\\", "HKU\\")
			.Replace("HKEY_CLASSES_ROOT\\", "HKCR\\");
		int separatorIndex = normalizedPath.IndexOf('\\');
		if (separatorIndex < 0)
		{
			return (hive: RegistryHive.LocalMachine, subKey: normalizedPath);
		}
		string hivePart = normalizedPath.Substring(0, separatorIndex);
		string subKeyRaw;
		// Correctif L3: index ET Substring sur la MÊME chaîne (normalizedPath) pour éviter
		// tout décalage de découpe si la version originale diffère de la normalisée.
		if (separatorIndex >= normalizedPath.Length - 1)
		{
			subKeyRaw = string.Empty;
		}
		else
		{
			int subKeyStart = separatorIndex + 1;
			subKeyRaw = normalizedPath.Substring(subKeyStart, normalizedPath.Length - subKeyStart);
		}
		string subKeyPart = subKeyRaw;
		return (hive: hivePart switch
		{
			"HKLM" => RegistryHive.LocalMachine, 
			"HKCU" => RegistryHive.CurrentUser, 
			"HKCC" => RegistryHive.CurrentConfig, 
			"HKU" => RegistryHive.Users, 
			"HKCR" => RegistryHive.ClassesRoot, 
			_ => RegistryHive.LocalMachine,
		}, subKey: subKeyPart);
	}

	private static object? ReadRegistryValue(RegistryHive hive, string subKey, string valueName)
	{
		try
		{
			using RegistryKey registryKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
			using RegistryKey registryKey2 = registryKey.OpenSubKey(subKey, writable: false);
			return registryKey2?.GetValue(valueName);
		}
		catch (UnauthorizedAccessException ex)
		{
			ErrorLogger.AddError($"[Registry] Accès refusé: {subKey}\\{valueName} - {ex.Message}");
			return null;
		}
		catch (SecurityException ex2)
		{
			ErrorLogger.AddError($"[Registry] Sécurité: {subKey}\\{valueName} - {ex2.Message}");
			return null;
		}
		catch (Exception ex3)
		{
			ErrorLogger.AddError($"[Registry] Erreur: {subKey}\\{valueName} - {ex3.GetType().Name}: {ex3.Message}");
			return null;
		}
	}

	private static string FormatRegistryValue(object? value, string valueType)
	{
		if (value == null)
		{
			return string.Empty;
		}
		if (!(value is int intValue))
		{
			if (!(value is long longValue))
			{
				if (!(value is string stringValue))
				{
					if (!(value is byte[] bytes))
					{
						if (value is string[] stringArray)
						{
							return string.Join("|", stringArray);
						}
						return value.ToString() ?? string.Empty;
					}
					return BitConverter.ToString(bytes).Replace("-", " ");
				}
				return stringValue;
			}
			return longValue.ToString();
		}
		return intValue.ToString();
	}

	private static bool CompareValues(string current, string expected, string valueType)
	{
		if (string.IsNullOrEmpty(current) && !string.IsNullOrEmpty(expected))
		{
			return false;
		}
		if (string.IsNullOrEmpty(expected))
		{
			return true;
		}
		if ((valueType.Contains("DWORD", StringComparison.OrdinalIgnoreCase) || valueType.Contains("QWORD", StringComparison.OrdinalIgnoreCase)) && long.TryParse(current, out var currentNum) && long.TryParse(expected, out var expectedNum))
		{
			return currentNum == expectedNum;
		}
		return string.Equals(current.Trim(), expected.Trim(), StringComparison.OrdinalIgnoreCase);
	}

	private static string BuildRegistryDescription(BaselinePolicy policy, string currentStr, bool isCompliant)
	{
		if (isCompliant)
		{
			return "La valeur '" + policy.ValueName + "' est conforme à la baseline MSCT.";
		}
		string currentDisplay = (string.IsNullOrEmpty(currentStr) ? "non définie" : ("'" + currentStr + "'"));
		return $"La valeur '{policy.ValueName}' est {currentDisplay} au lieu de '{policy.ExpectedValue}' (chemin: {policy.KeyPath}, GPO: {policy.GpoName}).";
	}

	private static Dictionary<string, string> GetAuditPolicies()
	{
		lock (_auditLock)
		{
			if (_auditPolicies != null)
			{
				return new Dictionary<string, string>(_auditPolicies, StringComparer.OrdinalIgnoreCase);
			}
			_auditPolicies = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			try
			{
				using Process process = Process.Start(new ProcessStartInfo("auditpol.exe", "/get /category:* /r")
				{
					RedirectStandardOutput = true,
					UseShellExecute = false,
					CreateNoWindow = true
				});
				if (process == null)
				{
					return _auditPolicies;
				}
				Task<string> task = process.StandardOutput.ReadToEndAsync();
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
				string rawOutput = "";
				try
				{
					if (task.Wait(1000))
					{
						rawOutput = task.Result;
					}
				}
				catch
				{
				}
				bool isHeader = true;
				string[] lines = rawOutput.Split(new char[2] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
				foreach (string line in lines)
				{
					if (isHeader)
					{
						isHeader = false;
						continue;
					}
					string[] fields = SplitCsvLine(line);
					if (fields.Length >= 7)
					{
						string subcategory = fields[2].Trim().Trim('"');
						string settingValue = fields[6].Trim().Trim('"');
						string auditSetting = settingValue switch
						{
							"0" => "No Auditing",
							"1" => "Success",
							"2" => "Failure",
							"3" => "Success and Failure",
							_ => settingValue,
						};
						if (!string.IsNullOrEmpty(subcategory))
						{
							_auditPolicies[subcategory] = auditSetting;
						}
					}
				}
			}
			catch (Exception ex)
			{
				ErrorLogger.Log(LogLevel.Warning, "[GapAnalyzer] auditpol.exe error: " + ex.Message, ex);
			}
			return new Dictionary<string, string>(_auditPolicies, StringComparer.OrdinalIgnoreCase);
		}
	}

	private static string[] SplitCsvLine(string line)
	{
		List<string> fields = new List<string>(8);
		bool inQuotes = false;
		StringBuilder stringBuilder = new StringBuilder(64);
		for (int i = 0; i < line.Length; i++)
		{
			char c = line[i];
			switch (c)
			{
			case '"':
				if (i + 1 < line.Length && line[i + 1] == '"' && inQuotes)
				{
					stringBuilder.Append('"');
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
					fields.Add(stringBuilder.ToString());
					stringBuilder.Clear();
					continue;
				}
				break;
			}
			stringBuilder.Append(c);
		}
		fields.Add(stringBuilder.ToString());
		return fields.ToArray();
	}

	private ComplianceGap AnalyzeAuditPolicy(BaselinePolicy policy)
	{
		Dictionary<string, string> auditPolicies = GetAuditPolicies();
		string key = ((!string.IsNullOrEmpty(policy.Section)) ? policy.Section : policy.ValueName);
		auditPolicies.TryGetValue(key, out string currentSetting);
		if (currentSetting == null)
		{
			currentSetting = string.Empty;
		}
		string expectedSetting = NormalizeAuditSetting(policy.ExpectedValue);
		string currentNormalized = NormalizeAuditSetting(currentSetting);
		bool isCompliant = string.Equals(currentNormalized, expectedSetting, StringComparison.OrdinalIgnoreCase) || IsAuditSubset(currentNormalized, expectedSetting);
		return new ComplianceGap
		{
			PolicyName = "Audit: " + policy.Section,
			RegistryPath = "Audit Policy",
			ValueName = policy.Section,
			BaselineValue = expectedSetting,
			CurrentValue = (string.IsNullOrEmpty(currentSetting) ? "(non configuré)" : currentSetting),
			IsCompliant = isCompliant,
			Severity = DetermineSeverity(policy),
			GpoName = policy.GpoName,
			Description = (isCompliant ? ("La politique d'audit '" + policy.Section + "' est conforme.") : $"Politique d'audit '{policy.Section}': valeur actuelle='{currentSetting}', attendue='{expectedSetting}'.")
		};
	}

	private static string NormalizeAuditSetting(string raw)
	{
		string trimmed = raw.Trim();
		switch (trimmed)
		{
		case "3":
			return "Success and Failure";
		case "2":
			return "Failure";
		case "1":
			return "Success";
		case "0":
			return "No Auditing";
		default:
		{
			if ((trimmed.Contains("Succès") || trimmed.Contains("Réussite") || trimmed.Contains("Success")) && (trimmed.Contains("Échec") || trimmed.Contains("échec") || trimmed.Contains("Failure")))
			{
				return "Success and Failure";
			}
			string successCheck = trimmed;
			if (successCheck.Contains("Succès") || successCheck.Contains("Réussite") || successCheck.Contains("Success"))
			{
				return "Success";
			}
			string failureCheck = trimmed;
			if (failureCheck.Contains("Échec") || failureCheck.Contains("échec") || failureCheck.Contains("Failure"))
			{
				return "Failure";
			}
			string noAuditCheck = trimmed;
			if (noAuditCheck.Contains("Pas d'audit") || noAuditCheck.Contains("Aucun audit") || noAuditCheck.Contains("No Auditing"))
			{
				return "No Auditing";
			}
			return raw;
		}
		}
	}

	private static bool IsAuditSubset(string current, string expected)
	{
		if (expected.Equals("Success and Failure", StringComparison.OrdinalIgnoreCase) && !current.Equals("Success and Failure", StringComparison.OrdinalIgnoreCase))
		{
			return false;
		}
		if (expected.Equals("Success", StringComparison.OrdinalIgnoreCase) && current.Equals("Success and Failure", StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}
		if (expected.Equals("Failure", StringComparison.OrdinalIgnoreCase) && current.Equals("Success and Failure", StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}
		return false;
	}

	private static Dictionary<string, string> GetAccountPolicies()
	{
		lock (_accountLock)
		{
			if (_accountPolicies != null)
			{
				return new Dictionary<string, string>(_accountPolicies, StringComparer.OrdinalIgnoreCase);
			}
			_accountPolicies = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			try
			{
				using Process process = Process.Start(new ProcessStartInfo("net.exe", "accounts")
				{
					RedirectStandardOutput = true,
					UseShellExecute = false,
					CreateNoWindow = true
				});
				if (process == null)
				{
					return _accountPolicies;
				}
				Task<string> task = process.StandardOutput.ReadToEndAsync();
				if (!process.WaitForExit(5000))
				{
					try
					{
						process.Kill();
					}
					catch
					{
					}
				}
				string rawOutput = "";
				try
				{
					if (task.Wait(1000))
					{
						rawOutput = task.Result;
					}
				}
				catch
				{
				}
				string[] lines = rawOutput.Split('\n');
				foreach (string line in lines)
				{
					int separatorIndex = line.IndexOf(':');
					if (separatorIndex >= 0)
					{
						string key = line.Substring(0, separatorIndex).Trim();
						string settingValue = line.Substring(separatorIndex + 1).Trim();
						if (!string.IsNullOrEmpty(key))
						{
							_accountPolicies[key] = settingValue;
						}
					}
				}
			}
			catch (Exception ex)
			{
				ErrorLogger.Log(LogLevel.Warning, "[GapAnalyzer] net accounts error: " + ex.Message, ex);
			}
			return new Dictionary<string, string>(_accountPolicies, StringComparer.OrdinalIgnoreCase);
		}
	}

	private ComplianceGap AnalyzePasswordPolicy(BaselinePolicy policy)
	{
		Dictionary<string, string> accountPolicies = GetAccountPolicies();
		string accountKey = policy.ValueName switch
		{
			"MinimumPasswordLength" => "Minimum password length",
			"MaximumPasswordAge" => "Maximum password age (days)", 
			"MinimumPasswordAge" => "Minimum password age (days)", 
			"PasswordHistorySize" => "Length of password history maintained", 
			"PasswordComplexity" => string.Empty, 
			_ => policy.ValueName, 
		};
		bool isCompliant;
		if (string.IsNullOrEmpty(accountKey) || !accountPolicies.TryGetValue(accountKey, out var currentValue))
		{
			currentValue = "(non récupéré)";
			isCompliant = false;
		}
		else
		{
			isCompliant = CompareValues(currentValue, policy.ExpectedValue, "REG_DWORD");
		}
		return new ComplianceGap
		{
			PolicyName = "Password Policy: " + policy.ValueName,
			RegistryPath = "Password Policy",
			ValueName = policy.ValueName,
			BaselineValue = policy.ExpectedValue,
			CurrentValue = currentValue,
			IsCompliant = isCompliant,
			Severity = DetermineSeverity(policy),
			GpoName = policy.GpoName,
			Description = (isCompliant ? ("La politique de mot de passe '" + policy.ValueName + "' est conforme.") : $"'{policy.ValueName}': valeur actuelle='{currentValue}', attendue='{policy.ExpectedValue}'.")
		};
	}

	private ComplianceGap AnalyzeAccountLockoutPolicy(BaselinePolicy policy)
	{
		Dictionary<string, string> accountPolicies = GetAccountPolicies();
		bool isCompliant;
		if (!accountPolicies.TryGetValue(policy.ValueName switch
		{
			"LockoutBadCount" => "Lockout threshold",
			"LockoutDuration" => "Lockout duration (minutes)",
			"ResetLockoutCount" => "Lockout observation window (minutes)",
			_ => policy.ValueName,
		}, out var currentValue))
		{
			currentValue = "(non récupéré)";
			isCompliant = false;
		}
		else
		{
			if (currentValue.Equals("Never", StringComparison.OrdinalIgnoreCase))
			{
				currentValue = "0";
			}
			isCompliant = CompareValues(currentValue, policy.ExpectedValue, "REG_DWORD");
		}
		return new ComplianceGap
		{
			PolicyName = "Account Lockout: " + policy.ValueName,
			RegistryPath = "Account Lockout Policy",
			ValueName = policy.ValueName,
			BaselineValue = policy.ExpectedValue,
			CurrentValue = currentValue,
			IsCompliant = isCompliant,
			Severity = DetermineSeverity(policy),
			GpoName = policy.GpoName,
			Description = (isCompliant ? ("La politique de verrouillage '" + policy.ValueName + "' est conforme.") : $"'{policy.ValueName}': valeur actuelle='{currentValue}', attendue='{policy.ExpectedValue}'.")
		};
	}

	private ComplianceGap AnalyzeSecurityOption(BaselinePolicy policy)
	{
		string currentValue = "(vérification manuelle requise)";
		// Correctif H5: non vérifiable = non conforme par défaut (à vérifier manuellement).
		// isCompliant ne passe à true qu'après une comparaison registre réussie.
		bool isCompliant = false;
		if (policy.KeyPath.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase) || policy.KeyPath.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase))
		{
			(RegistryHive hive, string subKey) splitPath = SplitRegistryPath(policy.KeyPath);
			RegistryHive hive = splitPath.hive;
			string subKey = splitPath.subKey;
			object rawValue = ReadRegistryValue(hive, subKey, policy.ValueName);
			if (rawValue != null)
			{
				currentValue = FormatRegistryValue(rawValue, policy.ValueType);
				isCompliant = CompareValues(currentValue, policy.ExpectedValue, policy.ValueType);
			}
			else
			{
				currentValue = "(non défini)";
				isCompliant = string.IsNullOrEmpty(policy.ExpectedValue);
			}
		}
		return new ComplianceGap
		{
			PolicyName = "Security Option: " + policy.ValueName,
			RegistryPath = policy.KeyPath,
			ValueName = policy.ValueName,
			BaselineValue = policy.ExpectedValue,
			CurrentValue = currentValue,
			IsCompliant = isCompliant,
			Severity = DetermineSeverity(policy),
			GpoName = policy.GpoName,
			Description = (isCompliant ? ("L'option de sécurité '" + policy.ValueName + "' est conforme.") : $"'{policy.ValueName}': valeur actuelle='{currentValue}', attendue='{policy.ExpectedValue}'.")
		};
	}

	private ComplianceGap AnalyzeUserRights(BaselinePolicy policy)
	{
		return new ComplianceGap
		{
			PolicyName = "User Rights: " + policy.ValueName,
			RegistryPath = "Privilege Rights",
			ValueName = policy.ValueName,
			BaselineValue = policy.ExpectedValue,
			CurrentValue = "Évalué par le collecteur « Droits utilisateur » (secedit)",
			IsCompliant = true,
			Severity = GapSeverity.Low,
			GpoName = policy.GpoName,
			Description = "H4 : le droit utilisateur '" + policy.ValueName + "' est audité directement par le collecteur « Droits utilisateur » (via secedit). Non recompté ici comme écart pour éviter la double vérité et la pollution de la liste MSCT."
		};
	}

	private static GapSeverity DetermineSeverity(BaselinePolicy policy)
	{
		string valueName = policy.ValueName ?? string.Empty;
		string keyPath = policy.KeyPath ?? string.Empty;
		string gpoName = policy.GpoName ?? string.Empty;
		foreach (string criticalKeyword in CriticalKeywords)
		{
			if (valueName.Contains(criticalKeyword, StringComparison.OrdinalIgnoreCase) || keyPath.Contains(criticalKeyword, StringComparison.OrdinalIgnoreCase))
			{
				return GapSeverity.Critical;
			}
		}
		if (keyPath.Contains("Control\\Lsa", StringComparison.OrdinalIgnoreCase) || keyPath.Contains("LanmanServer\\Parameters", StringComparison.OrdinalIgnoreCase) || keyPath.Contains("LanmanWorkstation\\Parameters", StringComparison.OrdinalIgnoreCase) || keyPath.Contains("VirtualizationBased", StringComparison.OrdinalIgnoreCase) || keyPath.Contains("CredentialGuard", StringComparison.OrdinalIgnoreCase) || keyPath.Contains("System\\CurrentControlSet\\Control\\Lsa", StringComparison.OrdinalIgnoreCase))
		{
			return GapSeverity.Critical;
		}
		if (keyPath.Contains("WindowsFirewall", StringComparison.OrdinalIgnoreCase) || keyPath.Contains("MpsSvc", StringComparison.OrdinalIgnoreCase))
		{
			return GapSeverity.Critical;
		}
		foreach (string highKeyword in HighKeywords)
		{
			if (valueName.Contains(highKeyword, StringComparison.OrdinalIgnoreCase))
			{
				return GapSeverity.High;
			}
		}
		if (policy.Type == PolicyType.PasswordPolicy || policy.Type == PolicyType.AccountLockout || policy.Type == PolicyType.AuditPolicy)
		{
			return GapSeverity.High;
		}
		if (keyPath.Contains("Schannel", StringComparison.OrdinalIgnoreCase) || keyPath.Contains("TLS", StringComparison.OrdinalIgnoreCase) || keyPath.Contains("SSL", StringComparison.OrdinalIgnoreCase))
		{
			return GapSeverity.High;
		}
		foreach (string mediumKeyword in MediumKeywords)
		{
			if (valueName.Contains(mediumKeyword, StringComparison.OrdinalIgnoreCase))
			{
				return GapSeverity.Medium;
			}
		}
		if (keyPath.Contains("System\\CurrentControlSet\\Control\\Lsa", StringComparison.OrdinalIgnoreCase) || keyPath.Contains("ConsentPrompt", StringComparison.OrdinalIgnoreCase) || gpoName.Contains("UAC", StringComparison.OrdinalIgnoreCase))
		{
			return GapSeverity.Medium;
		}
		if (keyPath.Contains("EventLog", StringComparison.OrdinalIgnoreCase) || valueName.Contains("MaxSize", StringComparison.OrdinalIgnoreCase))
		{
			return GapSeverity.Medium;
		}
		return GapSeverity.Low;
	}
}
