using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Core.Services.Analysis;

public class MsctToolkitParser
{
	private readonly string _toolkitPath;

	private readonly Dictionary<string, string> _gpoNameMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

	public MsctToolkitParser(string toolkitPath)
	{
		_toolkitPath = toolkitPath;
	}

	public static List<BaselinePolicy> ParseFromEmbeddedData(CancellationToken ct = default(CancellationToken))
	{
		ct.ThrowIfCancellationRequested();
		List<BaselinePolicy> baselinePolicies = MsctBaselineData.GetBaselinePolicies();
		ErrorLogger.Log(LogLevel.Info, $"[MsctToolkitParser] Loaded {baselinePolicies.Count} hardcoded baseline policies.");
		return baselinePolicies;
	}

	public async Task<List<BaselinePolicy>> ParseAsync(CancellationToken ct = default(CancellationToken))
	{
		// Correctif H2: PRIORITE au toolkit MSCT EXTERNE de l'organisation lorsqu'il est fourni
		// et existant. On ne retombe sur la baseline embarquee qu'en cas d'echec (exception,
		// 0 policy, ou chemin absent). Auparavant la baseline embarquee etait TOUJOURS retournee
		// en premier, rendant le chemin _toolkitPath (externe) mort.
		if (!string.IsNullOrWhiteSpace(_toolkitPath) && (File.Exists(_toolkitPath) || Directory.Exists(_toolkitPath)))
		{
			List<BaselinePolicy> externalPolicies = new List<BaselinePolicy>();
			try
			{
				string tempDir = Path.Combine(Path.GetTempPath(), $"CHECKSEC_MSCT_{Guid.NewGuid():N}");
				try
				{
					Directory.CreateDirectory(tempDir);
					bool extracted = false;
					string zipPath = FindBaselineZip();
					if (zipPath != null)
					{
						await Task.Run(delegate
						{
							ZipFile.ExtractToDirectory(zipPath, tempDir, overwriteFiles: true);
						}, ct);
						extracted = true;
					}
					if (extracted)
					{
						ct.ThrowIfCancellationRequested();
						await Task.Run(delegate
						{
							BuildGpoNameMap(tempDir);
						}, ct);
						ct.ThrowIfCancellationRequested();
						await Task.Run(delegate
						{
							ParseAllRegistryPol(tempDir, externalPolicies, ct);
						}, ct);
						ct.ThrowIfCancellationRequested();
						await Task.Run(delegate
						{
							ParseAllGptTmpl(tempDir, externalPolicies, ct);
						}, ct);
						ct.ThrowIfCancellationRequested();
						await Task.Run(delegate
						{
							ParseAllAuditCsv(tempDir, externalPolicies, ct);
						}, ct);
					}
					else
					{
						ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Toolkit externe present mais aucune baseline (ZIP) trouvee — repli sur baseline embarquee.");
					}
				}
				finally
				{
					try
					{
						Directory.Delete(tempDir, recursive: true);
					}
					catch (Exception ex3)
					{
						ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Cleanup temp directory failed: " + ex3.Message, ex3);
					}
				}
				// Succes: le toolkit externe a produit au moins une policy → on le retourne en priorite.
				if (externalPolicies.Count > 0)
				{
					ErrorLogger.Log(LogLevel.Info, $"[MsctToolkitParser] toolkit externe: {externalPolicies.Count} policies");
					return externalPolicies;
				}
				ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Toolkit externe: 0 policy — repli sur baseline embarquee.");
			}
			catch (OperationCanceledException)
			{
				// Propagation de l'annulation (aucun repli en cas d'annulation).
				throw;
			}
			catch (Exception exExternal)
			{
				ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Echec toolkit externe: " + exExternal.Message + " — repli sur baseline embarquee.", exExternal);
			}
		}

		// FALLBACK: baseline embarquee (comportement historique conserve).
		try
		{
			List<BaselinePolicy> embeddedPolicies = ParseFromEmbeddedData(ct);
			return embeddedPolicies;
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Embedded data fallback: " + ex2.Message, ex2);
		}
		return new List<BaselinePolicy>();
	}

	private string? FindBaselineZip()
	{
		if (!Directory.Exists(_toolkitPath))
		{
			return null;
		}
		try
		{
			foreach (string zipFile in Directory.EnumerateFiles(_toolkitPath, "*.zip", SearchOption.AllDirectories))
			{
				string fileName = Path.GetFileName(zipFile);
				if (fileName.Contains("Security Baseline", StringComparison.OrdinalIgnoreCase) || fileName.Contains("SecurityBaseline", StringComparison.OrdinalIgnoreCase) || fileName.Contains("Baseline", StringComparison.OrdinalIgnoreCase))
				{
					return zipFile;
				}
			}
			using IEnumerator<string> enumerator = Directory.EnumerateFiles(_toolkitPath, "*.zip", SearchOption.TopDirectoryOnly).GetEnumerator();
			if (enumerator.MoveNext())
			{
				return enumerator.Current;
			}
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Erreur recherche ZIP: " + ex.Message, ex);
		}
		return null;
	}

	private void BuildGpoNameMap(string rootDir)
	{
		try
		{
			foreach (string bkupInfoFile in Directory.EnumerateFiles(rootDir, "bkupInfo.xml", SearchOption.AllDirectories))
			{
				try
				{
					XDocument xDocument = XDocument.Load(bkupInfoFile);
					XNamespace xNamespace = xDocument.Root?.Name.Namespace ?? XNamespace.None;
					string displayName = xDocument.Root?.Element(xNamespace + "BackupInst")?.Element(xNamespace + "GPODisplayName")?.Value ?? xDocument.Root?.Descendants(xNamespace + "GPODisplayName").FirstOrDefault()?.Value ?? xDocument.Root?.Descendants("GPODisplayName").FirstOrDefault()?.Value;
					string guid = xDocument.Root?.Element(xNamespace + "BackupInst")?.Element(xNamespace + "GPOGUID")?.Value ?? xDocument.Root?.Descendants(xNamespace + "GPOGUID").FirstOrDefault()?.Value ?? xDocument.Root?.Descendants("GPOGUID").FirstOrDefault()?.Value;
					if (!string.IsNullOrEmpty(guid) && !string.IsNullOrEmpty(displayName))
					{
						_gpoNameMap[guid.Trim('{', '}').ToUpperInvariant()] = displayName;
					}
					string fileName = Path.GetFileName(Path.GetDirectoryName(bkupInfoFile));
					if (!string.IsNullOrEmpty(fileName) && !string.IsNullOrEmpty(displayName))
					{
						string key = fileName.Trim('{', '}').ToUpperInvariant();
						if (!_gpoNameMap.ContainsKey(key))
						{
							_gpoNameMap[key] = displayName;
						}
					}
				}
				catch (Exception ex)
				{
					ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Erreur bkupInfo.xml (" + bkupInfoFile + "): " + ex.Message, ex);
				}
			}
		}
		catch (Exception ex2)
		{
			ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Erreur enumeration bkupInfo.xml: " + ex2.Message, ex2);
		}
	}

	private string ResolveGpoName(string filePath)
	{
		string directoryName = Path.GetDirectoryName(filePath);
		while (!string.IsNullOrEmpty(directoryName))
		{
			string key = (Path.GetFileName(directoryName) ?? string.Empty).Trim('{', '}').ToUpperInvariant();
			if (_gpoNameMap.TryGetValue(key, out string gpoName))
			{
				return gpoName;
			}
			directoryName = Path.GetDirectoryName(directoryName);
		}
		return Path.GetFileName(Path.GetDirectoryName(filePath)) ?? "Unknown GPO";
	}

	private void ParseAllRegistryPol(string rootDir, List<BaselinePolicy> policies, CancellationToken ct)
	{
		try
		{
			foreach (string polFile in Directory.EnumerateFiles(rootDir, "registry.pol", SearchOption.AllDirectories))
			{
				ct.ThrowIfCancellationRequested();
				try
				{
					string gpoName = ResolveGpoName(polFile);
					List<BaselinePolicy> parsedPolicies = ParseRegistryPol(polFile, gpoName);
					policies.AddRange(parsedPolicies);
				}
				catch (Exception ex)
				{
					ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Erreur registry.pol (" + polFile + "): " + ex.Message, ex);
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex3)
		{
			ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Erreur enumeration registry.pol: " + ex3.Message, ex3);
		}
	}

	private static List<BaselinePolicy> ParseRegistryPol(string filePath, string gpoName)
	{
		List<BaselinePolicy> policies = new List<BaselinePolicy>();
		byte[] bytes = File.ReadAllBytes(filePath);
		if (bytes.Length < 8)
		{
			return policies;
		}
		if (bytes[0] != 80 || bytes[1] != 82 || bytes[2] != 101 || bytes[3] != 103)
		{
			return policies;
		}
		if (BitConverter.ToUInt32(bytes, 4) != 1)
		{
			return policies;
		}
		int pos = 8;
		while (pos < bytes.Length - 1 && pos + 1 < bytes.Length)
		{
			if (bytes[pos] != 91 || bytes[pos + 1] != 0)
			{
				pos++;
				continue;
			}
			pos += 2;
			string keyPath = ReadUtf16LeString(bytes, ref pos);
			if (pos + 1 >= bytes.Length)
			{
				break;
			}
			if (bytes[pos] == 59 && bytes[pos + 1] == 0)
			{
				pos += 2;
			}
			string valueName = ReadUtf16LeString(bytes, ref pos);
			if (pos + 1 >= bytes.Length)
			{
				break;
			}
			if (bytes[pos] == 59 && bytes[pos + 1] == 0)
			{
				pos += 2;
			}
			if (pos + 3 >= bytes.Length)
			{
				break;
			}
			uint regType = BitConverter.ToUInt32(bytes, pos);
			pos += 4;
			if (pos + 1 < bytes.Length && bytes[pos] == 59 && bytes[pos + 1] == 0)
			{
				pos += 2;
			}
			if (pos + 3 >= bytes.Length)
			{
				break;
			}
			uint dataLength = BitConverter.ToUInt32(bytes, pos);
			pos += 4;
			if (pos + 1 < bytes.Length && bytes[pos] == 59 && bytes[pos + 1] == 0)
			{
				pos += 2;
			}
			string expectedValue;
			string valueType;
			if (dataLength != 0 && pos + (int)dataLength <= bytes.Length)
			{
				byte[] valueData = new byte[dataLength];
				Array.Copy(bytes, pos, valueData, 0, (int)dataLength);
				pos += (int)dataLength;
				(expectedValue, valueType) = FormatRegistryValue(regType, valueData);
			}
			else
			{
				expectedValue = string.Empty;
				valueType = RegTypeToString(regType);
				pos += (int)dataLength;
			}
			if (pos + 1 < bytes.Length && bytes[pos] == 93 && bytes[pos + 1] == 0)
			{
				pos += 2;
			}
			if (!string.IsNullOrEmpty(keyPath) && !string.IsNullOrEmpty(valueName))
			{
				policies.Add(new BaselinePolicy
				{
					GpoName = gpoName,
					Type = PolicyType.Registry,
					KeyPath = keyPath,
					ValueName = valueName,
					ExpectedValue = expectedValue,
					ValueType = valueType,
					Section = "Registry Policy"
				});
			}
		}
		return policies;
	}

	private static string ReadUtf16LeString(byte[] data, ref int pos)
	{
		StringBuilder stringBuilder = new StringBuilder();
		while (pos + 1 < data.Length)
		{
			ushort charCode = BitConverter.ToUInt16(data, pos);
			pos += 2;
			if (charCode == 0)
			{
				break;
			}
			stringBuilder.Append((char)charCode);
		}
		return stringBuilder.ToString();
	}

	private static (string value, string typeStr) FormatRegistryValue(uint regType, byte[] data)
	{
		try
		{
			switch (regType)
			{
			case 1u:
				return (value: Encoding.Unicode.GetString(data).TrimEnd('\0'), typeStr: "REG_SZ");
			case 2u:
				return (value: Encoding.Unicode.GetString(data).TrimEnd('\0'), typeStr: "REG_EXPAND_SZ");
			case 3u:
				return (value: BitConverter.ToString(data).Replace("-", " "), typeStr: "REG_BINARY");
			case 4u:
				if (data.Length >= 4)
				{
					return (value: BitConverter.ToUInt32(data, 0).ToString(), typeStr: "REG_DWORD");
				}
				return (value: "(invalid DWORD)", typeStr: "REG_DWORD");
			case 5u:
				if (data.Length >= 4)
				{
					return (value: BitConverter.ToUInt32(new byte[4]
					{
						data[3],
						data[2],
						data[1],
						data[0]
					}, 0).ToString(), typeStr: "REG_DWORD_BIG_ENDIAN");
				}
				return (value: "(invalid)", typeStr: "REG_DWORD_BIG_ENDIAN");
			case 7u:
				return (value: Encoding.Unicode.GetString(data).Replace("\0", "|").TrimEnd('|'), typeStr: "REG_MULTI_SZ");
			case 11u:
				if (data.Length >= 8)
				{
					return (value: BitConverter.ToUInt64(data, 0).ToString(), typeStr: "REG_QWORD");
				}
				return (value: "(invalid QWORD)", typeStr: "REG_QWORD");
			default:
				return (value: BitConverter.ToString(data).Replace("-", " "), typeStr: RegTypeToString(regType));
			}
		}
		catch (Exception)
		{
			return (value: "(parse error)", typeStr: RegTypeToString(regType));
		}
	}

	private static string RegTypeToString(uint regType)
	{
		return regType switch
		{
			0u => "REG_NONE", 
			1u => "REG_SZ", 
			2u => "REG_EXPAND_SZ", 
			3u => "REG_BINARY", 
			4u => "REG_DWORD", 
			5u => "REG_DWORD_BIG_ENDIAN", 
			6u => "REG_LINK", 
			7u => "REG_MULTI_SZ", 
			8u => "REG_RESOURCE_LIST", 
			11u => "REG_QWORD", 
			_ => $"REG_TYPE_{regType}", 
		};
	}

	private void ParseAllGptTmpl(string rootDir, List<BaselinePolicy> policies, CancellationToken ct)
	{
		try
		{
			foreach (string infFile in Directory.EnumerateFiles(rootDir, "GptTmpl.inf", SearchOption.AllDirectories))
			{
				ct.ThrowIfCancellationRequested();
				try
				{
					string gpoName = ResolveGpoName(infFile);
					List<BaselinePolicy> parsedPolicies = ParseGptTmpl(infFile, gpoName);
					policies.AddRange(parsedPolicies);
				}
				catch (Exception ex)
				{
					ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Erreur GptTmpl.inf (" + infFile + "): " + ex.Message, ex);
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex3)
		{
			ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Erreur enumeration GptTmpl.inf: " + ex3.Message, ex3);
		}
	}

	private static List<BaselinePolicy> ParseGptTmpl(string filePath, string gpoName)
	{
		List<BaselinePolicy> policies = new List<BaselinePolicy>();
		string content;
		try
		{
			byte[] bytes = File.ReadAllBytes(filePath);
			content = ((bytes.Length >= 2 && bytes[0] == byte.MaxValue && bytes[1] == 254) ? Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2) : ((bytes.Length < 2 || bytes[0] != 254 || bytes[1] != byte.MaxValue) ? Encoding.UTF8.GetString(bytes) : Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2)));
		}
		catch (Exception)
		{
			content = File.ReadAllText(filePath);
		}
		string currentSection = string.Empty;
		string[] lines = content.Split('\n');
		for (int i = 0; i < lines.Length; i++)
		{
			string line = lines[i].Trim('\r', '\n', ' ');
			if (string.IsNullOrWhiteSpace(line) || line.StartsWith(';'))
			{
				continue;
			}
			if (line.StartsWith('[') && line.EndsWith(']'))
			{
				currentSection = line.Trim('[', ']').Trim();
				continue;
			}
			int equalsIndex = line.IndexOf('=');
			if (equalsIndex < 0)
			{
				continue;
			}
			string key = line.Substring(0, equalsIndex).Trim();
			string value = line.Substring(equalsIndex + 1).Trim();
			switch (currentSection)
			{
			case "System Access":
				policies.Add(ParseSystemAccessEntry(key, value, gpoName));
				break;
			case "Event Audit":
				policies.Add(new BaselinePolicy
				{
					GpoName = gpoName,
					Type = PolicyType.AuditPolicy,
					KeyPath = "Event Audit",
					ValueName = key,
					ExpectedValue = value,
					ValueType = "REG_DWORD",
					Section = "Event Audit"
				});
				break;
			case "Registry Values":
			{
				BaselinePolicy baselinePolicy = ParseRegistryValueEntry(line, gpoName);
				if (baselinePolicy != null)
				{
					policies.Add(baselinePolicy);
				}
				break;
			}
			case "Privilege Rights":
				policies.Add(new BaselinePolicy
				{
					GpoName = gpoName,
					Type = PolicyType.UserRightsAssignment,
					KeyPath = "Privilege Rights",
					ValueName = key,
					ExpectedValue = value,
					ValueType = "REG_SZ",
					Section = "Privilege Rights"
				});
				break;
			case "Kerberos Policy":
				policies.Add(new BaselinePolicy
				{
					GpoName = gpoName,
					Type = PolicyType.SecurityOption,
					KeyPath = "Kerberos Policy",
					ValueName = key,
					ExpectedValue = value,
					ValueType = "REG_DWORD",
					Section = "Kerberos Policy"
				});
				break;
			}
		}
		return policies;
	}

	private static BaselinePolicy ParseSystemAccessEntry(string key, string value, string gpoName)
	{
		PolicyType policyType;
		switch (key)
		{
		case "MinimumPasswordAge":
		case "PasswordComplexity":
		case "MaximumPasswordAge":
		case "ClearTextPassword":
		case "MinimumPasswordLength":
		case "PasswordHistorySize":
		case "RequireLogonToChangePassword":
			policyType = PolicyType.PasswordPolicy;
			break;
		case "ResetLockoutCount":
		case "LockoutBadCount":
		case "LockoutDuration":
			policyType = PolicyType.AccountLockout;
			break;
		default:
			policyType = PolicyType.SecurityOption;
			break;
		}
		PolicyType type = policyType;
		return new BaselinePolicy
		{
			GpoName = gpoName,
			Type = type,
			KeyPath = "System Access",
			ValueName = key,
			ExpectedValue = value,
			ValueType = "REG_DWORD",
			Section = "System Access"
		};
	}

	private static BaselinePolicy? ParseRegistryValueEntry(string line, string gpoName)
	{
		string[] parts = line.Split(',');
		if (parts.Length < 3)
		{
			return null;
		}
		string fullPath = parts[0].Trim();
		string typeCode = parts[1].Trim();
		string expectedValue = string.Join(",", parts, 2, parts.Length - 2).Trim().Trim('"');
		int separatorIndex = fullPath.LastIndexOf('\\');
		if (separatorIndex < 0)
		{
			return null;
		}
		string keyPath = fullPath.Substring(0, separatorIndex);
		string valueName = fullPath.Substring(separatorIndex + 1);
		keyPath = Regex.Replace(keyPath, "^MACHINE\\\\", "HKLM\\", RegexOptions.IgnoreCase);
		keyPath = Regex.Replace(keyPath, "^USER\\\\", "HKCU\\", RegexOptions.IgnoreCase);
		string valueType = typeCode switch
		{
			"1" => "REG_SZ",
			"2" => "REG_EXPAND_SZ",
			"3" => "REG_BINARY",
			"4" => "REG_DWORD",
			"7" => "REG_MULTI_SZ",
			_ => "REG_TYPE_" + typeCode,
		};
		return new BaselinePolicy
		{
			GpoName = gpoName,
			Type = PolicyType.Registry,
			KeyPath = keyPath,
			ValueName = valueName,
			ExpectedValue = expectedValue,
			ValueType = valueType,
			Section = "Registry Values"
		};
	}

	private void ParseAllAuditCsv(string rootDir, List<BaselinePolicy> policies, CancellationToken ct)
	{
		try
		{
			foreach (string csvFile in Directory.EnumerateFiles(rootDir, "audit.csv", SearchOption.AllDirectories))
			{
				ct.ThrowIfCancellationRequested();
				try
				{
					string gpoName = ResolveGpoName(csvFile);
					List<BaselinePolicy> parsedPolicies = ParseAuditCsv(csvFile, gpoName);
					policies.AddRange(parsedPolicies);
				}
				catch (Exception ex)
				{
					ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Erreur audit.csv (" + csvFile + "): " + ex.Message, ex);
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex3)
		{
			ErrorLogger.Log(LogLevel.Warning, "[MsctToolkitParser] Erreur enumeration audit.csv: " + ex3.Message, ex3);
		}
	}

	private static List<BaselinePolicy> ParseAuditCsv(string filePath, string gpoName)
	{
		List<BaselinePolicy> policies = new List<BaselinePolicy>();
		bool isHeader = true;
		foreach (string line in File.ReadLines(filePath, Encoding.UTF8))
		{
			if (isHeader)
			{
				isHeader = false;
				continue;
			}
			string[] fields = SplitCsvLine(line);
			if (fields.Length > 4)
			{
				string section = ((fields.Length > 2) ? fields[2].Trim() : string.Empty);
				string valueName = ((fields.Length > 3) ? fields[3].Trim() : string.Empty);
				string expectedValue = ((fields.Length > 4) ? fields[4].Trim() : string.Empty);
				if (fields.Length <= 6)
				{
					_ = string.Empty;
				}
				else
				{
					fields[6].Trim();
				}
				if (!string.IsNullOrEmpty(section))
				{
					policies.Add(new BaselinePolicy
					{
						GpoName = gpoName,
						Type = PolicyType.AuditPolicy,
						KeyPath = "Audit Policy",
						ValueName = valueName,
						ExpectedValue = expectedValue,
						ValueType = "REG_SZ",
						Section = section
					});
				}
			}
		}
		return policies;
	}

	private static string[] SplitCsvLine(string line)
	{
		List<string> fields = new List<string>();
		StringBuilder stringBuilder = new StringBuilder();
		bool inQuotes = false;
		for (int i = 0; i < line.Length; i++)
		{
			char c = line[i];
			switch (c)
			{
			case '"':
				if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
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
}
