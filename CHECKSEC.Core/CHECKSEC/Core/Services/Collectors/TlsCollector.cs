using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class TlsCollector : ISecurityCollector
{
	private const string SchannelBase = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL";

	private const string CipherSuitePolicyKey = "SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002";

	public string Name => "TLS / Cryptography";

	public string Category => "TLS / Cryptography";

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
			CollectTlsVersions(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectCipherSuites(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectHashAlgorithms(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectKeyExchangeAlgorithms(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectInternetSettings(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectSmbSecurity(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "TlsCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectTlsVersions(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		(string, string, bool, bool, string)[] protocolDefinitions = new(string, string, bool, bool, string)[6]
		{
			("SSL 2.0", "SSL 2.0", false, true, "SSL 2.0 is broken and vulnerable to DROWN, BEAST, and POODLE attacks. Must be disabled."),
			("SSL 3.0", "SSL 3.0", false, true, "SSL 3.0 is vulnerable to POODLE attack. Must be disabled."),
			("TLS 1.0", "TLS 1.0", false, false, "TLS 1.0 is deprecated per PCI DSS, NIST, and MSCT. Vulnerable to BEAST and POODLE attacks."),
			("TLS 1.1", "TLS 1.1", false, false, "TLS 1.1 is deprecated. Lacks support for modern cipher suites and AEAD encryption."),
			("TLS 1.2", "TLS 1.2", true, true, "TLS 1.2 is the current standard minimum. Must remain enabled for compatibility with most systems."),
			("TLS 1.3", "TLS 1.3", true, false, "TLS 1.3 provides forward secrecy, faster handshakes, and removes legacy insecure algorithms.")
		};
		for (int i = 0; i < protocolDefinitions.Length; i++)
		{
			(string, string, bool, bool, string) protocolTuple = protocolDefinitions[i];
			string tupleName = protocolTuple.Item1;
			string tupleRegKey = protocolTuple.Item2;
			bool tupleShouldEnable = protocolTuple.Item3;
			bool tupleCritical = protocolTuple.Item4;
			string tupleDesc = protocolTuple.Item5;
			ct.ThrowIfCancellationRequested();
			string protocolName = tupleName;
			string protocolRegKey = tupleRegKey;
			bool shouldEnable = tupleShouldEnable;
			bool critical = tupleCritical;
			string desc = tupleDesc;
			TryAdd(results, delegate
			{
				string serverRegPath = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\" + protocolRegKey + "\\Server";
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey serverKey = baseKey.OpenSubKey(serverRegPath);
				bool? enabledSetting = null;
				bool disabledByDefault = false;
				if (serverKey != null)
				{
					object enabledRaw = serverKey.GetValue("Enabled");
					object disabledByDefaultRaw = serverKey.GetValue("DisabledByDefault");
					if (enabledRaw != null)
					{
						enabledSetting = Convert.ToInt32(enabledRaw) != 0;
					}
					if (disabledByDefaultRaw != null)
					{
						disabledByDefault = Convert.ToInt32(disabledByDefaultRaw) == 1;
					}
				}
				bool effectivelyEnabled;
				string statusText;
				if (enabledSetting.HasValue)
				{
					effectivelyEnabled = enabledSetting.Value;
					statusText = (enabledSetting.Value ? "Enabled (registry)" : "Disabled (registry)");
					if (disabledByDefault)
					{
						statusText += " + DisabledByDefault=1";
					}
				}
				else
				{
					bool isModernProtocol = protocolName == "TLS 1.2" || protocolName == "TLS 1.3";
					bool isLegacySsl = protocolName == "SSL 2.0" || protocolName == "SSL 3.0";
					effectivelyEnabled = isModernProtocol || !isLegacySsl;
					statusText = "Key absent (default: " + (effectivelyEnabled ? "enabled" : "disabled") + ")";
				}
				int complianceFlag;
				if (shouldEnable && effectivelyEnabled)
				{
					complianceFlag = 1;
					goto IL_0154;
				}
				if (!shouldEnable)
				{
					complianceFlag = ((!effectivelyEnabled) ? 1 : 0);
					if (complianceFlag != 0)
					{
						goto IL_0154;
					}
				}
				else
				{
					complianceFlag = 0;
				}
				SecurityStatus status = ((!critical) ? SecurityStatus.Warning : SecurityStatus.Critical);
				goto IL_0169;
				IL_0169:
				string recommendation = ((complianceFlag != 0) ? (shouldEnable ? (protocolName + " server is correctly enabled.") : (protocolName + " server is correctly disabled.")) : ((!shouldEnable) ? $"Disable {protocolName} server: Set HKLM\\{serverRegPath}\\Enabled = 0 and DisabledByDefault = 1." : $"Enable {protocolName} server: Set HKLM\\{serverRegPath}\\Enabled = 1 and DisabledByDefault = 0."));
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Protocol " + protocolName + " - Server",
					CurrentValue = statusText,
					ExpectedValue = (shouldEnable ? "Enabled" : "Disabled"),
					Status = status,
					Description = desc,
					Recommendation = recommendation,
					Reference = "https://docs.microsoft.com/windows-server/security/tls/tls-registry-settings"
				};
				IL_0154:
				status = SecurityStatus.OK;
				goto IL_0169;
			});
			TryAdd(results, delegate
			{
				string clientRegPath = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\" + protocolRegKey + "\\Client";
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey clientKey = baseKey.OpenSubKey(clientRegPath);
				bool? enabledSetting = null;
				if (clientKey != null)
				{
					object enabledRaw = clientKey.GetValue("Enabled");
					if (enabledRaw != null)
					{
						enabledSetting = Convert.ToInt32(enabledRaw) != 0;
					}
				}
				bool isModernProtocol = protocolName == "TLS 1.2" || protocolName == "TLS 1.3";
				bool isLegacySsl = protocolName == "SSL 2.0" || protocolName == "SSL 3.0";
				bool effectivelyEnabled = (enabledSetting.HasValue ? enabledSetting.Value : (isModernProtocol || !isLegacySsl));
				string currentValue = ((!enabledSetting.HasValue) ? ("Key absent (default: " + (effectivelyEnabled ? "enabled" : "disabled") + ")") : (enabledSetting.Value ? "Enabled (registry)" : "Disabled (registry)"));
				bool compliant = (shouldEnable && effectivelyEnabled) || (!shouldEnable && !effectivelyEnabled);
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Protocol " + protocolName + " - Client",
					CurrentValue = currentValue,
					ExpectedValue = (shouldEnable ? "Enabled" : "Disabled"),
					Status = ((!compliant) ? ((!critical) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
					Description = "Client-side " + protocolName + " setting. " + desc,
					Recommendation = ((!compliant) ? (shouldEnable ? ("Enable " + protocolName + " for client.") : $"Disable {protocolName} for client: Set HKLM\\{clientRegPath}\\Enabled = 0.") : (shouldEnable ? (protocolName + " client enabled.") : (protocolName + " client disabled."))),
					Reference = "https://docs.microsoft.com/windows-server/security/tls/tls-registry-settings"
				};
			});
		}
	}

	private void CollectCipherSuites(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey sslPolicyKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002");
			object functionsValue = sslPolicyKey?.GetValue("Functions");
			if (functionsValue == null)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Cipher Suites: Policy Configuration",
					CurrentValue = "Not configured via policy (OS defaults apply)",
					ExpectedValue = "Custom policy configured",
					Status = SecurityStatus.Info,
					Description = "No custom cipher suite ordering policy is configured. Windows uses its default cipher suite list which may include legacy ciphers.",
					Recommendation = "Configure a custom cipher suite list via GPO or PowerShell to disable weak ciphers and prioritize AEAD suites.",
					Reference = "https://docs.microsoft.com/windows-server/security/tls/manage-tls"
				};
			}
			string[] configuredSuites = (functionsValue.ToString() ?? "").Split(new char[3] { ',', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
			List<string> weakSuites = new List<string>();
			List<string> strongAeadSuites = new List<string>();
			string[] weakPatterns = new string[9] { "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "ANON", "MD5", "PSK" };
			string[] strongAeadPatterns = new string[5] { "AES_256_GCM", "AES_128_GCM", "CHACHA20_POLY1305", "AES256_GCM", "AES128_GCM" };
			string[] suitesToScan = configuredSuites;
			for (int i = 0; i < suitesToScan.Length; i++)
			{
				string suiteName = suitesToScan[i].Trim();
				string[] patternsToMatch = weakPatterns;
				foreach (string weakPattern in patternsToMatch)
				{
					if (suiteName.IndexOf(weakPattern, StringComparison.OrdinalIgnoreCase) >= 0)
					{
						weakSuites.Add(suiteName);
						break;
					}
				}
				patternsToMatch = strongAeadPatterns;
				foreach (string strongPattern in patternsToMatch)
				{
					if (suiteName.IndexOf(strongPattern, StringComparison.OrdinalIgnoreCase) >= 0)
					{
						strongAeadSuites.Add(suiteName);
						break;
					}
				}
			}
			bool hasWeak = weakSuites.Count > 0;
			bool hasStrongAead = strongAeadSuites.Count > 0;
			string weakSummary = ((weakSuites.Count > 0) ? string.Join(", ", weakSuites) : "None");
			string aeadSummary = ((strongAeadSuites.Count > 0) ? $"{strongAeadSuites.Count} AEAD suites" : "None");
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Cipher Suites: Analysis",
				CurrentValue = $"{configuredSuites.Length} suites configured. Weak: {weakSummary}. Strong AEAD: {aeadSummary}",
				ExpectedValue = "No weak ciphers, strong AEAD suites present",
				Status = (hasWeak ? SecurityStatus.Critical : ((!hasStrongAead) ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = "Analysis of configured TLS cipher suites. Weak ciphers (RC4, DES, 3DES, NULL, EXPORT) can be broken and must be removed.",
				Recommendation = (hasWeak ? ("Remove weak cipher suites: " + weakSummary + ". Use only AEAD cipher suites (AES-GCM, ChaCha20-Poly1305).") : "No obviously weak cipher suites detected."),
				Reference = "https://docs.microsoft.com/windows-server/security/tls/manage-tls"
			};
		});
		(string, string, bool, string)[] cipherDefinitions = new(string, string, bool, string)[8]
		{
			("RC4 128/128", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 128/128", false, "RC4 is a broken stream cipher. Must be disabled."),
			("RC4 56/128", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 56/128", false, "RC4 56-bit is critically weak. Must be disabled."),
			("RC4 40/128", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 40/128", false, "RC4 40-bit export cipher is critically weak. Must be disabled."),
			("DES 56/56", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\DES 56/56", false, "DES is broken (56-bit key). Must be disabled."),
			("Triple DES 168", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 168", false, "3DES is deprecated and vulnerable to SWEET32 birthday attack. Should be disabled."),
			("NULL", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\NULL", false, "NULL cipher provides no encryption. Must be disabled."),
			("AES 128/128", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\AES 128/128", true, "AES-128 is a strong symmetric cipher. Should be enabled."),
			("AES 256/256", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\AES 256/256", true, "AES-256 is the strongest standard symmetric cipher. Should be enabled.")
		};
		for (int k = 0; k < cipherDefinitions.Length; k++)
		{
			(string, string, bool, string) cipherTuple = cipherDefinitions[k];
			string tupleName = cipherTuple.Item1;
			string tupleRegPath = cipherTuple.Item2;
			bool tupleShouldEnable = cipherTuple.Item3;
			string tupleDescription = cipherTuple.Item4;
			ct.ThrowIfCancellationRequested();
			string cn = tupleName;
			string rp = tupleRegPath;
			bool shouldEnable = tupleShouldEnable;
			string description = tupleDescription;
			TryAdd(results, delegate
			{
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey cipherKey = baseKey.OpenSubKey(rp);
				object enabledRaw = cipherKey?.GetValue("Enabled");
				bool? enabledSetting = null;
				if (enabledRaw != null && !(enabledRaw is DBNull))
				{
					try
					{
						enabledSetting = Convert.ToInt32(enabledRaw) != 0;
					}
					catch
					{
						enabledSetting = null;
					}
				}
				bool effectivelyEnabled = enabledSetting.GetValueOrDefault(shouldEnable);
				string currentValue = ((!enabledSetting.HasValue) ? "Not configured (OS default)" : (enabledSetting.Value ? "Enabled" : "Disabled"));
				bool compliant = (shouldEnable ? effectivelyEnabled : (!effectivelyEnabled));
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Cipher: " + cn,
					CurrentValue = currentValue,
					ExpectedValue = (shouldEnable ? "Enabled" : "Disabled"),
					Status = ((!compliant) ? (shouldEnable ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
					Description = description,
					Recommendation = (compliant ? (cn + " is correctly configured.") : (shouldEnable ? $"Enable {cn}: Set HKLM\\{rp}\\Enabled = 0xffffffff." : $"Disable {cn}: Set HKLM\\{rp}\\Enabled = 0.")),
					Reference = "https://docs.microsoft.com/windows-server/security/tls/tls-registry-settings"
				};
			});
		}
	}

	private void CollectHashAlgorithms(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		(string, string, bool, string)[] hashDefinitions = new(string, string, bool, string)[4]
		{
			("MD5", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\MD5", false, "MD5 is cryptographically broken (collision attacks). Must be disabled for TLS."),
			("SHA", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\SHA", true, "SHA-1 is deprecated for certificates but may still be needed for some TLS handshake elements. Monitor for removal."),
			("SHA256", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\SHA256", true, "SHA-256 is the standard hash for modern TLS. Should be enabled."),
			("SHA384", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\SHA384", true, "SHA-384 provides additional security margin. Should be enabled.")
		};
		for (int i = 0; i < hashDefinitions.Length; i++)
		{
			(string, string, bool, string) hashTuple = hashDefinitions[i];
			string tupleName = hashTuple.Item1;
			string tupleRegPath = hashTuple.Item2;
			bool tupleShouldEnable = hashTuple.Item3;
			string tupleDescription = hashTuple.Item4;
			ct.ThrowIfCancellationRequested();
			string hn = tupleName;
			string rp = tupleRegPath;
			bool shouldEnable = tupleShouldEnable;
			string description = tupleDescription;
			TryAdd(results, delegate
			{
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey hashKey = baseKey.OpenSubKey(rp);
				object enabledRaw = hashKey?.GetValue("Enabled");
				bool? enabledSetting = null;
				if (enabledRaw != null && !(enabledRaw is DBNull))
				{
					try
					{
						enabledSetting = Convert.ToInt32(enabledRaw) != 0;
					}
					catch
					{
						enabledSetting = null;
					}
				}
				bool effectivelyEnabled = enabledSetting ?? true;
				string currentValue = ((!enabledSetting.HasValue) ? "Not configured (OS default: enabled)" : (enabledSetting.Value ? "Enabled" : "Disabled"));
				bool compliant = (shouldEnable ? effectivelyEnabled : (!effectivelyEnabled));
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Hash Algorithm: " + hn,
					CurrentValue = currentValue,
					ExpectedValue = (shouldEnable ? "Enabled" : "Disabled"),
					Status = ((!compliant) ? (shouldEnable ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
					Description = description,
					Recommendation = (compliant ? (hn + " hash algorithm is correctly configured.") : (shouldEnable ? $"Enable {hn}: Set HKLM\\{rp}\\Enabled = 0xffffffff." : $"Disable {hn}: Set HKLM\\{rp}\\Enabled = 0.")),
					Reference = "https://docs.microsoft.com/windows-server/security/tls/tls-registry-settings"
				};
			});
		}
	}

	private void CollectKeyExchangeAlgorithms(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		(string, string, string)[] keyExchangeDefinitions = new(string, string, string)[3]
		{
			("Diffie-Hellman", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman", "Diffie-Hellman key exchange. Ensure minimum 2048-bit DH parameters to avoid Logjam attack."),
			("PKCS", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\PKCS", "RSA key exchange (PKCS). Does not provide forward secrecy; prefer ECDHE when possible."),
			("ECDH", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\ECDH", "Elliptic Curve Diffie-Hellman provides forward secrecy. Should be enabled and prioritized.")
		};
		for (int i = 0; i < keyExchangeDefinitions.Length; i++)
		{
			(string, string, string) keyExchangeTuple = keyExchangeDefinitions[i];
			string tupleName = keyExchangeTuple.Item1;
			string tupleRegPath = keyExchangeTuple.Item2;
			string tupleDescription = keyExchangeTuple.Item3;
			ct.ThrowIfCancellationRequested();
			string an = tupleName;
			string rp = tupleRegPath;
			string description = tupleDescription;
			TryAdd(results, delegate
			{
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey algorithmKey = baseKey.OpenSubKey(rp);
				object enabledRaw = algorithmKey?.GetValue("Enabled");
				bool? enabledSetting = null;
				if (enabledRaw != null && !(enabledRaw is DBNull))
				{
					try
					{
						enabledSetting = Convert.ToInt32(enabledRaw) != 0;
					}
					catch
					{
						enabledSetting = null;
					}
				}
				string currentValue = ((!enabledSetting.HasValue) ? "Not configured (OS default)" : (enabledSetting.Value ? "Enabled" : "Disabled"));
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Key Exchange: " + an,
					CurrentValue = currentValue,
					ExpectedValue = "Enabled",
					Status = SecurityStatus.Info,
					Description = description,
					Recommendation = ((an == "ECDH") ? "Prioritize ECDHE for forward secrecy." : ((an == "Diffie-Hellman") ? "Ensure DH parameters are at least 2048 bits." : "PKCS is acceptable for compatibility.")),
					Reference = "https://docs.microsoft.com/windows-server/security/tls/tls-registry-settings"
				};
			});
		}
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey dhKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman");
			object minKeyLengthRaw = dhKey?.GetValue("ServerMinKeyBitLength");
			int minKeyLength = ((minKeyLengthRaw != null) ? Convert.ToInt32(minKeyLengthRaw) : (-1));
			SecurityStatus status = ((minKeyLength <= 0) ? SecurityStatus.Warning : ((minKeyLength < 2048) ? SecurityStatus.Critical : SecurityStatus.OK));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Key Exchange: DH Minimum Key Length",
				CurrentValue = ((minKeyLength == -1) ? "Not configured (OS default)" : $"{minKeyLength} bits"),
				ExpectedValue = ">= 2048 bits (explicitly configured)",
				Status = status,
				Description = "Minimum Diffie-Hellman key size. Keys below 2048 bits are vulnerable to the Logjam attack, which allows downgrade to 512-bit export-grade DH. Not configured means the OS default applies, which may allow smaller keys.",
				Recommendation = ((minKeyLength >= 2048) ? "DH key length is adequate." : "Set ServerMinKeyBitLength to at least 2048 in HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman."),
				Reference = "https://weakdh.org/"
			};
		});
	}

	private void CollectInternetSettings(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey internetSettingsKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
			object secureProtocolsRaw = internetSettingsKey?.GetValue("SecureProtocols");
			if (secureProtocolsRaw == null)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "IE/WinHTTP: SecureProtocols",
					CurrentValue = "Not configured via policy",
					ExpectedValue = "Policy configured (TLS 1.2/1.3 only)",
					Status = SecurityStatus.Info,
					Description = "Internet Explorer and WinHTTP secure protocol settings. No policy override is present.",
					Recommendation = "Configure via GPO if IE or WinHTTP legacy protocol use is a concern.",
					Reference = "https://docs.microsoft.com/troubleshoot/windows-server/identity/enable-ldap-signing-in-windows-server"
				};
			}
			int secureProtocols = Convert.ToInt32(secureProtocolsRaw);
			// Correctif M5 : masques réalignés (SSL2=0x8, SSL3=0x20, TLS1.0=0x80, TLS1.1=0x200, TLS1.2=0x800, TLS1.3=0x2000)
			bool ssl2Enabled = (secureProtocols & 0x8) != 0;
			bool ssl3Enabled = (secureProtocols & 0x20) != 0;
			bool tls10Enabled = (secureProtocols & 0x80) != 0;
			bool tls11Enabled = (secureProtocols & 0x200) != 0;
			bool tls12Enabled = (secureProtocols & 0x800) != 0;
			bool tls13Enabled = (secureProtocols & 0x2000) != 0;
			bool hasWeakProtocol = ssl2Enabled || ssl3Enabled || tls10Enabled || tls11Enabled;
			bool hasModernProtocol = tls12Enabled || tls13Enabled;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "IE/WinHTTP: SecureProtocols",
				CurrentValue = $"0x{secureProtocols:X4} (SSL2.0:{ssl2Enabled}, SSL3.0:{ssl3Enabled}, TLS1.0:{tls10Enabled}, TLS1.1:{tls11Enabled}, TLS1.2:{tls12Enabled}, TLS1.3:{tls13Enabled})",
				ExpectedValue = "TLS 1.2 and TLS 1.3 only",
				Status = ((hasWeakProtocol || !hasModernProtocol) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "SecureProtocols bitmask controls which protocols IE and WinHTTP use. Bits: SSL 2.0 = 0x8, SSL 3.0 = 0x20, TLS 1.0 = 0x80, TLS 1.1 = 0x200, TLS 1.2 = 0x800, TLS 1.3 = 0x2000.",
				Recommendation = (hasWeakProtocol ? "Remove SSL 2.0 (0x8), SSL 3.0 (0x20), TLS 1.0 (0x80), and TLS 1.1 (0x200) from the SecureProtocols bitmask." : "Protocol configuration looks good."),
				Reference = ""
			};
		});
	}

	private void CollectSmbSecurity(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lanmanServerKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters");
			object hardeningLevelRaw = lanmanServerKey?.GetValue("SMBServerNameHardeningLevel");
			int hardeningLevel = ((hardeningLevelRaw != null) ? Convert.ToInt32(hardeningLevelRaw) : 0);
			string currentValue = hardeningLevel switch
			{
				0 => "0 - No hardening",
				1 => "1 - Audit mode",
				2 => "2 - Enforce (reject mismatched server names)",
				_ => $"{hardeningLevel} - Unknown",
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "SMB: Server Name Hardening Level",
				CurrentValue = currentValue,
				ExpectedValue = "2 (Enforce)",
				Status = hardeningLevel switch
				{
					1 => SecurityStatus.Warning,
					2 => SecurityStatus.OK,
					_ => SecurityStatus.Warning,
				},
				Description = "SMB server name hardening validates that the client connects to the intended server, helping prevent SMB relay attacks.",
				Recommendation = ((hardeningLevel == 2) ? "SMB name hardening is enforced." : "Set SMBServerNameHardeningLevel = 2 to enforce SMB server name validation."),
				Reference = "https://docs.microsoft.com/windows-server/storage/file-server/smb-security"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lanmanServerKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters");
			object encryptDataRaw = lanmanServerKey?.GetValue("EncryptData");
			bool encryptDataEnabled = ((encryptDataRaw != null) ? Convert.ToInt32(encryptDataRaw) : 0) == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "SMB: Server Encryption (EncryptData)",
				CurrentValue = (encryptDataEnabled ? "Enabled (1)" : "Disabled (0)"),
				ExpectedValue = "1 (Enabled for sensitive environments)",
				Status = ((!encryptDataEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "SMB encryption (SMB 3.0+) protects data in transit against network sniffing. Requires both server and client support.",
				Recommendation = (encryptDataEnabled ? "SMB server encryption is enabled." : "Enable SMB encryption (EncryptData = 1) for sensitive data environments."),
				Reference = "https://docs.microsoft.com/windows-server/storage/file-server/smb-security"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lanmanServerKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters");
			object rejectUnencryptedRaw = lanmanServerKey?.GetValue("RejectUnencryptedAccess");
			bool rejectUnencrypted = ((rejectUnencryptedRaw != null) ? Convert.ToInt32(rejectUnencryptedRaw) : 0) == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "SMB: Reject Unencrypted Access",
				CurrentValue = (rejectUnencrypted ? "Enabled (1)" : "Disabled (0)"),
				ExpectedValue = "1 (Enabled when encryption required)",
				Status = ((!rejectUnencrypted) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "Forces SMB clients to use encryption or be rejected. Only relevant when EncryptData=1.",
				Recommendation = (rejectUnencrypted ? "Unencrypted SMB access is rejected." : "Enable RejectUnencryptedAccess alongside EncryptData for complete SMB encryption enforcement."),
				Reference = "https://docs.microsoft.com/windows-server/storage/file-server/smb-security"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lanmanServerKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters");
			object requireSignatureRaw = lanmanServerKey?.GetValue("RequireSecuritySignature");
			int requireSignature = ((requireSignatureRaw != null) ? Convert.ToInt32(requireSignatureRaw) : 0);
			bool signingRequired = requireSignature == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "SMB: Server Signing Required",
				CurrentValue = (signingRequired ? "Required (1)" : $"Not required ({requireSignature})"),
				ExpectedValue = "1 (Required)",
				Status = ((!signingRequired) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "SMB signing authenticates each SMB packet, preventing man-in-the-middle and SMB relay attacks. Windows 11 24H2 enables this by default.",
				Recommendation = (signingRequired ? "SMB server signing is required." : "Set RequireSecuritySignature = 1 on the server to mandate SMB signing."),
				Reference = "https://docs.microsoft.com/windows-server/storage/file-server/smb-security"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lanmanWorkstationKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters");
			object requireSignatureRaw = lanmanWorkstationKey?.GetValue("RequireSecuritySignature");
			int requireSignature = ((requireSignatureRaw != null) ? Convert.ToInt32(requireSignatureRaw) : 0);
			bool signingRequired = requireSignature == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "SMB: Client Signing Required",
				CurrentValue = (signingRequired ? "Required (1)" : $"Not required ({requireSignature})"),
				ExpectedValue = "1 (Required)",
				Status = ((!signingRequired) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "SMB client signing ensures the client signs all SMB packets, preventing man-in-the-middle attacks on outbound connections.",
				Recommendation = (signingRequired ? "SMB client signing is required." : "Set RequireSecuritySignature = 1 in LanmanWorkstation\\Parameters to require client SMB signing."),
				Reference = "https://docs.microsoft.com/windows-server/storage/file-server/smb-security"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lanmanServerKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters");
			object smb1Raw = lanmanServerKey?.GetValue("SMB1");
			int smb1Value = ((smb1Raw != null) ? Convert.ToInt32(smb1Raw) : (-1));
			bool smb1Disabled = smb1Value == 0;
			string smb1Status = smb1Value switch
			{
				0 => "Disabled (0)",
				-1 => "Not explicitly configured (check Windows Features)",
				_ => $"Enabled ({smb1Value})",
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "SMB: SMBv1 Protocol",
				CurrentValue = smb1Status,
				ExpectedValue = "0 (Disabled)",
				Status = ((!smb1Disabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "SMBv1 is an ancient, insecure protocol exploited by EternalBlue (WannaCry, NotPetya). It must be disabled on all systems.",
				Recommendation = (smb1Disabled ? "SMBv1 is disabled." : "Disable SMBv1 immediately: Set-SmbServerConfiguration -EnableSMB1Protocol $false or Set HKLM\\...\\LanmanServer\\Parameters\\SMB1 = 0."),
				Reference = "https://docs.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
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
				Category = "TLS / Cryptography",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Check failed: " + ex.Message,
				Recommendation = "Review registry access permissions.",
				Reference = ""
			});
		}
	}
}
