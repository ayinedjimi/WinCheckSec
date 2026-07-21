using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services.Helpers;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class BitLockerCollector : ISecurityCollector
{
	private const string BitLockerWmiNamespace = "\\\\.\\root\\cimv2\\Security\\MicrosoftVolumeEncryption";

	private const string FveRegKey = "SOFTWARE\\Policies\\Microsoft\\FVE";

	public string Name => "BitLocker";

	public string Category => "Drive Encryption";

	public Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport collectorReport = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch stopwatch = Stopwatch.StartNew();
		if (WindowsInfo.IsHome)
		{
			collectorReport.Results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "BitLocker Availability",
				Status = SecurityStatus.Info,
				CurrentValue = "Windows " + WindowsInfo.Edition,
				ExpectedValue = "Pro/Enterprise/Education",
				Description = "BitLocker n'est pas disponible sur Windows Home. Device Encryption peut etre active comme alternative."
			});
			return Task.FromResult(collectorReport);
		}
		try
		{
			ct.ThrowIfCancellationRequested();
			CollectEncryptableVolumes(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectFvePolicy(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			collectorReport.ErrorMessage = "BitLockerCollector fatal error: " + ex2.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectEncryptableVolumes(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ManagementObjectSearcher searcher = new ManagementObjectSearcher(WmiHelper.GetScope("\\\\.\\root\\cimv2\\Security\\MicrosoftVolumeEncryption"), new ObjectQuery("SELECT * FROM Win32_EncryptableVolume"));
			try
			{
				bool foundVolume = false;
				bool systemDriveProtected = false;
				using ManagementObjectCollection volumes = searcher.Get();
				foreach (ManagementObject vol in volumes)
				{
					ManagementObject mo = vol;
					try
					{
						ct.ThrowIfCancellationRequested();
						foundVolume = true;
						string driveLetter = vol["DriveLetter"]?.ToString() ?? "Unknown";
						string deviceId = vol["DeviceID"]?.ToString() ?? "Unknown";
						bool isSystemDrive = driveLetter.Equals("C:", StringComparison.OrdinalIgnoreCase);
						int protectionStatus = WmiInt(vol, "ProtectionStatus");
						string protectionStr = protectionStatus switch
						{
							0 => "0 - Off", 
							1 => "1 - On", 
							2 => "2 - Unknown", 
							_ => $"{protectionStatus} - Unavailable", 
						};
						int conversionStatus = WmiInt(vol, "ConversionStatus");
						string conversionStr = conversionStatus switch
						{
							0 => "0 - Fully decrypted", 
							1 => "1 - Fully encrypted", 
							2 => "2 - Encryption in progress", 
							3 => "3 - Decryption in progress", 
							4 => "4 - Encryption paused", 
							5 => "5 - Decryption paused", 
							_ => $"{conversionStatus} - Unknown", 
						};
						int encryptionMethod = WmiInt(vol, "EncryptionMethod");
						string methodStr = encryptionMethod switch
						{
							0 => "0 - None", 
							1 => "1 - AES-CBC 128-bit", 
							2 => "2 - AES-CBC 256-bit", 
							3 => "3 - Hardware Encryption", 
							4 => "4 - XTS-AES 128-bit", 
							5 => "5 - XTS-AES 256-bit", 
							6 => "6 - AES-CBC 128-bit (diffuser)", 
							7 => "7 - AES-CBC 256-bit (diffuser)", 
							_ => $"{encryptionMethod} - Unknown", 
						};
						int encPct = WmiInt(vol, "EncryptionPercentage", 0);
						bool isInitialized = WmiBool(vol, "IsVolumeInitializedForProtection");
						if (protectionStatus == 1)
						{
							systemDriveProtected = isSystemDrive || systemDriveProtected;
						}
						TryAdd(results, delegate
						{
							bool isProtected = protectionStatus == 1;
							SecurityStatus status = ((!isSystemDrive) ? ((!isProtected) ? SecurityStatus.Warning : SecurityStatus.OK) : ((!isProtected) ? SecurityStatus.Critical : SecurityStatus.OK));
							return new SecurityResult
							{
								Category = Category,
								CheckName = "Volume " + driveLetter + ": Protection Status",
								CurrentValue = protectionStr,
								ExpectedValue = "1 - On",
								Status = status,
								Description = $"BitLocker protection status for volume {driveLetter} ({deviceId}). Unprotected drives expose data if the device is lost or stolen.",
								Recommendation = (isProtected ? ("Volume " + driveLetter + " is BitLocker protected.") : ("Enable BitLocker on volume " + driveLetter + ". System drive (C:) is critical.")),
								Reference = "https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-overview"
							};
						});
						TryAdd(results, delegate
						{
							bool isAesCbc = encryptionMethod == 1 || encryptionMethod == 6;
							bool isXtsAes = encryptionMethod == 4 || encryptionMethod == 5;
							return new SecurityResult
							{
								Category = Category,
								CheckName = "Volume " + driveLetter + ": Encryption Method",
								CurrentValue = methodStr,
								ExpectedValue = "XTS-AES 256-bit (5)",
								Status = ((encryptionMethod == 0) ? SecurityStatus.Critical : (isAesCbc ? SecurityStatus.Warning : ((!isXtsAes || encryptionMethod != 5) ? SecurityStatus.Warning : SecurityStatus.OK))),
								Description = "BitLocker encryption algorithm for volume " + driveLetter + ". XTS-AES 256-bit (method 5) is the strongest and recommended for OS and fixed drives.",
								Recommendation = ((isXtsAes && encryptionMethod == 5) ? "Using strongest encryption method (XTS-AES 256-bit)." : ((encryptionMethod == 0) ? "Volume is not encrypted." : "Re-encrypt using XTS-AES 256-bit for optimal security.")),
								Reference = "https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-countermeasures"
							};
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = Category,
							CheckName = "Volume " + driveLetter + ": Conversion Status",
							CurrentValue = $"{conversionStr} ({encPct}%)",
							ExpectedValue = "1 - Fully encrypted",
							Status = ((conversionStatus != 1) ? ((conversionStatus != 0) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
							Description = "Encryption conversion progress for volume " + driveLetter + ".",
							Recommendation = ((conversionStatus == 1) ? "Volume is fully encrypted." : "Allow BitLocker encryption to complete."),
							Reference = ""
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = Category,
							CheckName = "Volume " + driveLetter + ": Initialized for Protection",
							CurrentValue = (isInitialized ? "True" : "False"),
							ExpectedValue = "True",
							Status = ((!isInitialized) ? SecurityStatus.Warning : SecurityStatus.OK),
							Description = "Whether volume " + driveLetter + " has been initialized for BitLocker protection.",
							Recommendation = (isInitialized ? "Volume is initialized for BitLocker." : "Initialize volume for BitLocker protection."),
							Reference = ""
						});
						TryAdd(results, delegate
						{
							List<string> protectorTypes = new List<string>();
							bool hasRecoveryPassword = false;
							bool hasTpmProtector = false;
							try
							{
								ManagementBaseObject methodParameters = vol.GetMethodParameters("GetKeyProtectors");
								try
								{
									methodParameters["KeyProtectorType"] = 0;
									ManagementBaseObject managementBaseObject = vol.InvokeMethod("GetKeyProtectors", methodParameters, null);
									try
									{
										if (managementBaseObject?["VolumeKeyProtectorID"] is string[] protectorIds && protectorIds.Length != 0)
										{
											string[] protectorIdList = protectorIds;
											foreach (string protectorId in protectorIdList)
											{
												try
												{
													ManagementBaseObject methodParameters2 = vol.GetMethodParameters("GetKeyProtectorType");
													try
													{
														methodParameters2["VolumeKeyProtectorID"] = protectorId;
														ManagementBaseObject managementBaseObject2 = vol.InvokeMethod("GetKeyProtectorType", methodParameters2, null);
														try
														{
															object typeValue = managementBaseObject2?["KeyProtectorType"];
															int protectorType = ((typeValue != null && !(typeValue is DBNull)) ? Convert.ToInt32(typeValue) : (-1));
															protectorTypes.Add(protectorType switch
															{
																0 => "Unknown", 
																1 => "TPM", 
																2 => "ExternalKey", 
																3 => "NumericPassword (Recovery Key)", 
																4 => "TPMAndPIN", 
																5 => "TPMAndStartupKey", 
																6 => "TPMAndPINAndStartupKey", 
																7 => "PublicKey", 
																8 => "Passphrase", 
																9 => "TpmNetworkKey", 
																10 => "AdAccountOrGroup",
																_ => $"Type{protectorType}",
															});
															if (protectorType == 3)
															{
																hasRecoveryPassword = true;
															}
															if (protectorType == 1 || protectorType == 4 || protectorType == 5 || protectorType == 6)
															{
																hasTpmProtector = true;
															}
														}
														finally
														{
															((IDisposable)managementBaseObject2)?.Dispose();
														}
													}
													finally
													{
														((IDisposable)methodParameters2)?.Dispose();
													}
												}
												catch (ManagementException)
												{
													protectorTypes.Add("Unknown");
												}
												catch (Exception)
												{
													protectorTypes.Add("Unknown");
												}
											}
										}
									}
									finally
									{
										((IDisposable)managementBaseObject)?.Dispose();
									}
								}
								finally
								{
									((IDisposable)methodParameters)?.Dispose();
								}
							}
							catch (Exception ex3)
							{
								protectorTypes.Add("Error reading protectors: " + ex3.Message);
							}
							string protectorsText = ((protectorTypes.Count > 0) ? string.Join(", ", protectorTypes) : "None");
							bool hasTpmAndRecovery = hasTpmProtector && hasRecoveryPassword;
							return new SecurityResult
							{
								Category = Category,
								CheckName = "Volume " + driveLetter + ": Key Protectors",
								CurrentValue = protectorsText,
								ExpectedValue = "TPM + NumericPassword (Recovery Key)",
								Status = ((!hasTpmAndRecovery) ? ((protectorTypes.Count == 0 || protectorsText == "None") ? SecurityStatus.Critical : ((hasTpmProtector && !hasRecoveryPassword) ? SecurityStatus.Warning : SecurityStatus.Warning)) : SecurityStatus.OK),
								Description = "BitLocker key protectors for volume " + driveLetter + ". TPM protector ensures automatic unlock; Recovery Password provides emergency access.",
								Recommendation = (hasTpmAndRecovery ? "Volume has TPM and Recovery Key protectors." : (hasTpmProtector ? "Add a Recovery Password protector for emergency access." : (hasRecoveryPassword ? "Consider adding TPM protector for automatic unlock." : "Configure BitLocker with TPM and Recovery Password protectors."))),
								Reference = "https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-key-management-faq"
							};
						});
					}
					finally
					{
						((IDisposable)mo)?.Dispose();
					}
				}
				if (!foundVolume)
				{
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "Encryptable Volumes",
						CurrentValue = "No encryptable volumes found",
						ExpectedValue = "At least one volume",
						Status = SecurityStatus.Warning,
						Description = "No volumes were found in the BitLocker WMI namespace.",
						Recommendation = "Ensure BitLocker management is accessible and the system has encryptable drives.",
						Reference = ""
					});
				}
			}
			finally
			{
				((IDisposable)searcher)?.Dispose();
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex6)
		{
			bool manageBdeSucceeded = false;
			try
			{
				manageBdeSucceeded = CollectViaManageBde(results, ct);
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch
			{
			}
			if (!manageBdeSucceeded)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "BitLocker WMI Access",
					CurrentValue = "Error: " + ex6.Message,
					Status = SecurityStatus.Error,
					Description = "Failed to access BitLocker WMI namespace and manage-bde fallback also failed. BitLocker may not be available or requires elevation.",
					Recommendation = "Run CHECKSEC as Administrator. Ensure BitLocker feature is available on this Windows edition.",
					Reference = ""
				});
			}
		}
	}

	private bool CollectViaManageBde(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		string statusOutput;
		try
		{
			using Process process = Process.Start(new ProcessStartInfo
			{
				FileName = "manage-bde.exe",
				Arguments = "-status C:",
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			});
			if (process == null)
			{
				return false;
			}
			statusOutput = process.StandardOutput.ReadToEnd();
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
			if (string.IsNullOrWhiteSpace(statusOutput))
			{
				return false;
			}
		}
		catch
		{
			return false;
		}
		string protectionStatus = ParseManageBdeField(statusOutput, "(?:Protection Status|Status de la protection|État de la protection)\\s*:\\s*(.+)");
		string conversionStatus = ParseManageBdeField(statusOutput, "(?:Conversion Status|Status de la conversion|État de la conversion)\\s*:\\s*(.+)");
		string encryptionMethod = ParseManageBdeField(statusOutput, "(?:Encryption Method|Méthode de chiffrement)\\s*:\\s*(.+)");
		string lockStatus = ParseManageBdeField(statusOutput, "(?:Lock Status|État du verrouillage)\\s*:\\s*(.+)");
		string percentageText = ParseManageBdeField(statusOutput, "(?:Percentage Encrypted|Pourcentage chiffré)\\s*:\\s*(.+)");
		if (string.IsNullOrEmpty(protectionStatus) && string.IsNullOrEmpty(conversionStatus))
		{
			return false;
		}
		bool isProtected = protectionStatus.IndexOf("On", StringComparison.OrdinalIgnoreCase) >= 0 || protectionStatus.IndexOf("activé", StringComparison.OrdinalIgnoreCase) >= 0;
		bool isFullyEncrypted = conversionStatus.IndexOf("Fully Encrypted", StringComparison.OrdinalIgnoreCase) >= 0 || conversionStatus.IndexOf("Complètement chiffré", StringComparison.OrdinalIgnoreCase) >= 0 || conversionStatus.IndexOf("Entièrement chiffré", StringComparison.OrdinalIgnoreCase) >= 0;
		bool isFullyDecrypted = conversionStatus.IndexOf("Fully Decrypted", StringComparison.OrdinalIgnoreCase) >= 0 || conversionStatus.IndexOf("Entièrement déchiffré", StringComparison.OrdinalIgnoreCase) >= 0 || conversionStatus.IndexOf("Complètement déchiffré", StringComparison.OrdinalIgnoreCase) >= 0;
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Volume C: Protection Status (manage-bde)",
			CurrentValue = protectionStatus,
			ExpectedValue = "Protection On",
			Status = ((!isProtected) ? SecurityStatus.Critical : SecurityStatus.OK),
			Description = "BitLocker protection status for C: via manage-bde fallback (WMI was unavailable). " + (isProtected ? "Drive is protected." : "Drive is NOT protected."),
			Recommendation = (isProtected ? "Volume C: is BitLocker protected." : "Enable BitLocker on the system drive (C:)."),
			Reference = "https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-overview"
		});
		if (!string.IsNullOrEmpty(encryptionMethod))
		{
			bool isXtsAes256 = encryptionMethod.IndexOf("XTS-AES 256", StringComparison.OrdinalIgnoreCase) >= 0;
			bool isXtsAes257 = encryptionMethod.IndexOf("XTS-AES 128", StringComparison.OrdinalIgnoreCase) >= 0;
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Volume C: Encryption Method (manage-bde)",
				CurrentValue = encryptionMethod,
				ExpectedValue = "XTS-AES 256",
				Status = ((!isXtsAes256) ? (isXtsAes257 ? SecurityStatus.Warning : ((encryptionMethod.IndexOf("None", StringComparison.OrdinalIgnoreCase) < 0) ? SecurityStatus.Warning : SecurityStatus.Critical)) : SecurityStatus.OK),
				Description = "BitLocker encryption algorithm for C: (via manage-bde fallback).",
				Recommendation = (isXtsAes256 ? "Using strongest encryption method." : "Re-encrypt using XTS-AES 256-bit for optimal security."),
				Reference = "https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-countermeasures"
			});
		}
		if (!string.IsNullOrEmpty(conversionStatus))
		{
			string pctStr = ((!string.IsNullOrEmpty(percentageText)) ? (" (" + percentageText + ")") : "");
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Volume C: Conversion Status (manage-bde)",
				CurrentValue = conversionStatus + pctStr,
				ExpectedValue = "Fully Encrypted",
				Status = ((!isFullyEncrypted) ? ((!isFullyDecrypted) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
				Description = "Encryption conversion progress for C: (via manage-bde fallback).",
				Recommendation = (isFullyEncrypted ? "Volume is fully encrypted." : "Allow BitLocker encryption to complete."),
				Reference = ""
			});
		}
		if (!string.IsNullOrEmpty(lockStatus))
		{
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Volume C: Lock Status (manage-bde)",
				CurrentValue = lockStatus,
				ExpectedValue = "Unlocked (for OS drive)",
				Status = SecurityStatus.Info,
				Description = "BitLocker lock status for C: (via manage-bde fallback). OS drive is normally unlocked while running.",
				Recommendation = "OS drive should be unlocked during operation.",
				Reference = ""
			});
		}
		return true;
	}

	private static string ParseManageBdeField(string output, string pattern)
	{
		Match match = Regex.Match(output, pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline);
		if (!match.Success)
		{
			return string.Empty;
		}
		return match.Groups[1].Value.Trim();
	}

	private void CollectFvePolicy(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey fveKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\FVE");
			object rawValue = fveKey?.GetValue("UseAdvancedStartup");
			int useAdvancedStartup = ((rawValue != null) ? Convert.ToInt32(rawValue) : (-1));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "FVE Policy: UseAdvancedStartup",
				CurrentValue = ((useAdvancedStartup == -1) ? "Not configured" : useAdvancedStartup.ToString()),
				ExpectedValue = "1 (Enabled)",
				Status = ((useAdvancedStartup != 1) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "Requires additional authentication at startup (TPM+PIN, USB key, etc.). Provides stronger protection than TPM-only unlock.",
				Recommendation = "Enable advanced startup authentication for highest security.",
				Reference = "https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey fveKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\FVE");
			object rawValue = fveKey?.GetValue("EnableBDEWithNoTPM");
			int enableBdeWithNoTpm = ((rawValue != null) ? Convert.ToInt32(rawValue) : 0);
			bool noTpmAllowed = enableBdeWithNoTpm == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "FVE Policy: EnableBDEWithNoTPM",
				CurrentValue = ((enableBdeWithNoTpm == -1) ? "Not configured" : enableBdeWithNoTpm.ToString()),
				ExpectedValue = "0 (Disabled - require TPM)",
				Status = (noTpmAllowed ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Allows BitLocker without a TPM, requiring only a startup key or password. TPM-based protection is significantly stronger.",
				Recommendation = (noTpmAllowed ? "Disable BitLocker without TPM to enforce hardware-backed protection." : "BitLocker without TPM is not allowed."),
				Reference = "https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey fveKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\FVE");
			object rawValue = fveKey?.GetValue("UseTPM");
			int useTpm = ((rawValue != null) ? Convert.ToInt32(rawValue) : (-1));
			string currentValue = useTpm switch
			{
				0 => "0 - Disallow TPM",
				1 => "1 - Require TPM",
				2 => "2 - Allow TPM",
				_ => "Not configured",
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "FVE Policy: UseTPM",
				CurrentValue = currentValue,
				ExpectedValue = "1 (Require TPM)",
				Status = useTpm switch
				{
					2 => SecurityStatus.Warning, 
					1 => SecurityStatus.OK, 
					_ => SecurityStatus.Info, 
				},
				Description = "Policy for TPM use with BitLocker. Requiring TPM ensures hardware-backed key storage.",
				Recommendation = "Set UseTPM = 1 to require TPM for BitLocker.",
				Reference = "https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey fveKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\FVE");
			object rawValue = fveKey?.GetValue("UseTPMPIN");
			int useTpmPin = ((rawValue != null) ? Convert.ToInt32(rawValue) : (-1));
			string useTpmPinText = useTpmPin switch
			{
				0 => "0 - Disallow TPM+PIN",
				1 => "1 - Require TPM+PIN",
				2 => "2 - Allow TPM+PIN",
				_ => "Not configured",
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "FVE Policy: UseTPMPIN",
				CurrentValue = useTpmPinText,
				ExpectedValue = "1 (Require) or 2 (Allow) for high-security",
				Status = useTpmPin switch
				{
					2 => SecurityStatus.OK, 
					1 => SecurityStatus.OK, 
					_ => SecurityStatus.Info, 
				},
				Description = "TPM+PIN requires both hardware TPM and a user-defined PIN at boot, providing two-factor protection against offline attacks.",
				Recommendation = "Consider requiring TPM+PIN for systems at higher physical theft risk.",
				Reference = "https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey fveKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\FVE");
			object rawValue = fveKey?.GetValue("EncryptionMethodWithXtsFdv");
			int encMethodXtsFdv = ((rawValue != null) ? Convert.ToInt32(rawValue) : (-1));
			string methodText;
			object methodBoxed;
			switch (encMethodXtsFdv)
			{
			case 3:
				methodText = "3 - AES-CBC 128-bit";
				break;
			case 4:
				methodText = "4 - AES-CBC 256-bit";
				break;
			case 6:
				methodText = "6 - XTS-AES 128-bit";
				break;
			case 7:
				methodText = "7 - XTS-AES 256-bit (recommended)";
				break;
			default:
				methodBoxed = $"{encMethodXtsFdv}";
				goto IL_00a0;
			case -1:
				{
					methodBoxed = "Not configured (default)";
					goto IL_00a0;
				}
				IL_00a0:
				methodText = (string)methodBoxed;
				break;
			}
			string methodDisplay = methodText;
			bool isXtsAes256 = encMethodXtsFdv == 7;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "FVE Policy: EncryptionMethod (Fixed Drives)",
				CurrentValue = methodDisplay,
				ExpectedValue = "7 (XTS-AES 256-bit)",
				Status = ((!isXtsAes256) ? ((encMethodXtsFdv == 6) ? SecurityStatus.Warning : SecurityStatus.Info) : SecurityStatus.OK),
				Description = "Policy-mandated encryption algorithm for fixed data drives. XTS-AES 256-bit provides the strongest protection.",
				Recommendation = (isXtsAes256 ? "Optimal encryption method configured." : "Set EncryptionMethodWithXtsFdv = 7 for XTS-AES 256-bit on fixed drives."),
				Reference = "https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey fveKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\FVE");
			object rawValue = fveKey?.GetValue("EncryptionMethodWithXtsOs");
			int encMethodXtsOs = ((rawValue != null) ? Convert.ToInt32(rawValue) : (-1));
			string methodText;
			object methodBoxed;
			switch (encMethodXtsOs)
			{
			case 3:
				methodText = "3 - AES-CBC 128-bit";
				break;
			case 4:
				methodText = "4 - AES-CBC 256-bit";
				break;
			case 6:
				methodText = "6 - XTS-AES 128-bit";
				break;
			case 7:
				methodText = "7 - XTS-AES 256-bit (recommended)";
				break;
			default:
				methodBoxed = $"{encMethodXtsOs}";
				goto IL_00a0;
			case -1:
				{
					methodBoxed = "Not configured (default)";
					goto IL_00a0;
				}
				IL_00a0:
				methodText = (string)methodBoxed;
				break;
			}
			string methodDisplay = methodText;
			bool isXtsAes256 = encMethodXtsOs == 7;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "FVE Policy: EncryptionMethod (OS Drive)",
				CurrentValue = methodDisplay,
				ExpectedValue = "7 (XTS-AES 256-bit)",
				Status = ((!isXtsAes256) ? ((encMethodXtsOs == 6) ? SecurityStatus.Warning : SecurityStatus.Info) : SecurityStatus.OK),
				Description = "Policy-mandated encryption algorithm for OS drives. XTS-AES is only supported on Windows 10/11 1511+ and provides integrity protection.",
				Recommendation = (isXtsAes256 ? "Optimal encryption method for OS drive configured." : "Set EncryptionMethodWithXtsOs = 7 for XTS-AES 256-bit on OS drive."),
				Reference = "https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings"
			};
		});
	}

	private static int WmiInt(ManagementObject obj, string prop, int def = -1)
	{
		object value = obj[prop];
		if (value == null || value is DBNull)
		{
			return def;
		}
		return Convert.ToInt32(value);
	}

	private static bool WmiBool(ManagementObject obj, string prop, bool def = false)
	{
		object value = obj[prop];
		if (value == null || value is DBNull)
		{
			return def;
		}
		return Convert.ToBoolean(value);
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
				Category = "Drive Encryption",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Check failed: " + ex.Message,
				Recommendation = "Run as Administrator and verify BitLocker availability.",
				Reference = ""
			});
		}
	}
}
