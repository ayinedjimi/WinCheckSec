using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services.Helpers;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class SystemInfoCollector : ISecurityCollector
{
	public string Name => "System Information";

	public string Category => "System";

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
			CollectOsInfo(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectHardwareInfo(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectBiosInfo(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectTpmInfo(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectVirtualizationInfo(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectDiskInfo(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectNetworkInfo(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectDomainInfo(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectSecureBootInfo(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "SystemInfoCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectOsInfo(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
			try
			{
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				foreach (ManagementObject os in managementObjectCollection)
				{
					ManagementObject managementObject = os;
					try
					{
						ct.ThrowIfCancellationRequested();
						TryAdd(results, () => new SecurityResult
						{
							Category = "OS",
							CheckName = "OS Caption",
							CurrentValue = (os["Caption"]?.ToString() ?? "Unknown"),
							ExpectedValue = "Windows 11",
							Status = SecurityStatus.Info,
							Description = "Operating system name and edition.",
							Recommendation = "Ensure you are running a supported Windows 11 edition.",
							Reference = "https://docs.microsoft.com/windows/release-health/"
						});
						TryAdd(results, delegate
						{
							string osVersion = os["Version"]?.ToString() ?? "Unknown";
							return new SecurityResult
							{
								Category = "OS",
								CheckName = "OS Version",
								CurrentValue = osVersion,
								ExpectedValue = ">= 10.0.22000",
								Status = SecurityStatus.Info,
								Description = "Operating system kernel version string.",
								Recommendation = "Keep Windows fully patched.",
								Reference = "https://docs.microsoft.com/windows/release-health/"
							};
						});
						TryAdd(results, delegate
						{
							string buildNumber = os["BuildNumber"]?.ToString() ?? "Unknown";
							int parsedBuild;
							bool isWin11Build = (int.TryParse(buildNumber, out parsedBuild) ? parsedBuild : 0) >= 22000;
							return new SecurityResult
							{
								Category = "OS",
								CheckName = "OS Build Number",
								CurrentValue = buildNumber,
								ExpectedValue = ">= 22000 (Windows 11)",
								Status = ((!isWin11Build) ? SecurityStatus.Warning : SecurityStatus.OK),
								Description = "Build number determines feature availability and patch level. Windows 11 requires build 22000+.",
								Recommendation = (isWin11Build ? "System is running Windows 11." : "Upgrade to Windows 11 for improved security features."),
								Reference = "https://docs.microsoft.com/windows/release-health/"
							};
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = "OS",
							CheckName = "OS Architecture",
							CurrentValue = (os["OSArchitecture"]?.ToString() ?? "Unknown"),
							ExpectedValue = "64-bit",
							Status = ((!(os["OSArchitecture"]?.ToString() ?? "").Contains("64")) ? SecurityStatus.Warning : SecurityStatus.OK),
							Description = "64-bit OS provides additional security features like Kernel Patch Protection (PatchGuard).",
							Recommendation = "Run 64-bit Windows for full security feature support.",
							Reference = "https://docs.microsoft.com/windows/security/"
						});
						TryAdd(results, delegate
						{
							string installDateRaw = os["InstallDate"]?.ToString() ?? "";
							string installDateDisplay = "Unknown";
							if (!string.IsNullOrEmpty(installDateRaw) && installDateRaw.Length >= 8)
							{
								installDateDisplay = ManagementDateTimeConverter.ToDateTime(installDateRaw).ToString("yyyy-MM-dd HH:mm:ss");
							}
							return new SecurityResult
							{
								Category = "OS",
								CheckName = "OS Install Date",
								CurrentValue = installDateDisplay,
								ExpectedValue = "Any",
								Status = SecurityStatus.Info,
								Description = "Date when the operating system was installed.",
								Recommendation = "Note installation date for compliance records.",
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							string lastBootRaw = os["LastBootUpTime"]?.ToString() ?? "";
							string lastBootDisplay = "Unknown";
							TimeSpan uptime = TimeSpan.Zero;
							if (!string.IsNullOrEmpty(lastBootRaw) && lastBootRaw.Length >= 8)
							{
								DateTime lastBootTime = ManagementDateTimeConverter.ToDateTime(lastBootRaw);
								lastBootDisplay = lastBootTime.ToString("yyyy-MM-dd HH:mm:ss");
								uptime = DateTime.Now - lastBootTime;
							}
							return new SecurityResult
							{
								Category = "OS",
								CheckName = "Last Boot Time",
								CurrentValue = $"{lastBootDisplay} (Uptime: {(int)uptime.TotalDays}d {uptime.Hours}h {uptime.Minutes}m)",
								ExpectedValue = "< 30 days uptime recommended",
								Status = ((uptime.TotalDays > 30.0) ? SecurityStatus.Warning : SecurityStatus.OK),
								Description = "Systems with long uptimes may be missing security patches that require a reboot.",
								Recommendation = ((uptime.TotalDays > 30.0) ? "Reboot to apply pending security updates." : "Uptime is acceptable."),
								Reference = "https://docs.microsoft.com/windows/deployment/update/"
							};
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = "OS",
							CheckName = "System Directory",
							CurrentValue = (os["SystemDirectory"]?.ToString() ?? "Unknown"),
							ExpectedValue = "C:\\Windows\\system32",
							Status = SecurityStatus.Info,
							Description = "Path to the Windows system32 directory.",
							Recommendation = "Ensure the system directory is on a protected NTFS volume.",
							Reference = ""
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = "OS",
							CheckName = "Windows Directory",
							CurrentValue = (os["WindowsDirectory"]?.ToString() ?? "Unknown"),
							ExpectedValue = "C:\\Windows",
							Status = SecurityStatus.Info,
							Description = "Path to the Windows directory.",
							Recommendation = "",
							Reference = ""
						});
						TryAdd(results, delegate
						{
							string osLanguage = os["OSLanguage"]?.ToString() ?? "Unknown";
							return new SecurityResult
							{
								Category = "OS",
								CheckName = "OS Language Code",
								CurrentValue = osLanguage,
								ExpectedValue = "Any",
								Status = SecurityStatus.Info,
								Description = "Windows locale language code (e.g. 1033=English US).",
								Recommendation = "Verify locale meets organizational requirements.",
								Reference = ""
							};
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = "OS",
							CheckName = "Registered Owner",
							CurrentValue = (os["RegisteredUser"]?.ToString() ?? "Unknown"),
							ExpectedValue = "Organization name",
							Status = SecurityStatus.Info,
							Description = "Registered owner of the Windows license.",
							Recommendation = "Ensure owner information is set correctly per organizational policy.",
							Reference = ""
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = "OS",
							CheckName = "Registered Organization",
							CurrentValue = (os["Organization"]?.ToString() ?? "(Not set)"),
							ExpectedValue = "Organization name",
							Status = (string.IsNullOrEmpty(os["Organization"]?.ToString()) ? SecurityStatus.Warning : SecurityStatus.OK),
							Description = "Registered organization of the Windows license. Should be set per organizational policy.",
							Recommendation = "Set the organization name for proper asset tracking.",
							Reference = ""
						});
					}
					finally
					{
						((IDisposable)managementObject)?.Dispose();
					}
				}
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
				Category = "OS",
				CheckName = "OS Information",
				CurrentValue = "Error",
				ExpectedValue = "N/A",
				Status = SecurityStatus.Error,
				Description = "Failed to collect OS information: " + ex.Message,
				Recommendation = "Check WMI service is running.",
				Reference = ""
			});
		}
	}

	private void CollectHardwareInfo(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
			try
			{
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				foreach (ManagementObject computerSystem in managementObjectCollection)
				{
					ManagementObject managementObject = computerSystem;
					try
					{
						ct.ThrowIfCancellationRequested();
						TryAdd(results, () => new SecurityResult
						{
							Category = "Hardware",
							CheckName = "Manufacturer",
							CurrentValue = (computerSystem["Manufacturer"]?.ToString() ?? "Unknown"),
							ExpectedValue = "Known OEM",
							Status = SecurityStatus.Info,
							Description = "System hardware manufacturer.",
							Recommendation = "Verify hardware manufacturer for warranty and support purposes.",
							Reference = ""
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = "Hardware",
							CheckName = "Model",
							CurrentValue = (computerSystem["Model"]?.ToString() ?? "Unknown"),
							ExpectedValue = "Known model",
							Status = SecurityStatus.Info,
							Description = "System hardware model name.",
							Recommendation = "Verify hardware model for inventory and compliance.",
							Reference = ""
						});
						TryAdd(results, delegate
						{
							double memoryGb = (double)WmiULong(computerSystem, "TotalPhysicalMemory", 0uL) / 1073741824.0;
							return new SecurityResult
							{
								Category = "Hardware",
								CheckName = "Total Physical Memory",
								CurrentValue = $"{memoryGb:F2} GB",
								ExpectedValue = ">= 8 GB",
								Status = ((!(memoryGb >= 8.0)) ? SecurityStatus.Warning : SecurityStatus.OK),
								Description = "Total RAM available. Insufficient memory can limit security features like VBS/HVCI.",
								Recommendation = ((memoryGb < 8.0) ? "Increase RAM to at least 8 GB to support VBS and HVCI." : "RAM is sufficient."),
								Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/requirements-and-deployment-planning-guidelines-for-virtualization-based-protection-of-code-integrity"
							};
						});
						TryAdd(results, delegate
						{
							string processorCount = computerSystem["NumberOfProcessors"]?.ToString() ?? "Unknown";
							return new SecurityResult
							{
								Category = "Hardware",
								CheckName = "Number of Processors",
								CurrentValue = processorCount,
								ExpectedValue = ">= 1",
								Status = SecurityStatus.Info,
								Description = "Number of physical processors in the system.",
								Recommendation = "",
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							string systemType = computerSystem["SystemType"]?.ToString() ?? "Unknown";
							return new SecurityResult
							{
								Category = "Hardware",
								CheckName = "System Type",
								CurrentValue = systemType,
								ExpectedValue = "x64-based PC",
								Status = ((!systemType.Contains("x64")) ? SecurityStatus.Warning : SecurityStatus.OK),
								Description = "Processor architecture. x64 is required for all modern Windows security features.",
								Recommendation = "Ensure system is x64-based for full security feature support.",
								Reference = ""
							};
						});
					}
					finally
					{
						((IDisposable)managementObject)?.Dispose();
					}
				}
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
				Category = "Hardware",
				CheckName = "Hardware Information",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Failed to collect hardware info: " + ex.Message,
				Recommendation = "Check WMI availability.",
				Reference = ""
			});
		}
		try
		{
			ManagementObjectSearcher managementObjectSearcher2 = new ManagementObjectSearcher("SELECT * FROM Win32_Processor");
			try
			{
				using ManagementObjectCollection managementObjectCollection2 = managementObjectSearcher2.Get();
				int cpuIndex = 0;
				foreach (ManagementObject cpu in managementObjectCollection2)
				{
					ManagementObject managementObject2 = cpu;
					try
					{
						ct.ThrowIfCancellationRequested();
						string prefix = $"CPU[{cpuIndex}]";
						TryAdd(results, () => new SecurityResult
						{
							Category = "Hardware",
							CheckName = prefix + " Name",
							CurrentValue = (cpu["Name"]?.ToString() ?? "Unknown"),
							ExpectedValue = "Modern x64 CPU",
							Status = SecurityStatus.Info,
							Description = "Processor name and model.",
							Recommendation = "",
							Reference = ""
						});
						TryAdd(results, delegate
						{
							string maxSpeedRaw = cpu["MaxClockSpeed"]?.ToString() ?? "0";
							double parsedSpeed;
							double speedGhz = (double.TryParse(maxSpeedRaw, out parsedSpeed) ? (parsedSpeed / 1000.0) : 0.0);
							return new SecurityResult
							{
								Category = "Hardware",
								CheckName = prefix + " Max Speed",
								CurrentValue = $"{speedGhz:F2} GHz ({maxSpeedRaw} MHz)",
								ExpectedValue = "> 1 GHz",
								Status = SecurityStatus.Info,
								Description = "Maximum CPU clock speed.",
								Recommendation = "",
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							string coreCount = cpu["NumberOfCores"]?.ToString() ?? "Unknown";
							return new SecurityResult
							{
								Category = "Hardware",
								CheckName = prefix + " Cores",
								CurrentValue = coreCount,
								ExpectedValue = ">= 2",
								Status = SecurityStatus.Info,
								Description = "Number of physical cores. More cores can improve security scanning performance.",
								Recommendation = "",
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							string threadCount = cpu["NumberOfLogicalProcessors"]?.ToString() ?? "Unknown";
							return new SecurityResult
							{
								Category = "Hardware",
								CheckName = prefix + " Logical Processors (Threads)",
								CurrentValue = threadCount,
								ExpectedValue = ">= 2",
								Status = SecurityStatus.Info,
								Description = "Number of logical processors (hardware threads).",
								Recommendation = "",
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							string virtFirmware = cpu["VirtualizationFirmwareEnabled"]?.ToString() ?? "Unknown";
							bool virtEnabled = virtFirmware.Equals("True", StringComparison.OrdinalIgnoreCase);
							return new SecurityResult
							{
								Category = "Hardware",
								CheckName = prefix + " Virtualization Firmware Enabled",
								CurrentValue = virtFirmware,
								ExpectedValue = "True",
								Status = ((!virtEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
								Description = "Hardware virtualization (VT-x/AMD-V) must be enabled in firmware for VBS, HVCI, and Hyper-V.",
								Recommendation = (virtEnabled ? "Hardware virtualization is enabled." : "Enable hardware virtualization (Intel VT-x or AMD-V) in BIOS/UEFI settings."),
								Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
							};
						});
						cpuIndex++;
					}
					finally
					{
						((IDisposable)managementObject2)?.Dispose();
					}
				}
			}
			finally
			{
				((IDisposable)managementObjectSearcher2)?.Dispose();
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
				Category = "Hardware",
				CheckName = "CPU Information",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Failed to collect CPU info: " + ex.Message,
				Recommendation = "Check WMI availability.",
				Reference = ""
			});
		}
	}

	private void CollectBiosInfo(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS");
			try
			{
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				foreach (ManagementObject bios in managementObjectCollection)
				{
					ManagementObject managementObject = bios;
					try
					{
						ct.ThrowIfCancellationRequested();
						TryAdd(results, () => new SecurityResult
						{
							Category = "BIOS",
							CheckName = "BIOS Version",
							CurrentValue = (bios["SMBIOSBIOSVersion"]?.ToString() ?? "Unknown"),
							ExpectedValue = "Latest available",
							Status = SecurityStatus.Info,
							Description = "BIOS/UEFI firmware version. Outdated firmware may contain security vulnerabilities.",
							Recommendation = "Check with your hardware vendor for the latest BIOS/UEFI firmware update.",
							Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection"
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = "BIOS",
							CheckName = "BIOS Manufacturer",
							CurrentValue = (bios["Manufacturer"]?.ToString() ?? "Unknown"),
							ExpectedValue = "Known OEM",
							Status = SecurityStatus.Info,
							Description = "Firmware manufacturer.",
							Recommendation = "",
							Reference = ""
						});
						TryAdd(results, delegate
						{
							string releaseDateRaw = bios["ReleaseDate"]?.ToString() ?? "";
							string releaseDateDisplay = "Unknown";
							if (!string.IsNullOrEmpty(releaseDateRaw) && releaseDateRaw.Length >= 8)
							{
								releaseDateDisplay = ManagementDateTimeConverter.ToDateTime(releaseDateRaw).ToString("yyyy-MM-dd");
							}
							return new SecurityResult
							{
								Category = "BIOS",
								CheckName = "BIOS Release Date",
								CurrentValue = releaseDateDisplay,
								ExpectedValue = "Recent date",
								Status = SecurityStatus.Info,
								Description = "BIOS/UEFI firmware release date. Older firmware may lack security mitigations.",
								Recommendation = "Keep firmware updated to receive security patches.",
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							object biosCharacteristics = bios["BiosCharacteristics"];
							bool isUefi = false;
							if (biosCharacteristics is ushort[] characteristicsArray)
							{
								ushort[] characteristics = characteristicsArray;
								foreach (ushort characteristic in characteristics)
								{
									if (characteristic == 19 || characteristic == 20)
									{
										isUefi = true;
										break;
									}
								}
							}
							string smbiosMajorVersion = bios["SMBIOSMajorVersion"]?.ToString() ?? "0";
							return new SecurityResult
							{
								Category = "BIOS",
								CheckName = "UEFI / BIOS Type",
								CurrentValue = (isUefi ? "UEFI (BiosCharacteristics)" : "BIOS legacy ou inconnu") + " — SMBIOS Major Version: " + smbiosMajorVersion,
								ExpectedValue = "UEFI",
								Status = ((!isUefi) ? SecurityStatus.Warning : SecurityStatus.OK),
								Description = "UEFI firmware provides Secure Boot support and modern security features over legacy BIOS.",
								Recommendation = "Ensure system is using UEFI firmware, not legacy BIOS.",
								Reference = "https://docs.microsoft.com/windows-hardware/design/device-experiences/oem-secure-boot"
							};
						});
					}
					finally
					{
						((IDisposable)managementObject)?.Dispose();
					}
				}
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
				Category = "BIOS",
				CheckName = "BIOS Information",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Failed to collect BIOS info: " + ex.Message,
				Recommendation = "Check WMI availability.",
				Reference = ""
			});
		}
	}

	private void CollectSecureBootInfo(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey secureBootStateKey = baseKey64.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
			if (secureBootStateKey == null)
			{
				return new SecurityResult
				{
					Category = "BIOS",
					CheckName = "Secure Boot Status",
					CurrentValue = "Key not found (legacy BIOS or unsupported)",
					ExpectedValue = "Enabled (1)",
					Status = SecurityStatus.Critical,
					Description = "Secure Boot is a UEFI feature that prevents unauthorized bootloaders and OS loaders from running at startup. It protects against bootkit and rootkit attacks.",
					Recommendation = "Enable UEFI and Secure Boot in your firmware settings. Secure Boot is required for Windows 11.",
					Reference = "https://docs.microsoft.com/windows-hardware/design/device-experiences/oem-secure-boot"
				};
			}
			object secureBootEnabledValue = secureBootStateKey.GetValue("UEFISecureBootEnabled");
			bool secureBootEnabled = secureBootEnabledValue != null && Convert.ToInt32(secureBootEnabledValue) == 1;
			return new SecurityResult
			{
				Category = "BIOS",
				CheckName = "Secure Boot Status",
				CurrentValue = (secureBootEnabledValue?.ToString() ?? "Not set"),
				ExpectedValue = "1 (Enabled)",
				Status = ((!secureBootEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Secure Boot prevents unauthorized bootloaders and operating system loaders from running at startup, protecting against bootkits and rootkits.",
				Recommendation = (secureBootEnabled ? "Secure Boot is enabled." : "Enable Secure Boot in UEFI firmware settings immediately."),
				Reference = "https://docs.microsoft.com/windows-hardware/design/device-experiences/oem-secure-boot"
			};
		});
	}

	private void CollectTpmInfo(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(WmiHelper.GetScope("\\\\.\\root\\cimv2\\Security\\MicrosoftTpm"), new ObjectQuery("SELECT * FROM Win32_Tpm"));
			try
			{
				bool tpmDetected = false;
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				foreach (ManagementObject tpm in managementObjectCollection)
				{
					ManagementObject managementObject = tpm;
					try
					{
						tpmDetected = true;
						ct.ThrowIfCancellationRequested();
						TryAdd(results, delegate
						{
							string isEnabledRaw = tpm["IsEnabled_InitialValue"]?.ToString() ?? "Unknown";
							bool tpmEnabled = isEnabledRaw.Equals("True", StringComparison.OrdinalIgnoreCase);
							return new SecurityResult
							{
								Category = "TPM",
								CheckName = "TPM Enabled",
								CurrentValue = isEnabledRaw,
								ExpectedValue = "True",
								Status = ((!tpmEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
								Description = "A Trusted Platform Module (TPM) is a hardware security chip that stores cryptographic keys, enables BitLocker, Windows Hello, and attestation features.",
								Recommendation = (tpmEnabled ? "TPM is enabled." : "Enable TPM in BIOS/UEFI settings. TPM 2.0 is required for Windows 11."),
								Reference = "https://docs.microsoft.com/windows/security/information-protection/tpm/tpm-fundamentals"
							};
						});
						TryAdd(results, delegate
						{
							string isActivatedRaw = tpm["IsActivated_InitialValue"]?.ToString() ?? "Unknown";
							bool tpmActivated = isActivatedRaw.Equals("True", StringComparison.OrdinalIgnoreCase);
							return new SecurityResult
							{
								Category = "TPM",
								CheckName = "TPM Activated",
								CurrentValue = isActivatedRaw,
								ExpectedValue = "True",
								Status = ((!tpmActivated) ? SecurityStatus.Critical : SecurityStatus.OK),
								Description = "TPM must be activated to be used by Windows security features.",
								Recommendation = (tpmActivated ? "TPM is activated." : "Activate TPM in BIOS/UEFI settings."),
								Reference = "https://docs.microsoft.com/windows/security/information-protection/tpm/tpm-fundamentals"
							};
						});
						TryAdd(results, delegate
						{
							string isOwnedRaw = tpm["IsOwned_InitialValue"]?.ToString() ?? "Unknown";
							return new SecurityResult
							{
								Category = "TPM",
								CheckName = "TPM Owned",
								CurrentValue = isOwnedRaw,
								ExpectedValue = "True",
								Status = ((!isOwnedRaw.Equals("True", StringComparison.OrdinalIgnoreCase)) ? SecurityStatus.Warning : SecurityStatus.OK),
								Description = "TPM ownership indicates Windows has provisioned the TPM with an owner authorization value.",
								Recommendation = "Windows should automatically take TPM ownership. If not, check TPM management.",
								Reference = "https://docs.microsoft.com/windows/security/information-protection/tpm/initialize-and-configure-ownership-of-the-tpm"
							};
						});
						TryAdd(results, delegate
						{
							string specVersion = tpm["SpecVersion"]?.ToString() ?? "Unknown";
							bool isTpm2 = specVersion.StartsWith("2.");
							bool isTpm1 = specVersion.StartsWith("1.");
							SecurityStatus status = ((!isTpm2) ? (isTpm1 ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK);
							string recommendation = (isTpm2 ? "TPM 2.0 détecté." : (isTpm1 ? "TPM 1.2 détecté — TPM 2.0 recommandé pour Windows 11, BitLocker avancé et Credential Guard." : "Version TPM inconnue. Vérifiez le firmware TPM et mettez à jour vers TPM 2.0."));
							return new SecurityResult
							{
								Category = "TPM",
								CheckName = "TPM Spec Version",
								CurrentValue = specVersion,
								ExpectedValue = "2.0",
								Status = status,
								Description = "TPM 2.0 est requis pour Windows 11 et offre des algorithmes cryptographiques plus robustes (SHA-256, ECC) par rapport au TPM 1.2.",
								Recommendation = recommendation,
								Reference = "https://docs.microsoft.com/windows/security/information-protection/tpm/tpm-recommendations"
							};
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = "TPM",
							CheckName = "TPM Manufacturer Version",
							CurrentValue = (tpm["ManufacturerVersion"]?.ToString() ?? "Unknown"),
							ExpectedValue = "Latest",
							Status = SecurityStatus.Info,
							Description = "TPM firmware version from the manufacturer.",
							Recommendation = "Check with hardware vendor for latest TPM firmware updates.",
							Reference = ""
						});
					}
					finally
					{
						((IDisposable)managementObject)?.Dispose();
					}
				}
				if (!tpmDetected)
				{
					results.Add(new SecurityResult
					{
						Category = "TPM",
						CheckName = "TPM Present",
						CurrentValue = "No TPM detected",
						ExpectedValue = "TPM 2.0 present",
						Status = SecurityStatus.Critical,
						Description = "No TPM was found. TPM 2.0 is required for Windows 11 and many security features including BitLocker, Windows Hello for Business, and Credential Guard.",
						Recommendation = "Install or enable a TPM 2.0 chip. This may require a hardware upgrade.",
						Reference = "https://docs.microsoft.com/windows/security/information-protection/tpm/tpm-recommendations"
					});
				}
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
				Category = "TPM",
				CheckName = "TPM Information",
				CurrentValue = "Error accessing TPM WMI — using registry fallback",
				Status = SecurityStatus.Warning,
				Description = "Failed to query TPM via WMI: " + ex.Message + ". Fallback vers le registre.",
				Recommendation = "Ensure TPM is enabled and WMI is functional. Try tpm.msc to verify TPM status.",
				Reference = ""
			});
			CollectTpmRegistry(results, ct);
		}
	}

	private void CollectTpmRegistry(List<SecurityResult> results, CancellationToken ct)
	{
		TryAdd(results, delegate
		{
			string serviceState = "Unknown";
			try
			{
				ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT State FROM Win32_Service WHERE Name='TPM'");
				try
				{
					using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
					foreach (ManagementObject service in managementObjectCollection)
					{
						ManagementObject managementObject2 = service;
						try
						{
							serviceState = service["State"]?.ToString() ?? "Unknown";
						}
						finally
						{
							((IDisposable)managementObject2)?.Dispose();
						}
					}
				}
				finally
				{
					((IDisposable)managementObjectSearcher)?.Dispose();
				}
			}
			catch (ManagementException)
			{
			}
			catch (UnauthorizedAccessException)
			{
			}
			catch (Exception)
			{
			}
			using RegistryKey baseKey64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey tpmServiceKey = baseKey64.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\TPM");
			int serviceStart = ((tpmServiceKey?.GetValue("Start") is int startValue) ? startValue : (-1));
			bool serviceStartPresent = serviceStart >= 0;
			return new SecurityResult
			{
				Category = "TPM",
				CheckName = "TPM Service (Registry Fallback)",
				CurrentValue = $"TPM Service Start={serviceStart} ({serviceStart switch
				{
					4 => "Disabled", 
					3 => "Manual", 
					_ => serviceStart.ToString(),
				}}), State={serviceState}",
				ExpectedValue = "TPM service present and functional",
				Status = ((!serviceStartPresent) ? SecurityStatus.Warning : SecurityStatus.Info),
				Description = "TPM (Trusted Platform Module) est requis pour BitLocker, Credential Guard et Windows Hello.",
				Recommendation = (serviceStartPresent ? "TPM détecté via registre (WMI TPM indisponible)." : "Vérifiez que le TPM est activé dans le BIOS/UEFI."),
				Reference = "https://docs.microsoft.com/windows/security/information-protection/tpm/trusted-platform-module-overview"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey tpmWmiKey = baseKey64.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI");
			string specVersion = tpmWmiKey?.GetValue("SpecVersion")?.ToString();
			if (string.IsNullOrEmpty(specVersion))
			{
				return new SecurityResult
				{
					Category = "TPM",
					CheckName = "TPM Spec Version (Registry Fallback)",
					CurrentValue = "Non disponible",
					ExpectedValue = "2.0",
					Status = SecurityStatus.Warning,
					Description = "Impossible de déterminer la version TPM via le registre.",
					Recommendation = "Vérifiez la version TPM avec tpm.msc ou Get-Tpm.",
					Reference = "https://docs.microsoft.com/windows/security/information-protection/tpm/tpm-recommendations"
				};
			}
			bool isTpm2 = specVersion.StartsWith("2.");
			bool isTpm1 = specVersion.StartsWith("1.");
			SecurityStatus status = ((!isTpm2) ? (isTpm1 ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK);
			return new SecurityResult
			{
				Category = "TPM",
				CheckName = "TPM Spec Version (Registry Fallback)",
				CurrentValue = specVersion,
				ExpectedValue = "2.0",
				Status = status,
				Description = "TPM 2.0 est requis pour Windows 11 et offre des algorithmes cryptographiques plus robustes (SHA-256, ECC) par rapport au TPM 1.2.",
				Recommendation = (isTpm2 ? "TPM 2.0 détecté." : (isTpm1 ? "TPM 1.2 détecté — TPM 2.0 recommandé pour Windows 11, BitLocker avancé et Credential Guard." : "Version TPM inconnue. Mettez à jour vers TPM 2.0.")),
				Reference = "https://docs.microsoft.com/windows/security/information-protection/tpm/tpm-recommendations"
			};
		});
	}

	private void CollectVirtualizationInfo(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
			try
			{
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				foreach (ManagementObject computerSystem in managementObjectCollection)
				{
					ManagementObject managementObject = computerSystem;
					try
					{
						ct.ThrowIfCancellationRequested();
						TryAdd(results, delegate
						{
							string hypervisorPresent = computerSystem["HypervisorPresent"]?.ToString() ?? "Unknown";
							bool hypervisorActive = hypervisorPresent.Equals("True", StringComparison.OrdinalIgnoreCase);
							return new SecurityResult
							{
								Category = "Virtualization",
								CheckName = "Hypervisor Present",
								CurrentValue = hypervisorPresent,
								ExpectedValue = "True (for VBS/HVCI)",
								Status = ((!hypervisorActive) ? SecurityStatus.Info : SecurityStatus.OK),
								Description = "Indicates if a hypervisor is currently running. Required for Virtualization Based Security (VBS) features.",
								Recommendation = (hypervisorActive ? "Hypervisor is active, VBS features can run." : "Enable Hyper-V or VBS to activate the hypervisor."),
								Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
							};
						});
						TryAdd(results, delegate
						{
							object domainRoleValue = computerSystem["DomainRole"];
							int domainRole = ((domainRoleValue != null && !(domainRoleValue is DBNull)) ? Convert.ToInt32(domainRoleValue) : 0);
							string currentValue = domainRole switch
							{
								0 => "Standalone Workstation", 
								1 => "Member Workstation", 
								2 => "Standalone Server", 
								3 => "Member Server", 
								4 => "Backup Domain Controller", 
								5 => "Primary Domain Controller", 
								_ => $"Unknown ({domainRole})",
							};
							return new SecurityResult
							{
								Category = "System",
								CheckName = "Domain Role",
								CurrentValue = currentValue,
								ExpectedValue = "Workstation or Server",
								Status = SecurityStatus.Info,
								Description = "The computer's role in the network domain.",
								Recommendation = "",
								Reference = ""
							};
						});
					}
					finally
					{
						((IDisposable)managementObject)?.Dispose();
					}
				}
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
				Category = "Virtualization",
				CheckName = "Hypervisor Information",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Failed to collect virtualization info: " + ex.Message,
				Recommendation = "Check WMI service.",
				Reference = ""
			});
		}
		TryAdd(results, delegate
		{
			bool hyperVInstalled = false;
			try
			{
				ManagementObjectSearcher managementObjectSearcher2 = new ManagementObjectSearcher("SELECT * FROM Win32_OptionalFeature WHERE Name='Microsoft-Hyper-V'");
				try
				{
					using ManagementObjectCollection managementObjectCollection2 = managementObjectSearcher2.Get();
					foreach (ManagementObject feature in managementObjectCollection2)
					{
						ManagementObject managementObject3 = feature;
						try
						{
							hyperVInstalled = Convert.ToInt32(feature["InstallState"] ?? ((object)0)) == 1;
						}
						finally
						{
							((IDisposable)managementObject3)?.Dispose();
						}
					}
				}
				finally
				{
					((IDisposable)managementObjectSearcher2)?.Dispose();
				}
			}
			catch (ManagementException)
			{
			}
			catch (Exception)
			{
			}
			return new SecurityResult
			{
				Category = "Virtualization",
				CheckName = "Hyper-V Feature",
				CurrentValue = (hyperVInstalled ? "Installed" : "Not installed"),
				ExpectedValue = "Installed (for VBS)",
				Status = ((!hyperVInstalled) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "Hyper-V is the Windows hypervisor required for Virtualization Based Security (VBS), HVCI, and Credential Guard.",
				Recommendation = (hyperVInstalled ? "Hyper-V is installed." : "Enable Hyper-V feature to support VBS security features."),
				Reference = "https://docs.microsoft.com/windows-server/virtualization/hyper-v/hyper-v-technology-overview"
			};
		});
	}

	private void CollectDiskInfo(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType=3");
			try
			{
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				foreach (ManagementObject disk in managementObjectCollection)
				{
					ManagementObject managementObject = disk;
					try
					{
						ct.ThrowIfCancellationRequested();
						string letter = disk["DeviceID"]?.ToString() ?? "?";
						TryAdd(results, delegate
						{
							ulong sizeBytes = WmiULong(disk, "Size", 0uL);
							ulong freeBytes = WmiULong(disk, "FreeSpace", 0uL);
							double sizeGb = (double)sizeBytes / 1073741824.0;
							double freeGb = (double)freeBytes / 1073741824.0;
							double freePercent = ((sizeBytes != 0) ? ((double)freeBytes * 100.0 / (double)sizeBytes) : 0.0);
							bool lowSpace = freePercent < 10.0;
							return new SecurityResult
							{
								Category = "Storage",
								CheckName = "Drive " + letter + " Space",
								CurrentValue = $"{freeGb:F1} GB free of {sizeGb:F1} GB ({freePercent:F1}% free)",
								ExpectedValue = "> 10% free",
								Status = (lowSpace ? SecurityStatus.Warning : SecurityStatus.OK),
								Description = "Disk space on drive " + letter + ". Low disk space can impair security logging, update installation, and system stability.",
								Recommendation = (lowSpace ? ("Free up space on drive " + letter + ". Low disk space prevents security updates and logging.") : "Disk space is adequate."),
								Reference = ""
							};
						});
					}
					finally
					{
						((IDisposable)managementObject)?.Dispose();
					}
				}
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
				Category = "Storage",
				CheckName = "Disk Information",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Failed to collect disk info: " + ex.Message,
				Recommendation = "Check WMI service.",
				Reference = ""
			});
		}
	}

	private void CollectNetworkInfo(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True");
			try
			{
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				int adapterIdx = 0;
				foreach (ManagementObject nic in managementObjectCollection)
				{
					ManagementObject managementObject = nic;
					try
					{
						ct.ThrowIfCancellationRequested();
						string desc = nic["Description"]?.ToString() ?? $"Adapter {adapterIdx}";
						TryAdd(results, delegate
						{
							string[] ipAddresses = (nic["IPAddress"] as string[]) ?? Array.Empty<string>();
							string ipList = string.Join(", ", ipAddresses);
							return new SecurityResult
							{
								Category = "Network",
								CheckName = $"NIC [{adapterIdx}] IP Address",
								CurrentValue = desc + ": " + ipList,
								ExpectedValue = "Assigned",
								Status = SecurityStatus.Info,
								Description = "IP addresses assigned to this network adapter.",
								Recommendation = "Verify IP addresses are correct and from a trusted network.",
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							string macAddress = nic["MACAddress"]?.ToString() ?? "Unknown";
							return new SecurityResult
							{
								Category = "Network",
								CheckName = $"NIC [{adapterIdx}] MAC Address",
								CurrentValue = desc + ": " + macAddress,
								ExpectedValue = "Any",
								Status = SecurityStatus.Info,
								Description = "Hardware MAC address of the network adapter.",
								Recommendation = "Record MAC address for asset tracking and network access control.",
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							string dhcpEnabled = nic["DHCPEnabled"]?.ToString() ?? "Unknown";
							return new SecurityResult
							{
								Category = "Network",
								CheckName = $"NIC [{adapterIdx}] DHCP Enabled",
								CurrentValue = desc + ": " + dhcpEnabled,
								ExpectedValue = "Depends on policy",
								Status = SecurityStatus.Info,
								Description = "Whether this adapter uses DHCP for automatic IP assignment.",
								Recommendation = "Servers and sensitive systems should use static IP addresses.",
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							string[] dnsServers = (nic["DNSServerSearchOrder"] as string[]) ?? Array.Empty<string>();
							string dnsList = string.Join(", ", dnsServers);
							bool usesPublicDns = dnsList.Contains("8.8.8.8") || dnsList.Contains("1.1.1.1");
							return new SecurityResult
							{
								Category = "Network",
								CheckName = $"NIC [{adapterIdx}] DNS Servers",
								CurrentValue = desc + ": " + dnsList,
								ExpectedValue = "Internal or trusted DNS",
								Status = (usesPublicDns ? SecurityStatus.Warning : SecurityStatus.Info),
								Description = "DNS servers used by this adapter. Using external public DNS may bypass internal security controls.",
								Recommendation = (usesPublicDns ? "Consider using internal/corporate DNS servers to maintain DNS security controls." : "DNS configuration appears appropriate."),
								Reference = ""
							};
						});
						int currentAdapterIdx = adapterIdx;
						adapterIdx = currentAdapterIdx + 1;
					}
					finally
					{
						((IDisposable)managementObject)?.Dispose();
					}
				}
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
				Category = "Network",
				CheckName = "Network Adapter Information",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Failed to collect network info: " + ex.Message,
				Recommendation = "Check WMI service.",
				Reference = ""
			});
		}
	}

	private void CollectDomainInfo(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string domainName = "Unknown";
			bool partOfDomain = false;
			try
			{
				ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
				try
				{
					using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
					foreach (ManagementObject computerSystem in managementObjectCollection)
					{
						ManagementObject managementObject2 = computerSystem;
						try
						{
							domainName = computerSystem["Domain"]?.ToString() ?? "Unknown";
							partOfDomain = (computerSystem["PartOfDomain"]?.ToString() ?? "False").Equals("True", StringComparison.OrdinalIgnoreCase);
						}
						finally
						{
							((IDisposable)managementObject2)?.Dispose();
						}
					}
				}
				finally
				{
					((IDisposable)managementObjectSearcher)?.Dispose();
				}
			}
			catch (ManagementException)
			{
			}
			catch (Exception)
			{
			}
			return new SecurityResult
			{
				Category = "System",
				CheckName = "Domain / Workgroup Membership",
				CurrentValue = (partOfDomain ? ("Domain: " + domainName) : ("Workgroup: " + domainName)),
				ExpectedValue = "Domain-joined (recommended for enterprise)",
				Status = ((!partOfDomain) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "Domain-joined systems benefit from Group Policy security controls, centralized authentication, and compliance enforcement.",
				Recommendation = (partOfDomain ? "System is domain-joined, enabling Group Policy security controls." : "Consider joining the system to an Active Directory domain for centralized security management."),
				Reference = "https://docs.microsoft.com/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview"
			};
		});
	}

	private static ulong WmiULong(ManagementObject obj, string prop, ulong def = 0uL)
	{
		object rawValue = obj[prop];
		if (rawValue == null || rawValue is DBNull)
		{
			return def;
		}
		return Convert.ToUInt64(rawValue);
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
				Category = "System",
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
