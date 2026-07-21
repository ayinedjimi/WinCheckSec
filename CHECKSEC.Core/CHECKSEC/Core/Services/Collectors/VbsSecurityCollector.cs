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

public class VbsSecurityCollector : ISecurityCollector
{
	private sealed class DgWmiData
	{
		public int VirtualizationBasedSecurityStatus { get; set; } = -1;

		public uint[]? RequiredSecurityProperties { get; set; }

		public uint[]? AvailableSecurityProperties { get; set; }

		public uint[]? SecurityServicesConfigured { get; set; }

		public uint[]? SecurityServicesRunning { get; set; }

		public string? Error { get; set; }

		public bool IsServiceRunning(uint bit)
		{
			if (SecurityServicesRunning != null)
			{
				return Array.IndexOf(SecurityServicesRunning, bit) >= 0;
			}
			return false;
		}

		public bool IsServiceConfigured(uint bit)
		{
			if (SecurityServicesConfigured != null)
			{
				return Array.IndexOf(SecurityServicesConfigured, bit) >= 0;
			}
			return false;
		}
	}

	private const string DeviceGuardWmiNamespace = "\\\\.\\root\\Microsoft\\Windows\\DeviceGuard";

	public string Name => "VBS Security";

	public string Category => "Virtualization-Based Security";

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
			DgWmiData dg = CollectDeviceGuardWmi(ct);
			ct.ThrowIfCancellationRequested();
			CollectVbsWmi(collectorReport.Results, dg, ct);
			ct.ThrowIfCancellationRequested();
			CollectVbsRegistry(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectHvciRegistry(collectorReport.Results, dg, ct);
			ct.ThrowIfCancellationRequested();
			CollectCredentialGuard(collectorReport.Results, dg, ct);
			ct.ThrowIfCancellationRequested();
			CollectSystemGuard(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectSecureBoot(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectDmaProtection(collectorReport.Results, dg, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "VbsSecurityCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private DgWmiData CollectDeviceGuardWmi(CancellationToken ct)
	{
		DgWmiData dgWmiData = new DgWmiData();
		try
		{
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(WmiHelper.GetScope("\\\\.\\root\\Microsoft\\Windows\\DeviceGuard"), new ObjectQuery("SELECT * FROM Win32_DeviceGuard"));
			try
			{
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				foreach (ManagementObject item in managementObjectCollection)
				{
					ManagementObject managementObject2 = item;
					try
					{
						ct.ThrowIfCancellationRequested();
						dgWmiData.VirtualizationBasedSecurityStatus = WmiInt(item, "VirtualizationBasedSecurityStatus");
						dgWmiData.RequiredSecurityProperties = item["RequiredSecurityProperties"] as uint[];
						dgWmiData.AvailableSecurityProperties = item["AvailableSecurityProperties"] as uint[];
						dgWmiData.SecurityServicesConfigured = item["SecurityServicesConfigured"] as uint[];
						dgWmiData.SecurityServicesRunning = item["SecurityServicesRunning"] as uint[];
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
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			dgWmiData.Error = ex.Message;
		}
		return dgWmiData;
	}

	private void CollectVbsWmi(List<SecurityResult> results, DgWmiData dg, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		if (dg.Error != null)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "VBS WMI Access",
				CurrentValue = "Error: " + dg.Error,
				ExpectedValue = "Accessible",
				Status = SecurityStatus.Warning,
				Description = "Could not access Win32_DeviceGuard WMI class in root\\Microsoft\\Windows\\DeviceGuard. Registry fallback will be used.",
				Recommendation = "Ensure the system is Windows 10/11 and WMI is functional.",
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			});
			CollectVbsFromRegistry(results, ct);
			return;
		}
		TryAdd(results, delegate
		{
			int virtualizationBasedSecurityStatus = dg.VirtualizationBasedSecurityStatus;
			string currentValue = virtualizationBasedSecurityStatus switch
			{
				0 => "0 - Not enabled", 
				1 => "1 - Enabled but not running", 
				2 => "2 - Enabled and running", 
				_ => $"{virtualizationBasedSecurityStatus} - Unknown", 
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "VBS Status (WMI)",
				CurrentValue = currentValue,
				ExpectedValue = "2 (Enabled and running)",
				Status = virtualizationBasedSecurityStatus switch
				{
					1 => SecurityStatus.Warning, 
					2 => SecurityStatus.OK, 
					_ => SecurityStatus.Critical, 
				},
				Description = "Virtualization Based Security (VBS) uses hardware virtualization to create an isolated memory region (Virtual Secure Mode) that protects security-critical components from the main OS.",
				Recommendation = ((virtualizationBasedSecurityStatus == 2) ? "VBS is running." : "Enable VBS via Group Policy or Windows Security > Device Security > Core Isolation."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
		TryAdd(results, delegate
		{
			uint[] props = dg.RequiredSecurityProperties ?? Array.Empty<uint>();
			return new SecurityResult
			{
				Category = Category,
				CheckName = "VBS Required Security Properties",
				CurrentValue = DecodeSecurityProperties(props),
				ExpectedValue = "BaseVirtualization, SecureBoot, DMAProtection",
				Status = SecurityStatus.Info,
				Description = "Security properties required for VBS to run: 1=BaseVirtualization, 2=SecureBoot, 4=DMAProtection, 8=SecureMemoryOverwrite, 16=NXProtection, 32=SMM, 64=MBR.",
				Recommendation = "Verify required properties include at minimum BaseVirtualization and SecureBoot.",
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
		TryAdd(results, delegate
		{
			uint[] availableProperties = dg.AvailableSecurityProperties ?? Array.Empty<uint>();
			return new SecurityResult
			{
				Category = Category,
				CheckName = "VBS Available Security Properties",
				CurrentValue = DecodeSecurityProperties(availableProperties),
				ExpectedValue = "BaseVirtualization, SecureBoot, DMAProtection",
				Status = SecurityStatus.Info,
				Description = "Security properties available on this hardware platform for VBS.",
				Recommendation = "More available properties means stronger VBS configuration is possible.",
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
		TryAdd(results, delegate
		{
			uint[] services = dg.SecurityServicesConfigured ?? Array.Empty<uint>();
			return new SecurityResult
			{
				Category = Category,
				CheckName = "VBS Security Services Configured",
				CurrentValue = DecodeSecurityServices(services),
				ExpectedValue = "CredentialGuard, HVCI",
				Status = SecurityStatus.Info,
				Description = "VBS security services configured to run: 1=CredentialGuard, 2=HVCI, 4=UEFI lock.",
				Recommendation = "Configure CredentialGuard and HVCI for maximum protection.",
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
		TryAdd(results, delegate
		{
			uint[] runningServices = dg.SecurityServicesRunning ?? Array.Empty<uint>();
			return new SecurityResult
			{
				Category = Category,
				CheckName = "VBS Security Services Running",
				CurrentValue = DecodeSecurityServices(runningServices),
				ExpectedValue = "CredentialGuard, HVCI",
				Status = ((runningServices.Length == 0) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "VBS security services currently running: 1=CredentialGuard, 2=HVCI, 4=UEFI lock.",
				Recommendation = ((runningServices.Length == 0) ? "No VBS security services are running. Enable VBS and its security services." : "Verify expected services are running."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
	}

	private void CollectVbsFromRegistry(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey deviceGuardKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard");
			object vbsValue = deviceGuardKey?.GetValue("EnableVirtualizationBasedSecurity");
			int vbsEnabled = ((vbsValue != null) ? Convert.ToInt32(vbsValue) : (-1));
			bool isVbsEnabled = vbsEnabled == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "VBS Enabled (via registry fallback - WMI unavailable)",
				CurrentValue = ((vbsEnabled == -1) ? "Not configured" : vbsEnabled.ToString()),
				ExpectedValue = "1 (Enabled)",
				Status = ((!isVbsEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Virtualization Based Security (VBS) — valeur lue directement depuis le registre car WMI est indisponible. Valeur 1 = VBS activé.",
				Recommendation = (isVbsEnabled ? "VBS est activé (source registre)." : "Définir HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity = 1."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey hvciKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity");
			object hvciValue = hvciKey?.GetValue("Enabled");
			int hvciEnabled = ((hvciValue != null) ? Convert.ToInt32(hvciValue) : (-1));
			bool isHvciEnabled = hvciEnabled == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "HVCI (Memory Integrity) (via registry fallback - WMI unavailable)",
				CurrentValue = ((hvciEnabled == -1) ? "Not configured" : hvciEnabled.ToString()),
				ExpectedValue = "1 (Enabled)",
				Status = ((!isHvciEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Hypervisor-Protected Code Integrity (HVCI) — valeur registre. Protège l'intégrité du code noyau via VBS.",
				Recommendation = (isHvciEnabled ? "HVCI est activé (source registre)." : "Définir HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled = 1 et redémarrer."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey deviceGuardKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard");
			object lsaCfgFlagsValue = deviceGuardKey?.GetValue("LsaCfgFlags");
			int lsaCfgFlags = ((lsaCfgFlagsValue != null) ? Convert.ToInt32(lsaCfgFlagsValue) : (-1));
			string lsaCfgFlagsLabel;
			object lsaCfgFlagsLabelText;
			switch (lsaCfgFlags)
			{
			case 0:
				lsaCfgFlagsLabel = "0 - Désactivé";
				break;
			case 1:
				lsaCfgFlagsLabel = "1 - Activé avec verrou UEFI";
				break;
			case 2:
				lsaCfgFlagsLabel = "2 - Activé sans verrou UEFI";
				break;
			default:
				lsaCfgFlagsLabelText = $"{lsaCfgFlags} - Inconnu";
				goto IL_009a;
			case -1:
				{
					lsaCfgFlagsLabelText = "Non configuré (désactivé)";
					goto IL_009a;
				}
				IL_009a:
				lsaCfgFlagsLabel = (string)lsaCfgFlagsLabelText;
				break;
			}
			string currentValue = lsaCfgFlagsLabel;
			bool isCredentialGuardEnabled = lsaCfgFlags == 1 || lsaCfgFlags == 2;
			bool isEnterprise = WindowsInfo.IsEnterprise;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Credential Guard (via registry fallback - WMI unavailable)",
				CurrentValue = currentValue,
				ExpectedValue = "1 (Activé avec verrou UEFI)",
				Status = ((lsaCfgFlags != 1) ? (isCredentialGuardEnabled ? SecurityStatus.Warning : (isEnterprise ? SecurityStatus.Critical : SecurityStatus.Info)) : SecurityStatus.OK),
				Description = (isEnterprise ? "Credential Guard isole les secrets LSASS (hachages NTLM, tickets Kerberos) dans une région mémoire protégée par VBS — valeur registre." : ("Credential Guard nécessite Windows Enterprise/Education. Édition détectée : " + WindowsInfo.Edition + ".")),
				Recommendation = (isCredentialGuardEnabled ? "Credential Guard est activé (source registre)." : (isEnterprise ? "Définir HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\LsaCfgFlags = 1." : "Credential Guard n'est pas disponible sur cette édition de Windows.")),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/credential-guard/credential-guard-manage"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemGuardKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SystemGuard");
			object systemGuardValue = systemGuardKey?.GetValue("Enabled");
			int systemGuardEnabled = ((systemGuardValue != null) ? Convert.ToInt32(systemGuardValue) : (-1));
			bool isSystemGuardEnabled = systemGuardEnabled == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "System Guard / Secure Launch (via registry fallback - WMI unavailable)",
				CurrentValue = ((systemGuardEnabled == -1) ? "Non configuré" : systemGuardEnabled.ToString()),
				ExpectedValue = "1 (Activé)",
				Status = ((!isSystemGuardEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "System Guard Secure Launch (DRTM) — valeur registre. Établit une racine de confiance mesurée au démarrage.",
				Recommendation = (isSystemGuardEnabled ? "System Guard est activé (source registre)." : "Activer via HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SystemGuard\\Enabled = 1."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection"
			};
		});
	}

	private void CollectVbsRegistry(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey deviceGuardKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard");
			object vbsValue = deviceGuardKey?.GetValue("EnableVirtualizationBasedSecurity");
			int vbsEnabled = ((vbsValue != null) ? Convert.ToInt32(vbsValue) : (-1));
			bool isVbsEnabled = vbsEnabled == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "VBS Registry: EnableVirtualizationBasedSecurity",
				CurrentValue = ((vbsEnabled == -1) ? "Not configured" : vbsEnabled.ToString()),
				ExpectedValue = "1",
				Status = ((!isVbsEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Registry switch enabling Virtualization Based Security. Value 1 enables VBS. This is required for HVCI and Credential Guard.",
				Recommendation = (isVbsEnabled ? "VBS is enabled in registry." : "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity = 1."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey deviceGuardKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard");
			object platformFeaturesValue = deviceGuardKey?.GetValue("RequirePlatformSecurityFeatures");
			int platformFeatures = ((platformFeaturesValue != null) ? Convert.ToInt32(platformFeaturesValue) : (-1));
			string platformFeaturesLabel = ((platformFeatures == 1) ? "1 - Secure Boot" : ((platformFeatures != 3) ? ((platformFeatures == -1) ? "Not configured" : $"{platformFeatures} - Unknown") : "3 - Secure Boot + DMA Protection"));
			string currentValue = platformFeaturesLabel;
			bool hasSecureBootAndDma = platformFeatures == 3;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "VBS Registry: RequirePlatformSecurityFeatures",
				CurrentValue = currentValue,
				ExpectedValue = "3 (SecureBoot + DMA Protection)",
				Status = ((!hasSecureBootAndDma) ? ((platformFeatures == 1) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
				Description = "Platform security features required for VBS. Value 1=SecureBoot only; value 3=SecureBoot+DMA (stronger).",
				Recommendation = (hasSecureBootAndDma ? "Maximum platform security features required." : "Set value to 3 to require both Secure Boot and DMA protection for VBS."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey deviceGuardKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard");
			object hvciLockValue = deviceGuardKey?.GetValue("HypervisorEnforcedCodeIntegrityLock");
			int hvciLock = ((hvciLockValue != null) ? Convert.ToInt32(hvciLockValue) : (-1));
			bool isHvciLocked = hvciLock == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "VBS Registry: HypervisorEnforcedCodeIntegrityLock",
				CurrentValue = ((hvciLock == -1) ? "Not configured" : hvciLock.ToString()),
				ExpectedValue = "1 (Locked via UEFI)",
				Status = ((!isHvciLocked) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "UEFI lock prevents disabling HVCI without physical access to UEFI settings, protecting against offline attacks.",
				Recommendation = (isHvciLocked ? "HVCI is UEFI-locked." : "Set this value to 1 to lock HVCI via UEFI for stronger protection."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
	}

	private void CollectHvciRegistry(List<SecurityResult> results, DgWmiData dg, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey hvciKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity");
			object hvciValue = hvciKey?.GetValue("Enabled");
			int hvciEnabled = ((hvciValue != null) ? Convert.ToInt32(hvciValue) : (-1));
			bool isHvciEnabled = hvciEnabled == 1;
			bool isHvciRunning = dg.IsServiceRunning(2u);
			SecurityStatus status = ((!(isHvciEnabled && isHvciRunning)) ? (isHvciEnabled ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "HVCI Enabled (Registry)",
				CurrentValue = ((hvciEnabled == -1) ? "Not configured" : hvciEnabled.ToString()),
				ExpectedValue = "1",
				Status = status,
				Description = "Hypervisor-Protected Code Integrity (HVCI / Memory Integrity) uses VBS to validate kernel code integrity at runtime, preventing unsigned or malicious drivers from loading into the kernel.",
				Recommendation = (isHvciEnabled ? "HVCI is enabled." : "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled = 1 and reboot, or enable via Windows Security > Device Security > Core Isolation > Memory Integrity."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
		TryAdd(results, delegate
		{
			bool isHvciRunning = dg.IsServiceRunning(2u);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "HVCI Running (WMI)",
				CurrentValue = (isHvciRunning ? "Running" : "Not running"),
				ExpectedValue = "Running",
				Status = ((!isHvciRunning) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Confirms HVCI (bitmask bit 2 in SecurityServicesRunning) is actively running, providing kernel code integrity enforcement.",
				Recommendation = (isHvciRunning ? "HVCI is running." : "Enable HVCI and reboot. Check for incompatible drivers if HVCI fails to start."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey hvciKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity");
			object hvciLockedValue = hvciKey?.GetValue("Locked");
			int hvciLocked = ((hvciLockedValue != null) ? Convert.ToInt32(hvciLockedValue) : (-1));
			bool isHvciLocked = hvciLocked == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "HVCI UEFI Lock",
				CurrentValue = ((hvciLocked == -1) ? "Not configured (not locked)" : hvciLocked.ToString()),
				ExpectedValue = "1 (Locked)",
				Status = ((!isHvciLocked) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "UEFI lock for HVCI prevents disabling Memory Integrity without clearing UEFI variables, resisting administrative-level attacks.",
				Recommendation = (isHvciLocked ? "HVCI is UEFI-locked." : "Enable UEFI lock for HVCI to prevent tampering."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey hvciKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity");
			object wasEnabledByValue = hvciKey?.GetValue("WasEnabledBy");
			int wasEnabledBy = ((wasEnabledByValue != null) ? Convert.ToInt32(wasEnabledByValue) : (-1));
			string wasEnabledByLabel;
			object wasEnabledByLabelText;
			switch (wasEnabledBy)
			{
			case 0:
				wasEnabledByLabel = "0 - Manual configuration";
				break;
			case 1:
				wasEnabledByLabel = "1 - Group Policy (GPO)";
				break;
			case 2:
				wasEnabledByLabel = "2 - Mobile Device Management (MDM)";
				break;
			default:
				wasEnabledByLabelText = $"{wasEnabledBy} - Unknown";
				goto IL_009a;
			case -1:
				{
					wasEnabledByLabelText = "Not recorded";
					goto IL_009a;
				}
				IL_009a:
				wasEnabledByLabel = (string)wasEnabledByLabelText;
				break;
			}
			string currentValue = wasEnabledByLabel;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "HVCI Enabled By",
				CurrentValue = currentValue,
				ExpectedValue = "GPO or MDM",
				Status = ((wasEnabledBy != 1 && wasEnabledBy != 2) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "Indicates how HVCI was enabled. GPO or MDM enforcement is preferred for consistent policy application.",
				Recommendation = ((wasEnabledBy == 1 || wasEnabledBy == 2) ? "HVCI is centrally managed." : "Enable HVCI via Group Policy or MDM for consistent enterprise enforcement."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
	}

	private void CollectCredentialGuard(List<SecurityResult> results, DgWmiData dg, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey deviceGuardKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard");
			object lsaCfgFlagsValue = deviceGuardKey?.GetValue("LsaCfgFlags");
			int lsaCfgFlags = ((lsaCfgFlagsValue != null) ? Convert.ToInt32(lsaCfgFlagsValue) : (-1));
			string lsaCfgFlagsLabel;
			object lsaCfgFlagsLabelText;
			switch (lsaCfgFlags)
			{
			case 0:
				lsaCfgFlagsLabel = "0 - Disabled";
				break;
			case 1:
				lsaCfgFlagsLabel = "1 - Enabled with UEFI lock";
				break;
			case 2:
				lsaCfgFlagsLabel = "2 - Enabled without UEFI lock";
				break;
			default:
				lsaCfgFlagsLabelText = $"{lsaCfgFlags} - Unknown";
				goto IL_009a;
			case -1:
				{
					lsaCfgFlagsLabelText = "Not configured (disabled)";
					goto IL_009a;
				}
				IL_009a:
				lsaCfgFlagsLabel = (string)lsaCfgFlagsLabelText;
				break;
			}
			string currentValue = lsaCfgFlagsLabel;
			bool isCredentialGuardEnabled = lsaCfgFlags == 1 || lsaCfgFlags == 2;
			bool hasUefiLock = lsaCfgFlags == 1;
			bool isEnterprise = WindowsInfo.IsEnterprise;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Credential Guard: LsaCfgFlags",
				CurrentValue = currentValue,
				ExpectedValue = "1 (Enabled with UEFI lock)",
				Status = ((!hasUefiLock) ? (isCredentialGuardEnabled ? SecurityStatus.Warning : (isEnterprise ? SecurityStatus.Critical : SecurityStatus.Info)) : SecurityStatus.OK),
				Description = (isEnterprise ? "Credential Guard isolates LSASS secrets (NTLM hashes, Kerberos tickets) in a VBS-protected memory region, preventing Pass-the-Hash and Pass-the-Ticket attacks." : ("Credential Guard requires Windows Enterprise/Education edition. Detected edition: " + WindowsInfo.Edition + ".")),
				Recommendation = ((!isCredentialGuardEnabled) ? (isEnterprise ? "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\LsaCfgFlags = 1 to enable Credential Guard with UEFI lock." : "Credential Guard is not available on this Windows edition.") : (hasUefiLock ? "Credential Guard is enabled with UEFI lock." : "Consider using UEFI lock (value 1) for stronger Credential Guard protection.")),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/credential-guard/credential-guard-manage"
			};
		});
		TryAdd(results, delegate
		{
			bool isCredentialGuardRunning = dg.IsServiceRunning(1u);
			bool isEnterprise = WindowsInfo.IsEnterprise;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Credential Guard Running (WMI)",
				CurrentValue = (isCredentialGuardRunning ? "Running" : "Not running"),
				ExpectedValue = "Running",
				Status = ((!isCredentialGuardRunning) ? (isEnterprise ? SecurityStatus.Critical : SecurityStatus.Info) : SecurityStatus.OK),
				Description = (isEnterprise ? "Confirms Credential Guard (bit 1 in SecurityServicesRunning) is actively running and protecting LSASS secrets in VBS." : ("Credential Guard requires Windows Enterprise/Education edition. Detected edition: " + WindowsInfo.Edition + ".")),
				Recommendation = (isCredentialGuardRunning ? "Credential Guard is running." : (isEnterprise ? "Enable Credential Guard: requires VBS, UEFI Secure Boot, TPM 2.0, and a reboot." : "Credential Guard is not available on this Windows edition.")),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/credential-guard/credential-guard-manage"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object runAsPplValue = lsaKey?.GetValue("RunAsPPL");
			int runAsPpl = ((runAsPplValue != null) ? Convert.ToInt32(runAsPplValue) : (-1));
			bool isLsaPplEnabled = runAsPpl == 1 || runAsPpl == 2;
			string runAsPplLabel = ((runAsPpl == 1) ? "1 - PPL (Protected Process Light) with EDR" : ((runAsPpl != 2) ? ((runAsPpl == -1) ? "Not configured (disabled)" : $"{runAsPpl} - Unknown") : "2 - PPL without EDR"));
			string currentValue = runAsPplLabel;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA Protection (RunAsPPL)",
				CurrentValue = currentValue,
				ExpectedValue = "1 or 2 (PPL enabled)",
				Status = ((!isLsaPplEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "LSA Protected Process Light (PPL) prevents non-protected processes from reading LSASS memory, mitigating credential dumping attacks even without Credential Guard.",
				Recommendation = (isLsaPplEnabled ? "LSA PPL is enabled." : "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1 to enable LSA protection. Requires reboot."),
				Reference = "https://docs.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"
			};
		});
	}

	private void CollectSystemGuard(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemGuardKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SystemGuard");
			object systemGuardValue = systemGuardKey?.GetValue("Enabled");
			int systemGuardEnabled = ((systemGuardValue != null) ? Convert.ToInt32(systemGuardValue) : (-1));
			bool isSystemGuardEnabled = systemGuardEnabled == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "System Guard / Secure Launch",
				CurrentValue = ((systemGuardEnabled == -1) ? "Not configured" : systemGuardEnabled.ToString()),
				ExpectedValue = "1 (Enabled)",
				Status = ((!isSystemGuardEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "System Guard Secure Launch (DRTM - Dynamic Root of Trust for Measurement) uses Intel TXT or AMD SKINIT to establish a measured boot process, protecting the boot environment from firmware attacks.",
				Recommendation = (isSystemGuardEnabled ? "System Guard is enabled." : "Enable System Guard via HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SystemGuard\\Enabled = 1. Requires compatible hardware (Intel TXT or AMD SKINIT)."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection"
			};
		});
	}

	private void CollectSecureBoot(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey secureBootKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
			object secureBootValue = secureBootKey?.GetValue("UEFISecureBootEnabled");
			int secureBootEnabled = ((secureBootValue != null) ? Convert.ToInt32(secureBootValue) : (-1));
			bool isSecureBootEnabled = secureBootEnabled == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Secure Boot (VBS dependency)",
				CurrentValue = ((secureBootEnabled == -1) ? "Not present / Legacy BIOS" : (isSecureBootEnabled ? "Enabled (1)" : $"Disabled ({secureBootEnabled})")),
				ExpectedValue = "1 (Enabled)",
				Status = ((!isSecureBootEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Secure Boot is a prerequisite for VBS. It prevents unauthorized OS loaders and bootloaders from running, forming the chain of trust for the entire VBS stack.",
				Recommendation = (isSecureBootEnabled ? "Secure Boot is enabled." : "Enable Secure Boot in UEFI firmware settings. Required for VBS and Windows 11."),
				Reference = "https://docs.microsoft.com/windows-hardware/design/device-experiences/oem-secure-boot"
			};
		});
	}

	private void CollectDmaProtection(List<SecurityResult> results, DgWmiData dg, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey fveKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\FVE");
			object dmaProtectionValue = fveKey?.GetValue("DMAProtection");
			int dmaProtection = ((dmaProtectionValue != null) ? Convert.ToInt32(dmaProtectionValue) : (-1));
			bool isDmaProtectionEnabled = dmaProtection == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "DMA Protection Policy (FVE)",
				CurrentValue = ((dmaProtection == -1) ? "Not configured" : dmaProtection.ToString()),
				ExpectedValue = "1 (Enabled)",
				Status = ((!isDmaProtectionEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "DMA protection blocks DMA attacks from peripherals connected before Windows boots. Policy value in FVE key.",
				Recommendation = (isDmaProtectionEnabled ? "DMA protection policy is enabled." : "Enable DMA protection via Group Policy: Computer Configuration > Windows Settings > Security Settings > Device Guard."),
				Reference = "https://docs.microsoft.com/windows/security/information-protection/kernel-dma-protection-for-thunderbolt"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey dmaSecurityKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DmaSecurity");
			object dmaAvailableValue = dmaSecurityKey?.GetValue("DmaProtectionAvailable");
			int dmaAvailable = ((dmaAvailableValue != null) ? Convert.ToInt32(dmaAvailableValue) : (-1));
			bool isDmaProtectionAvailable = dmaAvailable == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Kernel DMA Protection Available",
				CurrentValue = ((dmaAvailable == -1) ? "Not reported / Not available" : (isDmaProtectionAvailable ? "Available (1)" : $"Not available ({dmaAvailable})")),
				ExpectedValue = "1 (Available)",
				Status = ((!isDmaProtectionAvailable) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Kernel DMA Protection (KDP) uses hardware IOMMU to block DMA attacks from hot-plugged devices. This value indicates hardware support.",
				Recommendation = (isDmaProtectionAvailable ? "Kernel DMA Protection is available on this hardware." : "Kernel DMA Protection requires IOMMU hardware (Intel VT-d or AMD-Vi). Check BIOS settings."),
				Reference = "https://docs.microsoft.com/windows/security/information-protection/kernel-dma-protection-for-thunderbolt"
			};
		});
		TryAdd(results, delegate
		{
			// Correctif M6a : DMAProtection = valeur d'énumération 3 (et non 4 = SecureMemoryOverwrite) dans Win32_DeviceGuard
			bool isDmaAvailable = dg.AvailableSecurityProperties != null && Array.IndexOf(dg.AvailableSecurityProperties, 3u) >= 0;
			bool isDmaRequired = dg.RequiredSecurityProperties != null && Array.IndexOf(dg.RequiredSecurityProperties, 3u) >= 0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "DMA Protection in VBS Properties (WMI)",
				CurrentValue = $"Available: {isDmaAvailable}, Required: {isDmaRequired}",
				ExpectedValue = "Available=True, Required=True",
				Status = ((!(isDmaAvailable && isDmaRequired)) ? (isDmaAvailable ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
				Description = "DMA Protection (enum value 3) presence in WMI VBS security properties. Available means hardware supports it; Required means VBS enforces it.",
				Recommendation = ((isDmaAvailable && isDmaRequired) ? "DMA Protection is available and required for VBS." : (isDmaAvailable ? "DMA Protection is available but not required. Set RequirePlatformSecurityFeatures = 3." : "Hardware DMA Protection (IOMMU) is not available on this platform.")),
				Reference = "https://docs.microsoft.com/windows/security/information-protection/kernel-dma-protection-for-thunderbolt"
			};
		});
	}

	private static string DecodeSecurityProperties(uint[] props)
	{
		if (props == null || props.Length == 0)
		{
			return "None";
		}
		List<string> propertyNames = new List<string>();
		foreach (uint property in props)
		{
			List<string> propertyNamesAlias = propertyNames;
			// Correctif M6b : SecurityProperties sont des valeurs d'ÉNUMÉRATION (1..7), pas un bitmask
			propertyNamesAlias.Add(property switch
			{
				1u => "BaseVirtualization",
				2u => "SecureBoot",
				3u => "DMAProtection",
				4u => "SecureMemoryOverwrite",
				5u => "NXProtection",
				6u => "SMM",
				7u => "MBEC",
				_ => $"Unknown({property})",
			});
		}
		return string.Join(", ", propertyNames);
	}

	private static string DecodeSecurityServices(uint[] services)
	{
		if (services == null || services.Length == 0)
		{
			return "None";
		}
		List<string> serviceNames = new List<string>();
		foreach (uint service in services)
		{
			List<string> serviceNamesAlias = serviceNames;
			// Correctif M6c : SecurityServices sont des valeurs d'ÉNUMÉRATION (1..5), pas un bitmask
			serviceNamesAlias.Add(service switch
			{
				1u => "CredentialGuard",
				2u => "HVCI (Memory Integrity)",
				3u => "SystemGuardSecureLaunch",
				4u => "SMMFirmwareMeasurement",
				5u => "KernelDMAProtection",
				_ => $"Unknown({service})",
			});
		}
		return string.Join(", ", serviceNames);
	}

	private static int WmiInt(ManagementObject obj, string prop, int def = -1)
	{
		object rawValue = obj[prop];
		if (rawValue == null || rawValue is DBNull)
		{
			return def;
		}
		return Convert.ToInt32(rawValue);
	}

	private static bool WmiBool(ManagementObject obj, string prop, bool def = false)
	{
		object rawValue = obj[prop];
		if (rawValue == null || rawValue is DBNull)
		{
			return def;
		}
		return Convert.ToBoolean(rawValue);
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
				Category = "Virtualization-Based Security",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Check failed: " + ex.Message,
				Recommendation = "Review WMI and registry access permissions.",
				Reference = ""
			});
		}
	}
}
