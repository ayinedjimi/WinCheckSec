using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class SecureBootPolicyCollector : ISecurityCollector
{
	private const string SecureBootKey = "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State";

	private const string UefiKey = "SYSTEM\\CurrentControlSet\\Control\\SecureBoot";

	private const string BiosKey = "HARDWARE\\DESCRIPTION\\System\\BIOS";

	public string Name => "Secure Boot & UEFI";

	public string Category => "Firmware";

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
			CollectSecureBootStatus(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectUefiDetails(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectFirmwareInfo(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "SecureBootPolicyCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectSecureBootStatus(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey secureBootStateKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
			if (secureBootStateKey == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Secure Boot",
					CurrentValue = "Non disponible (BIOS Legacy?)",
					ExpectedValue = "Activé",
					Status = SecurityStatus.Warning,
					Description = "La clé Secure Boot n'a pas été trouvée. Le système utilise peut-être un BIOS Legacy au lieu d'UEFI.",
					Recommendation = "Migrez vers UEFI avec Secure Boot activé pour une meilleure sécurité du démarrage.",
					Reference = "https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot"
				});
				return;
			}
			object secureBootEnabledValue = secureBootStateKey.GetValue("UEFISecureBootEnabled");
			if (secureBootEnabledValue != null)
			{
				int secureBootEnabled = Convert.ToInt32(secureBootEnabledValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Secure Boot — État",
					CurrentValue = ((secureBootEnabled == 1) ? "Activé" : "Désactivé"),
					ExpectedValue = "Activé (1)",
					Status = ((secureBootEnabled != 1) ? SecurityStatus.Critical : SecurityStatus.OK),
					Description = ((secureBootEnabled == 1) ? "Secure Boot est activé. Seuls les bootloaders et pilotes signés peuvent s'exécuter au démarrage." : "Secure Boot est DÉSACTIVÉ. Des bootloaders et rootkits non signés peuvent s'exécuter."),
					Recommendation = ((secureBootEnabled != 1) ? "Activez Secure Boot dans les paramètres UEFI/BIOS." : "Configuration correcte."),
					Reference = "https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot"
				});
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
				CheckName = "Secure Boot — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier Secure Boot: " + ex.Message,
				Recommendation = "Vérifiez les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}

	private void CollectUefiDetails(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey secureBootKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot");
			if (secureBootKey == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "UEFI",
					CurrentValue = "Non détecté",
					ExpectedValue = "UEFI",
					Status = SecurityStatus.Warning,
					Description = "La configuration UEFI n'est pas accessible.",
					Recommendation = "Vérifiez que le système est en mode UEFI.",
					Reference = ""
				});
				return;
			}
			object availableUpdatesValue = secureBootKey.GetValue("AvailableUpdates");
			if (availableUpdatesValue != null)
			{
				int availableUpdates = Convert.ToInt32(availableUpdatesValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Secure Boot — Mises à jour disponibles",
					CurrentValue = ((availableUpdates > 0) ? $"{availableUpdates} mise(s) à jour" : "Aucune"),
					ExpectedValue = "0",
					Status = ((availableUpdates > 0) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = ((availableUpdates > 0) ? $"{availableUpdates} mise(s) à jour Secure Boot disponible(s)." : "Aucune mise à jour Secure Boot en attente."),
					Recommendation = ((availableUpdates > 0) ? "Appliquez les mises à jour Secure Boot disponibles." : "Configuration à jour."),
					Reference = ""
				});
			}
			string[] subKeyNames = secureBootKey.GetSubKeyNames();
			bool hasPolicySubKey = false;
			string[] subKeyNamesArray = subKeyNames;
			for (int i = 0; i < subKeyNamesArray.Length; i++)
			{
				if (subKeyNamesArray[i].Equals("Policy", StringComparison.OrdinalIgnoreCase))
				{
					hasPolicySubKey = true;
					break;
				}
			}
			if (hasPolicySubKey)
			{
				using RegistryKey policyKey = secureBootKey.OpenSubKey("Policy");
				if (policyKey != null)
				{
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "Secure Boot — Politique personnalisée",
						CurrentValue = "Présente",
						ExpectedValue = "N/A",
						Status = SecurityStatus.Info,
						Description = "Une politique Secure Boot personnalisée est configurée.",
						Recommendation = "Vérifiez que la politique Secure Boot est conforme à vos exigences de sécurité.",
						Reference = ""
					});
				}
			}
			using RegistryKey secureBootStateKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
			object setupModeValue = secureBootStateKey?.GetValue("SetupMode");
			if (setupModeValue != null)
			{
				int setupMode = Convert.ToInt32(setupModeValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Secure Boot — Setup Mode",
					CurrentValue = ((setupMode == 0) ? "Désactivé (User Mode)" : "Activé (Setup Mode)"),
					ExpectedValue = "User Mode (0)",
					Status = ((setupMode != 0) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = ((setupMode == 0) ? "Le système est en User Mode. Les clés Secure Boot sont verrouillées." : "Le système est en Setup Mode! Les clés Secure Boot peuvent être modifiées."),
					Recommendation = ((setupMode != 0) ? "Quittez le Setup Mode pour verrouiller les clés Secure Boot." : "Configuration correcte."),
					Reference = ""
				});
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
				CheckName = "UEFI — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}

	private void CollectFirmwareInfo(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey biosKey = Registry.LocalMachine.OpenSubKey("HARDWARE\\DESCRIPTION\\System\\BIOS");
			if (biosKey == null)
			{
				return;
			}
			string biosVendor = biosKey.GetValue("BIOSVendor")?.ToString();
			string biosVersion = biosKey.GetValue("BIOSVersion")?.ToString();
			string biosReleaseDate = biosKey.GetValue("BIOSReleaseDate")?.ToString();
			if (!string.IsNullOrEmpty(biosVendor))
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Firmware — Informations",
					CurrentValue = $"{biosVendor} v{biosVersion ?? "N/A"} ({biosReleaseDate ?? "N/A"})",
					ExpectedValue = "Firmware à jour",
					Status = SecurityStatus.Info,
					Description = $"Fabricant: {biosVendor}, Version: {biosVersion ?? "N/A"}, Date: {biosReleaseDate ?? "N/A"}",
					Recommendation = "Assurez-vous que le firmware est à jour avec les derniers correctifs de sécurité.",
					Reference = ""
				});
			}
			try
			{
				ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskPartition WHERE Type LIKE '%GPT%'");
				try
				{
					using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
					bool hasGptPartition = false;
					using (ManagementObjectCollection.ManagementObjectEnumerator managementObjectEnumerator = managementObjectCollection.GetEnumerator())
					{
						if (managementObjectEnumerator.MoveNext())
						{
							_ = (ManagementObject)managementObjectEnumerator.Current;
							hasGptPartition = true;
						}
					}
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "Firmware — Mode de démarrage",
						CurrentValue = (hasGptPartition ? "UEFI (GPT détecté)" : "Probablement Legacy (MBR)"),
						ExpectedValue = "UEFI",
						Status = ((!hasGptPartition) ? SecurityStatus.Warning : SecurityStatus.OK),
						Description = (hasGptPartition ? "Le système utilise des partitions GPT, indiquant un démarrage UEFI." : "Aucune partition GPT détectée. Le système pourrait utiliser un BIOS Legacy."),
						Recommendation = (hasGptPartition ? "Configuration correcte." : "Migrez vers UEFI pour bénéficier de Secure Boot et d'autres protections firmware."),
						Reference = ""
					});
				}
				finally
				{
					((IDisposable)managementObjectSearcher)?.Dispose();
				}
			}
			catch
			{
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
				CheckName = "Firmware — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}
}
