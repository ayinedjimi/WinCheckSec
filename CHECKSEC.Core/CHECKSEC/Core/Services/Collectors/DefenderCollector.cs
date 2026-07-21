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

public class DefenderCollector : ISecurityCollector
{
	private const string DefenderWmiNamespace = "\\\\.\\root\\Microsoft\\Windows\\Defender";

	private const string DefenderRegKey = "SOFTWARE\\Microsoft\\Windows Defender";

	private const string DefenderPoliciesKey = "SOFTWARE\\Policies\\Microsoft\\Windows Defender";

	public string Name => "Windows Defender";

	public string Category => "Antivirus / Endpoint Protection";

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
			CollectDefenderWmiStatus(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectDefenderRegistrySettings(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectDefenderPolicySettings(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectElamStatus(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectTamperProtection(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectCloudProtection(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectAsrRules(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectControlledFolderAccess(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectExploitProtection(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			collectorReport.ErrorMessage = "DefenderCollector fatal error: " + ex2.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectDefenderWmiStatus(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ManagementObjectSearcher searcher = new ManagementObjectSearcher(WmiHelper.GetScope("\\\\.\\root\\Microsoft\\Windows\\Defender"), new ObjectQuery("SELECT * FROM MSFT_MpComputerStatus"));
			try
			{
				using ManagementObjectCollection statusCollection = searcher.Get();
				foreach (ManagementObject mpStatus in statusCollection)
				{
					ManagementObject mo = mpStatus;
					try
					{
						ct.ThrowIfCancellationRequested();
						TryAdd(results, delegate
						{
							string avEnabledValue = WmiStr(mpStatus, "AntivirusEnabled") ?? "Unknown";
							bool isEnabled = avEnabledValue.Equals("True", StringComparison.OrdinalIgnoreCase);
							return new SecurityResult
							{
								Category = Category,
								CheckName = "Antivirus Enabled",
								CurrentValue = avEnabledValue,
								ExpectedValue = "True",
								Status = ((!isEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
								Description = "Windows Defender Antivirus real-time scanning engine status. Disabling AV leaves the system unprotected against malware.",
								Recommendation = (isEnabled ? "Antivirus is enabled." : "Enable Windows Defender Antivirus immediately."),
								Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus"
							};
						});
						TryAdd(results, delegate
						{
							string antispywareValue = WmiStr(mpStatus, "AntispywareEnabled") ?? "Unknown";
							bool isEnabled = antispywareValue.Equals("True", StringComparison.OrdinalIgnoreCase);
							return new SecurityResult
							{
								Category = Category,
								CheckName = "Antispyware Enabled",
								CurrentValue = antispywareValue,
								ExpectedValue = "True",
								Status = ((!isEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
								Description = "Anti-spyware protection status. Prevents spyware, adware, and PUP detection.",
								Recommendation = (isEnabled ? "Antispyware is enabled." : "Enable antispyware protection."),
								Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/"
							};
						});
						TryAdd(results, delegate
						{
							(bool effective, string displayValue, SecurityStatus status) rtpStatus = ResolveProtectionStatus(WmiBool(mpStatus, "RealTimeProtectionEnabled"), "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", "Real-Time Protection");
							string displayValue = rtpStatus.displayValue;
							SecurityStatus status = rtpStatus.status;
							return new SecurityResult
							{
								Category = Category,
								CheckName = "Real-Time Protection Enabled",
								CurrentValue = displayValue,
								ExpectedValue = "True",
								Status = status,
								Description = "Real-time protection monitors file system, network, and process activity continuously. Disabling it allows malware to run undetected.",
								Recommendation = status switch
								{
									SecurityStatus.Warning => "WMI inconsistency detected — verify via Windows Security UI.", 
									SecurityStatus.OK => "Real-time protection is enabled.", 
									_ => "Enable real-time protection immediately.", 
								},
								Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus"
							};
						});
						TryAdd(results, delegate
						{
							int signatureAge = WmiInt(mpStatus, "AntivirusSignatureAge");
							// Correctif L2 : âge indéterminé (-1) ne doit pas être considéré OK
							bool isUnknownAge = signatureAge == -1;
							bool isStale = signatureAge > 7;
							bool isVeryStale = signatureAge > 14;
							return new SecurityResult
							{
								Category = Category,
								CheckName = "Antivirus Signature Age",
								CurrentValue = (isUnknownAge ? "Unknown" : $"{signatureAge} days"),
								ExpectedValue = "<= 7 days",
								Status = (isVeryStale ? SecurityStatus.Critical : (isStale ? SecurityStatus.Warning : (isUnknownAge ? SecurityStatus.Warning : SecurityStatus.OK))),
								Description = "Age of the antivirus signature database in days. Stale signatures cannot detect recently discovered malware.",
								Recommendation = (isUnknownAge ? "Signature age could not be determined. Verify Defender is running and healthy, then confirm signatures are current." : (isStale ? "Update antivirus signatures immediately. Signatures over 7 days old significantly reduce protection." : "Signatures are up to date.")),
								Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/manage-updates-baselines-microsoft-defender-antivirus"
							};
						});
						TryAdd(results, delegate
						{
							int antispywareSignatureAge = WmiInt(mpStatus, "AntispywareSignatureAge");
							bool isStale = antispywareSignatureAge > 7;
							return new SecurityResult
							{
								Category = Category,
								CheckName = "Antispyware Signature Age",
								CurrentValue = ((antispywareSignatureAge == -1) ? "Unknown" : $"{antispywareSignatureAge} days"),
								ExpectedValue = "<= 7 days",
								Status = (isStale ? SecurityStatus.Warning : SecurityStatus.OK),
								Description = "Age of the anti-spyware signature database.",
								Recommendation = (isStale ? "Update antispyware signatures." : "Signatures are current."),
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							string lastUpdatedRaw = mpStatus["AntivirusSignatureLastUpdated"]?.ToString() ?? "Unknown";
							string lastUpdatedDisplay = "Unknown";
							if (lastUpdatedRaw != "Unknown" && lastUpdatedRaw.Length >= 8)
							{
								try
								{
									lastUpdatedDisplay = ManagementDateTimeConverter.ToDateTime(lastUpdatedRaw).ToString("yyyy-MM-dd HH:mm:ss");
								}
								catch
								{
									lastUpdatedDisplay = lastUpdatedRaw;
								}
							}
							return new SecurityResult
							{
								Category = Category,
								CheckName = "AV Signature Last Updated",
								CurrentValue = lastUpdatedDisplay,
								ExpectedValue = "Within last 7 days",
								Status = SecurityStatus.Info,
								Description = "Timestamp of the last antivirus signature update.",
								Recommendation = "Ensure automatic updates are enabled.",
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							(bool effective, string displayValue, SecurityStatus status) behaviorStatus = ResolveProtectionStatus(WmiBool(mpStatus, "BehaviorMonitorEnabled"), "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableBehaviorMonitoring", "Behavior Monitoring");
							string displayValue = behaviorStatus.displayValue;
							SecurityStatus status = behaviorStatus.status;
							return new SecurityResult
							{
								Category = Category,
								CheckName = "Behavior Monitoring Enabled",
								CurrentValue = displayValue,
								ExpectedValue = "True",
								Status = status,
								Description = "Behavior monitoring tracks process behavior patterns to detect zero-day exploits and novel malware that evades signature detection.",
								Recommendation = status switch
								{
									SecurityStatus.Warning => "WMI inconsistency — verify via Windows Security UI.", 
									SecurityStatus.OK => "Behavior monitoring is enabled.", 
									_ => "Enable behavior monitoring for advanced threat detection.", 
								},
								Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/enable-network-protection"
							};
						});
						TryAdd(results, delegate
						{
							(bool effective, string displayValue, SecurityStatus status) ioavStatus = ResolveProtectionStatus(WmiBool(mpStatus, "IoavProtectionEnabled"), "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableIOAVProtection", "IOAV");
							string displayValue = ioavStatus.displayValue;
							SecurityStatus status = ioavStatus.status;
							if (status == SecurityStatus.Critical)
							{
								status = SecurityStatus.Warning;
							}
							return new SecurityResult
							{
								Category = Category,
								CheckName = "IOAV Protection (Download Scanning)",
								CurrentValue = displayValue,
								ExpectedValue = "True",
								Status = status,
								Description = "Internet On-Access Validation (IOAV) scans files downloaded from the internet and email attachments before they execute.",
								Recommendation = ((status == SecurityStatus.OK) ? "IOAV protection is enabled." : "Enable IOAV protection to scan downloaded files."),
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							(bool effective, string displayValue, SecurityStatus status) nisStatus = ResolveProtectionStatus(WmiBool(mpStatus, "NISEnabled"), "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\NIS", "DisableNIS", "NIS");
							string displayValue = nisStatus.displayValue;
							SecurityStatus status = nisStatus.status;
							if (status == SecurityStatus.Critical)
							{
								status = SecurityStatus.Warning;
							}
							return new SecurityResult
							{
								Category = Category,
								CheckName = "Network Inspection System (NIS) Enabled",
								CurrentValue = displayValue,
								ExpectedValue = "True",
								Status = status,
								Description = "Network Inspection System (NIS) inspects network traffic in real-time using protocol inspection engines to detect network-based exploits.",
								Recommendation = ((status == SecurityStatus.OK) ? "NIS is enabled." : "Enable NIS for network traffic inspection."),
								Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/"
							};
						});
						TryAdd(results, delegate
						{
							(bool effective, string displayValue, SecurityStatus status) onAccessStatus = ResolveProtectionStatus(WmiBool(mpStatus, "OnAccessProtectionEnabled"), "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableOnAccessProtection", "On-Access Protection");
							string displayValue = onAccessStatus.displayValue;
							SecurityStatus status = onAccessStatus.status;
							return new SecurityResult
							{
								Category = Category,
								CheckName = "On-Access Protection Enabled",
								CurrentValue = displayValue,
								ExpectedValue = "True",
								Status = status,
								Description = "On-access protection scans files when they are opened, copied, or moved. This is a core component of real-time AV protection.",
								Recommendation = status switch
								{
									SecurityStatus.Warning => "WMI inconsistency — verify via Windows Security UI.", 
									SecurityStatus.OK => "On-access protection is enabled.", 
									_ => "Enable on-access protection.", 
								},
								Reference = ""
							};
						});
						TryAdd(results, delegate
						{
							(bool effective, string displayValue, SecurityStatus status) networkInspectionStatus = ResolveProtectionStatus(WmiBool(mpStatus, "NetworkRealtimeInspectionEnabled"), "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\NIS", "DisableNIS", "Network Inspection");
							string displayValue = networkInspectionStatus.displayValue;
							SecurityStatus status = networkInspectionStatus.status;
							if (status == SecurityStatus.Critical)
							{
								status = SecurityStatus.Warning;
							}
							return new SecurityResult
							{
								Category = Category,
								CheckName = "Network Real-Time Inspection Enabled",
								CurrentValue = displayValue,
								ExpectedValue = "True",
								Status = status,
								Description = "Enables real-time inspection of network connections for known exploit signatures.",
								Recommendation = ((status == SecurityStatus.OK) ? "Network inspection is enabled." : "Enable network real-time inspection."),
								Reference = ""
							};
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = Category,
							CheckName = "AM Engine Version",
							CurrentValue = (WmiStr(mpStatus, "AMEngineVersion") ?? "Unknown"),
							ExpectedValue = "Latest",
							Status = SecurityStatus.Info,
							Description = "Windows Defender Anti-Malware engine version.",
							Recommendation = "Keep engine updated via Windows Update.",
							Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/manage-updates-baselines-microsoft-defender-antivirus"
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = Category,
							CheckName = "AM Product Version",
							CurrentValue = (WmiStr(mpStatus, "AMProductVersion") ?? "Unknown"),
							ExpectedValue = "Latest",
							Status = SecurityStatus.Info,
							Description = "Windows Defender product version number.",
							Recommendation = "Keep product updated.",
							Reference = ""
						});
						TryAdd(results, delegate
						{
							string serviceEnabledValue = WmiStr(mpStatus, "AMServiceEnabled") ?? "Unknown";
							bool isEnabled = serviceEnabledValue.Equals("True", StringComparison.OrdinalIgnoreCase);
							return new SecurityResult
							{
								Category = Category,
								CheckName = "AM Service Enabled",
								CurrentValue = serviceEnabledValue,
								ExpectedValue = "True",
								Status = ((!isEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
								Description = "Windows Defender Antivirus service (WinDefend) enabled status.",
								Recommendation = (isEnabled ? "Defender service is enabled." : "Start and enable the Windows Defender service."),
								Reference = ""
							};
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = Category,
							CheckName = "AM Service Version",
							CurrentValue = (WmiStr(mpStatus, "AMServiceVersion") ?? "Unknown"),
							ExpectedValue = "Latest",
							Status = SecurityStatus.Info,
							Description = "Windows Defender service version.",
							Recommendation = "",
							Reference = ""
						});
						TryAdd(results, () => new SecurityResult
						{
							Category = Category,
							CheckName = "Tamper Protection Source",
							CurrentValue = (WmiStr(mpStatus, "TamperProtectionSource") ?? "Unknown"),
							ExpectedValue = "Antivirus",
							Status = SecurityStatus.Info,
							Description = "Source managing Tamper Protection for Windows Defender settings.",
							Recommendation = "Tamper Protection should be managed by the antivirus or MDM.",
							Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection"
						});
					}
					finally
					{
						((IDisposable)mo)?.Dispose();
					}
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
		catch (Exception ex2)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Defender WMI Status",
				CurrentValue = "Error: " + ex2.Message,
				Status = SecurityStatus.Warning,
				Description = "Could not query MSFT_MpComputerStatus from WMI. Fallback vers le registre en cours.",
				Recommendation = "Ensure Windows Defender is installed and WMI service is running.",
				Reference = ""
			});
			CollectDefenderFromRegistry(results, ct);
		}
	}

	private void CollectDefenderFromRegistry(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey defenderKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender");
			object disableAvValue = defenderKey?.GetValue("DisableAntiVirus");
			bool isDisabled = ((disableAvValue != null) ? Convert.ToInt32(disableAvValue) : 0) == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Antivirus Enabled (via registry - WMI non disponible)",
				CurrentValue = ((disableAvValue == null) ? "Not set (default: enabled)" : (isDisabled ? "Disabled (1)" : "Enabled (0)")),
				ExpectedValue = "0 or not set (enabled)",
				Status = (isDisabled ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Statut de l'antivirus Windows Defender lu depuis le registre. DisableAntiVirus=1 signifie que la protection est désactivée.",
				Recommendation = (isDisabled ? "Réactiver Windows Defender immédiatement. Supprimer ou mettre à 0 la valeur DisableAntiVirus." : "Antivirus non désactivé par le registre."),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey defenderKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender");
			object disableSpywareValue = defenderKey?.GetValue("DisableAntiSpyware");
			bool isDisabled = ((disableSpywareValue != null) ? Convert.ToInt32(disableSpywareValue) : 0) == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Antispyware Enabled (via registry - WMI non disponible)",
				CurrentValue = ((disableSpywareValue == null) ? "Not set (default: enabled)" : (isDisabled ? "Disabled (1)" : "Enabled (0)")),
				ExpectedValue = "0 or not set (enabled)",
				Status = (isDisabled ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Statut de la protection anti-logiciels espions lu depuis le registre.",
				Recommendation = (isDisabled ? "Réactiver la protection anti-logiciels espions." : "Protection anti-logiciels espions active."),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey realtimeKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection");
			object disableRealtimeValue = realtimeKey?.GetValue("DisableRealtimeMonitoring");
			bool isDisabled = ((disableRealtimeValue != null) ? Convert.ToInt32(disableRealtimeValue) : 0) == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Real-Time Protection (via registry - WMI non disponible)",
				CurrentValue = ((disableRealtimeValue == null) ? "Not set (default: enabled)" : (isDisabled ? "Disabled (1)" : "Enabled (0)")),
				ExpectedValue = "0 or not set (enabled)",
				Status = (isDisabled ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Surveillance en temps réel de Windows Defender — valeur registre. Si désactivée, les logiciels malveillants peuvent s'exécuter sans être détectés.",
				Recommendation = (isDisabled ? "Réactiver la surveillance en temps réel immédiatement." : "Surveillance en temps réel active."),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey featuresKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Features");
			object tamperValue = featuresKey?.GetValue("TamperProtection");
			int tamperProtection = ((tamperValue != null) ? Convert.ToInt32(tamperValue) : (-1));
			string statusText;
			object statusLabel;
			switch (tamperProtection)
			{
			case 0:
				statusText = "0 - Désactivé";
				break;
			case 1:
				statusText = "1 - Non configuré";
				break;
			case 4:
				statusText = "4 - Désactivé par stratégie";
				break;
			case 5:
				statusText = "5 - Activé";
				break;
			default:
				statusLabel = $"{tamperProtection} - Inconnu";
				goto IL_00af;
			case -1:
				{
					statusLabel = "Non trouvé";
					goto IL_00af;
				}
				IL_00af:
				statusText = (string)statusLabel;
				break;
			}
			string displayValue = statusText;
			bool isEnabled = tamperProtection == 5;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Tamper Protection (via registry - WMI non disponible)",
				CurrentValue = displayValue,
				ExpectedValue = "5 (Activé)",
				Status = ((!isEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "La protection contre les falsifications empêche les modifications non autorisées des paramètres Windows Defender — valeur registre.",
				Recommendation = (isEnabled ? "Protection contre les falsifications activée." : "Activer via Sécurité Windows > Protection contre les virus et menaces."),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey spyNetKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender\\SpyNet");
			object spyNetReportingValue = spyNetKey?.GetValue("SpyNetReporting");
			int spyNetReporting = ((spyNetReportingValue != null) ? Convert.ToInt32(spyNetReportingValue) : (-1));
			string statusText;
			object statusLabel;
			switch (spyNetReporting)
			{
			case 0:
				statusText = "0 - Désactivé";
				break;
			case 1:
				statusText = "1 - Basique";
				break;
			case 2:
				statusText = "2 - Avancé (recommandé)";
				break;
			default:
				statusLabel = $"{spyNetReporting}";
				goto IL_008d;
			case -1:
				{
					statusLabel = "Non configuré (défaut : Basique)";
					goto IL_008d;
				}
				IL_008d:
				statusText = (string)statusLabel;
				break;
			}
			string displayValue = statusText;
			bool isAdvanced = spyNetReporting == 2;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Cloud Protection (SpyNet) (via registry - WMI non disponible)",
				CurrentValue = displayValue,
				ExpectedValue = "2 (Avancé)",
				Status = ((spyNetReporting == 0) ? SecurityStatus.Critical : ((!isAdvanced) ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = "Niveau de signalement de la protection cloud (MAPS) — valeur registre. Le mode avancé envoie plus de renseignements sur les menaces.",
				Recommendation = (isAdvanced ? "Protection cloud au niveau avancé." : ((spyNetReporting == 0) ? "Activer la protection cloud immédiatement." : "Configurer SpyNetReporting = 2 pour la protection cloud avancée.")),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/configure-cloud-delivered-protection-microsoft-defender-antivirus"
			};
		});
	}

	private void CollectDefenderRegistrySettings(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey defenderKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender");
			object disableSpywareValue = defenderKey?.GetValue("DisableAntiSpyware");
			int disableSpyware = ((disableSpywareValue != null) ? Convert.ToInt32(disableSpywareValue) : 0);
			bool isDisabled = disableSpyware == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Registry: DisableAntiSpyware",
				CurrentValue = ((disableSpywareValue == null) ? "Not set (default: enabled)" : disableSpyware.ToString()),
				ExpectedValue = "0 or not set",
				Status = (isDisabled ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Registry value that can disable anti-spyware protection. Setting this to 1 disables Defender entirely.",
				Recommendation = (isDisabled ? "Remove or set DisableAntiSpyware to 0 to re-enable Defender." : "Anti-spyware is not disabled via registry."),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey defenderKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender");
			object disableAvValue = defenderKey?.GetValue("DisableAntiVirus");
			int disableAv = ((disableAvValue != null) ? Convert.ToInt32(disableAvValue) : 0);
			bool isDisabled = disableAv == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Registry: DisableAntiVirus",
				CurrentValue = ((disableAvValue == null) ? "Not set (default: enabled)" : disableAv.ToString()),
				ExpectedValue = "0 or not set",
				Status = (isDisabled ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Registry value that can disable antivirus protection. This is an explicit AV kill-switch.",
				Recommendation = (isDisabled ? "Remove or set DisableAntiVirus to 0 immediately." : "Antivirus is not disabled via registry."),
				Reference = ""
			};
		});
	}

	private void CollectDefenderPolicySettings(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey realtimeKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection");
			object disableRealtimeValue = realtimeKey?.GetValue("DisableRealtimeMonitoring");
			bool isDisabled = ((disableRealtimeValue != null) ? Convert.ToInt32(disableRealtimeValue) : 0) == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "GPO: DisableRealtimeMonitoring",
				CurrentValue = ((disableRealtimeValue == null) ? "Not configured (enabled)" : (isDisabled ? "1 - Désactivé par GPO" : "0 (enabled)")),
				ExpectedValue = "0 or not configured",
				Status = (isDisabled ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Group Policy setting that can force-disable real-time monitoring (HKLM\\...\\Real-Time Protection\\DisableRealtimeMonitoring). Attackers may leverage this policy key to disable AV.",
				Recommendation = (isDisabled ? "Real-time monitoring is disabled by policy. Investigate and correct this GPO setting." : "Real-time monitoring is not disabled by policy."),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey realtimeKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection");
			object disableBehaviorValue = realtimeKey?.GetValue("DisableBehaviorMonitoring");
			bool isDisabled = ((disableBehaviorValue != null) ? Convert.ToInt32(disableBehaviorValue) : 0) == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "GPO: DisableBehaviorMonitoring",
				CurrentValue = ((disableBehaviorValue == null) ? "Not configured (enabled)" : (isDisabled ? "1 - Désactivé par GPO" : "0 (enabled)")),
				ExpectedValue = "0 or not configured",
				Status = (isDisabled ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Group Policy that can disable behavior monitoring, preventing detection of novel threats.",
				Recommendation = (isDisabled ? "Behavior monitoring is disabled by policy. Correct this GPO." : "Behavior monitoring is not disabled by policy."),
				Reference = ""
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey defenderKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender");
			object blockAtFirstSeenValue = defenderKey?.GetValue("DisableBlockAtFirstSeen");
			int blockAtFirstSeen = ((blockAtFirstSeenValue != null) ? Convert.ToInt32(blockAtFirstSeenValue) : 0);
			bool isDisabled = blockAtFirstSeen == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "GPO: DisableBlockAtFirstSeen",
				CurrentValue = ((blockAtFirstSeenValue == null) ? "Not configured (enabled)" : blockAtFirstSeen.ToString()),
				ExpectedValue = "0 or not configured",
				Status = (isDisabled ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Block at First Seen uses cloud intelligence to block new malware within seconds. Disabling it delays protection against novel threats.",
				Recommendation = (isDisabled ? "Enable Block at First Seen for faster response to new threats." : "Block at First Seen is enabled."),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey defenderKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender");
			object puaValue = defenderKey?.GetValue("PUAProtection");
			int puaProtection = ((puaValue != null) ? Convert.ToInt32(puaValue) : (-1));
			bool isBlock = puaProtection == 1;
			string displayText = ((puaProtection == 1) ? "1 - Block" : ((puaProtection != 2) ? ((puaProtection == -1) ? "Not configured" : $"{puaProtection}") : "2 - Audit only"));
			string displayValue = displayText;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "GPO: PUA Protection",
				CurrentValue = displayValue,
				ExpectedValue = "1 (Block)",
				Status = ((!isBlock) ? ((puaProtection == 2) ? SecurityStatus.Warning : SecurityStatus.Warning) : SecurityStatus.OK),
				Description = "Potentially Unwanted Application (PUA) protection blocks adware, miners, and bundled software that reduce security.",
				Recommendation = (isBlock ? "PUA protection is in Block mode." : "Set PUAProtection = 1 (Block mode) to prevent PUA installations."),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey networkProtectionKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection");
			object networkProtectionValue = networkProtectionKey?.GetValue("EnableNetworkProtection");
			int networkProtection = ((networkProtectionValue != null) ? Convert.ToInt32(networkProtectionValue) : (-1));
			bool isBlock = networkProtection == 1;
			string displayText = ((networkProtection == 1) ? "1 - Block" : ((networkProtection != 2) ? ((networkProtection == -1) ? "Not configured" : $"{networkProtection}") : "2 - Audit only"));
			string displayValue = displayText;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "GPO: Network Protection",
				CurrentValue = displayValue,
				ExpectedValue = "1 (Block)",
				Status = ((!isBlock) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Network Protection blocks outbound connections to known malicious IP addresses and domains, preventing C2 communication and malware downloads.",
				Recommendation = (isBlock ? "Network Protection is in Block mode." : "Enable Network Protection (Block mode) via GPO or Windows Security."),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/enable-network-protection"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey realtimeKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection");
			object disableIoavValue = realtimeKey?.GetValue("DisableIOAVProtection");
			bool isDisabled = ((disableIoavValue != null) ? Convert.ToInt32(disableIoavValue) : 0) == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "GPO: DisableIOAVProtection",
				CurrentValue = ((disableIoavValue == null) ? "Not configured (enabled)" : (isDisabled ? "1 - Désactivé par GPO" : "0 (enabled)")),
				ExpectedValue = "0 or not configured",
				Status = (isDisabled ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "IOAV (Internet On-Access Validation) scans downloaded files. Disabling it allows malicious downloads to execute without scanning.",
				Recommendation = (isDisabled ? "Enable IOAV protection to scan downloaded files." : "IOAV protection is not disabled."),
				Reference = ""
			};
		});
	}

	private void CollectElamStatus(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey earlyLaunchKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\EarlyLaunch");
			object driverLoadPolicyValue = earlyLaunchKey?.GetValue("DriverLoadPolicy");
			int driverLoadPolicy = ((driverLoadPolicyValue != null) ? Convert.ToInt32(driverLoadPolicyValue) : 3);
			string displayValue = driverLoadPolicy switch
			{
				0 => "0 - Good only",
				1 => "1 - Good and Unknown",
				3 => "3 - Good, Unknown, and Bad but Critical (default)",
				7 => "7 - All",
				8 => "8 - Disabled (ELAM disabled)",
				_ => $"{driverLoadPolicy} - Unknown",
			};
			bool isDisabled = driverLoadPolicy == 8;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "ELAM: Driver Load Policy",
				CurrentValue = displayValue,
				ExpectedValue = "Not 8 (ELAM enabled)",
				Status = (isDisabled ? SecurityStatus.Critical : ((driverLoadPolicy > 3) ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = "Early Launch Anti-Malware (ELAM) runs before other drivers at boot, detecting rootkits and boot-level malware. Policy 8 disables ELAM entirely.",
				Recommendation = (isDisabled ? "ELAM is disabled. Set DriverLoadPolicy to 3 to enable ELAM protection." : "ELAM is enabled. Consider value 0 (Good only) for maximum strictness."),
				Reference = "https://docs.microsoft.com/windows/compatibility/early-launch-antimalware"
			};
		});
	}

	private void CollectTamperProtection(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey featuresKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Features");
			object tamperValue = featuresKey?.GetValue("TamperProtection");
			int tamperProtection = ((tamperValue != null) ? Convert.ToInt32(tamperValue) : (-1));
			string statusText;
			object statusLabel;
			switch (tamperProtection)
			{
			case 0:
				statusText = "0 - Disabled";
				break;
			case 1:
				statusText = "1 - Not configured";
				break;
			case 4:
				statusText = "4 - Disabled by policy";
				break;
			case 5:
				statusText = "5 - Enabled";
				break;
			default:
				statusLabel = $"{tamperProtection} - Unknown";
				goto IL_00af;
			case -1:
				{
					statusLabel = "Not found";
					goto IL_00af;
				}
				IL_00af:
				statusText = (string)statusLabel;
				break;
			}
			string displayValue = statusText;
			bool isEnabled = tamperProtection == 5;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Tamper Protection",
				CurrentValue = displayValue,
				ExpectedValue = "5 (Enabled)",
				Status = ((!isEnabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Tamper Protection prevents unauthorized changes to Windows Defender settings by malware or attackers with admin rights. It blocks changes to AV signatures, real-time protection, and cloud protection.",
				Recommendation = (isEnabled ? "Tamper Protection is enabled." : "Enable Tamper Protection via Windows Security > Virus & Threat Protection > Virus & Threat Protection Settings."),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection"
			};
		});
	}

	private void CollectCloudProtection(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey spynetKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet");
			object spynetReportingValue = spynetKey?.GetValue("SpynetReporting");
			int spynetReporting = ((spynetReportingValue != null) ? Convert.ToInt32(spynetReportingValue) : (-1));
			string statusText;
			object statusLabel;
			switch (spynetReporting)
			{
			case 0:
				statusText = "0 - Disabled";
				break;
			case 1:
				statusText = "1 - Basic";
				break;
			case 2:
				statusText = "2 - Advanced (recommended)";
				break;
			default:
				statusLabel = $"{spynetReporting}";
				goto IL_008d;
			case -1:
				{
					statusLabel = "Not configured (default: Basic)";
					goto IL_008d;
				}
				IL_008d:
				statusText = (string)statusLabel;
				break;
			}
			string displayValue = statusText;
			bool isAdvanced = spynetReporting == 2;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Cloud Protection: SpynetReporting Level",
				CurrentValue = displayValue,
				ExpectedValue = "2 (Advanced)",
				Status = ((spynetReporting == 0) ? SecurityStatus.Critical : ((!isAdvanced) ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = "Cloud-delivered protection (MAPS) reporting level. Advanced reporting sends more threat intelligence to Microsoft for faster protection updates.",
				Recommendation = (isAdvanced ? "Cloud protection is at Advanced level." : ((spynetReporting == 0) ? "Enable cloud protection immediately." : "Set SpynetReporting = 2 for Advanced cloud protection.")),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/configure-cloud-delivered-protection-microsoft-defender-antivirus"
			};
		});
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey spynetKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet");
			object submitSamplesValue = spynetKey?.GetValue("SubmitSamplesConsent");
			int submitSamplesConsent = ((submitSamplesValue != null) ? Convert.ToInt32(submitSamplesValue) : (-1));
			string statusText;
			object statusLabel;
			switch (submitSamplesConsent)
			{
			case 0:
				statusText = "0 - Always prompt";
				break;
			case 1:
				statusText = "1 - Send safe samples automatically";
				break;
			case 2:
				statusText = "2 - Never send";
				break;
			case 3:
				statusText = "3 - Send all samples automatically";
				break;
			default:
				statusLabel = $"{submitSamplesConsent}";
				goto IL_009a;
			case -1:
				{
					statusLabel = "Not configured";
					goto IL_009a;
				}
				IL_009a:
				statusText = (string)statusLabel;
				break;
			}
			string displayValue = statusText;
			bool isConfigured = submitSamplesConsent == 1 || submitSamplesConsent == 3;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Cloud Protection: SubmitSamplesConsent",
				CurrentValue = displayValue,
				ExpectedValue = "1 (Send safe samples) or 3 (Send all samples)",
				Status = ((submitSamplesConsent == 2) ? SecurityStatus.Warning : ((!isConfigured) ? SecurityStatus.Info : SecurityStatus.OK)),
				Description = "Controls whether suspicious samples are sent to Microsoft for analysis. Sending samples improves protection accuracy and speed.",
				Recommendation = (isConfigured ? "Sample submission is configured." : ((submitSamplesConsent == 2) ? "Consider enabling sample submission for better cloud protection." : "Configure sample submission policy.")),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/configure-cloud-delivered-protection-microsoft-defender-antivirus"
			};
		});
	}

	private void CollectAsrRules(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey asrRulesKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules");
			if (asrRulesKey == null)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "ASR Rules Configured",
					CurrentValue = "No ASR rules configured",
					ExpectedValue = "Rules configured",
					Status = SecurityStatus.Warning,
					Description = "Attack Surface Reduction (ASR) rules block behaviors commonly used by malware such as Office macro abuse, script execution, credential theft, and ransomware-like behavior.",
					Recommendation = "Configure ASR rules via Group Policy or Intune. Key rules include blocking Office macros from creating child processes, credential theft from LSASS, and executable content from email.",
					Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference"
				};
			}
			string[] valueNames = asrRulesKey.GetValueNames();
			int blockCount = 0;
			int auditCount = 0;
			string[] ruleNames = valueNames;
			foreach (string name in ruleNames)
			{
				string ruleValue = asrRulesKey.GetValue(name)?.ToString() ?? "0";
				if (ruleValue == "1")
				{
					blockCount++;
				}
				else if (ruleValue == "2")
				{
					auditCount++;
				}
			}
			bool hasEnoughRules = blockCount >= 5;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "ASR Rules Configured",
				CurrentValue = $"{valueNames.Length} rules total: {blockCount} Block, {auditCount} Audit",
				ExpectedValue = ">= 5 rules in Block mode",
				Status = ((!hasEnoughRules) ? ((blockCount > 0) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
				Description = "Attack Surface Reduction rules restrict malware-like behaviors. Microsoft recommends enabling all applicable rules in Block mode.",
				Recommendation = (hasEnoughRules ? "ASR rules are configured." : $"Increase ASR rules to Block mode. Currently {blockCount} in Block mode. Target all recommended rules."),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference"
			};
		});
	}

	private void CollectControlledFolderAccess(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey cfaKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access");
			object cfaValue = cfaKey?.GetValue("EnableControlledFolderAccess");
			int cfaSetting = ((cfaValue != null) ? Convert.ToInt32(cfaValue) : 0);
			string displayValue = cfaSetting switch
			{
				0 => "0 - Disabled",
				1 => "1 - Block (enabled)",
				2 => "2 - Audit only",
				_ => $"{cfaSetting} - Unknown",
			};
			bool isEnabled = cfaSetting == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Controlled Folder Access",
				CurrentValue = displayValue,
				ExpectedValue = "1 (Block / Enabled)",
				Status = ((!isEnabled) ? ((cfaSetting == 2) ? SecurityStatus.Warning : SecurityStatus.Warning) : SecurityStatus.OK),
				Description = "Controlled Folder Access (ransomware protection) prevents unauthorized applications from modifying files in protected folders like Documents, Pictures, and Desktop.",
				Recommendation = (isEnabled ? "Controlled Folder Access is enabled." : "Enable Controlled Folder Access to protect against ransomware."),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/controlled-folders"
			};
		});
	}

	private void CollectExploitProtection(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey exploitProtectionKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Exploit Protection");
			bool isPresent = exploitProtectionKey != null;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Exploit Protection Registry Key",
				CurrentValue = (isPresent ? "Present" : "Not present"),
				ExpectedValue = "Present (configured)",
				Status = ((!isPresent) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "Exploit Protection provides system-wide and per-process exploit mitigations (DEP, ASLR, CFG, etc.) configurable via Windows Security.",
				Recommendation = "Configure Exploit Protection via Windows Security > App & Browser Control > Exploit Protection Settings.",
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/exploit-protection"
			};
		});
	}

	private static int WmiInt(ManagementObject obj, string prop, int def = -1)
	{
		try
		{
			object rawValue = obj[prop];
			return (rawValue != null && !(rawValue is DBNull)) ? Convert.ToInt32(rawValue) : def;
		}
		catch
		{
			return def;
		}
	}

	private static bool WmiBool(ManagementObject obj, string prop, bool def = false)
	{
		try
		{
			object rawValue = obj[prop];
			return (rawValue != null && !(rawValue is DBNull)) ? Convert.ToBoolean(rawValue) : def;
		}
		catch
		{
			return def;
		}
	}

	private static string? WmiStr(ManagementObject obj, string prop)
	{
		try
		{
			return obj[prop]?.ToString();
		}
		catch
		{
			return null;
		}
	}

	private static bool IsDisabledByGpo(string subKey, string valueName)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey gpoKey = baseKey.OpenSubKey(subKey);
			object gpoValue = gpoKey?.GetValue(valueName);
			return gpoValue != null && Convert.ToInt32(gpoValue) == 1;
		}
		catch
		{
			return false;
		}
	}

	private static (bool effective, string displayValue, SecurityStatus status) ResolveProtectionStatus(bool wmiValue, string gpoSubKey, string gpoValueName, string checkLabel)
	{
		bool isDisabledByGpo = IsDisabledByGpo(gpoSubKey, gpoValueName);
		if (wmiValue)
		{
			return (effective: true, displayValue: "True", status: SecurityStatus.OK);
		}
		if (!isDisabledByGpo)
		{
			return (effective: true, displayValue: "False (WMI) — GPO ne désactive pas " + checkLabel + " (probable incohérence WMI)", status: SecurityStatus.Warning);
		}
		return (effective: false, displayValue: "False (désactivé par GPO)", status: SecurityStatus.Critical);
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
				Category = "Antivirus / Endpoint Protection",
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
