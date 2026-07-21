using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class AsrRulesCollector : ISecurityCollector
{
	private const string AsrRegKey = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules";

	private static readonly Dictionary<string, string> KnownAsrRules = new Dictionary<string, string>
	{
		{ "56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers" },
		{ "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes" },
		{ "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes" },
		{ "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from LSASS" },
		{ "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail" },
		{ "01443614-cd74-433a-b99e-2ecdc07bfc25", "Block executable files from running unless they meet criteria" },
		{ "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts" },
		{ "d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded content" },
		{ "3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content" },
		{ "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes" },
		{ "26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes" },
		{ "e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription" },
		{ "d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands" },
		{ "33ddedf1-c6e0-47cb-833e-de6133960387", "Block rebooting machine in Safe Mode" },
		{ "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB" },
		{ "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block use of copied or impersonated system tools" },
		{ "a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers" },
		{ "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros" },
		{ "c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware" }
	};

	public string Name => "Règles ASR";

	public string Category => "Defender Avancé";

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
			CollectAsrRules(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			collectorReport.ErrorMessage = "AsrRulesCollector fatal error: " + ex2.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectAsrRules(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			RegistryKey key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules");
			try
			{
				if (key == null)
				{
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "Règles ASR",
						CurrentValue = "Non configuré",
						ExpectedValue = "Activé (1) ou Audit (2)",
						Status = SecurityStatus.Warning,
						Description = "Aucune règle ASR n'est configurée via GPO. Les règles ASR réduisent la surface d'attaque.",
						Recommendation = "Configurez les règles ASR via Microsoft Intune ou GPO.",
						Reference = "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference"
					});
					return;
				}
				foreach (KeyValuePair<string, string> knownAsrRule in KnownAsrRules)
				{
					var (guid, description) = knownAsrRule;
					ct.ThrowIfCancellationRequested();
					TryAdd(results, delegate
					{
						object ruleRegValue = key.GetValue(guid);
						string currentValue;
						SecurityStatus securityStatus;
						if (ruleRegValue == null)
						{
							currentValue = "Non configuré";
							securityStatus = SecurityStatus.Critical;
						}
						else
						{
							int ruleValue = Convert.ToInt32(ruleRegValue);
							(currentValue, securityStatus) = ruleValue switch
							{
								0 => ("Désactivé", SecurityStatus.Critical), 
								1 => ("Activé (Block)", SecurityStatus.OK), 
								2 => ("Audit", SecurityStatus.Warning), 
								6 => ("Warn", SecurityStatus.Warning), 
								_ => ($"Inconnu ({ruleValue})", SecurityStatus.Warning),
							};
						}
						return new SecurityResult
						{
							Category = Category,
							CheckName = "ASR: " + description,
							CurrentValue = currentValue,
							ExpectedValue = "Activé (Block)",
							Status = securityStatus,
							Description = "Règle ASR " + guid + ": " + description,
							Recommendation = ((securityStatus != 0) ? "Activez cette règle ASR en mode Block pour une protection maximale." : "Règle correctement configurée."),
							Reference = "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference"
						};
					});
				}
			}
			finally
			{
				if (key != null)
				{
					((IDisposable)key).Dispose();
				}
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
				CheckName = "Règles ASR — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de lire les règles ASR: " + ex2.Message,
				Recommendation = "Vérifiez les permissions d'accès au registre.",
				Reference = ""
			});
		}
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
				Category = "Defender Avancé",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Check failed: " + ex.Message,
				Recommendation = "Vérifiez les prérequis.",
				Reference = ""
			});
		}
	}
}
