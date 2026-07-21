using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class BluetoothCollector : ISecurityCollector
{
	private const string BtPolicyKey = "SOFTWARE\\Microsoft\\PolicyManager\\default\\Connectivity\\AllowBluetooth";

	private const string BtServiceKey = "SYSTEM\\CurrentControlSet\\Services\\BTHPORT";

	private const string BtRadioKey = "SYSTEM\\CurrentControlSet\\Services\\BthEnum";

	public string Name => "Sécurité Bluetooth";

	public string Category => "Périphériques";

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
			CollectBluetoothPolicy(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectBluetoothService(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			collectorReport.ErrorMessage = "BluetoothCollector fatal error: " + ex2.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectBluetoothPolicy(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey policyKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\PolicyManager\\default\\Connectivity\\AllowBluetooth");
			object policyValueRaw = policyKey?.GetValue("value");
			if (policyValueRaw != null)
			{
				int allowBluetooth = Convert.ToInt32(policyValueRaw);
				string policyLabel = allowBluetooth switch
				{
					0 => "Désactivé",
					1 => "Activé (pas de découverte)",
					2 => "Activé (complet)",
					_ => $"Inconnu ({allowBluetooth})",
				};
				SecurityStatus status = allowBluetooth switch
				{
					0 => SecurityStatus.OK,
					1 => SecurityStatus.Info,
					2 => SecurityStatus.Warning,
					_ => SecurityStatus.Info,
				};
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Bluetooth — Politique",
					CurrentValue = policyLabel,
					ExpectedValue = "Désactivé (0) sur les serveurs",
					Status = status,
					Description = "Politique Bluetooth: " + policyLabel + ". Le Bluetooth représente un vecteur d'attaque potentiel (BlueBorne, KNOB).",
					Recommendation = ((allowBluetooth != 0) ? "Désactivez le Bluetooth si non nécessaire, surtout sur les serveurs et postes sensibles." : "Configuration correcte."),
					Reference = "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-connectivity#allowbluetooth"
				});
			}
			else
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Bluetooth — Politique",
					CurrentValue = "Non configurée (activé par défaut)",
					ExpectedValue = "Configurée via politique",
					Status = SecurityStatus.Info,
					Description = "Aucune politique Bluetooth n'est configurée. Le Bluetooth utilise les paramètres par défaut.",
					Recommendation = "Configurez la politique Bluetooth selon les besoins de sécurité de l'environnement.",
					Reference = ""
				});
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
				CheckName = "Bluetooth Policy — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex2.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}

	private void CollectBluetoothService(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey serviceKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\BTHPORT");
			if (serviceKey == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Bluetooth — Service",
					CurrentValue = "Non installé",
					ExpectedValue = "N/A",
					Status = SecurityStatus.OK,
					Description = "Le service Bluetooth (BTHPORT) n'est pas installé sur cette machine.",
					Recommendation = "Aucune action nécessaire si le Bluetooth n'est pas requis.",
					Reference = ""
				});
				return;
			}
			object startValueRaw = serviceKey.GetValue("Start");
			if (startValueRaw != null)
			{
				int startType = Convert.ToInt32(startValueRaw);
				string startLabel = startType switch
				{
					0 => "Boot",
					1 => "System",
					2 => "Automatique",
					3 => "Manuel",
					4 => "Désactivé",
					_ => $"Inconnu ({startType})",
				};
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Bluetooth — Service (BTHPORT)",
					CurrentValue = startLabel,
					ExpectedValue = "Désactivé (4) si non nécessaire",
					Status = startType switch
					{
						3 => SecurityStatus.Info,
						4 => SecurityStatus.OK,
						_ => SecurityStatus.Warning,
					},
					Description = "Le service Bluetooth est configuré en mode: " + startLabel,
					Recommendation = ((startType != 4) ? "Désactivez le service Bluetooth si non nécessaire pour réduire la surface d'attaque." : "Configuration correcte."),
					Reference = ""
				});
			}
			using RegistryKey radioKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\BthEnum");
			bool radioDetected = radioKey != null;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Bluetooth — Radio",
				CurrentValue = (radioDetected ? "Détecté" : "Non détecté"),
				ExpectedValue = "N/A",
				Status = SecurityStatus.Info,
				Description = (radioDetected ? "Un adaptateur Bluetooth est détecté sur cette machine." : "Aucun adaptateur Bluetooth détecté."),
				Recommendation = (radioDetected ? "Si le Bluetooth n'est pas nécessaire, désactivez-le dans les paramètres ou le BIOS." : "Aucune action nécessaire."),
				Reference = ""
			});
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
				CheckName = "Bluetooth Service — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex2.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}
}
