using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class PrintSpoolerCollector : ISecurityCollector
{
	private const string SpoolerServiceKey = "SYSTEM\\CurrentControlSet\\Services\\Spooler";

	private const string PrintPoliciesKey = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers";

	private const string PointAndPrintKey = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint";

	public string Name => "Print Spooler";

	public string Category => "Services";

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
			CollectSpoolerStatus(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectPrintPolicies(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception exception)
		{
			collectorReport.ErrorMessage = "PrintSpoolerCollector fatal error: " + exception.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectSpoolerStatus(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey spoolerKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\Spooler");
			if (spoolerKey == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Service Print Spooler",
					CurrentValue = "Non trouvé",
					ExpectedValue = "Désactivé (serveurs)",
					Status = SecurityStatus.Info,
					Description = "Le service Print Spooler n'a pas été trouvé dans le registre.",
					Recommendation = "Vérifiez l'état du service manuellement.",
					Reference = "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-print-spooler"
				});
				return;
			}
			object startValue = spoolerKey.GetValue("Start");
			if (startValue != null)
			{
				int startMode = Convert.ToInt32(startValue);
				string startupModeLabel = startMode switch
				{
					2 => "Automatique",
					3 => "Manuel",
					4 => "Désactivé",
					_ => $"Inconnu ({startMode})",
				};
				SecurityStatus status = startMode switch
				{
					4 => SecurityStatus.OK,
					3 => SecurityStatus.Info,
					_ => SecurityStatus.Warning,
				};
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Service Print Spooler — Démarrage",
					CurrentValue = startupModeLabel,
					ExpectedValue = "Désactivé (sur les serveurs)",
					Status = status,
					Description = "Le service Spooler est configuré en mode: " + startupModeLabel + ". Sur les serveurs et contrôleurs de domaine, ce service devrait être désactivé (PrintNightmare CVE-2021-34527).",
					Recommendation = ((startMode != 4) ? "Désactivez le service Spooler sur les serveurs: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled" : "Configuration correcte pour un serveur."),
					Reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"
				});
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception exception)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Print Spooler — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier le Spooler: " + exception.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}

	private void CollectPrintPolicies(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey printersKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers");
			object rpcEndpointValue = printersKey?.GetValue("RegisterSpoolerRemoteRpcEndPoint");
			if (rpcEndpointValue != null)
			{
				bool rpcEndpointDisabled = Convert.ToInt32(rpcEndpointValue) == 2;
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Spooler RPC Endpoint distant",
					CurrentValue = (rpcEndpointDisabled ? "Désactivé" : "Activé"),
					ExpectedValue = "Désactivé",
					Status = ((!rpcEndpointDisabled) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = (rpcEndpointDisabled ? "Le point d'accès RPC distant du Spooler est désactivé." : "Le Spooler accepte les connexions RPC distantes, augmentant la surface d'attaque."),
					Recommendation = (rpcEndpointDisabled ? "Configuration correcte." : "Définissez RegisterSpoolerRemoteRpcEndPoint = 2 pour désactiver l'accès RPC distant."),
					Reference = ""
				});
			}
			else
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Spooler RPC Endpoint distant",
					CurrentValue = "Non configuré (activé par défaut)",
					ExpectedValue = "Désactivé",
					Status = SecurityStatus.Warning,
					Description = "Le point d'accès RPC distant du Spooler n'est pas explicitement configuré.",
					Recommendation = "Désactivez l'accès RPC distant du Spooler via GPO.",
					Reference = ""
				});
			}
			using RegistryKey pointAndPrintKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint");
			object noWarningValue = pointAndPrintKey?.GetValue("NoWarningNoElevationOnInstall");
			if (noWarningValue != null)
			{
				bool noWarningEnabled = Convert.ToInt32(noWarningValue) == 1;
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Point and Print — Pas d'avertissement",
					CurrentValue = (noWarningEnabled ? "Activé (dangereux)" : "Désactivé"),
					ExpectedValue = "Désactivé",
					Status = (noWarningEnabled ? SecurityStatus.Critical : SecurityStatus.OK),
					Description = (noWarningEnabled ? "Point and Print autorise l'installation de pilotes sans avertissement ni élévation." : "Point and Print requiert un avertissement/élévation pour l'installation de pilotes."),
					Recommendation = (noWarningEnabled ? "Désactivez NoWarningNoElevationOnInstall pour prévenir l'exploitation PrintNightmare." : "Configuration correcte."),
					Reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"
				});
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception exception)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Print Policies — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier les politiques d'impression: " + exception.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}
}
