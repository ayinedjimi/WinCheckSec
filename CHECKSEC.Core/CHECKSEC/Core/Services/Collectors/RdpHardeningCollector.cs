using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class RdpHardeningCollector : ISecurityCollector
{
	private const string TsKey = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server";

	private const string TsWinStaKey = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp";

	private const string TsPolicyKey = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services";

	public string Name => "Durcissement RDP";

	public string Category => "Accès Distant";

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
			CollectRdpStatus(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectNlaSettings(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectEncryptionSettings(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectPolicySettings(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "RdpHardeningCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectRdpStatus(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server");
			object denyConnectionsValue = registryKey?.GetValue("fDenyTSConnections");
			if (denyConnectionsValue != null)
			{
				bool rdpDenied = Convert.ToInt32(denyConnectionsValue) == 1;
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "RDP — État",
					CurrentValue = (rdpDenied ? "Désactivé" : "Activé"),
					ExpectedValue = "Désactivé (si non nécessaire)",
					Status = ((!rdpDenied) ? SecurityStatus.Info : SecurityStatus.OK),
					Description = (rdpDenied ? "Le Bureau à Distance (RDP) est désactivé." : "Le Bureau à Distance (RDP) est activé. Assurez-vous que l'accès est correctement sécurisé."),
					Recommendation = (rdpDenied ? "Configuration sécurisée si RDP n'est pas nécessaire." : "Si RDP est nécessaire, assurez-vous que NLA est activé, utilisez un VPN et limitez les accès."),
					Reference = "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"
				});
			}
			else
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "RDP — État",
					CurrentValue = "Non configuré",
					ExpectedValue = "Désactivé (si non nécessaire)",
					Status = SecurityStatus.Info,
					Description = "L'état RDP n'est pas explicitement configuré dans le registre.",
					Recommendation = "Vérifiez l'état de RDP via les paramètres système.",
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
				CheckName = "RDP État — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier l'état RDP: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}

	private void CollectNlaSettings(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp");
			object userAuthValue = registryKey?.GetValue("UserAuthentication");
			if (userAuthValue != null)
			{
				bool nlaRequired = Convert.ToInt32(userAuthValue) == 1;
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "RDP — NLA (Network Level Authentication)",
					CurrentValue = (nlaRequired ? "Requis" : "Non requis"),
					ExpectedValue = "Requis",
					Status = ((!nlaRequired) ? SecurityStatus.Critical : SecurityStatus.OK),
					Description = (nlaRequired ? "NLA est requis avant la connexion RDP. L'authentification est vérifiée avant d'établir la session." : "NLA n'est PAS requis! Un attaquant peut accéder à l'écran de connexion sans s'authentifier."),
					Recommendation = (nlaRequired ? "Configuration correcte." : "URGENT: Activez NLA pour RDP (UserAuthentication = 1)."),
					Reference = "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"
				});
			}
			else
			{
				using RegistryKey terminalServerKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server");
				object fallbackUserAuthValue = terminalServerKey?.GetValue("UserAuthentication");
				bool nlaRequiredFallback = fallbackUserAuthValue != null && Convert.ToInt32(fallbackUserAuthValue) == 1;
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "RDP — NLA (Network Level Authentication)",
					CurrentValue = (nlaRequiredFallback ? "Requis" : "Non configuré"),
					ExpectedValue = "Requis",
					Status = ((!nlaRequiredFallback) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = "NLA n'est pas configuré au niveau RDP-Tcp.",
					Recommendation = "Activez NLA pour toutes les connexions RDP.",
					Reference = ""
				});
			}
			object securityLayerValue = registryKey?.GetValue("SecurityLayer");
			if (securityLayerValue != null)
			{
				int securityLayer = Convert.ToInt32(securityLayerValue);
				string securityLayerLabel = securityLayer switch
				{
					0 => "RDP Security Layer (faible)",
					1 => "Negotiate",
					2 => "TLS/SSL",
					_ => $"Inconnu ({securityLayer})",
				};
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "RDP — Couche de sécurité",
					CurrentValue = securityLayerLabel,
					ExpectedValue = "TLS/SSL (2)",
					Status = ((securityLayer < 2) ? ((securityLayer != 1) ? SecurityStatus.Warning : SecurityStatus.Info) : SecurityStatus.OK),
					Description = "Couche de sécurité RDP: " + securityLayerLabel,
					Recommendation = ((securityLayer < 2) ? "Utilisez TLS/SSL (SecurityLayer = 2) pour le chiffrement RDP." : "Configuration correcte."),
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
				CheckName = "RDP NLA — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier NLA: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}

	private void CollectEncryptionSettings(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp");
			object minEncryptionValue = registryKey?.GetValue("MinEncryptionLevel");
			if (minEncryptionValue != null)
			{
				int encryptionLevel = Convert.ToInt32(minEncryptionValue);
				string encryptionLabel = encryptionLevel switch
				{
					1 => "Faible (56-bit)",
					2 => "Compatible client",
					3 => "Élevé (128-bit)",
					4 => "Conforme FIPS",
					_ => $"Inconnu ({encryptionLevel})",
				};
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "RDP — Niveau de chiffrement",
					CurrentValue = encryptionLabel,
					ExpectedValue = "Élevé (3) ou FIPS (4)",
					Status = ((encryptionLevel < 3) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = "Niveau de chiffrement RDP: " + encryptionLabel,
					Recommendation = ((encryptionLevel < 3) ? "Augmentez MinEncryptionLevel à 3 (High) ou 4 (FIPS)." : "Configuration correcte."),
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
				CheckName = "RDP Encryption — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}

	private void CollectPolicySettings(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services");
			if (registryKey != null)
			{
				object maxIdleTimeValue = registryKey.GetValue("MaxIdleTime");
				if (maxIdleTimeValue != null)
				{
					int maxIdleMs = Convert.ToInt32(maxIdleTimeValue);
					int maxIdleMinutes = maxIdleMs / 60000;
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "RDP — Timeout inactivité",
						CurrentValue = ((maxIdleMs == 0) ? "Illimité" : $"{maxIdleMinutes} minutes"),
						ExpectedValue = "≤ 15 minutes",
						Status = ((maxIdleMs <= 0 || maxIdleMinutes > 15) ? SecurityStatus.Warning : SecurityStatus.OK),
						Description = ((maxIdleMs == 0) ? "Aucun timeout d'inactivité RDP configuré." : $"Les sessions RDP inactives seront déconnectées après {maxIdleMinutes} minutes."),
						Recommendation = ((maxIdleMs == 0 || maxIdleMinutes > 15) ? "Configurez un timeout d'inactivité de 15 minutes maximum." : "Configuration correcte."),
						Reference = ""
					});
				}
				object disableClipValue = registryKey.GetValue("fDisableClip");
				if (disableClipValue != null)
				{
					bool clipboardDisabled = Convert.ToInt32(disableClipValue) == 1;
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "RDP — Presse-papiers",
						CurrentValue = (clipboardDisabled ? "Désactivé" : "Activé"),
						ExpectedValue = "Désactivé (environnements sensibles)",
						Status = ((!clipboardDisabled) ? SecurityStatus.Info : SecurityStatus.OK),
						Description = (clipboardDisabled ? "Le partage du presse-papiers RDP est désactivé." : "Le partage du presse-papiers RDP est activé."),
						Recommendation = "Désactivez le presse-papiers dans les environnements sensibles pour prévenir l'exfiltration de données.",
						Reference = ""
					});
				}
				object disableCdmValue = registryKey.GetValue("fDisableCdm");
				if (disableCdmValue != null)
				{
					bool driveRedirectionDisabled = Convert.ToInt32(disableCdmValue) == 1;
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "RDP — Redirection de lecteurs",
						CurrentValue = (driveRedirectionDisabled ? "Désactivée" : "Activée"),
						ExpectedValue = "Désactivée",
						Status = ((!driveRedirectionDisabled) ? SecurityStatus.Warning : SecurityStatus.OK),
						Description = (driveRedirectionDisabled ? "La redirection de lecteurs RDP est désactivée." : "La redirection de lecteurs RDP est activée, permettant l'accès aux lecteurs locaux."),
						Recommendation = (driveRedirectionDisabled ? "Configuration correcte." : "Désactivez la redirection de lecteurs pour limiter les risques d'exfiltration."),
						Reference = ""
					});
				}
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
				CheckName = "RDP Policies — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}
}
