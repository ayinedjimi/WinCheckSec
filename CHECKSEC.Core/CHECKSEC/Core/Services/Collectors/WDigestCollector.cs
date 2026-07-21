using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class WDigestCollector : ISecurityCollector
{
	private const string WDigestKey = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest";

	public string Name => "WDigest";

	public string Category => "Authentification";

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
			CollectWDigestSettings(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "WDigestCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectWDigestSettings(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest");
			if (registryKey == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "WDigest — UseLogonCredential",
					CurrentValue = "Clé absente (sécurisé sur Windows 8.1+)",
					ExpectedValue = "0 (désactivé)",
					Status = SecurityStatus.OK,
					Description = "La clé WDigest n'existe pas. Sur Windows 8.1+ et Server 2012 R2+, le cache WDigest est désactivé par défaut.",
					Recommendation = "Configuration par défaut sécurisée. Aucune action requise.",
					Reference = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn800953(v=ws.11)"
				});
				return;
			}
			object useLogonCredentialValue = registryKey.GetValue("UseLogonCredential");
			if (useLogonCredentialValue == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "WDigest — UseLogonCredential",
					CurrentValue = "Non défini (désactivé par défaut sur Win 8.1+)",
					ExpectedValue = "0 (désactivé)",
					Status = SecurityStatus.OK,
					Description = "UseLogonCredential n'est pas défini. Le comportement par défaut sur les systèmes modernes est sécurisé.",
					Recommendation = "Pour une sécurité explicite, définissez UseLogonCredential = 0.",
					Reference = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn800953(v=ws.11)"
				});
			}
			else
			{
				int useLogonCredential = Convert.ToInt32(useLogonCredentialValue);
				bool isDisabled = useLogonCredential == 0;
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "WDigest — UseLogonCredential",
					CurrentValue = ((useLogonCredential == 0) ? "0 (désactivé)" : $"{useLogonCredential} (ACTIVÉ — DANGER)"),
					ExpectedValue = "0 (désactivé)",
					Status = ((!isDisabled) ? SecurityStatus.Critical : SecurityStatus.OK),
					Description = (isDisabled ? "Le cache de credentials WDigest est désactivé. Les mots de passe ne sont pas stockés en clair en mémoire." : "CRITIQUE: WDigest stocke les mots de passe en clair en mémoire! Un attaquant avec Mimikatz peut les extraire."),
					Recommendation = (isDisabled ? "Configuration correcte." : "URGENT: Définissez UseLogonCredential = 0 immédiatement pour empêcher le stockage des credentials en clair."),
					Reference = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn800953(v=ws.11)"
				});
			}
			object negotiateValue = registryKey.GetValue("Negotiate");
			if (negotiateValue != null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "WDigest — Negotiate",
					CurrentValue = (negotiateValue.ToString() ?? "N/A"),
					ExpectedValue = "Configuré",
					Status = SecurityStatus.Info,
					Description = $"Valeur WDigest Negotiate: {negotiateValue}",
					Recommendation = "Consultez la documentation Microsoft pour les valeurs recommandées.",
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
				CheckName = "WDigest — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier WDigest: " + ex.Message,
				Recommendation = "Vérifiez les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}
}
