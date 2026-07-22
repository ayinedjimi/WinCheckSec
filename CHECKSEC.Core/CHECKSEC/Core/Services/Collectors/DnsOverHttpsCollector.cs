using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class DnsOverHttpsCollector : ISecurityCollector
{
	private const string DnsCacheKey = "SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters";

	public string Name => "DNS-over-HTTPS";

	public string Category => "Réseau";

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
			CollectDohSettings(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			collectorReport.ErrorMessage = "DnsOverHttpsCollector fatal error: " + ex2.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectDohSettings(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey parametersKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters");
			if (parametersKey == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "DNS-over-HTTPS (DoH)",
					CurrentValue = "Clé registre introuvable",
					ExpectedValue = "Activé (EnableAutoDoh = 2)",
					Status = SecurityStatus.Info,
					Description = "La clé de configuration DNS n'est pas accessible.",
					Recommendation = "Vérifiez la configuration DNS du système.",
					Reference = "https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support"
				});
				return;
			}
			object enableAutoDohValue = parametersKey.GetValue("EnableAutoDoh");
			if (enableAutoDohValue == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "DNS-over-HTTPS (DoH)",
					CurrentValue = "Non configuré",
					ExpectedValue = "Activé (2)",
					Status = SecurityStatus.Warning,
					Description = "DNS-over-HTTPS n'est pas configuré. Les requêtes DNS circulent en clair.",
					Recommendation = "Activez DoH en définissant EnableAutoDoh = 2 pour chiffrer les requêtes DNS.",
					Reference = "https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support"
				});
			}
			else
			{
				int enableAutoDoh = Convert.ToInt32(enableAutoDohValue);
				string statusText = enableAutoDoh switch
				{
					0 => "Désactivé",
					1 => "Autorisé (fallback en clair)",
					2 => "Requis (DoH uniquement)",
					_ => $"Inconnu ({enableAutoDoh})",
				};
				SecurityStatus dohStatus = enableAutoDoh switch
				{
					2 => SecurityStatus.OK,
					1 => SecurityStatus.Info,
					_ => SecurityStatus.Warning,
				};
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "DNS-over-HTTPS (DoH)",
					CurrentValue = statusText,
					ExpectedValue = "Requis (DoH uniquement)",
					Status = dohStatus,
					Description = "État DoH: " + statusText + ". DoH chiffre les requêtes DNS pour protéger la vie privée.",
					// Correctif M9 : dohStatus est un SecurityStatus (enum). On compare à la valeur nommée
					// SecurityStatus.OK (= 0) au lieu du littéral int 0, pour une comparaison explicite et robuste.
					Recommendation = ((dohStatus != SecurityStatus.OK) ? "Configurez EnableAutoDoh = 2 pour forcer l'utilisation de DoH." : "Configuration optimale."),
					Reference = "https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support"
				});
			}
			object dohFlagsValue = parametersKey.GetValue("DohFlags");
			if (dohFlagsValue != null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "DoH — Flags",
					CurrentValue = (dohFlagsValue.ToString() ?? "N/A"),
					ExpectedValue = "Configuré",
					Status = SecurityStatus.Info,
					Description = $"DohFlags configuré: {dohFlagsValue}",
					Recommendation = "Consultez la documentation pour les flags DoH appropriés.",
					Reference = ""
				});
			}
			// R4 : réintégration du contrôle DoHPolicy (politique GPO machine), souvent le vrai levier
			// de déploiement. Ne duplique pas EnableAutoDoh (paramètre du service Dnscache) : DoHPolicy
			// est une stratégie sous Policies\Microsoft\Windows NT\DNSClient.
			// DWORD : 0/absent = non configuré, 2 = autorisé, 3 = requis/obligatoire.
			ct.ThrowIfCancellationRequested();
			using (RegistryKey dnsClientPolicyKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient"))
			{
				object doHPolicyValue = dnsClientPolicyKey?.GetValue("DoHPolicy");
				int doHPolicy = (doHPolicyValue != null) ? Convert.ToInt32(doHPolicyValue) : 0;
				string doHPolicyText = doHPolicy switch
				{
					2 => "Autorisé (DoH autorisé mais non imposé)",
					3 => "Requis (DoH obligatoire)",
					_ => "Non configuré",
				};
				SecurityStatus doHPolicyStatus = doHPolicy switch
				{
					3 => SecurityStatus.OK,
					2 => SecurityStatus.Info,
					_ => SecurityStatus.Info,
				};
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "DNS-over-HTTPS — Politique GPO (DoHPolicy)",
					CurrentValue = doHPolicyText,
					ExpectedValue = "Requis (3)",
					Status = doHPolicyStatus,
					Description = "État de la politique GPO machine DoHPolicy: " + doHPolicyText + ". Cette stratégie (Policies\\Microsoft\\Windows NT\\DNSClient) impose le comportement DoH sur l'ensemble du poste.",
					Recommendation = ((doHPolicy == 3) ? "Configuration optimale : DoH imposé par GPO." : ((doHPolicy == 2) ? "DoH autorisé par GPO mais non obligatoire. Définissez DoHPolicy = 3 pour rendre DoH requis." : "DoH non imposé par GPO. Définissez DoHPolicy = 3 (requis) pour forcer le chiffrement des requêtes DNS via GPO.")),
					Reference = "https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support"
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
				CheckName = "DNS-over-HTTPS — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier DoH: " + ex2.Message,
				Recommendation = "Vérifiez les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}
}
