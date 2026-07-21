using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur de durcissement de l'authentification domaine côté poste.
// Vérifie la signature LDAP client et documente le channel binding LDAP (ADV190023).
// Contextualise la pertinence via l'appartenance au domaine (Win32_ComputerSystem.PartOfDomain).
// Ces durcissements sont optionnels côté poste : statuts nuancés (Info / Warning), jamais Critical.
public class DomainAuthHardeningCollector : ISecurityCollector
{
	public string Name => "Durcissement authentification domaine";

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
			// On détermine d'abord le contexte domaine : il conditionne la pertinence des autres checks.
			bool partOfDomain = CollectDomainContext(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectLdapClientSigning(collectorReport.Results, partOfDomain, ct);
			ct.ThrowIfCancellationRequested();
			CollectLdapChannelBinding(collectorReport.Results, partOfDomain, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception exception)
		{
			collectorReport.ErrorMessage = "DomainAuthHardeningCollector fatal error: " + exception.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// Contexte domaine (Info) : indique si la machine est jointe à un domaine.
	// Renvoie true si jointe. Sur un poste non joint, on évite de sur-alerter.
	private bool CollectDomainContext(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		bool partOfDomain = false;
		string domainName = "(inconnu)";
		try
		{
			ManagementObjectSearcher searcher = new ManagementObjectSearcher(
				"SELECT Domain, PartOfDomain FROM Win32_ComputerSystem");
			try
			{
				foreach (ManagementObject csObject in searcher.Get())
				{
					ManagementObject disposableWmiObject = csObject;
					try
					{
						object partOfDomainValue = csObject["PartOfDomain"];
						if (partOfDomainValue != null && !(partOfDomainValue is DBNull))
						{
							partOfDomain = Convert.ToBoolean(partOfDomainValue);
						}
						domainName = csObject["Domain"]?.ToString() ?? "(inconnu)";
					}
					finally
					{
						((IDisposable)disposableWmiObject)?.Dispose();
					}
				}
			}
			finally
			{
				((IDisposable)searcher)?.Dispose();
			}
		}
		catch
		{
			// En cas d'échec WMI, on reste prudent : traité comme non joint (évite de sur-alerter).
			partOfDomain = false;
		}
		bool capturedPartOfDomain = partOfDomain;
		string capturedDomain = domainName;
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Contexte : appartenance au domaine",
			CurrentValue = (capturedPartOfDomain ? ("Joint au domaine : " + capturedDomain) : "Non joint à un domaine (groupe de travail)"),
			ExpectedValue = "Contexte informatif",
			Status = SecurityStatus.Info,
			Description = (capturedPartOfDomain
				? "Ce poste est joint au domaine '" + capturedDomain + "'. Les contrôles de durcissement de l'authentification LDAP (signature, channel binding) sont pertinents dans ce contexte."
				: "Ce poste n'est pas joint à un domaine Active Directory. Les contrôles LDAP ci-dessous sont peu pertinents dans ce contexte et sont fournis à titre informatif."),
			Recommendation = (capturedPartOfDomain
				? "Vérifier les paramètres de signature et de channel binding LDAP ci-dessous."
				: "Poste non joint à un domaine — les checks LDAP sont peu pertinents ; aucune action requise."),
			Reference = "https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server"
		});
		return partOfDomain;
	}

	// Signature LDAP client : HKLM\SYSTEM\CurrentControlSet\Services\LDAP\LDAPClientIntegrity.
	// 2 = requis (attendu) ; 1 = négociation ; 0 = aucune (Warning) ; absent = non configuré (Info).
	private void CollectLdapClientSigning(List<SecurityResult> results, bool partOfDomain, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		bool capturedPartOfDomain = partOfDomain;
		TryAdd(results, delegate
		{
			int integrity = RegInt("SYSTEM\\CurrentControlSet\\Services\\LDAP", "LDAPClientIntegrity");
			string currentValue;
			SecurityStatus status;
			string recommendation;
			switch (integrity)
			{
			case 2:
				// Signature requise : configuration la plus sûre.
				currentValue = "2 (signature requise)";
				status = SecurityStatus.OK;
				recommendation = "La signature LDAP client est requise — configuration conforme au durcissement.";
				break;
			case 1:
				// Négociation : acceptable mais non contraignant.
				currentValue = "1 (négociation)";
				status = SecurityStatus.Info;
				recommendation = "La signature LDAP client est en mode négociation. Pour un durcissement maximal, définir LDAPClientIntegrity = 2 (signature requise).";
				break;
			case 0:
				// Aucune signature : durcissement recommandé.
				currentValue = "0 (aucune signature)";
				status = SecurityStatus.Warning;
				recommendation = "La signature LDAP client est explicitement désactivée. Durcissement recommandé : définir HKLM\\SYSTEM\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity = 2 (signature requise).";
				break;
			default:
				// Absent : négociation par défaut, non configuré.
				currentValue = "Non configuré (négociation par défaut)";
				status = SecurityStatus.Info;
				recommendation = "La valeur n'est pas configurée : le client LDAP utilise la négociation par défaut. Pour un durcissement maximal, définir LDAPClientIntegrity = 2 (signature requise).";
				break;
			}
			// Sur un poste non joint, le durcissement est peu pertinent : on rétrograde le Warning en Info.
			if (!capturedPartOfDomain && status == SecurityStatus.Warning)
			{
				status = SecurityStatus.Info;
				recommendation = "Poste non joint à un domaine : ce durcissement est peu pertinent. " + recommendation;
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Signature LDAP client (LDAPClientIntegrity)",
				CurrentValue = currentValue,
				ExpectedValue = "2 (signature requise)",
				Status = status,
				Description = "LDAPClientIntegrity contrôle si le client LDAP exige la signature des communications avec les contrôleurs de domaine. La signature protège contre les attaques de type relais et intercepteur (man-in-the-middle) sur le trafic LDAP.",
				Recommendation = recommendation,
				Reference = "https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server"
			};
		});
	}

	// Channel binding LDAP : documenté en Info côté poste.
	// Le renforcement principal (LdapEnforceChannelBinding) se configure côté contrôleur de domaine.
	private void CollectLdapChannelBinding(List<SecurityResult> results, bool partOfDomain, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		bool capturedPartOfDomain = partOfDomain;
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Channel binding LDAP (ADV190023 — contexte)",
			CurrentValue = (capturedPartOfDomain
				? "Poste joint au domaine — renforcement appliqué côté contrôleur de domaine"
				: "Poste non joint — renforcement non applicable localement"),
			ExpectedValue = "LdapEnforceChannelBinding configuré sur les contrôleurs de domaine",
			Status = SecurityStatus.Info,
			Description = "Le channel binding LDAP (LDAP over TLS) protège contre les attaques par relais NTLM. Le renforcement principal se configure CÔTÉ CONTRÔLEUR DE DOMAINE via HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LdapEnforceChannelBinding (valeur 2 = requis). Sur un poste de travail, ce paramètre n'a pas d'effet local : ce contrôle est fourni à titre contextuel.",
			Recommendation = "Vérifier que LdapEnforceChannelBinding = 2 est appliqué sur tous les contrôleurs de domaine (voir avis Microsoft ADV190023). Aucune action locale n'est requise sur ce poste.",
			Reference = "https://msrc.microsoft.com/update-guide/vulnerability/ADV190023"
		});
	}

	// Lecture d'une valeur DWORD sous HKLM en vue Registry64.
	private static int RegInt(string path, string valueName, int def = -1)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			object value = subKey?.GetValue(valueName);
			return (value != null && !(value is DBNull)) ? Convert.ToInt32(value) : def;
		}
		catch
		{
			return def;
		}
	}

	private void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			SecurityResult result = factory();
			if (result != null)
			{
				results.Add(result);
			}
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier l'accès au registre et WMI, et exécuter en tant qu'administrateur.",
				Reference = ""
			});
		}
	}
}
