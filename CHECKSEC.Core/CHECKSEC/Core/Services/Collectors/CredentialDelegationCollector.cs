using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class CredentialDelegationCollector : ISecurityCollector
{
	private const string CredDelegKey = "SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation";

	private const string CredSspKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters";

	public string Name => "Délégation de Credentials";

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
			CollectCredentialDelegation(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectCredSsp(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectRemoteCredGuard(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			collectorReport.ErrorMessage = "CredentialDelegationCollector fatal error: " + ex2.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectCredentialDelegation(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey credDelegKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation");
			if (credDelegKey == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Délégation de credentials",
					CurrentValue = "Non configurée (GPO)",
					ExpectedValue = "Configurée et restreinte",
					Status = SecurityStatus.Info,
					Description = "La politique de délégation de credentials n'est pas configurée via GPO.",
					Recommendation = "Configurez les politiques de délégation pour contrôler la transmission des credentials.",
					Reference = "https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard"
				});
				return;
			}
			object allowDefaultValue = credDelegKey.GetValue("AllowDefaultCredentials");
			if (allowDefaultValue != null)
			{
				int allowDefault = Convert.ToInt32(allowDefaultValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Délégation — Credentials par défaut",
					CurrentValue = ((allowDefault == 1) ? "Autorisée" : "Bloquée"),
					ExpectedValue = "Bloquée (0)",
					Status = ((allowDefault != 0) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = ((allowDefault == 1) ? "La délégation des credentials par défaut est autorisée." : "La délégation des credentials par défaut est bloquée."),
					Recommendation = ((allowDefault == 1) ? "Restreignez la délégation des credentials par défaut." : "Configuration correcte."),
					Reference = ""
				});
			}
			object allowFreshValue = credDelegKey.GetValue("AllowFreshCredentials");
			if (allowFreshValue != null)
			{
				int allowFresh = Convert.ToInt32(allowFreshValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Délégation — Fresh Credentials",
					CurrentValue = ((allowFresh == 1) ? "Autorisée" : "Bloquée"),
					ExpectedValue = "Contrôlée",
					Status = ((allowFresh != 0) ? SecurityStatus.Info : SecurityStatus.OK),
					Description = ((allowFresh == 1) ? "La délégation des credentials fraîches est autorisée." : "La délégation des credentials fraîches est bloquée."),
					Recommendation = "Contrôlez la délégation des fresh credentials selon vos besoins.",
					Reference = ""
				});
			}
			object allowSavedValue = credDelegKey.GetValue("AllowSavedCredentials");
			if (allowSavedValue != null)
			{
				int allowSaved = Convert.ToInt32(allowSavedValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Délégation — Credentials sauvegardées",
					CurrentValue = ((allowSaved == 1) ? "Autorisée" : "Bloquée"),
					ExpectedValue = "Bloquée (0)",
					Status = ((allowSaved != 0) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = ((allowSaved == 1) ? "La délégation des credentials sauvegardées est autorisée." : "La délégation des credentials sauvegardées est bloquée."),
					Recommendation = ((allowSaved == 1) ? "Bloquez la délégation des credentials sauvegardées pour limiter les risques." : "Configuration correcte."),
					Reference = ""
				});
			}
			object restrictedRemoteAdminValue = credDelegKey.GetValue("RestrictedRemoteAdministration");
			if (restrictedRemoteAdminValue != null)
			{
				int restrictedRemoteAdmin = Convert.ToInt32(restrictedRemoteAdminValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Restricted Remote Administration",
					CurrentValue = ((restrictedRemoteAdmin == 1) ? "Activée" : "Désactivée"),
					ExpectedValue = "Activée (1)",
					Status = ((restrictedRemoteAdmin != 1) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = ((restrictedRemoteAdmin == 1) ? "L'administration distante restreinte est activée." : "L'administration distante restreinte n'est pas activée."),
					Recommendation = ((restrictedRemoteAdmin != 1) ? "Activez l'administration distante restreinte pour protéger les credentials." : "Configuration correcte."),
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
				CheckName = "Credential Delegation — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex2.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}

	private void CollectCredSsp(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey credSspKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters");
			object encryptionOracleValue = credSspKey?.GetValue("AllowEncryptionOracle");
			if (encryptionOracleValue != null)
			{
				int encryptionOracle = Convert.ToInt32(encryptionOracleValue);
				string statusText = encryptionOracle switch
				{
					0 => "Force Updated Clients (sécurisé)",
					1 => "Mitigated",
					2 => "Vulnerable (dangereux)",
					_ => $"Inconnu ({encryptionOracle})",
				};
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "CredSSP — AllowEncryptionOracle",
					CurrentValue = statusText,
					ExpectedValue = "Force Updated Clients (0)",
					Status = encryptionOracle switch
					{
						1 => SecurityStatus.Warning,
						0 => SecurityStatus.OK,
						_ => SecurityStatus.Critical,
					},
					Description = "CredSSP Encryption Oracle Remediation: " + statusText + ". " + ((encryptionOracle == 2) ? "DANGER: Le système est vulnérable aux attaques CredSSP." : ""),
					Recommendation = ((encryptionOracle != 0) ? "Définissez AllowEncryptionOracle = 0 pour forcer les clients mis à jour." : "Configuration correcte."),
					Reference = "https://support.microsoft.com/en-us/help/4093492/credssp-updates-for-cve-2018-0886"
				});
			}
			else
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "CredSSP — AllowEncryptionOracle",
					CurrentValue = "Non configuré (défaut système)",
					ExpectedValue = "Force Updated Clients (0)",
					Status = SecurityStatus.Info,
					Description = "Le paramètre CredSSP AllowEncryptionOracle utilise la valeur par défaut du système.",
					Recommendation = "Vérifiez que les mises à jour CredSSP sont installées.",
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
				CheckName = "CredSSP — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex2.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}

	private void CollectRemoteCredGuard(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey lsaKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			object disableRestrictedAdminValue = lsaKey?.GetValue("DisableRestrictedAdmin");
			bool isEnabled = disableRestrictedAdminValue != null && Convert.ToInt32(disableRestrictedAdminValue) == 0;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Remote Credential Guard",
				CurrentValue = (isEnabled ? "Activé" : ((disableRestrictedAdminValue == null) ? "Non configuré" : "Désactivé")),
				ExpectedValue = "Activé",
				Status = ((!isEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = (isEnabled ? "Remote Credential Guard est activé. Les credentials ne sont pas envoyés au serveur distant." : "Remote Credential Guard n'est pas activé. Les credentials peuvent être exposés lors des connexions distantes."),
				Recommendation = (isEnabled ? "Configuration correcte." : "Activez Remote Credential Guard (DisableRestrictedAdmin = 0) pour protéger les credentials."),
				Reference = "https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard"
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
				CheckName = "Remote Credential Guard — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex2.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}
}
