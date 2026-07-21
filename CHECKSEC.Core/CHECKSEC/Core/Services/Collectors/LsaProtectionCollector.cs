using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class LsaProtectionCollector : ISecurityCollector
{
	private const string LsaKey = "SYSTEM\\CurrentControlSet\\Control\\Lsa";

	public string Name => "Protection LSA";

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
			CollectLsaProtection(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectLsaAdditional(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "LsaProtectionCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectLsaProtection(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey lsaKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			if (lsaKey == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "LSA Protection (RunAsPPL)",
					CurrentValue = "Clé registre introuvable",
					ExpectedValue = "1 (activé)",
					Status = SecurityStatus.Warning,
					Description = "Impossible d'accéder à la clé LSA dans le registre.",
					Recommendation = "Vérifiez les permissions d'accès au registre.",
					Reference = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"
				});
				return;
			}
			object runAsPplRaw = lsaKey.GetValue("RunAsPPL");
			if (runAsPplRaw == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "LSA Protection (RunAsPPL)",
					CurrentValue = "Non configuré",
					ExpectedValue = "1 (activé)",
					Status = SecurityStatus.Warning,
					Description = "La protection LSA (PPL) n'est pas configurée. LSASS peut être ciblé par des outils comme Mimikatz.",
					Recommendation = "Activez RunAsPPL = 1 sous HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa pour protéger le processus LSASS.",
					Reference = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"
				});
			}
			else
			{
				int runAsPplLevel = Convert.ToInt32(runAsPplRaw);
				bool isProtected = runAsPplLevel == 1 || runAsPplLevel == 2;
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "LSA Protection (RunAsPPL)",
					CurrentValue = runAsPplLevel switch
					{
						2 => "Activé (sans UEFI lock)",
						1 => "Activé (UEFI lock)",
						_ => $"Désactivé ({runAsPplLevel})",
					},
					ExpectedValue = "1 (activé avec UEFI lock)",
					Status = ((!isProtected) ? SecurityStatus.Critical : SecurityStatus.OK),
					Description = (isProtected ? "LSASS s'exécute en tant que processus protégé (PPL). Les outils d'extraction de credentials sont bloqués." : "LSASS n'est PAS protégé. Un attaquant peut extraire les credentials avec Mimikatz."),
					Recommendation = (isProtected ? "Configuration correcte." : "URGENT: Activez RunAsPPL = 1 pour protéger LSASS contre l'extraction de credentials."),
					Reference = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"
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
				CheckName = "LSA Protection — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier la protection LSA: " + ex.Message,
				Recommendation = "Vérifiez les permissions d'accès.",
				Reference = ""
			});
		}
	}

	private void CollectLsaAdditional(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey lsaKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			if (lsaKey != null)
			{
				object disableRestrictedAdminRaw = lsaKey.GetValue("DisableRestrictedAdmin");
				if (disableRestrictedAdminRaw != null)
				{
					bool isRestrictedAdminEnabled = Convert.ToInt32(disableRestrictedAdminRaw) == 0;
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "Restricted Admin Mode",
						CurrentValue = (isRestrictedAdminEnabled ? "Activé" : "Désactivé"),
						ExpectedValue = "Activé (0)",
						Status = ((!isRestrictedAdminEnabled) ? SecurityStatus.Info : SecurityStatus.OK),
						Description = (isRestrictedAdminEnabled ? "Le mode Restricted Admin est activé. Les credentials ne sont pas envoyés au serveur distant lors de RDP." : "Le mode Restricted Admin est désactivé."),
						Recommendation = "Activez le mode Restricted Admin pour RDP (DisableRestrictedAdmin = 0).",
						Reference = "https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard"
					});
				}
				object lmCompatibilityRaw = lsaKey.GetValue("LmCompatibilityLevel");
				if (lmCompatibilityRaw != null)
				{
					int lmCompatibilityLevel = Convert.ToInt32(lmCompatibilityRaw);
					string lmCompatibilityDescription = lmCompatibilityLevel switch
					{
						0 => "LM & NTLM",
						1 => "LM & NTLM, NTLMv2 si négocié",
						2 => "NTLM uniquement",
						3 => "NTLMv2 uniquement",
						4 => "NTLMv2 uniquement, refuser LM",
						5 => "NTLMv2 uniquement, refuser LM & NTLM",
						_ => $"Inconnu ({lmCompatibilityLevel})",
					};
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "LM Compatibility Level",
						CurrentValue = $"{lmCompatibilityLevel} — {lmCompatibilityDescription}",
						ExpectedValue = "5 (NTLMv2 uniquement)",
						Status = ((lmCompatibilityLevel < 3) ? ((lmCompatibilityLevel >= 1) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
						Description = "Niveau de compatibilité LAN Manager: " + lmCompatibilityDescription,
						Recommendation = ((lmCompatibilityLevel < 5) ? "Augmentez LmCompatibilityLevel à 5 pour n'autoriser que NTLMv2." : "Configuration correcte."),
						Reference = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"
					});
				}
				object noLmHashRaw = lsaKey.GetValue("NoLMHash");
				if (noLmHashRaw != null)
				{
					int noLmHash = Convert.ToInt32(noLmHashRaw);
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "Stockage hash LM",
						CurrentValue = ((noLmHash == 1) ? "Désactivé (sécurisé)" : "Activé (dangereux)"),
						ExpectedValue = "Désactivé (NoLMHash = 1)",
						Status = ((noLmHash != 1) ? SecurityStatus.Critical : SecurityStatus.OK),
						Description = ((noLmHash == 1) ? "Le stockage des hash LM est désactivé. Les mots de passe ne sont pas stockés dans ce format faible." : "Les hash LM sont stockés! Ces hash sont trivialement crackables."),
						Recommendation = ((noLmHash != 1) ? "Définissez NoLMHash = 1 pour empêcher le stockage des hash LM." : "Configuration correcte."),
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
				CheckName = "LSA Additional — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur lors de la vérification des paramètres LSA additionnels: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}
}
