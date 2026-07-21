using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class UacDetailCollector : ISecurityCollector
{
	private const string UacKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

	public string Name => "UAC Détaillé";

	public string Category => "Contrôle d'Accès";

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
			CollectUacSettings(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "UacDetailCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectUacSettings(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey systemPolicyKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
			if (systemPolicyKey == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "UAC — Configuration",
					CurrentValue = "Clé registre introuvable",
					ExpectedValue = "Configuré",
					Status = SecurityStatus.Warning,
					Description = "Impossible d'accéder à la clé de configuration UAC.",
					Recommendation = "Vérifiez les permissions d'accès au registre.",
					Reference = "https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/"
				});
				return;
			}
			object enableLuaValue = systemPolicyKey.GetValue("EnableLUA");
			if (enableLuaValue != null)
			{
				int enableLua = Convert.ToInt32(enableLuaValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "UAC — EnableLUA",
					CurrentValue = ((enableLua == 1) ? "Activé" : "DÉSACTIVÉ"),
					ExpectedValue = "Activé (1)",
					Status = ((enableLua != 1) ? SecurityStatus.Critical : SecurityStatus.OK),
					Description = ((enableLua == 1) ? "UAC est activé. Les applications s'exécutent avec des privilèges limités par défaut." : "CRITIQUE: UAC est désactivé! Toutes les applications s'exécutent avec les privilèges complets."),
					Recommendation = ((enableLua != 1) ? "URGENT: Réactivez UAC (EnableLUA = 1). La désactivation d'UAC est un risque majeur." : "Configuration correcte."),
					Reference = "https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/"
				});
			}
			object adminPromptValue = systemPolicyKey.GetValue("ConsentPromptBehaviorAdmin");
			if (adminPromptValue != null)
			{
				int adminPromptBehavior = Convert.ToInt32(adminPromptValue);
				string adminPromptLabel = adminPromptBehavior switch
				{
					0 => "Élever sans demander (dangereux)",
					1 => "Demander credentials sur bureau sécurisé",
					2 => "Demander consentement sur bureau sécurisé",
					3 => "Demander credentials",
					4 => "Demander consentement",
					5 => "Demander consentement pour binaires non-Windows",
					_ => $"Inconnu ({adminPromptBehavior})",
				};
				SecurityStatus computedStatus;
				switch (adminPromptBehavior)
				{
				case 0:
					computedStatus = SecurityStatus.Critical;
					break;
				case 1:
				case 2:
					computedStatus = SecurityStatus.OK;
					break;
				case 5:
					computedStatus = SecurityStatus.OK;
					break;
				case 3:
				case 4:
					computedStatus = SecurityStatus.Warning;
					break;
				default:
					computedStatus = SecurityStatus.Warning;
					break;
				}
				SecurityStatus adminPromptStatus = computedStatus;
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "UAC — Comportement Admin",
					CurrentValue = adminPromptLabel,
					ExpectedValue = "Demander credentials sur bureau sécurisé (1) ou consentement (2)",
					Status = adminPromptStatus,
					Description = "Comportement de l'invite UAC pour les administrateurs: " + adminPromptLabel,
					Recommendation = ((adminPromptBehavior == 0) ? "URGENT: Ne jamais utiliser l'élévation silencieuse. Définissez ConsentPromptBehaviorAdmin à 1 ou 2." : ((adminPromptStatus != 0) ? "Configurez UAC pour demander les credentials sur le bureau sécurisé (1)." : "Configuration correcte.")),
					Reference = "https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/"
				});
			}
			object userPromptValue = systemPolicyKey.GetValue("ConsentPromptBehaviorUser");
			if (userPromptValue != null)
			{
				int userPromptBehavior = Convert.ToInt32(userPromptValue);
				string userPromptLabel = userPromptBehavior switch
				{
					0 => "Refuser automatiquement",
					1 => "Demander credentials sur bureau sécurisé",
					3 => "Demander credentials",
					_ => $"Inconnu ({userPromptBehavior})",
				};
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "UAC — Comportement Utilisateur",
					CurrentValue = userPromptLabel,
					ExpectedValue = "Refuser automatiquement (0) ou Demander credentials (1)",
					Status = ((userPromptBehavior > 1) ? SecurityStatus.Info : SecurityStatus.OK),
					Description = "Comportement UAC pour les utilisateurs standard: " + userPromptLabel,
					Recommendation = "Configurez selon la politique de sécurité de l'organisation.",
					Reference = ""
				});
			}
			object filterAdminTokenValue = systemPolicyKey.GetValue("FilterAdministratorToken");
			if (filterAdminTokenValue != null)
			{
				int filterAdminToken = Convert.ToInt32(filterAdminTokenValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "UAC — FilterAdministratorToken",
					CurrentValue = ((filterAdminToken == 1) ? "Activé" : "Désactivé"),
					ExpectedValue = "Activé (1)",
					Status = ((filterAdminToken != 1) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = ((filterAdminToken == 1) ? "Le filtrage du token administrateur intégré est activé." : "Le compte Administrateur intégré n'est pas soumis au filtrage UAC."),
					Recommendation = ((filterAdminToken != 1) ? "Activez FilterAdministratorToken pour soumettre le compte Administrateur intégré à UAC." : "Configuration correcte."),
					Reference = ""
				});
			}
			object installerDetectionValue = systemPolicyKey.GetValue("EnableInstallerDetection");
			if (installerDetectionValue != null)
			{
				int installerDetection = Convert.ToInt32(installerDetectionValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "UAC — Détection d'installateur",
					CurrentValue = ((installerDetection == 1) ? "Activée" : "Désactivée"),
					ExpectedValue = "Activée (1)",
					Status = ((installerDetection != 1) ? SecurityStatus.Info : SecurityStatus.OK),
					Description = ((installerDetection == 1) ? "La détection d'installateur UAC est activée." : "La détection d'installateur UAC est désactivée."),
					Recommendation = "Gardez la détection d'installateur activée.",
					Reference = ""
				});
			}
			object secureDesktopValue = systemPolicyKey.GetValue("PromptOnSecureDesktop");
			if (secureDesktopValue != null)
			{
				int secureDesktopPrompt = Convert.ToInt32(secureDesktopValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "UAC — Bureau sécurisé",
					CurrentValue = ((secureDesktopPrompt == 1) ? "Activé" : "Désactivé"),
					ExpectedValue = "Activé (1)",
					Status = ((secureDesktopPrompt != 1) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = ((secureDesktopPrompt == 1) ? "Les invites UAC s'affichent sur le bureau sécurisé, empêchant les attaques par UI spoofing." : "Le bureau sécurisé est désactivé. Les invites UAC peuvent être usurpées par des malwares."),
					Recommendation = ((secureDesktopPrompt != 1) ? "Activez PromptOnSecureDesktop = 1 pour afficher les invites UAC sur le bureau sécurisé." : "Configuration correcte."),
					Reference = ""
				});
			}
			object virtualizationValue = systemPolicyKey.GetValue("EnableVirtualization");
			if (virtualizationValue != null)
			{
				int virtualization = Convert.ToInt32(virtualizationValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "UAC — Virtualisation",
					CurrentValue = ((virtualization == 1) ? "Activée" : "Désactivée"),
					ExpectedValue = "Activée (1)",
					Status = ((virtualization != 1) ? SecurityStatus.Info : SecurityStatus.OK),
					Description = ((virtualization == 1) ? "La virtualisation UAC est activée. Les écritures dans les emplacements protégés sont redirigées." : "La virtualisation UAC est désactivée."),
					Recommendation = "Gardez la virtualisation UAC activée pour la compatibilité des applications héritées.",
					Reference = ""
				});
			}
			object validateSignaturesValue = systemPolicyKey.GetValue("ValidateAdminCodeSignatures");
			if (validateSignaturesValue != null)
			{
				int validateSignatures = Convert.ToInt32(validateSignaturesValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "UAC — Validation signatures admin",
					CurrentValue = ((validateSignatures == 1) ? "Activée" : "Désactivée"),
					ExpectedValue = "Activée (1)",
					Status = ((validateSignatures != 1) ? SecurityStatus.Info : SecurityStatus.OK),
					Description = ((validateSignatures == 1) ? "UAC valide les signatures PKI des applications qui demandent une élévation." : "UAC ne vérifie pas les signatures des applications demandant une élévation."),
					Recommendation = ((validateSignatures != 1) ? "Activez la validation des signatures pour renforcer la sécurité UAC." : "Configuration correcte."),
					Reference = ""
				});
			}
			object secureUiaPathsValue = systemPolicyKey.GetValue("EnableSecureUIAPaths");
			if (secureUiaPathsValue != null)
			{
				int secureUiaPaths = Convert.ToInt32(secureUiaPathsValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "UAC — Chemins UIA sécurisés",
					CurrentValue = ((secureUiaPaths == 1) ? "Activé" : "Désactivé"),
					ExpectedValue = "Activé (1)",
					Status = ((secureUiaPaths != 1) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = ((secureUiaPaths == 1) ? "Seules les applications UIA lancées depuis des emplacements sécurisés peuvent s'élever." : "Les chemins UIA sécurisés ne sont pas appliqués."),
					Recommendation = ((secureUiaPaths != 1) ? "Activez EnableSecureUIAPaths pour empêcher les attaques UIA." : "Configuration correcte."),
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
				CheckName = "UAC — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier la configuration UAC: " + ex.Message,
				Recommendation = "Vérifiez les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}
}
