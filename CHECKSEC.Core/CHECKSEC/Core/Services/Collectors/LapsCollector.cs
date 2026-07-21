using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class LapsCollector : ISecurityCollector
{
	private const string LegacyLapsKey = "SOFTWARE\\Policies\\Microsoft Services\\AdmPwd";

	private const string WindowsLapsKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS\\Config";

	public string Name => "LAPS";

	public string Category => "Gestion des Comptes";

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
			CollectLegacyLaps(collectorReport.Results, ct);
			// H3 : le LAPS natif (Windows LAPS) est couvert par WindowsLapsCollector, qui lit
			// le bon chemin (SOFTWARE\Microsoft\Policies\LAPS). L'ancien CollectWindowsLaps lisait
			// un chemin erroné (…\CurrentVersion\LAPS\Config) → faux « non configuré ». Retiré.
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "LapsCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectLegacyLaps(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey admPwdKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft Services\\AdmPwd");
			if (admPwdKey == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "LAPS Legacy (AdmPwd)",
					CurrentValue = "Non installé",
					ExpectedValue = "Activé",
					Status = SecurityStatus.Info,
					Description = "Microsoft LAPS (Legacy) n'est pas installé ou configuré.",
					Recommendation = "Envisagez d'utiliser Windows LAPS (intégré à Windows) pour gérer les mots de passe admin locaux.",
					Reference = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"
				});
				return;
			}
			object admPwdEnabledValue = admPwdKey.GetValue("AdmPwdEnabled");
			bool isEnabled = admPwdEnabledValue != null && Convert.ToInt32(admPwdEnabledValue) == 1;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "LAPS Legacy — AdmPwdEnabled",
				CurrentValue = (isEnabled ? "Activé" : "Désactivé"),
				ExpectedValue = "Activé",
				Status = ((!isEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = (isEnabled ? "LAPS Legacy est activé. Les mots de passe admin locaux sont gérés automatiquement." : "LAPS Legacy est installé mais désactivé."),
				Recommendation = (isEnabled ? "Configuration correcte." : "Activez LAPS pour la rotation automatique des mots de passe admin locaux."),
				Reference = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"
			});
			object passwordComplexityValue = admPwdKey.GetValue("PasswordComplexity");
			if (passwordComplexityValue != null)
			{
				int passwordComplexity = Convert.ToInt32(passwordComplexityValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "LAPS Legacy — Complexité mot de passe",
					CurrentValue = passwordComplexity.ToString(),
					ExpectedValue = "4 (lettres majuscules/minuscules, chiffres, caractères spéciaux)",
					Status = ((passwordComplexity < 3) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = $"Niveau de complexité des mots de passe LAPS: {passwordComplexity}",
					Recommendation = "Utilisez une complexité de 4 pour une sécurité maximale.",
					Reference = ""
				});
			}
			object passwordLengthValue = admPwdKey.GetValue("PasswordLength");
			if (passwordLengthValue != null)
			{
				int passwordLength = Convert.ToInt32(passwordLengthValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "LAPS Legacy — Longueur mot de passe",
					CurrentValue = $"{passwordLength} caractères",
					ExpectedValue = "≥ 14 caractères",
					Status = ((passwordLength < 14) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = $"Longueur configurée: {passwordLength} caractères.",
					Recommendation = ((passwordLength < 14) ? "Augmentez la longueur minimale à 14 caractères." : "Configuration correcte."),
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
				CheckName = "LAPS Legacy — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier LAPS Legacy: " + ex.Message,
				Recommendation = "Vérifiez les permissions d'accès.",
				Reference = ""
			});
		}
	}

	private void CollectWindowsLaps(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey lapsConfigKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS\\Config");
			if (lapsConfigKey == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Windows LAPS",
					CurrentValue = "Non configuré",
					ExpectedValue = "Configuré",
					Status = SecurityStatus.Warning,
					Description = "Windows LAPS n'est pas configuré sur cette machine.",
					Recommendation = "Configurez Windows LAPS via Intune ou GPO pour gérer les mots de passe admin locaux.",
					Reference = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"
				});
				return;
			}
			object backupDirectoryValue = lapsConfigKey.GetValue("BackupDirectory");
			if (backupDirectoryValue != null)
			{
				int backupDirectory = Convert.ToInt32(backupDirectoryValue);
				string backupDirectoryLabel = backupDirectory switch
				{
					0 => "Désactivé",
					1 => "Azure AD",
					2 => "Active Directory",
					_ => $"Inconnu ({backupDirectory})",
				};
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Windows LAPS — Répertoire de sauvegarde",
					CurrentValue = backupDirectoryLabel,
					ExpectedValue = "Azure AD ou Active Directory",
					Status = ((backupDirectory <= 0) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = "Le mot de passe est sauvegardé dans: " + backupDirectoryLabel,
					Recommendation = ((backupDirectory == 0) ? "Configurez une destination de sauvegarde." : "Configuration correcte."),
					Reference = ""
				});
			}
			object passwordAgeDaysValue = lapsConfigKey.GetValue("PasswordAgeDays");
			if (passwordAgeDaysValue != null)
			{
				int passwordAgeDays = Convert.ToInt32(passwordAgeDaysValue);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Windows LAPS — Âge du mot de passe",
					CurrentValue = $"{passwordAgeDays} jours",
					ExpectedValue = "≤ 30 jours",
					Status = ((passwordAgeDays > 30) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = $"Le mot de passe est renouvelé tous les {passwordAgeDays} jours.",
					Recommendation = ((passwordAgeDays > 30) ? "Réduisez la durée de vie du mot de passe à 30 jours maximum." : "Configuration correcte."),
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
				CheckName = "Windows LAPS — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier Windows LAPS: " + ex.Message,
				Recommendation = "Vérifiez les permissions d'accès.",
				Reference = ""
			});
		}
	}
}
