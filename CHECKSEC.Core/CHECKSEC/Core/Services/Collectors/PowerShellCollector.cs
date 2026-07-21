using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class PowerShellCollector : ISecurityCollector
{
	private const string PsKey = "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell";

	private const string PsScriptBlockKey = "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging";

	private const string PsTranscriptionKey = "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription";

	private const string PsModuleLoggingKey = "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging";

	private const string PsExecutionPolicyKey = "SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell";

	public string Name => "Sécurité PowerShell";

	public string Category => "Scripts";

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
			CollectExecutionPolicy(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectScriptBlockLogging(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectTranscription(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectModuleLogging(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectConstrainedLanguage(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "PowerShellCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectExecutionPolicy(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey policyKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell");
			object enableScriptsValue = policyKey?.GetValue("EnableScripts");
			using RegistryKey shellIdKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell");
			string executionPolicy = shellIdKey?.GetValue("ExecutionPolicy")?.ToString() ?? "Non défini";
			SecurityStatus status;
			if (enableScriptsValue != null && Convert.ToInt32(enableScriptsValue) == 0)
			{
				executionPolicy = "Disabled (par GPO)";
				status = SecurityStatus.OK;
			}
			else
			{
				status = executionPolicy.ToLowerInvariant() switch
				{
					"restricted" => SecurityStatus.OK, 
					"allsigned" => SecurityStatus.OK, 
					"remotesigned" => SecurityStatus.Info, 
					"unrestricted" => SecurityStatus.Warning, 
					"bypass" => SecurityStatus.Critical, 
					_ => SecurityStatus.Info, 
				};
			}
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "PowerShell — Politique d'exécution",
				CurrentValue = executionPolicy,
				ExpectedValue = "AllSigned ou Restricted",
				Status = status,
				Description = "Politique d'exécution PowerShell: " + executionPolicy + ". Cette politique contrôle quels scripts PowerShell peuvent être exécutés.",
				Recommendation = ((status != 0) ? "Définissez la politique d'exécution à 'AllSigned' ou 'Restricted' via GPO." : "Configuration correcte."),
				Reference = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies"
			});
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
				CheckName = "PowerShell Execution Policy — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}

	private void CollectScriptBlockLogging(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey scriptBlockKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging");
			object scriptBlockLoggingValue = scriptBlockKey?.GetValue("EnableScriptBlockLogging");
			bool isScriptBlockLoggingEnabled = scriptBlockLoggingValue != null && Convert.ToInt32(scriptBlockLoggingValue) == 1;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "PowerShell — Script Block Logging",
				CurrentValue = (isScriptBlockLoggingEnabled ? "Activé" : "Désactivé"),
				ExpectedValue = "Activé",
				Status = ((!isScriptBlockLoggingEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = (isScriptBlockLoggingEnabled ? "Le Script Block Logging est activé. Tous les blocs de scripts exécutés sont journalisés." : "Le Script Block Logging est désactivé. Les scripts malveillants ne seront pas journalisés."),
				Recommendation = (isScriptBlockLoggingEnabled ? "Configuration correcte." : "Activez EnableScriptBlockLogging = 1 via GPO pour détecter les scripts malveillants."),
				Reference = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows"
			});
			object invocationLoggingValue = scriptBlockKey?.GetValue("EnableScriptBlockInvocationLogging");
			if (invocationLoggingValue != null)
			{
				bool isInvocationLoggingEnabled = Convert.ToInt32(invocationLoggingValue) == 1;
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "PowerShell — Script Block Invocation Logging",
					CurrentValue = (isInvocationLoggingEnabled ? "Activé" : "Désactivé"),
					ExpectedValue = "Activé",
					Status = ((!isInvocationLoggingEnabled) ? SecurityStatus.Info : SecurityStatus.OK),
					Description = "Journalisation des invocations de blocs de scripts (début/fin).",
					Recommendation = "Activez pour une traçabilité complète.",
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
				CheckName = "Script Block Logging — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}

	private void CollectTranscription(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey transcriptionKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription");
			object transcriptingValue = transcriptionKey?.GetValue("EnableTranscripting");
			bool isTranscriptionEnabled = transcriptingValue != null && Convert.ToInt32(transcriptingValue) == 1;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "PowerShell — Transcription",
				CurrentValue = (isTranscriptionEnabled ? "Activée" : "Désactivée"),
				ExpectedValue = "Activée",
				Status = ((!isTranscriptionEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = (isTranscriptionEnabled ? "La transcription PowerShell est activée. Toutes les commandes et sorties sont enregistrées." : "La transcription PowerShell est désactivée."),
				Recommendation = (isTranscriptionEnabled ? "Configuration correcte." : "Activez la transcription PowerShell pour enregistrer toute l'activité."),
				Reference = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows"
			});
			if (isTranscriptionEnabled)
			{
				string outputDirectory = transcriptionKey?.GetValue("OutputDirectory")?.ToString();
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "PowerShell — Répertoire de transcription",
					CurrentValue = (string.IsNullOrEmpty(outputDirectory) ? "Par défaut (profil utilisateur)" : outputDirectory),
					ExpectedValue = "Répertoire sécurisé centralisé",
					Status = SecurityStatus.Info,
					Description = "Répertoire de sortie: " + (string.IsNullOrEmpty(outputDirectory) ? "défaut" : outputDirectory),
					Recommendation = "Utilisez un répertoire centralisé et sécurisé avec accès restreint.",
					Reference = ""
				});
				object invocationHeaderValue = transcriptionKey?.GetValue("EnableInvocationHeader");
				if (invocationHeaderValue != null)
				{
					bool isInvocationHeaderEnabled = Convert.ToInt32(invocationHeaderValue) == 1;
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "PowerShell — En-têtes d'invocation",
						CurrentValue = (isInvocationHeaderEnabled ? "Activés" : "Désactivés"),
						ExpectedValue = "Activés",
						Status = ((!isInvocationHeaderEnabled) ? SecurityStatus.Info : SecurityStatus.OK),
						Description = "Les en-têtes d'invocation incluent l'horodatage de chaque commande.",
						Recommendation = "Activez pour une meilleure traçabilité.",
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
				CheckName = "Transcription — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}

	private void CollectModuleLogging(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey moduleLoggingKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging");
			object moduleLoggingValue = moduleLoggingKey?.GetValue("EnableModuleLogging");
			bool isModuleLoggingEnabled = moduleLoggingValue != null && Convert.ToInt32(moduleLoggingValue) == 1;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "PowerShell — Module Logging",
				CurrentValue = (isModuleLoggingEnabled ? "Activé" : "Désactivé"),
				ExpectedValue = "Activé",
				Status = ((!isModuleLoggingEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = (isModuleLoggingEnabled ? "Le module logging est activé. L'exécution des cmdlets est journalisée." : "Le module logging est désactivé."),
				Recommendation = (isModuleLoggingEnabled ? "Configuration correcte." : "Activez le module logging pour surveiller l'utilisation des cmdlets."),
				Reference = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows"
			});
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
				CheckName = "Module Logging — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}

	private void CollectConstrainedLanguage(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			string lockdownPolicy = Environment.GetEnvironmentVariable("__PSLockdownPolicy");
			bool isConstrainedLanguageEnabled = lockdownPolicy != null && lockdownPolicy != "0";
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "PowerShell — Constrained Language Mode",
				CurrentValue = (isConstrainedLanguageEnabled ? ("Activé (" + lockdownPolicy + ")") : "Désactivé (FullLanguage)"),
				ExpectedValue = "Activé (avec WDAC/AppLocker)",
				Status = ((!isConstrainedLanguageEnabled) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = (isConstrainedLanguageEnabled ? "PowerShell s'exécute en mode Constrained Language, limitant les fonctionnalités dangereuses." : "PowerShell s'exécute en mode FullLanguage. Toutes les fonctionnalités sont disponibles."),
				Recommendation = (isConstrainedLanguageEnabled ? "Configuration correcte." : "Envisagez d'activer CLM via WDAC ou AppLocker pour restreindre les fonctionnalités PowerShell dangereuses."),
				Reference = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes"
			});
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
				CheckName = "Constrained Language — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}
}
