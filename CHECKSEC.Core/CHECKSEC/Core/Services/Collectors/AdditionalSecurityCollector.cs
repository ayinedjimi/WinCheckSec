using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services.Helpers;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class AdditionalSecurityCollector : ISecurityCollector
{
	public string Name => "Sécurité Additionnelle";

	public string Category => "Configuration Système";

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
			CollectPowerShellSecurity(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectCredentialSecurity(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectScriptExecution(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectWindowsUpdateSecurity(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectMemoryCpuSecurity(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectServicesSecurity(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectNetworkSecurityAdditional(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectAntimalwareSecurity(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectHardwareSecurityAdditional(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			collectorReport.ErrorMessage = "AdditionalSecurityCollector fatal error: " + ex2.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectPowerShellSecurity(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string machinePolicy = RegString("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell", "ExecutionPolicy");
			string userPolicy = RegString("HKCU", "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell", "ExecutionPolicy");
			string effectivePolicy = machinePolicy ?? userPolicy ?? "Not configured (default: Restricted)";
			bool isUnsafe = string.Equals(effectivePolicy, "Unrestricted", StringComparison.OrdinalIgnoreCase) || string.Equals(effectivePolicy, "Bypass", StringComparison.OrdinalIgnoreCase);
			bool isSafe = string.Equals(effectivePolicy, "AllSigned", StringComparison.OrdinalIgnoreCase) || string.Equals(effectivePolicy, "RemoteSigned", StringComparison.OrdinalIgnoreCase);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "PowerShell: Execution Policy (GPO)",
				CurrentValue = "Machine: " + (machinePolicy ?? "Not set") + ", User: " + (userPolicy ?? "Not set"),
				ExpectedValue = "AllSigned ou RemoteSigned",
				Status = (isUnsafe ? SecurityStatus.Critical : ((!isSafe) ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = "La stratégie d'exécution PowerShell contrôle quels scripts peuvent être exécutés. 'Unrestricted' ou 'Bypass' permettent l'exécution de tout script, y compris malveillants. 'AllSigned' exige une signature numérique pour tous les scripts.",
				Recommendation = (isUnsafe ? "Définir la stratégie d'exécution PowerShell sur 'AllSigned' ou 'RemoteSigned' via GPO : Computer Configuration > Windows Settings > Administrative Templates > Windows Components > Windows PowerShell > Turn on Script Execution." : (isSafe ? "La stratégie d'exécution PowerShell est correctement configurée." : "Configurer la stratégie d'exécution PowerShell via GPO pour limiter l'exécution de scripts non signés.")),
				Reference = "https://docs.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int scriptBlockLogging = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", "EnableScriptBlockLogging");
			bool isEnabled = scriptBlockLogging == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "PowerShell: ScriptBlock Logging",
				CurrentValue = ((scriptBlockLogging == -1) ? "Non configuré (désactivé par défaut)" : scriptBlockLogging.ToString()),
				ExpectedValue = "1 (Activé)",
				Status = ((!isEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "La journalisation ScriptBlock enregistre le contenu de tous les blocs de script PowerShell dans le journal d'événements Windows (ID 4104). Essentiel pour la détection des attaques basées sur PowerShell, notamment l'obfuscation et les charges utiles malveillantes.",
				Recommendation = (isEnabled ? "La journalisation ScriptBlock PowerShell est activée." : "Activer via GPO : Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging. Définir HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging = 1."),
				Reference = "https://docs.microsoft.com/powershell/scripting/windows-powershell/wmf/whats-new/script-logging"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int moduleLogging = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging", "EnableModuleLogging");
			bool isEnabled = moduleLogging == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "PowerShell: Module Logging",
				CurrentValue = ((moduleLogging == -1) ? "Non configuré (désactivé par défaut)" : moduleLogging.ToString()),
				ExpectedValue = "1 (Activé)",
				Status = ((!isEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "La journalisation des modules PowerShell enregistre l'exécution de toutes les commandes PowerShell, incluant les noms de modules et les paramètres. Permet de tracer l'activité PowerShell des attaquants même lorsqu'ils utilisent des modules importés.",
				Recommendation = (isEnabled ? "La journalisation des modules PowerShell est activée." : "Activer via GPO : Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging. Définir HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\EnableModuleLogging = 1."),
				Reference = "https://docs.microsoft.com/powershell/scripting/windows-powershell/wmf/whats-new/script-logging"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int transcription = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription", "EnableTranscripting");
			bool isEnabled = transcription == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "PowerShell: Transcription",
				CurrentValue = ((transcription == -1) ? "Non configuré (désactivé par défaut)" : transcription.ToString()),
				ExpectedValue = "1 (Activé pour haute sécurité)",
				Status = ((!isEnabled) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "La transcription PowerShell enregistre toutes les entrées et sorties de chaque session PowerShell dans un fichier texte. Utile pour les enquêtes forensiques et la conformité. Recommandé dans les environnements à haute sécurité.",
				Recommendation = (isEnabled ? "La transcription PowerShell est activée." : "Pour les environnements haute sécurité, activer via GPO : Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Transcription."),
				Reference = "https://docs.microsoft.com/powershell/scripting/windows-powershell/wmf/whats-new/script-logging"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			RegInt("HKLM", "SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine", "PSCompatibleVersion");
			bool v2Installed = false;
			try
			{
				ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT InstallState FROM Win32_OptionalFeature WHERE Name='MicrosoftWindowsPowerShellV2Root'");
				try
				{
					foreach (ManagementObject feature in searcher.Get())
					{
						ManagementObject mo = feature;
						try
						{
							object installState = feature["InstallState"];
							if (installState != null && !(installState is DBNull))
							{
								v2Installed = Convert.ToInt32(installState) == 1;
							}
						}
						finally
						{
							((IDisposable)mo)?.Dispose();
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
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "PowerShell v2 (risque de contournement)",
				CurrentValue = (v2Installed ? "Installé (potentiellement actif)" : "Non détecté via WMI"),
				ExpectedValue = "Désactivé/Non installé",
				Status = (v2Installed ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "PowerShell v2 ne prend pas en charge les fonctions de sécurité modernes (AMSI, ScriptBlock Logging, Constrained Language Mode). Les attaquants peuvent l'utiliser pour contourner les contrôles de sécurité en invoquant 'powershell -version 2'.",
				Recommendation = (v2Installed ? "Désactiver PowerShell v2 via : Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root (PowerShell admin) ou via Panneau de configuration > Programmes > Activer ou désactiver des fonctionnalités Windows." : "PowerShell v2 ne semble pas installé. Vérifier régulièrement via : Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root"),
				Reference = "https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/"
			};
		});
		// R7/M3 : couverture Constrained Language Mode (CLM), en compensation du retrait du PowerShellCollector.
		// On lit le REGISTRE (et NON la variable d'environnement du process, qui donnerait un faux négatif) :
		// __PSLockdownPolicy peut être stocké en REG_SZ ou REG_DWORD ; RegString renvoie sa représentation
		// texte dans les deux cas. Valeur « 4 » = ConstrainedLanguage forcé au niveau système.
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string lockdownPolicy = RegString("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "__PSLockdownPolicy");
			bool clmForced = string.Equals(lockdownPolicy?.Trim(), "4", StringComparison.OrdinalIgnoreCase);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "PowerShell: Constrained Language Mode",
				CurrentValue = $"__PSLockdownPolicy={lockdownPolicy ?? "Non défini"}",
				ExpectedValue = "4 (ConstrainedLanguage forcé globalement)",
				Status = (clmForced ? SecurityStatus.OK : SecurityStatus.Info),
				Description = "Le mode de langage restreint (Constrained Language Mode) limite l'accès aux API sensibles (COM, .NET, appels Win32) depuis PowerShell, réduisant fortement la surface d'attaque des scripts malveillants. Il est le plus souvent appliqué via WDAC/AppLocker ; la valeur registre __PSLockdownPolicy=4 le force au niveau système.",
				Recommendation = (clmForced ? "CLM forcé globalement (__PSLockdownPolicy=4)." : "Langage complet (CLM non forcé globalement — généralement appliqué via WDAC/AppLocker, voir Application Control)."),
				Reference = "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_modes"
			};
		});
	}

	private void CollectCredentialSecurity(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int useLogonCredential = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential");
			bool storesPlaintext = useLogonCredential == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "WDigest: Stockage en clair des mots de passe",
				CurrentValue = ((useLogonCredential == -1) ? "Non configuré (0 par défaut sur Windows 8.1+)" : useLogonCredential.ToString()),
				ExpectedValue = "0 (désactivé) ou non configuré",
				Status = (storesPlaintext ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "CRITIQUE : WDigest UseLogonCredential=1 force Windows à stocker les mots de passe en texte clair dans la mémoire LSASS. Mimikatz et outils similaires peuvent extraire ces mots de passe directement. Cette valeur est parfois activée par des attaquants pour faciliter le mouvement latéral.",
				Recommendation = (storesPlaintext ? "URGENT : Définir HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential = 0 immédiatement. Vérifier si cette valeur a été modifiée par un attaquant. Changer tous les mots de passe des utilisateurs concernés." : "WDigest est correctement configuré. Les mots de passe ne sont pas stockés en clair."),
				Reference = "https://docs.microsoft.com/security-updates/securityadvisories/2014/2871997"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string cachedCountText = RegString("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "CachedLogonsCount");
			int cachedLogonsCount = -1;
			if (cachedCountText != null && int.TryParse(cachedCountText, out var parsedCount))
			{
				cachedLogonsCount = parsedCount;
			}
			bool isSecure = cachedLogonsCount == 0 || cachedLogonsCount == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Identifiants mis en cache (CachedLogonsCount)",
				CurrentValue = (cachedCountText ?? "Non configuré (défaut : 10)"),
				ExpectedValue = "0 ou 1 pour haute sécurité",
				Status = ((cachedLogonsCount > 5 || cachedLogonsCount == -1) ? SecurityStatus.Warning : ((cachedLogonsCount > 1) ? SecurityStatus.Info : SecurityStatus.OK)),
				Description = "Windows met en cache les identifiants de connexion pour permettre la connexion hors-ligne. Ces identifiants mis en cache peuvent être extraits par des attaquants disposant d'un accès physique ou administrateur au système (attaque 'Pass-the-Cache'). La valeur par défaut est 10.",
				Recommendation = (isSecure ? "Limite de mise en cache des identifiants configurée pour haute sécurité." : "Pour les systèmes hautement sensibles, définir HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount = 0 ou 1. Attention : valeur 0 empêche toute connexion hors-ligne."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/interactive-logon-number-of-previous-logons-to-cache"
			};
		});
	}

	private void CollectScriptExecution(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int policySetting = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Script Host\\Settings", "Enabled");
			int legacySetting = RegInt("HKLM", "SOFTWARE\\Microsoft\\Windows Script Host\\Settings", "Enabled");
			bool isDisabled = policySetting == 0 || legacySetting == 0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows Script Host (WSH) — désactivé",
				CurrentValue = "Policy: " + ((policySetting == -1) ? "Non configuré" : policySetting.ToString()) + ", Legacy: " + ((legacySetting == -1) ? "Non configuré" : legacySetting.ToString()),
				ExpectedValue = "0 (désactivé) sur au moins une clé",
				Status = ((!isDisabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Windows Script Host (WSH) permet l'exécution de scripts VBScript et JScript directement depuis l'explorateur ou la ligne de commande. Vecteur d'attaque courant pour les logiciels malveillants distribués via pièces jointes email (fichiers .vbs, .js, .wsf). La désactivation de WSH réduit significativement la surface d'attaque.",
				Recommendation = (isDisabled ? "Windows Script Host est désactivé — bonne configuration." : "Désactiver WSH via GPO : définir HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Script Host\\Settings\\Enabled = 0, ou utiliser HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\Enabled = 0."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-defender-exploit-guard/exploit-protection"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int noDriveTypeAutoRun = RegInt("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoDriveTypeAutoRun");
			bool isDisabled = noDriveTypeAutoRun == 255 || noDriveTypeAutoRun == 255;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "AutoRun désactivé (NoDriveTypeAutoRun)",
				CurrentValue = ((noDriveTypeAutoRun == -1) ? "Non configuré" : $"0x{noDriveTypeAutoRun:X2} ({noDriveTypeAutoRun})"),
				ExpectedValue = "255 (0xFF) — tous les lecteurs",
				Status = ((!isDisabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "AutoRun exécute automatiquement le contenu des supports amovibles (USB, CD). Cette fonctionnalité est exploitée par des logiciels malveillants comme Conficker et Stuxnet pour se propager via clés USB. La valeur 255 (0xFF) désactive l'AutoRun pour tous les types de lecteurs.",
				Recommendation = (isDisabled ? "AutoRun est désactivé pour tous les types de lecteurs." : "Désactiver l'AutoRun via GPO : Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Turn off AutoPlay. Ou définir HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun = 255."),
				Reference = "https://support.microsoft.com/kb/967715"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int noAutoRun = RegInt("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoAutoRun");
			bool isDisabled = noAutoRun == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "AutoPlay désactivé (NoAutoRun)",
				CurrentValue = ((noAutoRun == -1) ? "Non configuré" : noAutoRun.ToString()),
				ExpectedValue = "1 (désactivé)",
				Status = ((!isDisabled) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "AutoPlay affiche une boîte de dialogue proposant des actions à effectuer lorsqu'un support est inséré. Désactiver AutoPlay réduit le risque d'exécution non intentionnelle de contenu malveillant depuis des supports amovibles.",
				Recommendation = (isDisabled ? "AutoPlay est désactivé." : "Désactiver AutoPlay via HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoAutoRun = 1 ou via GPO."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/"
			};
		});
	}

	private void CollectWindowsUpdateSecurity(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int noAutoUpdate = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", "NoAutoUpdate");
			bool isDisabled = noAutoUpdate == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows Update: Mise à jour automatique",
				CurrentValue = ((noAutoUpdate == -1) ? "Non configuré (mise à jour auto active)" : (isDisabled ? "Désactivé (1)" : "Activé (0)")),
				ExpectedValue = "0 ou non configuré (mises à jour automatiques actives)",
				Status = (isDisabled ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Les mises à jour automatiques de Windows sont essentielles pour corriger les vulnérabilités de sécurité. La désactivation laisse le système exposé aux exploits connus pour lesquels des correctifs existent. La majorité des attaques exploitent des vulnérabilités avec des patches disponibles.",
				Recommendation = (isDisabled ? "CRITIQUE : Réactiver les mises à jour automatiques immédiatement. Définir HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\\NoAutoUpdate = 0 ou supprimer la valeur." : "Les mises à jour automatiques Windows sont actives."),
				Reference = "https://docs.microsoft.com/windows/deployment/update/waas-wu-settings"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string pauseStartTime = RegString("HKLM", "SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings", "PauseFeatureUpdatesStartTime");
			bool isPaused = !string.IsNullOrEmpty(pauseStartTime);
			DateTime pauseDate = DateTime.MinValue;
			if (isPaused && DateTime.TryParse(pauseStartTime, out var parsedDate))
			{
				pauseDate = parsedDate;
			}
			bool isRecentlyPaused = isPaused && (DateTime.Now - pauseDate).TotalDays < 35.0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows Update: Mises à jour non suspendues",
				CurrentValue = (isPaused ? ("Suspendu depuis : " + pauseStartTime) : "Non suspendu"),
				ExpectedValue = "Non suspendu",
				Status = (isRecentlyPaused ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "La suspension des mises à jour Windows empêche l'installation de correctifs de sécurité critiques. Une suspension prolongée augmente significativement le risque d'exploitation de vulnérabilités connues.",
				Recommendation = (isRecentlyPaused ? "Les mises à jour Windows sont actuellement suspendues. Reprendre les mises à jour immédiatement via Paramètres > Windows Update." : (isPaused ? ("Les mises à jour semblent avoir été suspendues (date : " + pauseStartTime + "). Vérifier l'état actuel des mises à jour.") : "Les mises à jour Windows ne sont pas suspendues.")),
				Reference = "https://docs.microsoft.com/windows/deployment/update/waas-manage-updates-wsus"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string wsusServer = RegString("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate", "WUServer");
			bool isConfigured = !string.IsNullOrEmpty(wsusServer);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "WSUS / Serveur de mises à jour configuré",
				CurrentValue = (isConfigured ? ("WSUS : " + wsusServer) : "Non configuré (utilise Windows Update public)"),
				ExpectedValue = "WSUS interne configuré (pour environnements entreprise)",
				Status = SecurityStatus.Info,
				Description = "Un serveur WSUS (Windows Server Update Services) permet de contrôler et centraliser la distribution des mises à jour Windows. En entreprise, cela permet de tester les mises à jour avant déploiement et d'assurer la conformité.",
				Recommendation = (isConfigured ? ("WSUS configuré sur : " + wsusServer + ". Vérifier que le serveur WSUS est à jour et approuve les mises à jour de sécurité critiques dans les délais.") : "Aucun serveur WSUS configuré. Pour les environnements entreprise, déployer WSUS ou utiliser Microsoft Endpoint Manager pour gérer les mises à jour."),
				Reference = "https://docs.microsoft.com/windows-server/administration/windows-server-update-services/get-started/windows-server-update-services-wsus"
			};
		});
	}

	private void CollectMemoryCpuSecurity(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int featureSettingsOverride = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "FeatureSettingsOverride");
			int featureSettingsOverrideMask = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "FeatureSettingsOverrideMask");
			bool mitigationsDisabled = featureSettingsOverride == 3 && featureSettingsOverrideMask == 3;
			bool keysAbsent = featureSettingsOverride == -1 && featureSettingsOverrideMask == -1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Atténuations Spectre/Meltdown",
				CurrentValue = (keysAbsent ? "Clés absentes (atténuations OS actives par défaut)" : $"FeatureSettingsOverride={featureSettingsOverride}, FeatureSettingsOverrideMask={featureSettingsOverrideMask}"),
				ExpectedValue = "Clés absentes OU valeurs != (3,3)",
				Status = (mitigationsDisabled ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Les atténuations Spectre (CVE-2017-5753, CVE-2017-5715) et Meltdown (CVE-2017-5754) protègent contre les attaques par canal caché sur le processeur. FeatureSettingsOverride=3 et FeatureSettingsOverrideMask=3 DÉSACTIVENT ces protections, exposant le système à des attaques permettant de lire la mémoire noyau et d'autres processus.",
				Recommendation = (mitigationsDisabled ? "CRITIQUE : Les atténuations Spectre/Meltdown sont explicitement désactivées ! Supprimer les valeurs FeatureSettingsOverride et FeatureSettingsOverrideMask du registre, ou contacter votre administrateur système." : "Les atténuations Spectre/Meltdown sont actives (configuration par défaut ou correcte)."),
				Reference = "https://support.microsoft.com/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int disableNX = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel", "DisableNX");
			bool isDisabled = disableNX == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Data Execution Prevention (DEP/NX)",
				CurrentValue = ((disableNX == -1) ? "Non configuré (DEP actif par défaut)" : (isDisabled ? "Désactivé (1)" : $"Activé ({disableNX})")),
				ExpectedValue = "0 ou non configuré (DEP activé)",
				Status = (isDisabled ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "La prévention de l'exécution des données (DEP/NX) empêche l'exécution de code depuis des zones mémoire marquées comme données (pile, tas). C'est une défense fondamentale contre les exploits de type buffer overflow et shellcode. La clé DisableNX=1 contourne cette protection hardware.",
				Recommendation = (isDisabled ? "CRITIQUE : DEP est désactivé par registre ! Définir HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\\DisableNX = 0 ou supprimer la valeur et redémarrer." : "DEP/NX est actif — protection contre les exploits de dépassement de tampon en place."),
				Reference = "https://docs.microsoft.com/windows/win32/memory/data-execution-prevention"
			};
		});
	}

	private void CollectServicesSecurity(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int startValue = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry", "Start");
			string serviceState = "Unknown";
			try
			{
				ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT State FROM Win32_Service WHERE Name='RemoteRegistry'");
				try
				{
					foreach (ManagementObject serviceObject in searcher.Get())
					{
						ManagementObject mo = serviceObject;
						try
						{
							serviceState = serviceObject["State"]?.ToString() ?? "Unknown";
						}
						finally
						{
							((IDisposable)mo)?.Dispose();
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
			}
			bool isDisabled = startValue == 4;
			string startLabel;
			object startLabelObj;
			switch (startValue)
			{
			case 2:
				startLabel = "2 - Automatique";
				break;
			case 3:
				startLabel = "3 - Manuel";
				break;
			case 4:
				startLabel = "4 - Désactivé";
				break;
			default:
				startLabelObj = $"{startValue}";
				goto IL_00fd;
			case -1:
				{
					startLabelObj = "Non trouvé";
					goto IL_00fd;
				}
				IL_00fd:
				startLabel = (string)startLabelObj;
				break;
			}
			string startText = startLabel;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Service Remote Registry — désactivé",
				CurrentValue = "Start=" + startText + ", State=" + serviceState,
				ExpectedValue = "4 (Désactivé)",
				Status = ((!isDisabled) ? ((startValue != 2) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
				Description = "Le service Remote Registry permet à des utilisateurs distants de lire et modifier le registre Windows. Même avec des contrôles d'accès appropriés, ce service augmente la surface d'attaque. Il est recommandé de le désactiver sur les postes de travail et serveurs non-DC.",
				Recommendation = (isDisabled ? "Le service Remote Registry est correctement désactivé." : "Désactiver le service Remote Registry : Set-Service RemoteRegistry -StartupType Disabled (PowerShell admin), ou via Services.msc, ou définir HKLM\\SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry\\Start = 4."),
				Reference = "https://docs.microsoft.com/windows-server/administration/windows-server-2008-r2-and-2008/cc754820"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int spoolerStart = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Services\\Spooler", "Start");
			int remoteRpcEndpoint = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers", "RegisterSpoolerRemoteRpcEndPoint");
			bool spoolerRunning = spoolerStart == 2 || spoolerStart == 3;
			bool rpcBlocked = remoteRpcEndpoint == 2;
			string spoolerLabel;
			object spoolerLabelObj;
			switch (spoolerStart)
			{
			case 2:
				spoolerLabel = "2 - Automatique (en cours d'exécution probable)";
				break;
			case 3:
				spoolerLabel = "3 - Manuel";
				break;
			case 4:
				spoolerLabel = "4 - Désactivé";
				break;
			default:
				spoolerLabelObj = $"{spoolerStart}";
				goto IL_0091;
			case -1:
				{
					spoolerLabelObj = "Non trouvé";
					goto IL_0091;
				}
				IL_0091:
				spoolerLabel = (string)spoolerLabelObj;
				break;
			}
			string spoolerStartText = spoolerLabel;
			SecurityStatus status = (spoolerRunning ? (rpcBlocked ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Print Spooler (PrintNightmare CVE-2021-34527)",
				CurrentValue = $"Spooler Start={spoolerStartText}, RegisterSpoolerRemoteRpcEndPoint={remoteRpcEndpoint}",
				ExpectedValue = "Spooler désactivé OU RegisterSpoolerRemoteRpcEndPoint=2",
				Status = status,
				Description = "PrintNightmare (CVE-2021-34527, CVE-2021-1675) est une vulnérabilité critique dans le service Print Spooler permettant l'exécution de code à distance et l'élévation de privilèges locale. Le service Spooler actif avec l'endpoint RPC exposé est la configuration la plus risquée.",
				Recommendation = ((!spoolerRunning) ? "Print Spooler est désactivé — protection PrintNightmare en place." : (rpcBlocked ? "Le Spooler fonctionne mais l'endpoint RPC distant est bloqué. Pour une protection maximale, désactiver le Spooler sur les non-serveurs d'impression : Stop-Service Spooler; Set-Service Spooler -StartupType Disabled" : "CRITIQUE : Print Spooler actif et endpoint RPC exposé ! Désactiver le Spooler ou définir HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RegisterSpoolerRemoteRpcEndPoint = 2 et appliquer les patches MS21-34527.")),
				Reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"
			};
		});
	}

	private void CollectNetworkSecurityAdditional(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			List<string> unusualPorts = new List<string>();
			int establishedCount = 0;
			try
			{
				IPGlobalProperties ipProperties = IPGlobalProperties.GetIPGlobalProperties();
				IPEndPoint[] activeTcpListeners = ipProperties.GetActiveTcpListeners();
				TcpConnectionInformation[] activeTcpConnections = ipProperties.GetActiveTcpConnections();
				HashSet<int> commonPorts = new HashSet<int>
				{
					135, 139, 445, 3389, 5040, 7680, 49152, 49153, 49154, 49155,
					49156, 49157
				};
				IPEndPoint[] listeners = activeTcpListeners;
				foreach (IPEndPoint listener in listeners)
				{
					if (!commonPorts.Contains(listener.Port))
					{
						unusualPorts.Add($":{listener.Port}({listener.Address})");
					}
				}
				TcpConnectionInformation[] connections = activeTcpConnections;
				for (int i = 0; i < connections.Length; i++)
				{
					if (connections[i].State == TcpState.Established)
					{
						establishedCount++;
					}
				}
			}
			catch
			{
				unusualPorts.Add("Erreur lors de la lecture des connexions réseau");
			}
			bool tooManyPorts = unusualPorts.Count > 10;
			string portSummary = ((unusualPorts.Count == 0) ? "Aucun port inhabituel en écoute" : (string.Join(", ", (unusualPorts.Count > 15) ? unusualPorts.GetRange(0, 15) : unusualPorts) + ((unusualPorts.Count > 15) ? $" ... +{unusualPorts.Count - 15} autres" : "")));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Ports TCP en écoute inhabituels",
				CurrentValue = $"{unusualPorts.Count} ports inhabituels, {establishedCount} connexions établies. {portSummary}",
				ExpectedValue = "Minimum de ports en écoute",
				Status = (tooManyPorts ? SecurityStatus.Warning : SecurityStatus.Info),
				Description = "Un grand nombre de ports TCP en écoute augmente la surface d'attaque du système. Chaque service en écoute est un point d'entrée potentiel pour des attaquants. Les ports inhabituels peuvent indiquer des logiciels malveillants, des backdoors ou des services non autorisés.",
				Recommendation = (tooManyPorts ? $"Audit des {unusualPorts.Count} ports inhabituels recommandé. Utiliser 'netstat -ano' et identifier chaque processus associé. Désactiver les services non nécessaires." : "Le nombre de ports en écoute semble normal. Vérifier périodiquement avec 'netstat -ano'."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers\\etc\\hosts");
			List<string> nonStandardEntries = new List<string>();
			try
			{
				if (File.Exists(hostsPath))
				{
					string[] lines = File.ReadAllLines(hostsPath);
					for (int j = 0; j < lines.Length; j++)
					{
						string line = lines[j].Trim();
						if (!string.IsNullOrEmpty(line) && !line.StartsWith("#") && !line.StartsWith("127.0.0.1") && !line.StartsWith("::1") && !line.StartsWith("0.0.0.0 0.0.0.0"))
						{
							nonStandardEntries.Add(line);
						}
					}
				}
			}
			catch (Exception ex)
			{
				nonStandardEntries.Add("Erreur de lecture : " + ex.Message);
			}
			bool hasNonStandard = nonStandardEntries.Count > 0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Intégrité du fichier hosts",
				CurrentValue = (hasNonStandard ? $"{nonStandardEntries.Count} entrée(s) non standard : {string.Join("; ", (nonStandardEntries.Count > 5) ? nonStandardEntries.GetRange(0, 5) : nonStandardEntries)}" : "Aucune entrée non standard détectée"),
				ExpectedValue = "Uniquement les entrées localhost standard",
				Status = (hasNonStandard ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Le fichier hosts Windows peut être modifié par des logiciels malveillants pour rediriger le trafic réseau vers des serveurs malveillants (pharming), contourner les filtres de sécurité DNS, ou bloquer les mises à jour antivirus. Toute entrée non standard mérite une investigation.",
				Recommendation = (hasNonStandard ? $"Vérifier les {nonStandardEntries.Count} entrées non standard dans {hostsPath}. Les entrées suspectes peuvent indiquer une compromission du système." : ("Le fichier hosts (" + hostsPath + ") ne contient que des entrées standard.")),
				Reference = "https://docs.microsoft.com/troubleshoot/windows-client/networking/configure-tcpip-networking"
			};
		});
		// Correctif M1 : le résultat « DNS over HTTPS (DoH) » a été retiré d'ici.
		// La détection DoH est consolidée dans DnsOverHttpsCollector, désormais seule source,
		// afin d'éviter les sévérités contradictoires entre collecteurs.
	}

	private void CollectAntimalwareSecurity(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int cfaSetting = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access", "EnableControlledFolderAccess");
			int networkProtection = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection", "EnableNetworkProtection");
			string statusText = ((cfaSetting == 1) ? "1 (Activé)" : ((cfaSetting != 2) ? ((cfaSetting == -1) ? "Non configuré" : cfaSetting.ToString()) : "2 (Audit)"));
			string cfaStatusText = statusText;
			statusText = ((networkProtection == 1) ? "1 (Activé)" : ((networkProtection != 2) ? ((networkProtection == -1) ? "Non configuré" : networkProtection.ToString()) : "2 (Audit)"));
			string networkStatusText = statusText;
			bool cfaEnabled = cfaSetting == 1;
			bool networkEnabled = networkProtection == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Defender Exploit Guard (CFA + Network Protection)",
				CurrentValue = "Accès aux dossiers contrôlés=" + cfaStatusText + ", Protection réseau=" + networkStatusText,
				ExpectedValue = "1 (Activé) pour les deux",
				Status = ((!(cfaEnabled && networkEnabled)) ? ((cfaEnabled || networkEnabled) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
				Description = "L'accès aux dossiers contrôlés (CFA) protège contre les ransomwares en empêchant les applications non autorisées de modifier les fichiers dans les dossiers protégés. La protection réseau bloque les connexions sortantes vers des domaines malveillants connus.",
				Recommendation = ((cfaEnabled && networkEnabled) ? "Defender Exploit Guard est correctement configuré." : ("Activer via GPO ou Intune : " + ((!cfaEnabled) ? "Accès aux dossiers contrôlés (EnableControlledFolderAccess=1); " : "") + ((!networkEnabled) ? "Protection réseau (EnableNetworkProtection=1)" : ""))),
				Reference = "https://docs.microsoft.com/microsoft-365/security/defender-endpoint/controlled-folders"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int policySetting = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\System", "EnableSmartScreen");
			string legacySetting = RegString("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer", "SmartScreenEnabled");
			bool policyEnabled = policySetting == 1 || policySetting == 2;
			bool legacyEnabled = string.Equals(legacySetting, "On", StringComparison.OrdinalIgnoreCase) || string.Equals(legacySetting, "Warn", StringComparison.OrdinalIgnoreCase);
			bool smartScreenEnabled = policyEnabled || legacyEnabled;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows SmartScreen",
				CurrentValue = $"Policy={policySetting}, Legacy='{legacySetting ?? "Non trouvé"}'",
				ExpectedValue = "Policy=1 ou 2, ou Legacy='On'/'Warn'",
				Status = ((!smartScreenEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Windows SmartScreen vérifie les fichiers téléchargés et les applications contre une base de données cloud de logiciels malveillants connus. Il bloque l'exécution des fichiers suspects et avertit l'utilisateur. SmartScreen réduit significativement le risque d'infections par des téléchargements malveillants.",
				Recommendation = (smartScreenEnabled ? "SmartScreen est activé." : "Activer SmartScreen via GPO (HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\EnableSmartScreen = 1 ou 2) ou via Sécurité Windows > Contrôle des applications et du navigateur."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/microsoft-defender-smartscreen/microsoft-defender-smartscreen-overview"
			};
		});
	}

	private void CollectHardwareSecurityAdditional(List<SecurityResult> results, CancellationToken ct)
	{
		// R2 : le check LAPS a été retiré d'ici. Il lisait un chemin erroné
		// (SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config) qui n'est PAS
		// l'emplacement réel de la configuration LAPS (GPO/MDM), d'où un faux Warning « =False ».
		// La couverture LAPS est intégralement déléguée :
		//   - Windows LAPS (natif) → WindowsLapsCollector (lit le bon chemin Policies\LAPS) ;
		//   - LAPS legacy (AdmPwd) → LapsCollector.
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int hvciEnabled = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", "Enabled");
			int hvciLocked = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", "Locked");
			bool hvciRunning = false;
			try
			{
				ManagementObjectSearcher searcher = new ManagementObjectSearcher(WmiHelper.GetScope("\\\\.\\root\\Microsoft\\Windows\\DeviceGuard"), new ObjectQuery("SELECT SecurityServicesRunning FROM Win32_DeviceGuard"));
				try
				{
					foreach (ManagementObject deviceGuardObject in searcher.Get())
					{
						ManagementObject mo = deviceGuardObject;
						try
						{
							if (deviceGuardObject["SecurityServicesRunning"] is uint[] securityServices && Array.IndexOf(securityServices, 2u) >= 0)
							{
								hvciRunning = true;
							}
						}
						finally
						{
							((IDisposable)mo)?.Dispose();
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
			}
			bool isConfigured = hvciEnabled == 1;
			bool isLocked = hvciLocked == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Intégrité de la mémoire (Core Isolation / HVCI)",
				CurrentValue = $"Registre Enabled={hvciEnabled}, Locked={hvciLocked}, WMI Running={hvciRunning}",
				ExpectedValue = "Enabled=1, idéalement Locked=1",
				Status = ((!(isConfigured && hvciRunning)) ? (isConfigured ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK),
				Description = "L'intégrité de la mémoire (HVCI - Hypervisor-Protected Code Integrity) utilise la virtualisation hardware pour valider l'intégrité du code noyau. Elle empêche le chargement de pilotes non signés ou malveillants, protège contre les exploits de type 'kernel driver' utilisés par des rootkits avancés.",
				Recommendation = ((isConfigured && hvciRunning) ? ("HVCI/Intégrité mémoire est activé et en cours d'exécution." + (isLocked ? " Verrou UEFI actif." : " Considérer l'activation du verrou UEFI (Locked=1).")) : (isConfigured ? "HVCI est configuré mais son état d'exécution n'est pas confirmé. Vérifier dans Sécurité Windows > Sécurité de l'appareil > Isolation du noyau." : "Activer HVCI via Sécurité Windows > Sécurité de l'appareil > Isolation du noyau > Intégrité de la mémoire, ou GPO/MDM. Un redémarrage est requis.")),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
			};
		});
	}

	private static int RegInt(string hive, string path, string valueName, int def = -1)
	{
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKLM") ? RegistryHive.LocalMachine : ((!(hiveName == "HKCU")) ? RegistryHive.LocalMachine : RegistryHive.CurrentUser));
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			object value = subKey?.GetValue(valueName);
			return (value != null && !(value is DBNull)) ? Convert.ToInt32(value) : def;
		}
		catch
		{
			return def;
		}
	}

	private static string? RegString(string hive, string path, string valueName)
	{
		string result;
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKLM") ? RegistryHive.LocalMachine : ((!(hiveName == "HKCU")) ? RegistryHive.LocalMachine : RegistryHive.CurrentUser));
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			result = subKey?.GetValue(valueName)?.ToString();
		}
		catch
		{
			result = null;
		}
		return result;
	}

	private static void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			results.Add(factory());
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = "Configuration Système",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les permissions d'accès au registre et WMI.",
				Reference = ""
			});
		}
	}
}
