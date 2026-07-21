using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class OfficeMacroCollector : ISecurityCollector
{
	private static readonly string[] OfficeVersions = new string[3] { "16.0", "15.0", "14.0" };

	private static readonly (string Key, string Label)[] OfficeApps = new(string, string)[6]
	{
		("Word", "Word"),
		("Excel", "Excel"),
		("PowerPoint", "PowerPoint"),
		("Access", "Access"),
		("Outlook", "Outlook"),
		("Publisher", "Publisher")
	};

	public string Name => "Sécurité Microsoft Office";

	public string Category => "Sécurité Applicative";

	public async Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		Stopwatch stopwatch = Stopwatch.StartNew();
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		try
		{
			await Task.Run(delegate
			{
				List<string> versions = DetectInstalledOfficeVersions();
				ct.ThrowIfCancellationRequested();
				CheckMacroSecurity(report.Results, versions);
				ct.ThrowIfCancellationRequested();
				CheckProtectedView(report.Results, versions);
				ct.ThrowIfCancellationRequested();
				CheckTrustedLocations(report.Results, versions);
				ct.ThrowIfCancellationRequested();
				CheckActiveX(report.Results, versions);
				ct.ThrowIfCancellationRequested();
				CheckDde(report.Results, versions);
				ct.ThrowIfCancellationRequested();
				CheckOutlookSecurity(report.Results, versions);
				ct.ThrowIfCancellationRequested();
				BuildSummary(report.Results, versions);
			}, ct);
		}
		catch (OperationCanceledException)
		{
			report.ErrorMessage = "Collecte annulée.";
			throw;
		}
		catch (Exception exception)
		{
			report.ErrorMessage = "Erreur générale OfficeMacroCollector : " + exception.Message;
		}
		finally
		{
			stopwatch.Stop();
			report.Duration = stopwatch.Elapsed;
		}
		return report;
	}

	private static List<string> DetectInstalledOfficeVersions()
	{
		List<string> installedVersions = new List<string>();
		string[] officeVersions = OfficeVersions;
		foreach (string version in officeVersions)
		{
			string commonPath = "SOFTWARE\\Microsoft\\Office\\" + version + "\\Common";
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey commonKey = baseKey.OpenSubKey(commonPath, writable: false);
			if (commonKey != null)
			{
				installedVersions.Add(version);
			}
		}
		return installedVersions;
	}

	private static string VersionLabel(string ver)
	{
		return ver switch
		{
			"14.0" => "Office 2010",
			"15.0" => "Office 2013",
			"16.0" => "Office 2016/2019/365",
			_ => "Office " + ver,
		};
	}

	private void CheckMacroSecurity(List<SecurityResult> results, List<string> versions)
	{
		if (versions.Count == 0)
		{
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Macros VBA - Office non détecté",
				CurrentValue = "Microsoft Office non installé",
				ExpectedValue = "N/A",
				Status = SecurityStatus.Info,
				Description = "Aucune version de Microsoft Office détectée dans le registre (14.0, 15.0, 16.0). Cette vérification ne s'applique pas à ce système.",
				Recommendation = "Aucune action requise si Office n'est pas installé.",
				CollectedAt = DateTime.Now
			});
			return;
		}
		foreach (string ver in versions)
		{
			(string, string)[] officeApps = OfficeApps;
			for (int i = 0; i < officeApps.Length; i++)
			{
				(string, string) appEntry = officeApps[i];
				string appKey = appEntry.Item1;
				string appLabel = appEntry.Item2;
				string gpoPath = $"SOFTWARE\\Policies\\Microsoft\\Office\\{ver}\\{appKey}\\Security";
				string userPath = $"SOFTWARE\\Microsoft\\Office\\{ver}\\{appKey}\\Security";
				TryAdd(results, delegate
				{
					object gpoVbaWarnings = ReadRegHklm(gpoPath, "VBAWarnings");
					object userVbaWarnings = ReadRegHkcu(userPath, "VBAWarnings");
					object gpoLevel = ReadRegHklm(gpoPath, "Level");
					int vbaWarningsValue = -1;
					string configSource = "Non configuré";
					if (gpoVbaWarnings != null)
					{
						vbaWarningsValue = Convert.ToInt32(gpoVbaWarnings);
						configSource = "GPO (HKLM)";
					}
					else if (gpoLevel != null)
					{
						vbaWarningsValue = Convert.ToInt32(gpoLevel);
						configSource = "GPO Level (HKLM)";
					}
					else if (userVbaWarnings != null)
					{
						vbaWarningsValue = Convert.ToInt32(userVbaWarnings);
						configSource = "Utilisateur (HKCU)";
					}
					object gpoBlockMacros = ReadRegHklm(gpoPath, "BlockMacrosFromInternet");
					object userBlockMacros = ReadRegHkcu(userPath, "BlockMacrosFromInternet");
					int blockMacrosValue = ((gpoBlockMacros != null) ? Convert.ToInt32(gpoBlockMacros) : ((userBlockMacros != null) ? Convert.ToInt32(userBlockMacros) : (-1)));
					object noTrustBarRaw = ReadRegHklm(gpoPath + "\\TrustBar", "NoTrustBar");
					int noTrustBar = ((noTrustBarRaw != null) ? Convert.ToInt32(noTrustBarRaw) : 0);
					string vbaWarningsLabel = vbaWarningsValue switch
					{
						1 => "1 - Toutes les macros activées (CRITIQUE)",
						2 => "2 - Désactivées avec notification (OK)",
						3 => "3 - Désactivées sauf signées numériquement (BIEN)",
						4 => "4 - Toutes les macros désactivées (OPTIMAL)",
						_ => "Non configuré (comportement par défaut = 2)",
					};
					SecurityStatus status = ((vbaWarningsValue == 1) ? SecurityStatus.Critical : ((vbaWarningsValue == 2 || vbaWarningsValue < 0) ? SecurityStatus.Warning : SecurityStatus.OK));
					bool internetMacrosBlocked = blockMacrosValue == 1;
					if (!internetMacrosBlocked && status == SecurityStatus.OK)
					{
						status = SecurityStatus.Warning;
					}
					string blockMacrosLabel = ((blockMacrosValue < 0) ? "Non configuré" : ((blockMacrosValue == 1) ? "1 - Bloqué (correct)" : "0 - Non bloqué (risque)"));
					bool trustBarHidden = noTrustBar == 1 && vbaWarningsValue != 4;
					string currentValue = $"VBAWarnings={vbaWarningsLabel} [{configSource}] | BlockMacrosFromInternet={blockMacrosLabel}" + (trustBarHidden ? " | AVERTISSEMENT: NoTrustBar=1 (barre de sécurité masquée!)" : "");
					return new SecurityResult
					{
						Category = Category,
						CheckName = $"Macros VBA - {appLabel} ({VersionLabel(ver)})",
						CurrentValue = currentValue,
						ExpectedValue = "VBAWarnings=3 ou 4 | BlockMacrosFromInternet=1",
						Status = ((trustBarHidden && status != SecurityStatus.Critical) ? SecurityStatus.Critical : status),
						Description = ((vbaWarningsValue == 1) ? ($"CRITIQUE : Les macros VBA sont entièrement activées dans {appLabel} ({VersionLabel(ver)}). " + "Tout document reçu par email ou téléchargé peut exécuter du code arbitraire (ransomware, spyware, etc.). Source de la configuration : " + configSource + ".") : ($"Paramètre de sécurité des macros VBA pour {appLabel} ({VersionLabel(ver)}) : {vbaWarningsLabel}. BlockMacrosFromInternet : {blockMacrosLabel}. " + (trustBarHidden ? "La barre de sécurité est masquée — l'utilisateur ne verra pas les alertes de macro!" : ""))),
						Recommendation = ((vbaWarningsValue == 1) ? ("Définir VBAWarnings=4 (désactiver toutes les macros) ou minimum 3 (seulement signées) pour " + appLabel + " via GPO. Configurer BlockMacrosFromInternet=1 pour bloquer les macros des fichiers Internet.") : ((!internetMacrosBlocked) ? ("Activer BlockMacrosFromInternet=1 pour " + appLabel + " via GPO pour bloquer l'exécution de macros depuis les fichiers téléchargés.") : "Configuration acceptable. Préférer VBAWarnings=4 si les macros ne sont pas utilisées.")),
						Reference = "CIS Microsoft Office Benchmark | ANSSI - Macros Office | MITRE ATT&CK T1204.002",
						CollectedAt = DateTime.Now
					};
				});
			}
		}
	}

	private void CheckProtectedView(List<SecurityResult> results, List<string> versions)
	{
		(string, string)[] protectedViewApps = new(string, string)[3]
		{
			("Word", "Word"),
			("Excel", "Excel"),
			("PowerPoint", "PowerPoint")
		};
		foreach (string ver in versions)
		{
			(string, string)[] appEntries = protectedViewApps;
			for (int i = 0; i < appEntries.Length; i++)
			{
				(string, string) appEntry = appEntries[i];
				string appKey = appEntry.Item1;
				string appLabel = appEntry.Item2;
				string pvPath = $"SOFTWARE\\Policies\\Microsoft\\Office\\{ver}\\{appKey}\\Security\\ProtectedView";
				TryAdd(results, delegate
				{
					object internetFilesRaw = ReadRegHklm(pvPath, "DisableInternetFilesInPV");
					object attachmentsRaw = ReadRegHklm(pvPath, "DisableAttachmentsInPV");
					object unsafeLocationsRaw = ReadRegHklm(pvPath, "DisableUnsafeLocationsInPV");
					int disableInternetFiles = ((internetFilesRaw != null) ? Convert.ToInt32(internetFilesRaw) : 0);
					int disableAttachments = ((attachmentsRaw != null) ? Convert.ToInt32(attachmentsRaw) : 0);
					int disableUnsafeLocations = ((unsafeLocationsRaw != null) ? Convert.ToInt32(unsafeLocationsRaw) : 0);
					bool internetDisabled = disableInternetFiles == 1;
					bool attachmentsDisabled = disableAttachments == 1;
					bool unsafeLocationsDisabled = disableUnsafeLocations == 1;
					bool anyDisabled = internetDisabled || attachmentsDisabled || unsafeLocationsDisabled;
					List<string> disabledSources = new List<string>();
					if (internetDisabled)
					{
						disabledSources.Add("Fichiers Internet (DisableInternetFilesInPV=1)");
					}
					if (attachmentsDisabled)
					{
						disabledSources.Add("Pièces jointes (DisableAttachmentsInPV=1)");
					}
					if (unsafeLocationsDisabled)
					{
						disabledSources.Add("Emplacements non sûrs (DisableUnsafeLocationsInPV=1)");
					}
					return new SecurityResult
					{
						Category = Category,
						CheckName = $"Affichage protégé - {appLabel} ({VersionLabel(ver)})",
						CurrentValue = (anyDisabled ? ("Désactivé pour : " + string.Join(", ", disabledSources)) : "Actif pour toutes les sources (Internet, pièces jointes, emplacements non sûrs)"),
						ExpectedValue = "DisableInternetFilesInPV=0 | DisableAttachmentsInPV=0 | DisableUnsafeLocationsInPV=0",
						Status = (anyDisabled ? SecurityStatus.Critical : SecurityStatus.OK),
						Description = (anyDisabled ? ($"CRITIQUE : L'Affichage protégé est désactivé pour {appLabel} ({VersionLabel(ver)}) pour les sources suivantes : {string.Join(", ", disabledSources)}. " + "L'Affichage protégé est la première ligne de défense contre les documents malveillants — sa désactivation expose directement le système.") : ($"L'Affichage protégé est correctement activé pour toutes les sources dans {appLabel} ({VersionLabel(ver)}). " + "Les fichiers provenant d'Internet, des pièces jointes et d'emplacements non sûrs s'ouvrent en mode lecture seule isolé.")),
						Recommendation = (anyDisabled ? ($"Réactiver immédiatement l'Affichage protégé pour {appLabel} via GPO : Computer Configuration > Administrative Templates > Microsoft {appLabel} > {appLabel} Options > Security > Trust Center > Protected View. " + "Définir toutes les options DisableXxxInPV à 0.") : "Aucune action requise. Maintenir cette configuration via GPO pour éviter toute modification par les utilisateurs."),
						Reference = "CIS Microsoft Office Benchmark | ANSSI - Office Sécurisé | MITRE ATT&CK T1566",
						CollectedAt = DateTime.Now
					};
				});
			}
		}
	}

	private void CheckTrustedLocations(List<SecurityResult> results, List<string> versions)
	{
		foreach (string ver in versions)
		{
			(string, string)[] officeApps = OfficeApps;
			for (int i = 0; i < officeApps.Length; i++)
			{
				var (appKey, appLabel) = officeApps[i];
				TryAdd(results, delegate
				{
					string trustedLocationsPath = $"SOFTWARE\\Microsoft\\Office\\{ver}\\{appKey}\\Security\\Trusted Locations";
					_ = trustedLocationsPath + "\\AllowNetworkLocations";
					IEnumerable<string> subKeyNames = EnumerateSubKeysHkcu(trustedLocationsPath);
					int customLocationCount = 0;
					int subFolderCount = 0;
					List<string> customPaths = new List<string>();
					foreach (string subKeyName in subKeyNames)
					{
						string locationKey = trustedLocationsPath + "\\" + subKeyName;
						string locationPath = (ReadRegHkcu(locationKey, "Path") as string) ?? string.Empty;
						object allowSubFoldersRaw = ReadRegHkcu(locationKey, "AllowSubFolders");
						int allowSubFolders = ((allowSubFoldersRaw != null) ? Convert.ToInt32(allowSubFoldersRaw) : 0);
						if (locationPath.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) < 0 || (locationPath.IndexOf("Templates", StringComparison.OrdinalIgnoreCase) < 0 && locationPath.IndexOf("AddIns", StringComparison.OrdinalIgnoreCase) < 0 && locationPath.IndexOf("Office", StringComparison.OrdinalIgnoreCase) < 0))
						{
							customLocationCount++;
							if (allowSubFolders == 1)
							{
								subFolderCount++;
							}
							if (!string.IsNullOrWhiteSpace(locationPath))
							{
								customPaths.Add(locationPath + ((allowSubFolders == 1) ? " [+sous-dossiers]" : ""));
							}
						}
					}
					object allowNetworkRaw = ReadRegHkcu(trustedLocationsPath ?? "", "AllowNetworkLocations");
					int allowNetwork = ((allowNetworkRaw != null) ? Convert.ToInt32(allowNetworkRaw) : 0);
					SecurityStatus status = ((customLocationCount > 0 && allowNetwork == 1) ? SecurityStatus.Critical : ((customLocationCount > 0 || allowNetwork == 1) ? SecurityStatus.Warning : SecurityStatus.OK));
					string pathsLabel = ((customPaths.Count > 0) ? (string.Join(" | ", customPaths.Take(5)) + ((customPaths.Count > 5) ? $" (+{customPaths.Count - 5} autres)" : "")) : "(aucun)");
					return new SecurityResult
					{
						Category = Category,
						CheckName = $"Emplacements approuvés - {appLabel} ({VersionLabel(ver)})",
						CurrentValue = $"{customLocationCount} emplacement(s) personnalisé(s) | Réseau autorisé={allowNetwork} | Chemins={pathsLabel}",
						ExpectedValue = "0 emplacement personnalisé | AllowNetworkLocations=0",
						Status = status,
						Description = ((customLocationCount > 0) ? ($"{customLocationCount} emplacement(s) de confiance personnalisé(s) configuré(s) dans {appLabel} ({VersionLabel(ver)}). " + ((subFolderCount > 0) ? $"{subFolderCount} inclut les sous-dossiers (portée très large). " : "") + ((allowNetwork == 1) ? "Les emplacements réseau sont autorisés comme emplacements approuvés — risque élevé." : "")) : ($"Aucun emplacement de confiance personnalisé pour {appLabel} ({VersionLabel(ver)}). " + ((allowNetwork == 1) ? "Les emplacements réseau sont autorisés — un attaquant pourrait référencer un partage malveillant." : "Configuration correcte."))),
						Recommendation = ((customLocationCount > 0) ? ("Auditer les emplacements de confiance de " + appLabel + " et supprimer les entrées non nécessaires. Ne conserver que les emplacements strictement indispensables et jamais les partages réseau. Configurer via GPO pour empêcher les utilisateurs d'ajouter des emplacements de confiance.") : ((allowNetwork == 1) ? "Désactiver les emplacements réseau approuvés (AllowNetworkLocations=0) via GPO." : "Aucune action requise.")),
						Reference = "CIS Microsoft Office Benchmark - Trusted Locations | MITRE ATT&CK T1204",
						CollectedAt = DateTime.Now
					};
				});
			}
		}
	}

	private void CheckActiveX(List<SecurityResult> results, List<string> versions)
	{
		TryAdd(results, delegate
		{
			object globalDisableRaw = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Office\\Common\\Security", "DisableAllActiveX");
			int globalDisable = ((globalDisableRaw != null) ? Convert.ToInt32(globalDisableRaw) : (-1));
			bool globallyDisabled = globalDisable == 1;
			List<string> overrides = new List<string>();
			bool hasEnabledApp = false;
			foreach (string version in versions)
			{
				(string, string)[] officeApps = OfficeApps;
				for (int i = 0; i < officeApps.Length; i++)
				{
					(string, string) appEntry = officeApps[i];
					string appKey = appEntry.Item1;
					string appLabel = appEntry.Item2;
					object appDisableRaw = ReadRegHklm($"SOFTWARE\\Policies\\Microsoft\\Office\\{version}\\{appKey}\\Security", "DisableAllActiveX");
					if (appDisableRaw != null)
					{
						int appDisable = Convert.ToInt32(appDisableRaw);
						if (appDisable != 1)
						{
							hasEnabledApp = true;
							overrides.Add($"{appLabel} ({VersionLabel(version)}): DisableAllActiveX={appDisable}");
						}
					}
				}
			}
			// Correctif H3 : l'ancienne expression se réduisait à "!globallyDisabled ? Warning : OK",
			// ignorant hasEnabledApp (une app réactivant ActiveX malgré la désactivation globale).
			// Toute réactivation applicative doit désormais déclencher un Warning.
			SecurityStatus status = ((!globallyDisabled) || hasEnabledApp) ? SecurityStatus.Warning : SecurityStatus.OK;
			string currentValue = ((globalDisable >= 0) ? $"Global DisableAllActiveX={globalDisable} | {((overrides.Count > 0) ? string.Join("; ", overrides) : "Pas de surcharge par app")}" : ("Contrôle global non configuré | " + ((overrides.Count > 0) ? string.Join("; ", overrides) : "Aucune surcharge par app")));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "ActiveX - Désactivation globale Office",
				CurrentValue = currentValue,
				ExpectedValue = "DisableAllActiveX=1 (global ou par application)",
				Status = status,
				Description = (globallyDisabled ? "Les contrôles ActiveX sont désactivés globalement pour toutes les applications Office — configuration optimale." : "Les contrôles ActiveX ne sont pas désactivés globalement dans Office. ActiveX peut être utilisé pour exécuter du code arbitraire via des documents Office malveillants (ex : CVE de type mshta, DCOM)."),
				Recommendation = ((!globallyDisabled) ? "Définir DisableAllActiveX=1 dans HKLM\\SOFTWARE\\Policies\\Microsoft\\Office\\Common\\Security via GPO. Si des contrôles ActiveX légitimes sont requis, les approuver individuellement plutôt que d'activer globalement." : "Aucune action requise."),
				Reference = "CIS Microsoft Office Benchmark - ActiveX | MITRE ATT&CK T1559",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CheckDde(List<SecurityResult> results, List<string> versions)
	{
		(string, string)[] ddeApps = new(string, string)[2]
		{
			("Word", "Word"),
			("Excel", "Excel")
		};
		foreach (string ver in versions)
		{
			(string, string)[] appEntries = ddeApps;
			for (int i = 0; i < appEntries.Length; i++)
			{
				var (appKey, appLabel) = appEntries[i];
				TryAdd(results, delegate
				{
					string gpoPath = $"SOFTWARE\\Policies\\Microsoft\\Office\\{ver}\\{appKey}\\Options";
					string userPath = $"SOFTWARE\\Microsoft\\Office\\{ver}\\{appKey}\\Options";
					object gpoDontUpdate = ReadRegHklm(gpoPath, "DontUpdateLinks");
					object userDontUpdate = ReadRegHkcu(userPath, "DontUpdateLinks");
					int dontUpdateLinks = -1;
					string configSource = "Non configuré";
					if (gpoDontUpdate != null)
					{
						dontUpdateLinks = Convert.ToInt32(gpoDontUpdate);
						configSource = "GPO (HKLM)";
					}
					else if (userDontUpdate != null)
					{
						dontUpdateLinks = Convert.ToInt32(userDontUpdate);
						configSource = "Utilisateur (HKCU)";
					}
					bool updatesDisabled = dontUpdateLinks == 1;
					bool notConfigured = dontUpdateLinks < 0;
					return new SecurityResult
					{
						Category = Category,
						CheckName = $"DDE - Mise à jour automatique désactivée - {appLabel} ({VersionLabel(ver)})",
						CurrentValue = (notConfigured ? "Non configuré (mise à jour DDE active par défaut)" : $"DontUpdateLinks={dontUpdateLinks} [{configSource}]"),
						ExpectedValue = "DontUpdateLinks=1",
						Status = ((!updatesDisabled) ? SecurityStatus.Warning : SecurityStatus.OK),
						Description = (updatesDisabled ? ($"La mise à jour automatique des liens DDE est désactivée dans {appLabel} ({VersionLabel(ver)}). " + "Les attaques par injection DDE (ex : phishing via champs Word/Excel) ne peuvent pas s'exécuter automatiquement.") : (notConfigured ? ($"DontUpdateLinks n'est pas configuré pour {appLabel} ({VersionLabel(ver)}). " + "Par défaut, Office peut mettre à jour les liaisons DDE à l'ouverture d'un document — vecteur d'attaque utilisé dans des campagnes de phishing (ex : Fancy Bear 2017).") : $"DontUpdateLinks=0 pour {appLabel} ({VersionLabel(ver)}) — les mises à jour DDE automatiques sont activées.")),
						Recommendation = ((!updatesDisabled) ? $"Définir DontUpdateLinks=1 pour {appLabel} via GPO : Computer Configuration > Administrative Templates > Microsoft {appLabel} > {appLabel} Options > 'Update automatic links at Open'." : "Aucune action requise."),
						Reference = "MITRE ATT&CK T1559.002 - DDE | Microsoft ADV170021 | ANSSI - Sécurité Office",
						CollectedAt = DateTime.Now
					};
				});
			}
		}
	}

	private void CheckOutlookSecurity(List<SecurityResult> results, List<string> versions)
	{
		foreach (string ver in versions)
		{
			string basePath = "SOFTWARE\\Policies\\Microsoft\\Office\\" + ver + "\\Outlook";
			TryAdd(results, delegate
			{
				object levelRaw = ReadRegHklm(basePath + "\\Security", "Level");
				int level = ((levelRaw != null) ? Convert.ToInt32(levelRaw) : (-1));
				string levelLabel = level switch
				{
					1 => "1 - Aucune restriction",
					2 => "2 - Avertissement mais accès autorisé",
					3 => "3 - Blocage avec demande (recommandé)",
					4 => "4 - Blocage total sans demande",
					_ => "Non configuré (comportement par défaut)",
				};
				bool isBlocking = level == 3 || level == 4;
				SecurityStatus status = ((level == 1) ? SecurityStatus.Critical : ((!isBlocking) ? SecurityStatus.Warning : SecurityStatus.OK));
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Outlook - Niveau de sécurité pièces jointes (" + VersionLabel(ver) + ")",
					CurrentValue = levelLabel,
					ExpectedValue = "Level=3 (Bloquer avec demande) ou Level=4",
					Status = status,
					Description = ((level == 1) ? "CRITIQUE : Outlook est configuré sans restriction de pièces jointes. Tout type de fichier joint (exécutables, scripts, macros) peut être ouvert directement depuis Outlook." : ((level < 0) ? ("Le niveau de sécurité des pièces jointes Outlook (" + VersionLabel(ver) + ") n'est pas configuré via GPO. Le comportement dépend du profil utilisateur et peut être modifié par l'utilisateur.") : $"Niveau de sécurité Outlook ({VersionLabel(ver)}) : {levelLabel}.")),
					Recommendation = ((!isBlocking) ? ("Configurer Level=3 pour Outlook " + VersionLabel(ver) + " via GPO pour bloquer les pièces jointes dangereuses avec invite à l'utilisateur.") : "Configuration correcte. Maintenir ce paramètre via GPO."),
					Reference = "CIS Microsoft Outlook Benchmark | ANSSI - Messagerie sécurisée",
					CollectedAt = DateTime.Now
				};
			});
			TryAdd(results, delegate
			{
				object guardRaw = ReadRegHklm(basePath + "\\Security", "DisableOutlookObjectModelGuard");
				int guardDisabled = ((guardRaw != null) ? Convert.ToInt32(guardRaw) : 0);
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Outlook - Garde Modèle Objet (" + VersionLabel(ver) + ")",
					CurrentValue = $"DisableOutlookObjectModelGuard={guardDisabled}",
					ExpectedValue = "0 (garde activée)",
					Status = ((guardDisabled == 1) ? SecurityStatus.Critical : SecurityStatus.OK),
					Description = ((guardDisabled == 1) ? "CRITIQUE : La garde du modèle objet Outlook est désactivée. Des scripts VBA ou des add-ins malveillants peuvent accéder au carnet d'adresses, envoyer des emails et lire les messages sans aucun avertissement." : "La garde du modèle objet Outlook est active — les tentatives d'accès programmatique au carnet d'adresses déclenchent une confirmation utilisateur."),
					Recommendation = ((guardDisabled == 1) ? "Définir DisableOutlookObjectModelGuard=0 ou supprimer la valeur pour restaurer la protection." : "Aucune action requise."),
					Reference = "Microsoft Docs - Outlook Object Model Guard | MITRE ATT&CK T1114",
					CollectedAt = DateTime.Now
				};
			});
			TryAdd(results, delegate
			{
				object hyperlinksRaw = ReadRegHklm(basePath, "DisableHyperlinks");
				int disableHyperlinks = ((hyperlinksRaw != null) ? Convert.ToInt32(hyperlinksRaw) : 0);
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Outlook - Hyperliens dans les emails (" + VersionLabel(ver) + ")",
					CurrentValue = $"DisableHyperlinks={disableHyperlinks}",
					ExpectedValue = "0 (hyperliens actifs avec prudence) ou 1 selon politique",
					Status = ((disableHyperlinks == 1) ? SecurityStatus.Warning : SecurityStatus.Info),
					Description = ((disableHyperlinks == 1) ? "Les hyperliens sont désactivés dans Outlook. Les utilisateurs ne peuvent pas cliquer sur les liens dans les emails — protection contre le phishing mais peut impacter la productivité et masquer les destinations des URLs." : "Les hyperliens sont actifs dans Outlook. Les utilisateurs peuvent cliquer sur les liens des emails — vérifier que la protection contre les URLs malveillantes est assurée par d'autres moyens (filtrage web, antiphishing)."),
					Recommendation = ((disableHyperlinks == 1) ? "Évaluer si la désactivation des hyperliens est toujours pertinente. Privilégier un filtre URL (Defender ATP Safe Links, proxy web) pour bloquer les liens malveillants tout en conservant l'expérience utilisateur." : "Configurer une solution de protection URL (Microsoft Defender for Office 365 Safe Links ou équivalent) pour analyser les liens à la volée."),
					Reference = "ANSSI - Messagerie | Microsoft Defender for Office 365",
					CollectedAt = DateTime.Now
				};
			});
			TryAdd(results, delegate
			{
				object minKeyRaw = ReadRegHklm(basePath + "\\Security", "MinEncKey");
				int minEncKey = ((minKeyRaw != null) ? Convert.ToInt32(minKeyRaw) : (-1));
				bool isConfigured = minEncKey > 0;
				bool isStrong = minEncKey >= 256;
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Outlook - Longueur minimale clé S/MIME (" + VersionLabel(ver) + ")",
					CurrentValue = (isConfigured ? $"{minEncKey} bits" : "Non configuré"),
					ExpectedValue = "≥ 256 bits (AES-256)",
					Status = ((!isConfigured) ? SecurityStatus.Info : ((!isStrong) ? SecurityStatus.Warning : SecurityStatus.OK)),
					Description = ((!isConfigured) ? ("La longueur minimale de clé de chiffrement S/MIME n'est pas configurée pour Outlook (" + VersionLabel(ver) + "). Le chiffrement S/MIME peut utiliser des algorithmes faibles si non contraint.") : (isStrong ? $"La longueur minimale de clé S/MIME est configurée à {minEncKey} bits — conforme aux recommandations modernes (AES-256)." : ($"La longueur minimale de clé S/MIME est configurée à {minEncKey} bits — inférieure à 256 bits. " + "Des clés courtes sont vulnérables aux attaques par force brute sur les messages archivés."))),
					Recommendation = ((!isStrong) ? "Configurer MinEncKey=256 (AES-256) via GPO pour Outlook S/MIME. Éviter RC2 (40/128 bits) et 3DES (168 bits) — préférer AES-256." : "Aucune action requise."),
					Reference = "ANSSI - Chiffrement de la messagerie | RFC 8551 S/MIME 4.0",
					CollectedAt = DateTime.Now
				};
			});
		}
	}

	private void BuildSummary(List<SecurityResult> results, List<string> versions)
	{
		TryAdd(results, delegate
		{
			int criticalMacros = results.Count((SecurityResult r) => r.CheckName.StartsWith("Macros VBA") && r.Status == SecurityStatus.Critical);
			int protectedViewIssues = results.Count((SecurityResult r) => r.CheckName.StartsWith("Affichage protégé") && r.Status == SecurityStatus.Critical);
			int riskyTrustedLocations = results.Count((SecurityResult r) => r.CheckName.StartsWith("Emplacements approuvés") && r.Status >= SecurityStatus.Warning);
			bool officeInstalled = versions.Count > 0;
			string versionsLabel = (officeInstalled ? string.Join(", ", versions.Select(VersionLabel)) : "Non détecté");
			SecurityStatus status = ((!officeInstalled) ? SecurityStatus.Info : ((criticalMacros > 0 || protectedViewIssues > 0) ? SecurityStatus.Critical : ((riskyTrustedLocations > 0) ? SecurityStatus.Warning : SecurityStatus.OK)));
			string currentValue = (officeInstalled ? $"Office installé : {versionsLabel} | Paramètres macros critiques : {criticalMacros} | Problèmes Protected View : {protectedViewIssues} | Emplacements approuvés à risque : {riskyTrustedLocations}" : "Microsoft Office non détecté sur ce système.");
			return new SecurityResult
			{
				Category = Category,
				CheckName = "SYNTHÈSE - Sécurité Microsoft Office",
				CurrentValue = currentValue,
				ExpectedValue = "0 paramètre macro critique | 0 problème Protected View | 0 emplacement approuvé à risque",
				Status = status,
				Description = (officeInstalled ? $"Synthèse de l'audit de sécurité Microsoft Office. Versions détectées : {versionsLabel}. {criticalMacros} configuration(s) critique(s) de macros, {protectedViewIssues} problème(s) de Protected View, {riskyTrustedLocations} emplacement(s) approuvé(s) à risque." : "Microsoft Office n'est pas installé sur ce système — aucun risque lié aux macros Office."),
				Recommendation = ((criticalMacros > 0) ? "Action immédiate requise : corriger les paramètres de sécurité des macros critiques identifiés ci-dessus." : ((protectedViewIssues > 0) ? "Réactiver le mode Affichage protégé pour les applications Office concernées." : "Maintenir la surveillance des configurations Office via GPO et audits réguliers.")),
				Reference = "CIS Microsoft Office Benchmark | ANSSI - Sécurité des postes | MITRE ATT&CK T1204",
				CollectedAt = DateTime.Now
			};
		});
	}

	private static object? ReadRegHklm(string subKey, string valueName)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey targetKey = baseKey.OpenSubKey(subKey, writable: false);
			return targetKey?.GetValue(valueName);
		}
		catch
		{
			return null;
		}
	}

	private static object? ReadRegHkcu(string subKey, string valueName)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
			using RegistryKey targetKey = baseKey.OpenSubKey(subKey, writable: false);
			return targetKey?.GetValue(valueName);
		}
		catch
		{
			return null;
		}
	}

	private static IEnumerable<string> EnumerateSubKeysHkcu(string subKey)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
			using RegistryKey targetKey = baseKey.OpenSubKey(subKey, writable: false);
			return targetKey?.GetSubKeyNames() ?? Array.Empty<string>();
		}
		catch
		{
			return Array.Empty<string>();
		}
	}

	private static int WmiInt(ManagementBaseObject obj, string prop, int def = -1)
	{
		object propertyValue = obj[prop];
		if (propertyValue == null || propertyValue is DBNull)
		{
			return def;
		}
		return Convert.ToInt32(propertyValue);
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
				Category = "Sécurité Applicative",
				CheckName = "Erreur de vérification",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Échec d'une vérification sécurité Office : " + ex.Message,
				CollectedAt = DateTime.Now
			});
		}
	}
}
