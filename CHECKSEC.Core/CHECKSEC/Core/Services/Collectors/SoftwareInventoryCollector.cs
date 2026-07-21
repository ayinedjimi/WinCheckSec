using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class SoftwareInventoryCollector : ISecurityCollector
{
	private record DangerousEntry(string MatchFragment, SecurityStatus Status, string Reason, string Recommendation, string Reference, string? MinVersion = null);

	private record VersionedEntry(string MatchFragment, string MinVersion, SecurityStatus Status, string ReasonTemplate, string Recommendation, string Reference);

	private record SoftwareEntry(string DisplayName, string Version, string Publisher, string InstallDate, long EstimatedSizeKb);

	private static readonly List<DangerousEntry> DangerousSoftwareList = new List<DangerousEntry>
	{
		new DangerousEntry("Adobe Flash Player", SecurityStatus.Critical, "Adobe Flash Player est en fin de vie depuis le 31 décembre 2020. Aucun correctif de sécurité ne sera jamais publié. Des centaines de CVE critiques restent non corrigées. Ce composant constitue un vecteur d'attaque majeur.", "Désinstaller immédiatement Adobe Flash Player. Aucune alternative officielle n'existe.", "https://www.adobe.com/products/flashplayer/end-of-life.html"),
		new DangerousEntry("Microsoft Silverlight", SecurityStatus.Critical, "Microsoft Silverlight est en fin de vie depuis le 12 octobre 2021. Aucun correctif de sécurité n'est disponible depuis cette date.", "Désinstaller Microsoft Silverlight. Les applications dépendantes doivent migrer vers HTML5.", "https://support.microsoft.com/lifecycle/search?alpha=Silverlight"),
		new DangerousEntry("QuickTime", SecurityStatus.Critical, "Apple QuickTime pour Windows est en fin de vie depuis 2016. Des CVE critiques non corrigées (ZDI-16-241, ZDI-16-242) permettent l'exécution de code arbitraire.", "Désinstaller QuickTime pour Windows immédiatement. Apple ne fournit plus de mises à jour pour la plateforme Windows.", "https://support.apple.com/HT205771"),
		new DangerousEntry("Python 2", SecurityStatus.Warning, "Python 2 est en fin de vie depuis le 1er janvier 2020. Aucun correctif de sécurité n'est disponible. Les dépendances Python 2 peuvent contenir des vulnérabilités non corrigées.", "Migrer vers Python 3. Désinstaller Python 2 si aucune dépendance critique ne l'exige.", "https://www.python.org/doc/sunset-python-2/"),
		new DangerousEntry("TeamViewer", SecurityStatus.Warning, "TeamViewer est un outil d'accès à distance légitime mais fréquemment ciblé par les attaquants et les campagnes de fraude au support technique. Sa présence doit être justifiée.", "Vérifier si TeamViewer est autorisé par la politique de sécurité. S'assurer qu'il est à jour, protégé par un mot de passe fort et que l'accès non sollicité est désactivé.", "https://www.cisa.gov/uscert/ncas/alerts/aa20-120a"),
		new DangerousEntry("AnyDesk", SecurityStatus.Warning, "AnyDesk est un outil d'accès à distance légitime mais fréquemment utilisé dans des attaques de type BEC, ransomware et fraude au support technique.", "Vérifier si AnyDesk est autorisé. Mettre à jour vers la dernière version. Surveiller les connexions entrantes via les journaux d'événements.", "https://anydesk.com/security"),
		new DangerousEntry("Wireshark", SecurityStatus.Warning, "Wireshark est un analyseur de paquets réseau. Sa présence sur un système de production doit être justifiée par un besoin opérationnel documenté.", "Vérifier si Wireshark est autorisé. Le supprimer des postes ne nécessitant pas d'analyse réseau.", "https://www.wireshark.org/"),
		new DangerousEntry("Nmap", SecurityStatus.Warning, "Nmap est un scanner réseau. Sur un poste utilisateur standard, sa présence indique une activité inhabituelle ou un outil de reconnaissance potentiellement malveillant.", "Vérifier l'autorisation. Supprimer si non justifié par un rôle d'administrateur réseau.", "https://nmap.org/"),
		new DangerousEntry("Metasploit", SecurityStatus.Critical, "Metasploit Framework est un outil d'exploitation professionnel. Sa présence sur un système de production est un indicateur de compromission (IoC) majeur à moins d'être sur un poste dédié au test d'intrusion.", "Isoler la machine, lancer une investigation forensique immédiate. Supprimer Metasploit si non autorisé.", "https://www.metasploit.com/"),
		new DangerousEntry("Cobalt Strike", SecurityStatus.Critical, "Cobalt Strike est un framework C2 (Command & Control) utilisé par les équipes rouges mais massivement repris par les groupes APT et ransomware. Sa présence est un IoC critique.", "Isolation immédiate du système. Investigation forensique obligatoire. Signalement à l'équipe SOC/CERT.", "https://www.cobaltstrike.com/"),
		new DangerousEntry("Mimikatz", SecurityStatus.Critical, "Mimikatz est un outil de vol de credentials Windows (LSASS dump, Pass-the-Hash, Pass-the-Ticket, DCSync). Sa présence sur un système de production est un IoC critique de compromission.", "Isolation immédiate. Investigation forensique. Rotation de tous les mots de passe et tickets Kerberos. Signalement SOC/CERT.", "https://github.com/gentilkiwi/mimikatz"),
		new DangerousEntry("Process Hacker", SecurityStatus.Warning, "Process Hacker / System Informer est un outil d'administration avancé permettant d'inspecter et modifier des processus. Il peut être utilisé pour contourner des contrôles de sécurité.", "Vérifier l'autorisation. Supprimer des postes standards. Acceptable uniquement sur les postes d'administrateurs système.", "https://processhacker.sourceforge.io/"),
		new DangerousEntry("System Informer", SecurityStatus.Warning, "System Informer (ex-Process Hacker) est un outil d'administration avancé. Sa présence doit être justifiée.", "Vérifier l'autorisation. Supprimer des postes standards.", "https://systeminformer.sourceforge.io/"),
		new DangerousEntry("x64dbg", SecurityStatus.Warning, "x64dbg est un débogueur Windows utilisé en rétro-ingénierie et analyse de malware. Sa présence sur un poste standard doit être justifiée.", "Acceptable uniquement sur les postes des analystes sécurité. Vérifier l'autorisation.", "https://x64dbg.com/"),
		new DangerousEntry("OllyDbg", SecurityStatus.Warning, "OllyDbg est un débogueur Windows utilisé en rétro-ingénierie. Sa présence sur un poste standard doit être justifiée.", "Acceptable uniquement sur les postes des analystes sécurité.", "http://www.ollydbg.de/"),
		new DangerousEntry("IDA Pro", SecurityStatus.Warning, "IDA Pro est un désassembleur/débogueur professionnel. Outil de rétro-ingénierie avancé dont la présence doit être justifiée.", "Acceptable uniquement sur les postes des analystes malware/sécurité. Vérifier la licence et l'autorisation.", "https://hex-rays.com/ida-pro/"),
		new DangerousEntry("Ghidra", SecurityStatus.Warning, "Ghidra est un outil de rétro-ingénierie développé par la NSA. Sa présence doit être justifiée par un rôle d'analyste sécurité.", "Acceptable uniquement sur les postes dédiés à l'analyse de sécurité.", "https://ghidra-sre.org/"),
		new DangerousEntry("Burp Suite", SecurityStatus.Warning, "Burp Suite est un proxy d'interception HTTP utilisé pour les tests d'intrusion web. Sa présence sur un poste standard est anormale.", "Acceptable uniquement sur les postes des testeurs d'intrusion. Vérifier l'autorisation.", "https://portswigger.net/burp"),
		new DangerousEntry("Tor Browser", SecurityStatus.Warning, "Le navigateur Tor permet une navigation anonymisée via le réseau Tor. Son usage peut contourner les contrôles de filtrage web de l'entreprise.", "Vérifier si l'usage est autorisé. Généralement proscrit sur les systèmes d'entreprise.", "https://www.torproject.org/"),
		new DangerousEntry("ProxyCap", SecurityStatus.Warning, "ProxyCap est un outil de tunneling qui peut être utilisé pour contourner les contrôles réseau de l'entreprise.", "Vérifier si l'usage est autorisé. Supprimer si non justifié.", "https://www.proxycap.com/")
	};

	private static readonly List<VersionedEntry> VersionedSoftwareList = new List<VersionedEntry>
	{
		new VersionedEntry("WinRAR", "6.23", SecurityStatus.Critical, "WinRAR version {0} est vulnérable à CVE-2023-38831 (RCE critique). La version minimale sécurisée est {1}.", "Mettre à jour WinRAR vers la version 6.23 ou supérieure immédiatement. CVE-2023-38831 est activement exploitée dans la nature.", "https://nvd.nist.gov/vuln/detail/CVE-2023-38831"),
		new VersionedEntry("PuTTY", "0.81", SecurityStatus.Critical, "PuTTY version {0} est vulnérable à CVE-2024-31497 (fuite de clé privée ECDSA via biais dans la génération de nonces). Version minimale sécurisée : {1}.", "Mettre à jour PuTTY vers la version 0.81 ou supérieure. Révoquer et régénérer toutes les clés privées ECDSA potentiellement exposées.", "https://nvd.nist.gov/vuln/detail/CVE-2024-31497"),
		new VersionedEntry("VLC", "3.0.20", SecurityStatus.Warning, "VLC version {0} peut présenter des vulnérabilités corrigées dans la version {1}.", "Mettre à jour VLC media player vers la version 3.0.20 ou supérieure.", "https://www.videolan.org/security/"),
		new VersionedEntry("7-Zip", "24.0", SecurityStatus.Info, "7-Zip version {0} peut être concerné par CVE-2024-11477. Version minimale recommandée : {1}.", "Mettre à jour 7-Zip vers la version 24.x pour bénéficier des derniers correctifs de sécurité.", "https://nvd.nist.gov/vuln/detail/CVE-2024-11477"),
		new VersionedEntry("Adobe Acrobat", "2024.0", SecurityStatus.Warning, "Adobe Acrobat/Reader version {0} peut présenter des vulnérabilités. Les versions antérieures à 2024 ne reçoivent plus de mises à jour de sécurité actives.", "Mettre à jour Adobe Acrobat/Reader vers la version 2024 ou supérieure, ou migrer vers un lecteur PDF alternatif maintenu.", "https://helpx.adobe.com/security/products/acrobat.html")
	};

	public string Name => "Inventaire Logiciels";

	public string Category => "Gestion des Actifs";

	public async Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch sw = Stopwatch.StartNew();
		try
		{
			await Task.Run(delegate
			{
				ct.ThrowIfCancellationRequested();
				List<SoftwareEntry> software = CollectInstalledSoftware(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckDangerousSoftware(report.Results, software, ct);
				ct.ThrowIfCancellationRequested();
				CheckSecuritySoftware(report.Results, software, ct);
				ct.ThrowIfCancellationRequested();
				CheckWindowsFeatures(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckDotNetVersions(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckBrowserExtensions(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckAppxPackages(report.Results, ct);
			}, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception fatalEx)
		{
			report.ErrorMessage = "SoftwareInventoryCollector — erreur fatale : " + fatalEx.Message;
		}
		finally
		{
			sw.Stop();
			report.Duration = sw.Elapsed;
		}
		return report;
	}

	private List<SoftwareEntry> CollectInstalledSoftware(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		Dictionary<string, SoftwareEntry> all = new Dictionary<string, SoftwareEntry>(StringComparer.OrdinalIgnoreCase);
		using (RegistryKey hklm64Key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
		{
			EnumerateHive(hklm64Key, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
		}
		ct.ThrowIfCancellationRequested();
		using (RegistryKey hklm32Key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
		{
			EnumerateHive(hklm32Key, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
		}
		ct.ThrowIfCancellationRequested();
		using (RegistryKey hkcuKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
		{
			EnumerateHive(hkcuKey, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
		}
		ct.ThrowIfCancellationRequested();
		// Amélioration 1 : parcourir les autres profils utilisateurs via HKEY_USERS.
		// Sur une machine multi-utilisateurs, les logiciels installés « par utilisateur » par
		// d'autres comptes ne sont pas visibles dans le seul HKCU du compte qui exécute le scan.
		// Best-effort : certains profils sont déchargés / nécessitent des droits.
		// La déduplication est assurée par le dictionnaire 'all' (clé DisplayName+Version)
		// et le test 'if (!all.ContainsKey(entryKey))' déjà présent dans EnumerateHive.
		int profilesScanned = 0;
		try
		{
			using RegistryKey usersBaseKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
			// SID système/service à ignorer (LocalSystem, LocalService, NetworkService).
			HashSet<string> systemSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
			{
				"S-1-5-18", "S-1-5-19", "S-1-5-20"
			};
			foreach (string sidName in usersBaseKey.GetSubKeyNames())
			{
				ct.ThrowIfCancellationRequested();
				// Ne garder que les SID de comptes utilisateurs réels (S-1-5-21-...).
				// Ignorer les hives *_Classes et les SID système/service.
				if (string.IsNullOrEmpty(sidName)
					|| sidName.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)
					|| !sidName.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
					|| systemSids.Contains(sidName))
				{
					continue;
				}
				try
				{
					// Vue 64-bit puis vue 32-bit (WOW6432Node) du profil.
					EnumerateHive(usersBaseKey, sidName + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
					EnumerateHive(usersBaseKey, sidName + "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
					profilesScanned++;
				}
				catch (OperationCanceledException)
				{
					throw;
				}
				catch (Exception)
				{
					// Un profil illisible (déchargé, droits insuffisants) ne doit pas casser le collecteur.
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception)
		{
		}
		ct.ThrowIfCancellationRequested();
		List<SoftwareEntry> sortedSoftware = all.Values.OrderBy((SoftwareEntry s) => s.DisplayName).ToList();
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Inventaire : Nombre total de logiciels",
			CurrentValue = $"{sortedSoftware.Count} logiciels détectés",
			ExpectedValue = "Inventaire complet",
			Status = SecurityStatus.Info,
			Description = $"{sortedSoftware.Count} logiciels uniques ont été détectés dans le registre Windows (HKLM 64-bit, HKLM 32-bit/WOW6432Node, HKCU, et {profilesScanned} autre(s) profil(s) utilisateur via HKEY_USERS). " + "Cette méthode basée sur le registre est plus fiable et plus rapide que WMI Win32_Product qui peut déclencher des réparations MSI.",
			Recommendation = "Maintenir un inventaire logiciel à jour et supprimer les logiciels inutilisés pour réduire la surface d'attaque.",
			Reference = "https://learn.microsoft.com/windows/win32/msi/uninstall-registry-key"
		});
		List<SoftwareEntry> recent = (from s in sortedSoftware
			where !string.IsNullOrEmpty(s.InstallDate) && s.InstallDate.Length == 8
			orderby s.InstallDate descending
			select s).Take(50).ToList();
		if (recent.Count > 0)
		{
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Inventaire : 50 logiciels récents (par date d'installation)",
				CurrentValue = string.Join(" | ", recent.Select((SoftwareEntry s) => $"{s.DisplayName} {s.Version} ({FormatInstallDate(s.InstallDate)})")),
				ExpectedValue = "Suivi des installations récentes",
				Status = SecurityStatus.Info,
				Description = "Les 50 logiciels installés le plus récemment. Surveiller les installations inattendues, particulièrement sur des systèmes de production.",
				Recommendation = "Comparer la liste avec les tickets de changement (ITSM). Toute installation non documentée doit être investiguée.",
				Reference = ""
			});
		}
		IEnumerable<string> byPublisher = from g in (from s in sortedSoftware
				group s by (!string.IsNullOrWhiteSpace(s.Publisher)) ? s.Publisher : "(Éditeur inconnu)" into g
				orderby g.Count() descending
				select g).Take(10)
			select $"{g.Key}: {g.Count()}";
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Inventaire : Top 10 éditeurs",
			CurrentValue = string.Join(" | ", byPublisher),
			ExpectedValue = "Répartition des éditeurs",
			Status = SecurityStatus.Info,
			Description = "Répartition des logiciels installés par éditeur (top 10). Permet d'identifier les éditeurs dominants et les logiciels sans éditeur (potentiellement dangereux).",
			Recommendation = "Investiguer les logiciels sans éditeur identifié. Vérifier que tous les éditeurs sont approuvés par la politique d'achat.",
			Reference = ""
		});
		return sortedSoftware;
		void EnumerateHive(RegistryKey baseKey, string subPath)
		{
			try
			{
				using RegistryKey uninstallKey = baseKey.OpenSubKey(subPath);
				if (uninstallKey != null)
				{
					string[] subKeyNames = uninstallKey.GetSubKeyNames();
					foreach (string name in subKeyNames)
					{
						ct.ThrowIfCancellationRequested();
						try
						{
							using RegistryKey appKey = uninstallKey.OpenSubKey(name);
							if (appKey != null)
							{
								string displayName = (appKey.GetValue("DisplayName") as string) ?? string.Empty;
								if (!string.IsNullOrWhiteSpace(displayName))
								{
									// Correctif fiabilité : ignorer les composants système (SystemComponent=1),
									// c.-à-d. redistribuables/KB/composants internes, pour ne pas polluer l'inventaire.
									object systemComponentValue = appKey.GetValue("SystemComponent");
									if (systemComponentValue != null)
									{
										int systemComponent = 0;
										try
										{
											systemComponent = Convert.ToInt32(systemComponentValue);
										}
										catch
										{
											systemComponent = 0;
										}
										if (systemComponent == 1)
										{
											continue;
										}
									}
									string displayVersion = (appKey.GetValue("DisplayVersion") as string) ?? string.Empty;
									string publisher = (appKey.GetValue("Publisher") as string) ?? string.Empty;
									string installDate = (appKey.GetValue("InstallDate") as string) ?? string.Empty;
									long estimatedSizeKb = 0L;
									object sizeValue = appKey.GetValue("EstimatedSize");
									if (sizeValue != null)
									{
										// Correctif fiabilité : isoler le parsing d'EstimatedSize pour qu'une valeur
										// malformée ne fasse pas sauter TOUTE l'entrée logiciel (0 en cas d'échec).
										try
										{
											estimatedSizeKb = Convert.ToInt64(sizeValue);
										}
										catch
										{
											estimatedSizeKb = 0L;
										}
									}
									string entryKey = displayName + "|" + displayVersion;
									if (!all.ContainsKey(entryKey))
									{
										all[entryKey] = new SoftwareEntry(displayName, displayVersion, publisher, installDate, estimatedSizeKb);
									}
								}
							}
						}
						catch (OperationCanceledException)
						{
							throw;
						}
						catch (Exception)
						{
						}
					}
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception)
			{
			}
		}
	}

	private static string FormatInstallDate(string raw)
	{
		if (raw.Length == 8 && int.TryParse(raw.Substring(0, 4), out var year) && int.TryParse(raw.Substring(4, 2), out var month) && int.TryParse(raw.Substring(6, 2), out var day))
		{
			try
			{
				return new DateTime(year, month, day).ToString("yyyy-MM-dd");
			}
			catch (Exception)
			{
			}
		}
		return raw;
	}

	// Amélioration 3 : matching moins fragile. Pour les fragments courts et ambigus
	// (moins de 4 caractères, ex. "SE"), on impose une correspondance à limites de mots
	// (\b...\b, insensible à la casse) afin de réduire les faux positifs (ex. "SE" qui
	// matcherait « Microsoft Visual C++ » ou n'importe quel mot contenant ces lettres).
	// Les fragments longs et non ambigus conservent le matching par sous-chaîne d'origine.
	private static bool FragmentMatches(string displayName, string fragment)
	{
		if (string.IsNullOrEmpty(displayName) || string.IsNullOrEmpty(fragment))
		{
			return false;
		}
		if (fragment.Length < 4)
		{
			try
			{
				return Regex.IsMatch(displayName, "\\b" + Regex.Escape(fragment) + "\\b", RegexOptions.IgnoreCase);
			}
			catch (Exception)
			{
				// En cas d'échec regex, on retombe sur le comportement par sous-chaîne.
				return displayName.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0;
			}
		}
		return displayName.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0;
	}

	private void CheckDangerousSoftware(List<SecurityResult> results, List<SoftwareEntry> software, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		int detectionCount = 0;
		foreach (DangerousEntry entry in DangerousSoftwareList)
		{
			ct.ThrowIfCancellationRequested();
			foreach (SoftwareEntry matchedSoftware in software.Where((SoftwareEntry s) => FragmentMatches(s.DisplayName, entry.MatchFragment)).ToList())
			{
				detectionCount++;
				string capturedName = matchedSoftware.DisplayName;
				string capturedVersion = matchedSoftware.Version;
				DangerousEntry capturedEntry = entry;
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Logiciel risqué : " + capturedName,
					CurrentValue = "Installé — version : " + (string.IsNullOrEmpty(capturedVersion) ? "inconnue" : capturedVersion),
					ExpectedValue = ((capturedEntry.Status == SecurityStatus.Critical) ? "Absent / désinstallé" : "Autorisé et justifié"),
					Status = capturedEntry.Status,
					Description = capturedEntry.Reason,
					Recommendation = capturedEntry.Recommendation,
					Reference = capturedEntry.Reference
				});
			}
		}
		foreach (VersionedEntry entry2 in VersionedSoftwareList)
		{
			ct.ThrowIfCancellationRequested();
			foreach (SoftwareEntry matchedVulnSoftware in software.Where((SoftwareEntry s) => FragmentMatches(s.DisplayName, entry2.MatchFragment)).ToList())
			{
				if (IsVersionLessThan(matchedVulnSoftware.Version, entry2.MinVersion))
				{
					detectionCount++;
					string capturedName2 = matchedVulnSoftware.DisplayName;
					string capturedVersion2 = matchedVulnSoftware.Version;
					VersionedEntry capturedEntry2 = entry2;
					TryAdd(results, () => new SecurityResult
					{
						Category = Category,
						CheckName = "Logiciel vulnérable : " + capturedName2,
						CurrentValue = "Version installée : " + (string.IsNullOrEmpty(capturedVersion2) ? "inconnue" : capturedVersion2) + " < " + capturedEntry2.MinVersion,
						ExpectedValue = ">= " + capturedEntry2.MinVersion,
						Status = capturedEntry2.Status,
						Description = string.Format(capturedEntry2.ReasonTemplate, capturedVersion2, capturedEntry2.MinVersion),
						Recommendation = capturedEntry2.Recommendation,
						Reference = capturedEntry2.Reference
					});
				}
			}
		}
		ct.ThrowIfCancellationRequested();
		CheckJavaVersions(results, software);
		if (detectionCount == 0)
		{
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Logiciels dangereux / obsolètes",
				CurrentValue = "Aucun logiciel dangereux connu détecté",
				ExpectedValue = "Aucun",
				Status = SecurityStatus.OK,
				Description = "Aucun logiciel de la liste de référence (EOL, CVE connues, outils de hacking) n'a été détecté.",
				Recommendation = "Maintenir cette liste à jour et ré-exécuter régulièrement l'inventaire.",
				Reference = ""
			});
		}
	}

	private void CheckJavaVersions(List<SecurityResult> results, List<SoftwareEntry> software)
	{
		foreach (SoftwareEntry javaEntry in software.Where((SoftwareEntry s) => s.DisplayName.IndexOf("Java", StringComparison.OrdinalIgnoreCase) >= 0 && (s.DisplayName.IndexOf("Runtime", StringComparison.OrdinalIgnoreCase) >= 0 || s.DisplayName.IndexOf("JRE", StringComparison.OrdinalIgnoreCase) >= 0 || s.DisplayName.IndexOf("JDK", StringComparison.OrdinalIgnoreCase) >= 0 || FragmentMatches(s.DisplayName, "SE"))).ToList())
		{
			string version = javaEntry.Version;
			string capturedName = javaEntry.DisplayName;
			string capturedVersion = version;
			if (version.StartsWith("6.") || version.StartsWith("7.") || capturedName.Contains(" 6 ") || capturedName.Contains(" 7 "))
			{
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Java EOL : " + capturedName,
					CurrentValue = "Version : " + capturedVersion,
					ExpectedValue = "Java 8u401 ou supérieur (Java 17/21 LTS recommandé)",
					Status = SecurityStatus.Critical,
					Description = "Java " + capturedVersion + " est en fin de vie depuis plusieurs années. De nombreuses CVE critiques non corrigées existent pour ces versions anciennes. Java 6 EOL depuis 2013, Java 7 EOL depuis 2015.",
					Recommendation = "Désinstaller Java 6/7 immédiatement. Migrer vers Java 17 LTS ou Java 21 LTS (versions LTS Oracle/OpenJDK actuelles).",
					Reference = "https://www.oracle.com/java/technologies/java-se-support-roadmap.html"
				});
			}
			else if ((version.StartsWith("8.") || capturedName.Contains(" 8 ") || capturedName.Contains("8u")) && IsJava8OlderThan401(version))
			{
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Java 8 obsolète : " + capturedName,
					CurrentValue = "Version : " + capturedVersion,
					ExpectedValue = ">= 8u401 (Java 8 Update 401)",
					Status = SecurityStatus.Critical,
					Description = "Java 8 version " + capturedVersion + " est antérieure à 8u401 et présente des vulnérabilités connues non corrigées.",
					Recommendation = "Mettre à jour vers Java 8u401 ou supérieur, ou migrer vers Java 17/21 LTS.",
					Reference = "https://www.oracle.com/java/technologies/javase/8-relnotes.html"
				});
			}
		}
	}

	private static bool IsJava8OlderThan401(string version)
	{
		string[] parts = version.Split('.');
		if (parts.Length >= 3 && int.TryParse(parts[2], out var build))
		{
			return ((build >= 1000) ? (build / 10) : build) < 401;
		}
		return false;
	}

	private static bool IsVersionLessThan(string installed, string minimum)
	{
		if (string.IsNullOrEmpty(installed))
		{
			return true;
		}
		try
		{
			Version installedVersion = NormalizeVersion(installed);
			Version minimumVersion = NormalizeVersion(minimum);
			return installedVersion < minimumVersion;
		}
		catch
		{
			return false;
		}
	}

	private static Version NormalizeVersion(string v)
	{
		StringBuilder versionBuilder = new StringBuilder();
		bool previousWasDot = false;
		foreach (char c in v)
		{
			if (char.IsDigit(c))
			{
				versionBuilder.Append(c);
				previousWasDot = false;
				continue;
			}
			if (c != '.' || previousWasDot)
			{
				break;
			}
			versionBuilder.Append(c);
			previousWasDot = true;
		}
		string normalized = versionBuilder.ToString().TrimEnd('.');
		if (string.IsNullOrEmpty(normalized))
		{
			return new Version(0, 0);
		}
		// Correctif H4 : l'ancienne boucle "while (parts.Length < 2)" ne recalculait jamais 'parts'
		// → boucle infinie pour une version sans point (ex. "2024"). Le return ci-dessous gère
		// déjà le padding (.0) via son ternaire, la boucle est donc supprimée.
		return Version.Parse((normalized.Split('.').Length < 2) ? (normalized + ".0") : normalized);
	}

	private void CheckSecuritySoftware(List<SecurityResult> results, List<SoftwareEntry> software, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		// Correctif fiabilité : suppression du doublon "Cylance" (présent deux fois), taille 28 → 27.
		string[] avKeywords = new string[27]
		{
			"Symantec", "Norton", "McAfee", "Trellix", "Trend Micro", "TrendMicro", "Kaspersky", "ESET", "Bitdefender", "Sophos",
			"CrowdStrike", "SentinelOne", "Carbon Black", "Cylance", "Malwarebytes", "Windows Defender", "Microsoft Defender", "F-Secure", "G Data", "Panda",
			"Avast", "AVG", "Avira", "Webroot", "Comodo", "Vipre", "Tanium"
		};
		string[] siemKeywords = new string[9] { "Splunk Universal Forwarder", "Splunk", "QRadar", "ArcSight", "Elastic Agent", "Elastic", "LogRhythm", "Sumo Logic", "Graylog" };
		string[] backupKeywords = new string[8] { "Veeam", "Acronis", "Commvault", "Backup Exec", "Arcserve", "Druva", "Zerto", "Carbonite" };
		List<string> detected = new List<string>();
		string[] currentKeywords = avKeywords;
		foreach (string avKeyword in currentKeywords)
		{
			ct.ThrowIfCancellationRequested();
			if (software.Any((SoftwareEntry s) => FragmentMatches(s.DisplayName, avKeyword)))
			{
				detected.Add("AV/EDR: " + avKeyword);
			}
		}
		currentKeywords = siemKeywords;
		foreach (string siemKeyword in currentKeywords)
		{
			ct.ThrowIfCancellationRequested();
			if (software.Any((SoftwareEntry s) => FragmentMatches(s.DisplayName, siemKeyword)))
			{
				detected.Add("SIEM/Agent: " + siemKeyword);
			}
		}
		currentKeywords = backupKeywords;
		foreach (string backupKeyword in currentKeywords)
		{
			ct.ThrowIfCancellationRequested();
			if (software.Any((SoftwareEntry s) => FragmentMatches(s.DisplayName, backupKeyword)))
			{
				detected.Add("Backup: " + backupKeyword);
			}
		}
		ct.ThrowIfCancellationRequested();
		bool sysmonFound = false;
		TryAdd(results, delegate
		{
			using RegistryKey servicesBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey servicesKey = servicesBaseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services");
			if (servicesKey != null)
			{
				string[] sysmonNames = new string[2] { "Sysmon", "Sysmon64" };
				foreach (string serviceName in sysmonNames)
				{
					using RegistryKey sysmonServiceKey = servicesKey.OpenSubKey(serviceName);
					if (sysmonServiceKey != null)
					{
						sysmonFound = true;
						detected.Add("Surveillance: " + serviceName);
						break;
					}
				}
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Sysmon : Service détecté",
				CurrentValue = (sysmonFound ? "Sysmon installé" : "Sysmon absent"),
				ExpectedValue = "Sysmon installé (recommandé)",
				Status = ((!sysmonFound) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Sysmon (System Monitor) est un service Windows qui journalise en détail les créations de processus, connexions réseau, modifications de fichiers. Il est fortement recommandé comme source de données pour la détection des menaces.",
				Recommendation = (sysmonFound ? "Sysmon est actif. Vérifier que sa configuration (sysmonconfig.xml) couvre les règles recommandées (SwiftOnSecurity ou Olaf Hartong)." : "Déployer Sysmon avec une configuration appropriée. Ressource : https://github.com/SwiftOnSecurity/sysmon-config"),
				Reference = "https://learn.microsoft.com/sysinternals/downloads/sysmon"
			};
		});
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Logiciels de sécurité détectés",
			CurrentValue = ((detected.Count > 0) ? string.Join(" | ", detected) : "Aucun logiciel de sécurité reconnu"),
			ExpectedValue = "Au moins un AV/EDR et un agent SIEM",
			Status = ((detected.Count <= 0) ? SecurityStatus.Warning : SecurityStatus.OK),
			Description = "Inventaire des logiciels de sécurité identifiés : antivirus, EDR, agents SIEM, outils de sauvegarde, outils de surveillance. Leur présence est un indicateur positif de maturité de sécurité.",
			Recommendation = ((detected.Count == 0) ? "Aucun logiciel de sécurité reconnu n'a été détecté. Vérifier l'inventaire manuellement et déployer un EDR si non présent." : "Vérifier que les logiciels de sécurité détectés sont à jour et actifs."),
			Reference = "https://www.cisa.gov/resources-tools/resources/free-cybersecurity-services-and-tools"
		});
	}

	private void CheckWindowsFeatures(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		Dictionary<string, (SecurityStatus, string, string, string)> featureMap = new Dictionary<string, (SecurityStatus, string, string, string)>
		{
			["TelnetClient"] = (SecurityStatus.Warning, "Le client Telnet transmet toutes les données (y compris les mots de passe) en clair sur le réseau. Il ne doit pas être installé sur les systèmes modernes.", "Désactiver la fonctionnalité Telnet Client : 'Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient'. Utiliser SSH à la place.", "https://attack.mitre.org/techniques/T1021/004/"),
			["TFTP"] = (SecurityStatus.Warning, "Le client TFTP (Trivial File Transfer Protocol) ne supporte aucune authentification. Il peut être utilisé pour exfiltrer des données ou télécharger des outils malveillants.", "Désactiver TFTP Client : 'Disable-WindowsOptionalFeature -Online -FeatureName TFTP'. Utiliser SFTP ou SCP pour les transferts sécurisés.", "https://attack.mitre.org/techniques/T1105/"),
			["MicrosoftWindowsPowerShellV2Root"] = (SecurityStatus.Warning, "PowerShell v2 ne supporte pas AMSI (Antimalware Scan Interface), ni la journalisation des blocs de script (Script Block Logging), ni Constrained Language Mode. Il peut être utilisé pour contourner les contrôles de sécurité basés sur PowerShell v5+.", "Désactiver PowerShell v2 : 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root'. Vérifier qu'aucun script ne dépend de PS v2.", "https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/"),
			["SMB1Protocol"] = (SecurityStatus.Critical, "SMBv1 est un protocole obsolète (30 ans) qui a permis la propagation des malwares WannaCry (CVE-2017-0144/EternalBlue) et NotPetya. Il ne doit absolument pas être activé sur des systèmes modernes.", "Désactiver SMBv1 immédiatement : 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'. Vérifier qu'aucun serveur NAS ou équipement ancien ne requiert SMBv1 (migrer vers SMBv2/v3).", "https://support.microsoft.com/kb/2696547"),
			["SimpleTCPIP"] = (SecurityStatus.Warning, "Simple TCP/IP Services installe des services echo, discard, daytime, chargen et qotd. Ces services peuvent être utilisés pour des attaques d'amplification ou de réflexion.", "Désactiver Simple TCP/IP Services : 'Disable-WindowsOptionalFeature -Online -FeatureName SimpleTCP'. Ces services n'ont aucun usage sur un système moderne.", "https://learn.microsoft.com/windows-server/networking/technologies/simple-tcpip-services")
		};
		bool anyFeatureDetected = false;
		try
		{
			using RegistryKey cbsBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey packagesKey = cbsBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages");
			if (packagesKey == null)
			{
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Fonctionnalités Windows optionnelles",
					CurrentValue = "Clé CBS introuvable",
					Status = SecurityStatus.Error,
					Description = "La clé de registre Component Based Servicing est introuvable. Vérifier les droits d'accès.",
					Recommendation = "Exécuter CHECKSEC en tant qu'administrateur.",
					Reference = ""
				});
				return;
			}
			foreach (string featureName in featureMap.Keys)
			{
				ct.ThrowIfCancellationRequested();
				(SecurityStatus, string, string, string) featureInfo = featureMap[featureName];
				bool featureInstalled = false;
				try
				{
					string[] subKeyNames = packagesKey.GetSubKeyNames();
					foreach (string packageName in subKeyNames)
					{
						ct.ThrowIfCancellationRequested();
						if (packageName.IndexOf(featureName, StringComparison.OrdinalIgnoreCase) < 0)
						{
							continue;
						}
						try
						{
							using RegistryKey packageKey = packagesKey.OpenSubKey(packageName);
							if (packageKey != null)
							{
								object stateValue = packageKey.GetValue("CurrentState");
								if (stateValue != null && Convert.ToInt32(stateValue) == 7)
								{
									featureInstalled = true;
									break;
								}
							}
						}
						catch (Exception)
						{
						}
					}
				}
				catch (OperationCanceledException)
				{
					throw;
				}
				catch (Exception)
				{
				}
				if (featureInstalled)
				{
					anyFeatureDetected = true;
					string capturedFeatureName = featureName;
					(SecurityStatus Status, string Description, string Recommendation, string Reference) capturedInfo = featureInfo;
					TryAdd(results, () => new SecurityResult
					{
						Category = Category,
						CheckName = "Fonctionnalité dangereuse : " + capturedFeatureName,
						CurrentValue = "Installée (State=7)",
						ExpectedValue = "Désactivée / Non installée",
						Status = capturedInfo.Status,
						Description = capturedInfo.Description,
						Recommendation = capturedInfo.Recommendation,
						Reference = capturedInfo.Reference
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
				CheckName = "Fonctionnalités Windows optionnelles",
				CurrentValue = "Erreur : " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Impossible d'énumérer les fonctionnalités Windows via le registre CBS.",
				Recommendation = "Exécuter CHECKSEC en tant qu'administrateur.",
				Reference = ""
			});
			return;
		}
		if (!anyFeatureDetected)
		{
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Fonctionnalités Windows optionnelles dangereuses",
				CurrentValue = "Aucune fonctionnalité dangereuse connue détectée",
				ExpectedValue = "Aucune",
				Status = SecurityStatus.OK,
				Description = "Aucune des fonctionnalités optionnelles dangereuses surveillées (Telnet, TFTP, PowerShell v2, SMBv1, SimpleTCP) n'est installée.",
				Recommendation = "Continuer à surveiller les fonctionnalités optionnelles lors des mises à jour de Windows.",
				Reference = ""
			});
		}
	}

	private void CheckDotNetVersions(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		List<string> detected = new List<string>();
		TryAdd(results, delegate
		{
			List<string> versions = new List<string>();
			using RegistryKey ndpBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey ndpKey = ndpBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP");
			if (ndpKey != null)
			{
				string[] subKeyNames = ndpKey.GetSubKeyNames();
				foreach (string versionName in subKeyNames)
				{
					ct.ThrowIfCancellationRequested();
					if (!(versionName == "v4"))
					{
						using RegistryKey versionKey = ndpKey.OpenSubKey(versionName);
						if (versionKey != null)
						{
							object installValue = versionKey.GetValue("Install");
							object spValue = versionKey.GetValue("SP");
							string versionString = versionKey.GetValue("Version") as string;
							if (installValue != null && Convert.ToInt32(installValue) == 1)
							{
								versions.Add($"{versionName} SP{spValue} ({versionString ?? "?"})");
							}
						}
					}
				}
			}
			using RegistryKey fullKey = ndpBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full");
			if (fullKey != null)
			{
				object releaseValue = fullKey.GetValue("Release");
				string releaseLabel = ((releaseValue != null) ? DecodeNetFxRelease(Convert.ToInt32(releaseValue)) : "v4 (release inconnu)");
				versions.Add(releaseLabel);
				detected.Add(releaseLabel);
			}
			if (versions.Count == 0)
			{
				versions.Add("Aucun .NET Framework détecté");
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = ".NET Framework : Versions installées",
				CurrentValue = string.Join(" | ", versions),
				ExpectedValue = ".NET Framework 4.8 ou supérieur",
				Status = SecurityStatus.Info,
				Description = "Versions du .NET Framework installées. .NET Framework 4.8 est la dernière version majeure du .NET Framework classique (Windows uniquement).",
				Recommendation = "S'assurer que les mises à jour cumulatives .NET Framework sont appliquées via Windows Update.",
				Reference = "https://learn.microsoft.com/dotnet/framework/migration-guide/versions-and-dependencies"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			List<string> coreVersions = new List<string>();
			using RegistryKey dotnetBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			string[] regEntries = new string[2] { "x64", "x86" };
			foreach (string arch in regEntries)
			{
				ct.ThrowIfCancellationRequested();
				using RegistryKey runtimeKey = dotnetBaseKey.OpenSubKey("SOFTWARE\\dotnet\\Setup\\InstalledVersions\\" + arch + "\\sharedfx\\Microsoft.NETCore.App");
				if (runtimeKey != null)
				{
					string[] valueNames = runtimeKey.GetValueNames();
					foreach (string runtimeVersion in valueNames)
					{
						ct.ThrowIfCancellationRequested();
						if (!string.IsNullOrEmpty(runtimeVersion))
						{
							coreVersions.Add($".NET {runtimeVersion} ({arch})");
						}
					}
				}
			}
			using RegistryKey sdkKey = dotnetBaseKey.OpenSubKey("SOFTWARE\\dotnet\\Setup\\InstalledVersions\\x64\\sdk");
			if (sdkKey != null)
			{
				regEntries = sdkKey.GetValueNames();
				foreach (string sdkVersion in regEntries)
				{
					ct.ThrowIfCancellationRequested();
					if (!string.IsNullOrEmpty(sdkVersion))
					{
						coreVersions.Add("SDK " + sdkVersion + " (x64)");
					}
				}
			}
			if (coreVersions.Count == 0)
			{
				coreVersions.Add("Aucun .NET 5+ détecté");
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = ".NET (Core) : Versions installées",
				CurrentValue = string.Join(" | ", coreVersions),
				ExpectedValue = ".NET 8 LTS ou .NET 9 (versions supportées)",
				Status = SecurityStatus.Info,
				Description = "Versions de .NET (anciennement .NET Core) installées. .NET 8 est la version LTS actuelle (support jusqu'en novembre 2026). .NET 9 est la version courante. Les versions .NET 5, 6, 7 sont en fin de vie.",
				Recommendation = "Migrer les applications .NET 5/6/7 vers .NET 8 LTS ou .NET 9. Supprimer les runtimes obsolètes non nécessaires.",
				Reference = "https://dotnet.microsoft.com/platform/support/policy/dotnet-core"
			};
		});
	}

	private static string DecodeNetFxRelease(int release)
	{
		if (release >= 393295)
		{
			if (release >= 461308)
			{
				if (release >= 528040)
				{
					if (release >= 533320)
					{
						return $"v4.8.1 (release {release})";
					}
					return $"v4.8 (release {release})";
				}
				if (release >= 461808)
				{
					return $"v4.7.2 (release {release})";
				}
				return $"v4.7.1 (release {release})";
			}
			if (release >= 394802)
			{
				if (release >= 460798)
				{
					return $"v4.7 (release {release})";
				}
				return $"v4.6.2 (release {release})";
			}
			if (release >= 394254)
			{
				return $"v4.6.1 (release {release})";
			}
			return $"v4.6 (release {release})";
		}
		if (release >= 378675)
		{
			if (release >= 379893)
			{
				return $"v4.5.2 (release {release})";
			}
			return $"v4.5.1 (release {release})";
		}
		if (release >= 378389)
		{
			return $"v4.5 (release {release})";
		}
		return $"v4 inconnu (release {release})";
	}

	private void CheckBrowserExtensions(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
		string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
		CheckBrowserExtensionPath(results, ct, "Google Chrome", Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Extensions"));
		ct.ThrowIfCancellationRequested();
		CheckBrowserExtensionPath(results, ct, "Microsoft Edge", Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Extensions"));
		ct.ThrowIfCancellationRequested();
		CheckFirefoxExtensions(results, ct, appData);
	}

	private void CheckBrowserExtensionPath(List<SecurityResult> results, CancellationToken ct, string browserName, string extensionsPath)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			if (!Directory.Exists(extensionsPath))
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = browserName + " : Extensions",
					CurrentValue = "Navigateur non installé ou profil absent",
					ExpectedValue = "< 20 extensions",
					Status = SecurityStatus.Info,
					Description = $"Le répertoire d'extensions {browserName} est introuvable. {browserName} n'est probablement pas installé pour cet utilisateur.",
					Recommendation = "",
					Reference = ""
				};
			}
			int extensionCount = (from d in Directory.GetDirectories(extensionsPath)
				where Path.GetFileName(d) != "Temp"
				select d).ToArray().Length;
			bool tooMany = extensionCount > 20;
			return new SecurityResult
			{
				Category = Category,
				CheckName = browserName + " : Extensions installées",
				CurrentValue = $"{extensionCount} extension(s)",
				ExpectedValue = "< 20 extensions",
				Status = (tooMany ? SecurityStatus.Warning : SecurityStatus.Info),
				Description = $"{extensionCount} extension(s) détectée(s) dans le profil {browserName} par défaut. " + "Un nombre élevé d'extensions augmente la surface d'attaque : les extensions peuvent accéder au contenu des pages web, intercepter des formulaires et exfiltrer des données sensibles.",
				Recommendation = (tooMany ? ($"Auditer les {extensionCount} extensions {browserName}. Supprimer les extensions non essentielles. " + "Utiliser une politique de groupe pour restreindre les extensions autorisées.") : ("Nombre d'extensions " + browserName + " acceptable. Vérifier régulièrement les extensions installées.")),
				Reference = "https://attack.mitre.org/techniques/T1176/"
			};
		});
	}

	private void CheckFirefoxExtensions(List<SecurityResult> results, CancellationToken ct, string appData)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			string profilesPath = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
			if (!Directory.Exists(profilesPath))
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Mozilla Firefox : Extensions",
					CurrentValue = "Firefox non installé ou profil absent",
					ExpectedValue = "< 20 extensions",
					Status = SecurityStatus.Info,
					Description = "Le répertoire de profils Firefox est introuvable. Firefox n'est probablement pas installé pour cet utilisateur.",
					Recommendation = "",
					Reference = ""
				};
			}
			int extensionCount = 0;
			int profileCount = 0;
			string[] directories = Directory.GetDirectories(profilesPath);
			foreach (string profileDir in directories)
			{
				ct.ThrowIfCancellationRequested();
				profileCount++;
				string extensionsDir = Path.Combine(profileDir, "extensions");
				if (Directory.Exists(extensionsDir))
				{
					extensionCount += Directory.GetFileSystemEntries(extensionsDir).Length;
				}
				extensionCount += Directory.GetFiles(profileDir, "*.xpi").Length;
			}
			bool tooMany = extensionCount > 20;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Mozilla Firefox : Extensions installées",
				CurrentValue = $"{extensionCount} extension(s) dans {profileCount} profil(s)",
				ExpectedValue = "< 20 extensions",
				Status = (tooMany ? SecurityStatus.Warning : SecurityStatus.Info),
				Description = $"{extensionCount} extension(s) Firefox détectée(s) dans {profileCount} profil(s). " + "Les extensions Firefox ont accès aux pages web et peuvent intercepter des données sensibles.",
				Recommendation = (tooMany ? $"Auditer les {extensionCount} extensions Firefox. Utiliser les politiques Firefox (policies.json) pour restreindre les extensions." : "Nombre d'extensions Firefox acceptable."),
				Reference = "https://support.mozilla.org/kb/add-ons-policies"
			};
		});
	}

	// Amélioration 2 : inventaire AppX / MSIX (applications Microsoft Store).
	// Ces applications ne figurent PAS dans les clés de désinstallation classiques et
	// étaient donc invisibles pour l'inventaire. On les énumère via le registre
	// (option la plus robuste : invariante à la localisation, rapide, sans dépendance
	// ni appel PowerShell) sous la clé AppModel\Repository\Packages.
	// Best-effort : try/catch englobant, agrégation (pas de liste de centaines de résultats).
	private void CheckAppxPackages(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int totalPackages = 0;
			// Éditeurs (PublisherId / DisplayName) non-Microsoft notables, dédupliqués.
			SortedSet<string> nonMicrosoftPublishers = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
			using RegistryKey appxBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey packagesKey = appxBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages");
			if (packagesKey == null)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "AppX / MSIX (Microsoft Store)",
					CurrentValue = "Dépôt AppX introuvable",
					ExpectedValue = "Inventaire des paquets AppX/MSIX",
					Status = SecurityStatus.Info,
					Description = "La clé de registre du dépôt de paquets AppX (AppModel\\Repository\\Packages) est introuvable. Les applications Microsoft Store ne peuvent pas être inventoriées via le registre sur ce système.",
					Recommendation = "Aucune action requise si le système n'utilise pas d'applications Store.",
					Reference = "https://learn.microsoft.com/windows/msix/"
				};
			}
			string[] packageFullNames = packagesKey.GetSubKeyNames();
			foreach (string packageFullName in packageFullNames)
			{
				ct.ThrowIfCancellationRequested();
				if (string.IsNullOrEmpty(packageFullName))
				{
					continue;
				}
				totalPackages++;
				try
				{
					// Le nom de la sous-clé est le PackageFullName :
					// Name_Version_Architecture_ResourceId_PublisherId
					// L'éditeur (PublisherId ou DisplayName) permet de repérer les paquets non-Microsoft.
					using RegistryKey packageKey = packagesKey.OpenSubKey(packageFullName);
					string publisher = string.Empty;
					if (packageKey != null)
					{
						publisher = (packageKey.GetValue("PublisherDisplayName") as string) ?? string.Empty;
					}
					// Un paquet est considéré « Microsoft » si son nom ou son éditeur le mentionne
					// explicitement (Microsoft, Windows). Sinon on le remonte comme non-Microsoft.
					bool isMicrosoft = packageFullName.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase)
						|| packageFullName.StartsWith("MicrosoftWindows.", StringComparison.OrdinalIgnoreCase)
						|| packageFullName.StartsWith("windows.", StringComparison.OrdinalIgnoreCase)
						|| packageFullName.StartsWith("MicrosoftCorporationII.", StringComparison.OrdinalIgnoreCase)
						|| publisher.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
					if (!isMicrosoft)
					{
						// Extraire le nom lisible (première partie avant le premier '_').
						int sep = packageFullName.IndexOf('_');
						string readableName = (sep > 0) ? packageFullName.Substring(0, sep) : packageFullName;
						nonMicrosoftPublishers.Add(string.IsNullOrWhiteSpace(publisher) ? readableName : (readableName + " (" + publisher + ")"));
					}
				}
				catch (OperationCanceledException)
				{
					throw;
				}
				catch (Exception)
				{
					// Un paquet illisible ne doit pas casser l'inventaire.
				}
			}
			// Liste courte des éditeurs non-Microsoft (max 15 pour ne pas gonfler le rapport).
			List<string> shortList = nonMicrosoftPublishers.Take(15).ToList();
			string nonMsSummary = (nonMicrosoftPublishers.Count == 0)
				? "aucun paquet non-Microsoft notable"
				: string.Join(", ", shortList) + ((nonMicrosoftPublishers.Count > shortList.Count) ? $" (+{nonMicrosoftPublishers.Count - shortList.Count} autre(s))" : string.Empty);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "AppX / MSIX : Paquets Microsoft Store",
				CurrentValue = $"{totalPackages} paquet(s) AppX/MSIX ; {nonMicrosoftPublishers.Count} non-Microsoft",
				ExpectedValue = "Inventaire maîtrisé des applications Store",
				Status = SecurityStatus.Info,
				Description = $"{totalPackages} paquets AppX/MSIX (applications Microsoft Store) sont enregistrés sur le système, dont {nonMicrosoftPublishers.Count} paquet(s) non-Microsoft. Éditeurs/paquets non-Microsoft notables : " + nonMsSummary + ". Ces applications ne figurent pas dans les clés de désinstallation classiques.",
				Recommendation = "Vérifier que les applications Store non-Microsoft installées sont autorisées par la politique de sécurité. Envisager une stratégie AppLocker / WDAC pour contrôler les paquets MSIX autorisés.",
				Reference = "https://learn.microsoft.com/windows/msix/"
			};
		});
	}

	private void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			results.Add(factory());
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
				CheckName = "Erreur de vérification",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les droits d'accès au registre et relancer en tant qu'administrateur.",
				Reference = ""
			});
		}
	}
}
