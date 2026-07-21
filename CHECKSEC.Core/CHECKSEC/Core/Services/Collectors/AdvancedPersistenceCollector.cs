using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur de mécanismes de persistance avancés NON couverts par AutoRunsCollector :
// COM hijacking (HKCU), AppCertDlls, AppInit_DLLs (contrôle croisé), packages LSA,
// backdoors des binaires d'accessibilité via IFEO Debugger, moniteurs d'impression et KnownDLLs.
// Règle transverse : tout binaire/DLL référencé depuis Temp/AppData/Users/Public/ProgramData
// (au lieu de System32 / Program Files) est considéré comme suspect.
public class AdvancedPersistenceCollector : ISecurityCollector
{
	// Packages LSA légitimes standard (comparaison insensible à la casse).
	private static readonly HashSet<string> KnownLsaPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		"msv1_0", "kerberos", "wdigest", "tspkg", "pku2u", "cloudap", "schannel", "negoexts"
	};

	// Binaires d'accessibilité classiquement détournés (backdoor « Sticky Keys »).
	private static readonly string[] AccessibilityBinaries = new string[]
	{
		"sethc.exe", "utilman.exe", "osk.exe", "Narrator.exe", "Magnify.exe", "DisplaySwitch.exe", "AtBroker.exe"
	};

	public string Name => "Persistance avancée";

	public string Category => "Autoruns & Persistance";

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
			CollectComHijacking(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectAppCertDlls(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectAppInitDlls(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectLsaPackages(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectAccessibilityBackdoors(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectPrintMonitors(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectKnownDlls(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "AdvancedPersistenceCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// ------------------------------------------------------------------
	// COM Hijacking : un CLSID redéfini dans HKCU\Software\Classes\CLSID surcharge
	// la définition HKLM. S'il pointe vers un chemin utilisateur (AppData/Temp), c'est
	// une technique de hijack COM classique.
	// ------------------------------------------------------------------
	private void CollectComHijacking(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		int suspiciousCount = 0;
		int totalOverrides = 0;
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
			using RegistryKey clsidRoot = baseKey.OpenSubKey("Software\\Classes\\CLSID");
			if (clsidRoot != null)
			{
				string[] clsids = clsidRoot.GetSubKeyNames();
				foreach (string clsid in clsids)
				{
					ct.ThrowIfCancellationRequested();
					// On lit InprocServer32 (DLL) et LocalServer32 (EXE).
					string inproc = ReadClsidServer(clsidRoot, clsid, "InprocServer32");
					string local = ReadClsidServer(clsidRoot, clsid, "LocalServer32");
					if (string.IsNullOrEmpty(inproc) && string.IsNullOrEmpty(local))
					{
						continue;
					}
					totalOverrides++;
					// Le serveur effectivement examiné (priorité à InprocServer32).
					string server = !string.IsNullOrEmpty(inproc) ? inproc : local;
					string serverType = !string.IsNullOrEmpty(inproc) ? "InprocServer32" : "LocalServer32";
					bool suspicious = IsSuspiciousPath(server);
					// N'émettre un résultat individuel QUE pour les surcharges vers un chemin
					// SUSPECT : un système normal comporte des milliers de CLSID HKCU légitimes,
					// il ne faut donc pas générer un Warning par CLSID (bruit + score faussé).
					// Les surcharges non suspectes sont uniquement comptées pour la synthèse.
					if (suspicious)
					{
						suspiciousCount++;
						string capturedClsid = clsid;
						string capturedServer = server;
						string capturedType = serverType;
						TryAdd(results, () => new SecurityResult
						{
							Category = Category,
							CheckName = "COM Hijacking (HKCU): " + capturedClsid,
							CurrentValue = capturedType + " = " + capturedServer,
							ExpectedValue = "Aucune surcharge HKCU vers un chemin utilisateur (AppData/Temp)",
							Status = SecurityStatus.Critical,
							Description = $"Le CLSID {capturedClsid} est redéfini dans HKCU\\Software\\Classes\\CLSID vers un chemin utilisateur (AppData/Temp/Users), signature typique d'un COM hijack pour persistance ou exécution furtive.",
							Recommendation = $"URGENT : investiguer le CLSID {capturedClsid}. Vérifier la légitimité du binaire '{capturedServer}'. Comparer avec la définition HKLM d'origine. Supprimer la clé HKCU\\Software\\Classes\\CLSID\\{capturedClsid} si non autorisée.",
							Reference = "https://attack.mitre.org/techniques/T1546/015/"
						});
					}
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
				CheckName = "COM Hijacking (HKCU)",
				CurrentValue = "Erreur : " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Échec de l'énumération de HKCU\\Software\\Classes\\CLSID.",
				Recommendation = "Vérifier les permissions d'accès au registre utilisateur.",
				Reference = ""
			});
			return;
		}
		// Résumé (Info si aucune surcharge, sinon récapitulatif).
		int total = totalOverrides;
		int susp = suspiciousCount;
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "COM Hijacking : Synthèse",
			CurrentValue = $"{total} CLSID surchargés en HKCU, {susp} vers un chemin utilisateur suspect",
			ExpectedValue = "0 surcharge vers un chemin utilisateur",
			Status = ((susp > 0) ? SecurityStatus.Critical : SecurityStatus.Info),
			Description = $"{total} CLSID sont redéfinis dans le ruche utilisateur (HKCU), dont {susp} pointant vers un chemin utilisateur suspect. Les surcharges HKCU sont un vecteur de persistance/hijack COM discret.",
			Recommendation = ((susp > 0) ? "Investiguer en priorité les CLSID marqués Critical ci-dessus." : "Aucune surcharge COM suspecte détectée dans HKCU."),
			Reference = "https://attack.mitre.org/techniques/T1546/015/"
		});
	}

	// Lit la valeur par défaut du sous-serveur (InprocServer32/LocalServer32) d'un CLSID HKCU.
	private static string ReadClsidServer(RegistryKey clsidRoot, string clsid, string serverSubKey)
	{
		try
		{
			using RegistryKey serverKey = clsidRoot.OpenSubKey(clsid + "\\" + serverSubKey);
			return serverKey?.GetValue(null)?.ToString() ?? string.Empty;
		}
		catch
		{
			return string.Empty;
		}
	}

	// ------------------------------------------------------------------
	// AppCertDLLs : toute DLL listée est injectée dans chaque process appelant
	// CreateProcess/CreateProcessAsUser/WinExec. La présence de la moindre valeur
	// est un indicateur de persistance/injection.
	// ------------------------------------------------------------------
	private void CollectAppCertDlls(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			List<string> values = new List<string>();
			bool anySuspicious = false;
			using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
			using (RegistryKey appCertKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"))
			{
				if (appCertKey != null)
				{
					foreach (string valueName in appCertKey.GetValueNames())
					{
						string dll = appCertKey.GetValue(valueName)?.ToString() ?? string.Empty;
						values.Add(valueName + " = " + dll);
						if (IsSuspiciousPath(dll))
						{
							anySuspicious = true;
						}
					}
				}
			}
			bool hasEntries = values.Count > 0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "AppCertDLLs",
				CurrentValue = (hasEntries ? string.Join(" | ", values) : "(vide)"),
				ExpectedValue = "Aucune valeur (clé vide ou absente)",
				// Toute valeur => Warning ; chemin utilisateur => Critical.
				Status = (hasEntries ? (anySuspicious ? SecurityStatus.Critical : SecurityStatus.Warning) : SecurityStatus.OK),
				Description = "Les DLL listées sous AppCertDlls sont chargées dans TOUT processus appelant CreateProcess. C'est un mécanisme d'injection global et de persistance rarement utilisé légitimement. Toute entrée doit être justifiée.",
				Recommendation = (hasEntries
					? "Investiguer chaque DLL listée sous HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls. Supprimer les entrées non autorisées (injection dans tout nouveau process)."
					: "Aucune entrée AppCertDlls — configuration attendue."),
				Reference = "https://attack.mitre.org/techniques/T1546/009/"
			};
		});
	}

	// ------------------------------------------------------------------
	// AppInit_DLLs : partiellement couvert par AutoRunsCollector. On ne remonte
	// un signal fort (Warning) que si non vide ET actif (LoadAppInit_DLLs=1).
	// Sinon Info (pour éviter la duplication bruyante).
	// ------------------------------------------------------------------
	private void CollectAppInitDlls(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string appInit = RegString("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "AppInit_DLLs") ?? string.Empty;
			int load = RegInt("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "LoadAppInit_DLLs");
			bool hasDlls = !string.IsNullOrWhiteSpace(appInit);
			bool active = load == 1 && hasDlls;
			bool suspicious = IsSuspiciousPath(appInit);
			SecurityStatus status;
			if (!hasDlls)
			{
				// Vide : simple confirmation contextuelle (déjà couvert par Autoruns).
				status = SecurityStatus.Info;
			}
			else if (active)
			{
				status = (suspicious ? SecurityStatus.Critical : SecurityStatus.Warning);
			}
			else
			{
				// DLL présente mais mécanisme désactivé (LoadAppInit_DLLs != 1).
				status = SecurityStatus.Warning;
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "AppInit_DLLs (contrôle croisé)",
				CurrentValue = $"LoadAppInit_DLLs={FormatReg(load)}, AppInit_DLLs=\"{appInit}\"",
				ExpectedValue = "AppInit_DLLs vide et LoadAppInit_DLLs=0",
				Status = status,
				Description = "AppInit_DLLs charge les DLL listées dans tout processus liant User32.dll. Mécanisme d'injection/persistance classique. Ce contrôle complète le collecteur Autoruns : il n'émet une alerte que si des DLL sont réellement configurées.",
				Recommendation = (active
					? ("AppInit_DLLs actif avec : \"" + appInit + "\". Vider AppInit_DLLs et définir LoadAppInit_DLLs=0 si non intentionnel.")
					: (hasDlls
						? "Des DLL sont présentes dans AppInit_DLLs bien que le mécanisme soit désactivé. Vérifier et nettoyer la valeur."
						: "AppInit_DLLs est vide — aucun risque de ce mécanisme.")),
				Reference = "https://attack.mitre.org/techniques/T1546/010/"
			};
		});
	}

	// ------------------------------------------------------------------
	// LSA Security Packages / Authentication Packages : tout package non standard
	// est un indicateur d'injection SSP (type mimilib / mimikatz).
	// ------------------------------------------------------------------
	private void CollectLsaPackages(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		(string valueName, string label)[] checks = new (string, string)[2]
		{
			("Security Packages", "LSA: Security Packages"),
			("Authentication Packages", "LSA: Authentication Packages")
		};
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey lsaKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
			foreach (var (valueName, label) in checks)
			{
				ct.ThrowIfCancellationRequested();
				string vn = valueName;
				string lbl = label;
				TryAdd(results, delegate
				{
					string[] packages = ReadMultiString(lsaKey, vn);
					// On tolère les entrées vides ("" utilisé comme séparateur historique).
					List<string> nonStandard = packages
						.Where(p => !string.IsNullOrWhiteSpace(p) && !KnownLsaPackages.Contains(p.Trim()))
						.Select(p => p.Trim())
						.ToList();
					bool hasNonStandard = nonStandard.Count > 0;
					return new SecurityResult
					{
						Category = Category,
						CheckName = lbl,
						CurrentValue = ((packages.Length == 0) ? "(aucun)" : string.Join(", ", packages)),
						ExpectedValue = "Packages standard uniquement (" + string.Join(", ", KnownLsaPackages) + ")",
						Status = (hasNonStandard ? SecurityStatus.Warning : SecurityStatus.OK),
						Description = "Les packages LSA (" + vn + ") sont chargés dans le processus LSASS. Un package non standard peut être une DLL de vol d'identifiants (SSP malveillant type mimilib), chargée à chaque authentification.",
						Recommendation = (hasNonStandard
							? ("Packages non standard détectés : " + string.Join(", ", nonStandard) + ". Vérifier la légitimité de chaque DLL correspondante dans System32 et retirer les entrées non autorisées de HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\" + vn + ".")
							: "Uniquement des packages LSA standard — configuration attendue."),
						Reference = "https://attack.mitre.org/techniques/T1547/005/"
					};
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
				CheckName = "LSA Packages",
				CurrentValue = "Erreur : " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Échec de lecture des packages LSA.",
				Recommendation = "Exécuter en tant qu'administrateur.",
				Reference = ""
			});
		}
	}

	// ------------------------------------------------------------------
	// Backdoors des binaires d'accessibilité (« Sticky Keys ») : un Debugger IFEO
	// sur sethc.exe/utilman.exe/etc. redirige l'exécution (souvent vers cmd.exe)
	// depuis l'écran de verrouillage => backdoor classique => Critical.
	// ------------------------------------------------------------------
	private void CollectAccessibilityBackdoors(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
		foreach (string exe in AccessibilityBinaries)
		{
			ct.ThrowIfCancellationRequested();
			string binary = exe;
			TryAdd(results, delegate
			{
				// 1) Debugger IFEO éventuel.
				string debugger = RegString("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + binary, "Debugger");
				bool hasDebugger = !string.IsNullOrWhiteSpace(debugger);
				// 2) Présence du fichier d'origine dans System32.
				string fullPath = Path.Combine(system32, binary);
				bool fileExists = false;
				try
				{
					fileExists = File.Exists(fullPath);
				}
				catch
				{
				}

				SecurityStatus status;
				string currentValue;
				string recommendation;
				if (hasDebugger)
				{
					// Backdoor Sticky Keys : critique quel que soit le chemin du debugger.
					status = SecurityStatus.Critical;
					currentValue = "IFEO Debugger = " + debugger + (fileExists ? "" : " ; fichier System32 ABSENT");
					recommendation = $"URGENT : un Debugger IFEO est défini sur {binary} (→ {debugger}). Backdoor d'accessibilité classique exploitable depuis l'écran de verrouillage. Supprimer immédiatement HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{binary}\\Debugger et rechercher une compromission.";
				}
				else if (!fileExists)
				{
					// Binaire manquant : anomalie (remplacement/suppression possible).
					status = SecurityStatus.Warning;
					currentValue = "Aucun Debugger IFEO ; mais " + fullPath + " est ABSENT";
					recommendation = $"Le binaire d'accessibilité {binary} est absent de System32. Vérifier s'il a été supprimé ou remplacé (sfc /scannow).";
				}
				else
				{
					status = SecurityStatus.OK;
					currentValue = "Aucun Debugger IFEO ; fichier présent (" + fullPath + ")";
					recommendation = "Aucune backdoor d'accessibilité détectée pour " + binary + ".";
				}
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Accessibilité (backdoor Sticky Keys): " + binary,
					CurrentValue = currentValue,
					ExpectedValue = "Aucun Debugger IFEO et binaire présent dans System32",
					Status = status,
					Description = $"Les binaires d'accessibilité comme {binary} sont lançables depuis l'écran de verrouillage. Un Debugger IFEO permet de rediriger leur exécution (souvent vers cmd.exe) pour obtenir un shell SYSTEM sans authentification.",
					Recommendation = recommendation,
					Reference = "https://attack.mitre.org/techniques/T1546/008/"
				};
			});
		}
	}

	// ------------------------------------------------------------------
	// Print Monitors : un moniteur d'impression dont la DLL (valeur "Driver") se
	// trouve hors System32 est suspect (persistance / exécution SYSTEM via spooler).
	// ------------------------------------------------------------------
	private void CollectPrintMonitors(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey monitorsKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors");
			if (monitorsKey == null)
			{
				return;
			}
			int flagged = 0;
			foreach (string monitor in monitorsKey.GetSubKeyNames())
			{
				ct.ThrowIfCancellationRequested();
				string driver;
				try
				{
					using RegistryKey monKey = monitorsKey.OpenSubKey(monitor);
					driver = monKey?.GetValue("Driver")?.ToString() ?? string.Empty;
				}
				catch
				{
					continue;
				}
				if (string.IsNullOrEmpty(driver))
				{
					continue;
				}
				// La valeur Driver est un nom de DLL relatif à System32 par défaut. On
				// ne signale que si un chemin absolu suspect (hors System32) est présent.
				bool hasPath = driver.Contains("\\");
				bool suspicious = hasPath && IsSuspiciousPath(driver);
				if (!suspicious)
				{
					continue;
				}
				flagged++;
				string capturedMonitor = monitor;
				string capturedDriver = driver;
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Print Monitor: " + capturedMonitor,
					CurrentValue = "Driver = " + capturedDriver,
					ExpectedValue = "DLL de moniteur dans System32",
					Status = SecurityStatus.Warning,
					Description = $"Le moniteur d'impression '{capturedMonitor}' référence une DLL '{capturedDriver}' hors de System32. Les moniteurs de port sont chargés par le service Spooler (SYSTEM) et sont un vecteur de persistance/élévation.",
					Recommendation = $"Vérifier la légitimité de la DLL '{capturedDriver}' du moniteur '{capturedMonitor}'. Supprimer l'entrée sous HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\{capturedMonitor} si non autorisée.",
					Reference = "https://attack.mitre.org/techniques/T1547/010/"
				});
			}
			if (flagged == 0)
			{
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Print Monitors",
					CurrentValue = "Aucun moniteur avec DLL en chemin non standard",
					ExpectedValue = "Uniquement des moniteurs standard (System32)",
					Status = SecurityStatus.OK,
					Description = "Aucun moniteur d'impression ne référence de DLL dans un chemin non standard.",
					Recommendation = "Aucune action requise.",
					Reference = "https://attack.mitre.org/techniques/T1547/010/"
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
				CheckName = "Print Monitors",
				CurrentValue = "Erreur : " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Échec de l'énumération des moniteurs d'impression.",
				Recommendation = "Exécuter en tant qu'administrateur.",
				Reference = ""
			});
		}
	}

	// ------------------------------------------------------------------
	// KnownDLLs : liste des DLL préchargées de confiance. Toute entrée inhabituelle
	// (pointant vers un chemin, ou non présente dans System32) est signalée (Info).
	// ------------------------------------------------------------------
	private void CollectKnownDlls(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey knownKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs");
			if (knownKey == null)
			{
				return;
			}
			List<string> unusual = new List<string>();
			foreach (string valueName in knownKey.GetValueNames())
			{
				ct.ThrowIfCancellationRequested();
				// DllDirectory / DllDirectory32 sont des valeurs de configuration, pas des DLL.
				if (valueName.StartsWith("DllDirectory", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
				string dll = knownKey.GetValue(valueName)?.ToString() ?? string.Empty;
				// Inhabituel si un chemin est présent (les KnownDLLs sont normalement de
				// simples noms de fichiers), ou si le fichier n'existe pas dans System32.
				bool hasPath = dll.Contains("\\") || dll.Contains("/");
				bool existsInSystem32 = false;
				try
				{
					existsInSystem32 = File.Exists(Path.Combine(system32, dll));
				}
				catch
				{
				}
				if (hasPath || !existsInSystem32)
				{
					unusual.Add(valueName + " = " + dll);
				}
			}
			bool hasUnusual = unusual.Count > 0;
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "KnownDLLs",
				CurrentValue = (hasUnusual ? string.Join(" | ", unusual) : "Toutes les entrées sont standard (noms simples présents dans System32)"),
				ExpectedValue = "Noms de DLL standard présents dans System32",
				// Signalement informatif (les faux positifs restent possibles).
				Status = (hasUnusual ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "KnownDLLs définit les DLL préchargées de confiance par le gestionnaire de session. Une entrée inhabituelle (chemin explicite ou DLL absente de System32) peut indiquer une tentative de détournement du mécanisme de chargement.",
				Recommendation = (hasUnusual
					? "Vérifier les entrées KnownDLLs inhabituelles listées. Comparer à une installation Windows saine ; toute entrée non standard doit être justifiée."
					: "Les entrées KnownDLLs correspondent aux DLL système attendues."),
				Reference = "https://attack.mitre.org/techniques/T1574/"
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
				CheckName = "KnownDLLs",
				CurrentValue = "Erreur : " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Échec de lecture de KnownDLLs.",
				Recommendation = "Exécuter en tant qu'administrateur.",
				Reference = ""
			});
		}
	}

	// ------------------------------------------------------------------
	// Détection de chemin suspect : binaire/DLL hébergé dans une zone inscriptible
	// par l'utilisateur (Temp/AppData/Users/Public/ProgramData) au lieu de
	// System32 / Program Files.
	// ------------------------------------------------------------------
	private static bool IsSuspiciousPath(string rawPath)
	{
		if (string.IsNullOrWhiteSpace(rawPath))
		{
			return false;
		}
		// On nettoie les guillemets et arguments éventuels, puis on développe les variables.
		string path = rawPath.Trim().Trim('"');
		try
		{
			path = Environment.ExpandEnvironmentVariables(path);
		}
		catch
		{
		}
		string lower = path.ToLowerInvariant();
		// Variables d'environnement non développées (contexte différent) prises en compte.
		if (lower.Contains("%temp%") || lower.Contains("%tmp%") || lower.Contains("%appdata%") || lower.Contains("%localappdata%") || lower.Contains("%public%"))
		{
			return true;
		}
		if (lower.Contains("\\temp\\") || lower.Contains("\\appdata\\") || lower.Contains("\\users\\") || lower.Contains("\\public\\"))
		{
			return true;
		}
		// ProgramData est suspect SAUF l'arborescence Microsoft (souvent légitime).
		if (lower.Contains("\\programdata\\") && !lower.Contains("\\programdata\\microsoft\\"))
		{
			return true;
		}
		return false;
	}

	private static string FormatReg(int value)
	{
		return (value == -1) ? "absent" : value.ToString();
	}

	// Lit une valeur REG_MULTI_SZ (ou une chaîne séparée par des NUL) sous forme de tableau.
	private static string[] ReadMultiString(RegistryKey key, string valueName)
	{
		if (key == null)
		{
			return Array.Empty<string>();
		}
		object raw = key.GetValue(valueName);
		if (raw is string[] arr)
		{
			return arr;
		}
		if (raw != null)
		{
			return raw.ToString().Split(new char[] { '\0', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
		}
		return Array.Empty<string>();
	}

	// ------------------------------------------------------------------
	// Helpers registre 64 bits (RegistryView.Registry64) — même contrat que les
	// autres collecteurs.
	// ------------------------------------------------------------------
	private static int RegInt(string hive, string path, string valueName, int def = -1)
	{
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine);
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
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine);
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			return subKey?.GetValue(valueName)?.ToString();
		}
		catch
		{
			return null;
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
				CheckName = "Erreur de vérification",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}
}
