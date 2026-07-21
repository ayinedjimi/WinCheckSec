using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur CHECKSEC : Intégrité du démarrage (Secure Boot & UEFI).
// Vérifie les protections liées au démarrage et à l'intégrité du code noyau :
//  - Microsoft Vulnerable Driver Blocklist (anti-BYOVD) via le registre (signal fiable) ;
//  - options de démarrage sensibles via bcdedit (testsigning, nointegritychecks, debug...) ;
//  - synthèse de l'application de la signature des pilotes (Driver Signature Enforcement) ;
//  - mode des clés Secure Boot (contexte, best-effort) ;
//  - configuration au boot de HVCI (contexte, l'état running étant couvert par VbsSecurity).
public class BootIntegrityCollector : ISecurityCollector
{
	public string Name => "Intégrité du démarrage";

	public string Category => "Secure Boot & UEFI";

	public async Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch sw = Stopwatch.StartNew();
		try
		{
			// Timeout interne lié au token d'annulation reçu : borne la durée totale du collecteur.
			using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
			timeoutCts.CancelAfter(TimeSpan.FromSeconds(20L));
			CancellationToken internalCt = timeoutCts.Token;

			internalCt.ThrowIfCancellationRequested();
			// 1) Blocklist des pilotes vulnérables (registre) — signal le plus fiable.
			CollectVulnerableDriverBlocklist(report.Results, internalCt);

			internalCt.ThrowIfCancellationRequested();
			// 2) Options de démarrage bcdedit (testsigning, nointegritychecks, debug...).
			Dictionary<string, string> bcdOptions = await RunBcdEditAsync(internalCt);

			internalCt.ThrowIfCancellationRequested();
			CheckBootDebugOptions(report.Results, bcdOptions, internalCt);

			internalCt.ThrowIfCancellationRequested();
			// 3) Synthèse : application de la signature des pilotes.
			CheckDriverSignatureEnforcement(report.Results, bcdOptions, internalCt);

			internalCt.ThrowIfCancellationRequested();
			// 4) Mode des clés Secure Boot (contexte, best-effort).
			CollectSecureBootKeyMode(report.Results, internalCt);

			internalCt.ThrowIfCancellationRequested();
			// 5) Configuration HVCI au boot (contexte).
			CollectHvciBootConfiguration(report.Results, internalCt);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			report.ErrorMessage = "BootIntegrityCollector fatal error: " + ex2.Message;
		}
		finally
		{
			sw.Stop();
			report.Duration = sw.Elapsed;
		}
		return report;
	}

	// --- 1) Microsoft Vulnerable Driver Blocklist (anti-BYOVD) --------------------------------

	private void CollectVulnerableDriverBlocklist(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			// VulnerableDriverBlocklistEnable : 1 = activé (blocage BYOVD), 0/absent = non bloqué.
			int blocklist = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Control\\CI\\Config", "VulnerableDriverBlocklistEnable");
			bool isEnabled = blocklist == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Microsoft Vulnerable Driver Blocklist (BYOVD)",
				CurrentValue = ((blocklist == -1) ? "Non configuré (clé absente)" : (isEnabled ? "1 (Activé)" : "0 (Désactivé)")),
				ExpectedValue = "1 (Activé)",
				Status = (isEnabled ? SecurityStatus.OK : SecurityStatus.Warning),
				Description = "La Microsoft Vulnerable Driver Blocklist bloque le chargement des pilotes signés connus comme vulnérables. Elle contre les attaques BYOVD (Bring Your Own Vulnerable Driver), où un attaquant charge un pilote légitime mais vulnérable pour obtenir un accès noyau, désactiver l'EDR ou contourner les protections. C'est le signal le plus fiable car lu directement dans le registre.",
				Recommendation = (isEnabled ? "La blocklist des pilotes vulnérables est activée — protection BYOVD en place." : "Activer la blocklist : définir HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\\VulnerableDriverBlocklistEnable = 1 (activé automatiquement avec l'intégrité de la mémoire/HVCI et sur Windows 11 par défaut). Un redémarrage est requis."),
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules"
			};
		});
	}

	// --- 2) Options de démarrage bcdedit -------------------------------------------------------

	// Exécute 'bcdedit /enum {current}' et retourne les paires nom->valeur.
	// Les NOMS d'éléments bcdedit sont invariants de locale (testsigning, nointegritychecks, debug...),
	// seules les valeurs sont localisées (Yes/Oui/1). L'entrée "__error__" signale un échec.
	private async Task<Dictionary<string, string>> RunBcdEditAsync(CancellationToken ct)
	{
		Dictionary<string, string> options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		try
		{
			ProcessStartInfo startInfo = new ProcessStartInfo("bcdedit.exe", "/enum {current}")
			{
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true,
				// bcdedit écrit en encodage console (OEM) : lecture avec la page de codes OEM installée.
				StandardOutputEncoding = GetSafeOemEncoding()
			};

			// Timeout lié au token : borne l'exécution du processus.
			using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
			timeoutCts.CancelAfter(TimeSpan.FromSeconds(12L));

			using Process proc = Process.Start(startInfo);
			if (proc == null)
			{
				options["__error__"] = "Impossible de démarrer bcdedit.exe";
				return options;
			}

			string output;
			try
			{
				output = await proc.StandardOutput.ReadToEndAsync(timeoutCts.Token);
				await proc.WaitForExitAsync(timeoutCts.Token);
			}
			catch (OperationCanceledException)
			{
				// Annulation (token parent ou timeout) : on tue le processus pour ne pas le laisser en zombie.
				try
				{
					proc.Kill();
				}
				catch
				{
				}
				throw;
			}

			if (proc.ExitCode != 0)
			{
				// Sortie non nulle : typiquement accès refusé (bcdedit nécessite des privilèges administrateur).
				options["__error__"] = $"bcdedit a retourné le code {proc.ExitCode} (privilèges administrateur requis ?)";
				return options;
			}

			// Chaque ligne utile a la forme "<nom>    <valeur>" ; le nom est le premier token.
			string[] lines = output.Split(new char[2] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
			foreach (string rawLine in lines)
			{
				string line = rawLine.Trim();
				if (line.Length == 0)
				{
					continue;
				}
				int sep = -1;
				for (int i = 0; i < line.Length; i++)
				{
					if (line[i] == ' ' || line[i] == '\t')
					{
						sep = i;
						break;
					}
				}
				if (sep <= 0)
				{
					continue;
				}
				string key = line.Substring(0, sep).Trim();
				string value = line.Substring(sep).Trim();
				if (!string.IsNullOrEmpty(key))
				{
					// On conserve la dernière occurrence : suffisant pour les éléments recherchés.
					options[key] = value;
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			options["__error__"] = ex.Message;
		}
		return options;
	}

	// Détermine si une valeur bcdedit exprime un état "activé" (multi-locale : Yes/Oui/1/On/true).
	private static bool IsBcdValueEnabled(string value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return false;
		}
		string v = value.Trim();
		return v.Equals("Yes", StringComparison.OrdinalIgnoreCase)
			|| v.Equals("Oui", StringComparison.OrdinalIgnoreCase)
			|| v.Equals("1", StringComparison.OrdinalIgnoreCase)
			|| v.Equals("On", StringComparison.OrdinalIgnoreCase)
			|| v.Equals("true", StringComparison.OrdinalIgnoreCase)
			|| v.Equals("Ja", StringComparison.OrdinalIgnoreCase)
			|| v.Equals("Sí", StringComparison.OrdinalIgnoreCase)
			|| v.Equals("Si", StringComparison.OrdinalIgnoreCase);
	}

	private void CheckBootDebugOptions(List<SecurityResult> results, Dictionary<string, string> bcdOptions, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// Si bcdedit n'a pas pu être lu, on émet un seul résultat Info et on n'évalue pas les options.
		if (bcdOptions.ContainsKey("__error__"))
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Options de démarrage bcdedit",
				CurrentValue = "État bcdedit non lisible : " + bcdOptions["__error__"],
				ExpectedValue = "Sortie bcdedit lisible (exécution administrateur)",
				Status = SecurityStatus.Info,
				Description = "L'analyse des options de démarrage (testsigning, nointegritychecks, debug...) nécessite l'exécution de 'bcdedit /enum {current}' avec des privilèges administrateur. La sortie n'a pas pu être obtenue, ces vérifications ne peuvent donc pas être effectuées.",
				Recommendation = "Exécuter CHECKSEC en tant qu'administrateur pour permettre l'analyse des options de démarrage via bcdedit.",
				Reference = "https://learn.microsoft.com/windows-hardware/drivers/devtest/bcdedit"
			});
			return;
		}

		// Définition des éléments sensibles : (nom bcdedit, libellé, statut si activé, description).
		// Nom absent = état sûr par défaut (option désactivée) => OK.
		(string, string, SecurityStatus, string)[] checks = new (string, string, SecurityStatus, string)[5]
		{
			("testsigning", "Test Signing Mode",  SecurityStatus.Critical, "Le mode Test Signing autorise le chargement de pilotes signés par des certificats de test (non approuvés par Microsoft). Un attaquant peut ainsi charger des pilotes noyau arbitraires, contournant l'application de la signature des pilotes."),
			("nointegritychecks", "No Integrity Checks", SecurityStatus.Critical, "L'option nointegritychecks DÉSACTIVE la vérification de l'intégrité du code au démarrage, permettant le chargement de pilotes non signés ou altérés. C'est un contournement complet de la protection d'intégrité du noyau."),
			("debug", "Kernel Debugging", SecurityStatus.Warning, "Le débogage noyau (debug) est activé. Un débogueur connecté peut lire/modifier la mémoire noyau et désactiver des protections. À réserver aux machines de développement."),
			("bootdebug", "Boot Debugging", SecurityStatus.Warning, "Le débogage du chargeur de démarrage (bootdebug) est activé, exposant les premières phases du démarrage à un débogueur. À réserver au développement."),
			("flightsigning", "Flight Signing", SecurityStatus.Warning, "Le mode flightsigning autorise les pilotes signés par les certificats de préversion (Insider/Flight). Il élargit l'ensemble des pilotes acceptés au-delà de la production.")
		};

		foreach ((string, string, SecurityStatus, string) check in checks)
		{
			ct.ThrowIfCancellationRequested();
			string optionName = check.Item1;
			string label = check.Item2;
			SecurityStatus enabledStatus = check.Item3;
			string desc = check.Item4;
			TryAdd(results, delegate
			{
				bool present = bcdOptions.TryGetValue(optionName, out string rawValue);
				bool enabled = present && IsBcdValueEnabled(rawValue);
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Démarrage: " + label + " (" + optionName + ")",
					CurrentValue = (present ? (label + " présent = " + rawValue) : "Absent (désactivé par défaut)"),
					ExpectedValue = "Absent / désactivé",
					Status = (enabled ? enabledStatus : SecurityStatus.OK),
					Description = desc,
					Recommendation = (enabled
						? ("Désactiver l'option : exécuter 'bcdedit /set {current} " + optionName + " off' (ou /deletevalue) en administrateur, puis redémarrer. Vérifier pourquoi cette option a été activée (potentielle altération malveillante).")
						: (label + " n'est pas activé — état sûr (valeur par défaut).")),
					Reference = "https://learn.microsoft.com/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-"
				};
			});
		}
	}

	// --- 3) Synthèse Driver Signature Enforcement ---------------------------------------------

	private void CheckDriverSignatureEnforcement(List<SecurityResult> results, Dictionary<string, string> bcdOptions, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			bool bcdReadable = !bcdOptions.ContainsKey("__error__");
			bool testSigning = bcdOptions.TryGetValue("testsigning", out string tsVal) && IsBcdValueEnabled(tsVal);
			bool noIntegrity = bcdOptions.TryGetValue("nointegritychecks", out string niVal) && IsBcdValueEnabled(niVal);

			// L'application de la signature est contournée si testsigning OU nointegritychecks est actif.
			bool enforcementBypassed = testSigning || noIntegrity;

			SecurityStatus status;
			string currentValue;
			if (!bcdReadable)
			{
				status = SecurityStatus.Info;
				currentValue = "Indéterminé (sortie bcdedit non lisible)";
			}
			else if (enforcementBypassed)
			{
				status = SecurityStatus.Critical;
				currentValue = "Contournée (" + (testSigning ? "testsigning " : "") + (noIntegrity ? "nointegritychecks" : "").Trim() + ")";
			}
			else
			{
				status = SecurityStatus.OK;
				currentValue = "Active (aucun contournement détecté)";
			}

			return new SecurityResult
			{
				Category = Category,
				CheckName = "Driver Signature Enforcement (synthèse)",
				CurrentValue = currentValue,
				ExpectedValue = "Active (testsigning et nointegritychecks désactivés)",
				Status = status,
				Description = "L'application de la signature des pilotes (Driver Signature Enforcement, DSE) impose que tout pilote en mode noyau soit signé par un éditeur approuvé. Cette synthèse est déduite des options de démarrage : testsigning et nointegritychecks désactivent chacune cette protection. Sans DSE, des rootkits et pilotes malveillants peuvent être chargés dans le noyau.",
				Recommendation = (status == SecurityStatus.OK
					? "L'application de la signature des pilotes est active — bon état."
					: (status == SecurityStatus.Critical
						? "URGENT : réactiver l'application de la signature en désactivant testsigning et nointegritychecks via bcdedit (voir vérifications ci-dessus), puis redémarrer."
						: "Impossible de déterminer l'état de la signature des pilotes : exécuter CHECKSEC en administrateur pour lire bcdedit.")),
				Reference = "https://learn.microsoft.com/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-"
			};
		});
	}

	// --- 4) Mode des clés Secure Boot (best-effort, contexte) ---------------------------------

	private void CollectSecureBootKeyMode(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			// La présence de la clé SecureBoot indique un firmware UEFI compatible.
			// On tente de distinguer un mode "clés personnalisées" du mode standard (best-effort).
			// Note : le Setup Mode est couvert par un autre collecteur — on ne le duplique pas ici.
			bool keyPresent = false;
			string detail = "Non lisible";
			try
			{
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey sbKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot");
				if (sbKey != null)
				{
					keyPresent = true;
					using RegistryKey stateKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
					// UEFICAMode / autres valeurs peuvent renseigner sur le jeu de clés utilisé.
					object customMode = stateKey?.GetValue("UEFISecureBootEnabled");
					object caMode = stateKey?.GetValue("UEFICAMode");
					if (caMode != null && !(caMode is DBNull))
					{
						int mode = Convert.ToInt32(caMode);
						// 0 : clés Microsoft standard ; valeurs non nulles : jeu de clés personnalisé/étendu (indicatif).
						detail = (mode == 0) ? "Clés standard (Microsoft)" : $"Mode clés personnalisées/étendu (UEFICAMode={mode})";
					}
					else if (customMode != null && !(customMode is DBNull))
					{
						detail = "Secure Boot présent (mode clés non détaillé)";
					}
					else
					{
						detail = "Secure Boot présent (détail des clés indisponible)";
					}
				}
			}
			catch
			{
				keyPresent = false;
				detail = "Accès registre SecureBoot indisponible";
			}

			return new SecurityResult
			{
				Category = Category,
				CheckName = "Secure Boot — mode des clés",
				CurrentValue = (keyPresent ? detail : "Clé SecureBoot absente (firmware Legacy/BIOS ou accès restreint)"),
				ExpectedValue = "Clés standard Microsoft ou clés personnalisées maîtrisées",
				Status = SecurityStatus.Info,
				Description = "Secure Boot valide la chaîne de démarrage à l'aide de clés stockées dans le firmware UEFI. Le mode « clés personnalisées » (Custom Keys) permet d'approuver des composants supplémentaires ; il est légitime en environnement maîtrisé mais peut, s'il est mal géré, autoriser des chargeurs de démarrage non Microsoft. Ce contrôle est informatif (l'état d'activation de Secure Boot et le Setup Mode sont évalués ailleurs).",
				Recommendation = (keyPresent
					? "Vérifier que le mode des clés Secure Boot correspond à la politique de l'organisation (clés Microsoft standard, ou clés personnalisées documentées et maîtrisées)."
					: "Si le matériel le supporte, activer Secure Boot dans le firmware UEFI et utiliser un jeu de clés maîtrisé."),
				Reference = "https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-secure-boot"
			};
		});
	}

	// --- 5) Configuration HVCI au boot (contexte) ---------------------------------------------

	private void CollectHvciBootConfiguration(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			// État configuré au boot (registre) ; l'état "running" réel est fourni par VbsSecurity.
			int hvciEnabled = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", "Enabled");
			bool configured = hvciEnabled == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "HVCI configuré au démarrage (contexte)",
				CurrentValue = ((hvciEnabled == -1) ? "Non configuré (clé absente)" : (configured ? "Enabled=1 (activé au boot)" : $"Enabled={hvciEnabled}")),
				ExpectedValue = "1 (activé) — recoupe l'état running de VbsSecurity",
				Status = SecurityStatus.Info,
				Description = "HypervisorEnforcedCodeIntegrity (HVCI) valide l'intégrité du code noyau via la virtualisation matérielle et empêche le chargement de pilotes non signés/altérés. Cette valeur de registre reflète la configuration prévue au démarrage ; l'état d'exécution effectif (running) est déjà évalué par le collecteur VBS/Isolation du noyau. Ce contrôle apporte le contexte de démarrage sans le dupliquer.",
				Recommendation = (configured
					? "HVCI est configuré pour s'activer au démarrage. Confirmer l'état d'exécution via le collecteur VBS/Isolation du noyau."
					: "Pour renforcer l'intégrité du démarrage, activer l'intégrité de la mémoire (HVCI) via Sécurité Windows > Sécurité de l'appareil > Isolation du noyau, ou via GPO/MDM. Un redémarrage est requis."),
				Reference = "https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity"
			};
		});
	}

	// --- Helpers ------------------------------------------------------------------------------

	private static int RegInt(string hive, string path, string valueName, int def = -1)
	{
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine);
			// Vue 64 bits explicite pour éviter la redirection WOW64 sur un processus 32 bits.
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

	private static Encoding GetSafeOemEncoding()
	{
		try
		{
			// Page de codes OEM installée : correspond à l'encodage de la console Windows.
			return Encoding.GetEncoding(CultureInfo.InstalledUICulture.TextInfo.OEMCodePage);
		}
		catch
		{
			return Encoding.UTF8;
		}
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
				Category = "Secure Boot & UEFI",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les permissions d'accès au registre et l'exécution en administrateur (bcdedit).",
				Reference = ""
			});
		}
	}
}
