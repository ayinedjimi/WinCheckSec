using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur CHECKSEC : durcissement des navigateurs (Microsoft Edge et Google Chrome).
// Il lit les stratégies (GPO / MDM) appliquées via le registre HKLM afin de vérifier que
// les principales fonctions de sécurité (SmartScreen/Safe Browsing, contrôle des extensions,
// restrictions de téléchargement, TLS minimum, gestionnaire de mots de passe) sont en place.
//
// Distinction importante :
//   - « navigateur NON géré par stratégie » : aucune clé Policies présente => Info (pas d'alerte).
//   - « configuré mais NON sécurisé »       : la ruche existe mais le réglage est absent/faible => Warning.
public class BrowserHardeningCollector : ISecurityCollector
{
	public string Name => "Durcissement navigateurs";

	public string Category => "Navigateurs";

	// Chemins des ruches de stratégie dans HKLM.
	private const string EdgePolicyPath = "SOFTWARE\\Policies\\Microsoft\\Edge";

	private const string ChromePolicyPath = "SOFTWARE\\Policies\\Google\\Chrome";

	// Références documentaires officielles.
	private const string EdgeReference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies";

	private const string ChromeReference = "https://chromeenterprise.google/policies/";

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
			CollectEdge(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectChrome(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			// Propagation de l'annulation sans la traiter comme une erreur fatale.
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "BrowserHardeningCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// ------------------------------------------------------------------
	// Microsoft Edge (SOFTWARE\Policies\Microsoft\Edge)
	// ------------------------------------------------------------------
	private void CollectEdge(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// Si la ruche de stratégie Edge n'existe pas => navigateur non géré : un seul résultat Info.
		if (!KeyExists(EdgePolicyPath))
		{
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Microsoft Edge — géré par stratégie",
				CurrentValue = "Aucune stratégie détectée (" + EdgePolicyPath + " absent)",
				ExpectedValue = "Navigateur géré par GPO/MDM",
				Status = SecurityStatus.Info,
				Description = "Aucune stratégie d'entreprise Microsoft Edge n'a été trouvée dans le registre. Le navigateur n'est pas géré par GPO/Intune : les fonctions de sécurité (SmartScreen, contrôle des extensions, restrictions de téléchargement, TLS minimum) dépendent alors des réglages utilisateur et ne sont pas verrouillées.",
				Recommendation = "Si Microsoft Edge est utilisé en entreprise, déployer les modèles d'administration Edge et appliquer une stratégie de durcissement (SmartScreen, extensions, téléchargements, TLS).",
				Reference = EdgeReference
			});
			return;
		}

		// --- SmartScreen (SmartScreenEnabled + PUA + PreventSmartScreenPromptOverride) ---
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int smartScreen = RegInt(EdgePolicyPath, "SmartScreenEnabled");
			int puaEnabled = RegInt(EdgePolicyPath, "SmartScreenPuaEnabled");
			int preventOverride = RegInt(EdgePolicyPath, "PreventSmartScreenPromptOverride");
			bool smartScreenOn = smartScreen == 1;
			bool puaOn = puaEnabled == 1;
			bool overrideBlocked = preventOverride == 1;
			bool fullyHardened = smartScreenOn && puaOn && overrideBlocked;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Edge: Microsoft Defender SmartScreen",
				CurrentValue = $"SmartScreenEnabled={FormatInt(smartScreen)}, PuaEnabled={FormatInt(puaEnabled)}, PreventPromptOverride={FormatInt(preventOverride)}",
				ExpectedValue = "SmartScreenEnabled=1, SmartScreenPuaEnabled=1, PreventSmartScreenPromptOverride=1",
				Status = (fullyHardened ? SecurityStatus.OK : (smartScreenOn ? SecurityStatus.Warning : SecurityStatus.Warning)),
				Description = "Microsoft Defender SmartScreen protège contre les sites d'hameçonnage, les téléchargements malveillants et les applications potentiellement indésirables (PUA). Le blocage de la possibilité de contourner l'avertissement (PreventSmartScreenPromptOverride) empêche l'utilisateur d'ignorer les alertes.",
				Recommendation = (fullyHardened ? "SmartScreen est pleinement activé et durci." : "Définir SmartScreenEnabled=1, SmartScreenPuaEnabled=1 et PreventSmartScreenPromptOverride=1 dans " + EdgePolicyPath + " via GPO."),
				Reference = EdgeReference
			};
		});

		// --- Gestionnaire de mots de passe (PasswordManagerEnabled) ---
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int pwdManager = RegInt(EdgePolicyPath, "PasswordManagerEnabled");
			// En environnement géré, 0 (désactivé au profit d'un coffre d'entreprise) est recommandé.
			bool disabled = pwdManager == 0;
			bool notConfigured = pwdManager == -1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Edge: Gestionnaire de mots de passe intégré",
				CurrentValue = FormatInt(pwdManager),
				ExpectedValue = "0 (désactivé) en environnement géré",
				Status = (disabled ? SecurityStatus.OK : (notConfigured ? SecurityStatus.Info : SecurityStatus.Warning)),
				Description = "Le gestionnaire de mots de passe intégré au navigateur stocke les identifiants dans le profil. En environnement géré, il est recommandé de le désactiver (PasswordManagerEnabled=0) au profit d'un coffre-fort d'entreprise centralisé et audité.",
				Recommendation = (disabled ? "Le gestionnaire de mots de passe intégré est désactivé." : (notConfigured ? "Réglage non configuré : définir explicitement PasswordManagerEnabled selon la politique (0 recommandé si un coffre d'entreprise est utilisé)." : "PasswordManagerEnabled=1 : le stockage des mots de passe dans le navigateur est actif. Envisager PasswordManagerEnabled=0 si un coffre d'entreprise est en place.")),
				Reference = EdgeReference
			};
		});

		// --- Extensions imposées/bloquées (blocklist "*" + allowlist/forcelist) ---
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string blockFirst = RegString(EdgePolicyPath + "\\ExtensionInstallBlocklist", "1");
			bool blockAll = string.Equals(blockFirst, "*", StringComparison.Ordinal);
			bool hasAllowlist = KeyExists(EdgePolicyPath + "\\ExtensionInstallAllowlist");
			bool hasForcelist = KeyExists(EdgePolicyPath + "\\ExtensionInstallForcelist");
			bool hasAllowOrForce = hasAllowlist || hasForcelist;
			bool hardened = blockAll && hasAllowOrForce;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Edge: Contrôle des extensions (blocklist/allowlist)",
				CurrentValue = $"ExtensionInstallBlocklist\\1={(blockFirst ?? "Non défini")}, Allowlist={(hasAllowlist ? "présente" : "absente")}, Forcelist={(hasForcelist ? "présente" : "absente")}",
				ExpectedValue = "Blocklist\\1=\"*\" (tout bloqué) + Allowlist ou Forcelist",
				Status = (hardened ? SecurityStatus.OK : (blockAll ? SecurityStatus.Warning : SecurityStatus.Warning)),
				Description = "Bloquer toutes les extensions par défaut (ExtensionInstallBlocklist\\1=\"*\") puis n'autoriser explicitement que celles validées (ExtensionInstallAllowlist) ou les imposer (ExtensionInstallForcelist) empêche l'installation d'extensions malveillantes ou d'exfiltration de données.",
				Recommendation = (hardened ? "Le contrôle des extensions est correctement durci (deny-all + liste d'autorisation)." : (blockAll ? "Blocklist \"*\" présente mais aucune Allowlist/Forcelist : définir la liste des extensions autorisées." : "Définir ExtensionInstallBlocklist\\1=\"*\" pour bloquer toutes les extensions par défaut, puis renseigner ExtensionInstallAllowlist/Forcelist.")),
				Reference = EdgeReference
			};
		});

		// --- Restrictions de téléchargement (DownloadRestrictions) ---
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int downloadRestrictions = RegInt(EdgePolicyPath, "DownloadRestrictions");
			bool restricted = downloadRestrictions >= 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Edge: Restrictions de téléchargement",
				CurrentValue = FormatInt(downloadRestrictions),
				ExpectedValue = ">= 1 (bloquer les téléchargements dangereux)",
				Status = (restricted ? SecurityStatus.OK : SecurityStatus.Warning),
				Description = "DownloadRestrictions contrôle le blocage des téléchargements jugés dangereux par SmartScreen. La valeur 1 bloque les téléchargements malveillants, 2 les dangereux et non vérifiés, 3 tout téléchargement dangereux. La valeur 0 (ou absence) n'applique aucune restriction.",
				Recommendation = (restricted ? "Les restrictions de téléchargement sont actives." : "Définir DownloadRestrictions >= 1 dans " + EdgePolicyPath + " pour bloquer les téléchargements dangereux."),
				Reference = EdgeReference
			};
		});

		// --- TLS minimum (SSLVersionMin) ---
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string sslMin = RegString(EdgePolicyPath, "SSLVersionMin");
			bool isTls12 = string.Equals(sslMin, "tls1.2", StringComparison.OrdinalIgnoreCase);
			bool isTls13 = string.Equals(sslMin, "tls1.3", StringComparison.OrdinalIgnoreCase);
			bool secure = isTls12 || isTls13;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Edge: Version TLS minimale (SSLVersionMin)",
				CurrentValue = (sslMin ?? "Non configuré (défaut navigateur)"),
				ExpectedValue = "tls1.2 (ou tls1.3)",
				Status = (secure ? SecurityStatus.OK : SecurityStatus.Warning),
				Description = "SSLVersionMin impose la version TLS minimale acceptée par le navigateur. Les protocoles TLS 1.0 et TLS 1.1 sont obsolètes et vulnérables. Imposer tls1.2 au minimum empêche les connexions via des protocoles faibles.",
				Recommendation = (secure ? "La version TLS minimale est correctement fixée." : "Définir SSLVersionMin=\"tls1.2\" dans " + EdgePolicyPath + " via GPO."),
				Reference = EdgeReference
			};
		});
	}

	// ------------------------------------------------------------------
	// Google Chrome (SOFTWARE\Policies\Google\Chrome)
	// ------------------------------------------------------------------
	private void CollectChrome(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// Si la ruche de stratégie Chrome n'existe pas => navigateur non géré : un seul résultat Info.
		if (!KeyExists(ChromePolicyPath))
		{
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Google Chrome — géré par stratégie",
				CurrentValue = "Aucune stratégie détectée (" + ChromePolicyPath + " absent)",
				ExpectedValue = "Navigateur géré par GPO/MDM",
				Status = SecurityStatus.Info,
				Description = "Aucune stratégie d'entreprise Google Chrome n'a été trouvée dans le registre. Le navigateur n'est pas géré par GPO/MDM : les fonctions de sécurité (Safe Browsing, contrôle des extensions, restrictions de téléchargement) dépendent alors des réglages utilisateur et ne sont pas verrouillées.",
				Recommendation = "Si Google Chrome est utilisé en entreprise, déployer les modèles d'administration Chrome (Chrome Enterprise) et appliquer une stratégie de durcissement.",
				Reference = ChromeReference
			});
			return;
		}

		// --- Safe Browsing (SafeBrowsingProtectionLevel) ---
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int level = RegInt(ChromePolicyPath, "SafeBrowsingProtectionLevel");
			bool enabled = level == 1 || level == 2;
			string label = level switch
			{
				0 => "0 - Désactivé",
				1 => "1 - Protection standard",
				2 => "2 - Protection renforcée",
				-1 => "Non configuré",
				_ => level.ToString(),
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Chrome: Safe Browsing (SafeBrowsingProtectionLevel)",
				CurrentValue = label,
				ExpectedValue = "1 (standard) ou 2 (renforcée)",
				Status = (enabled ? SecurityStatus.OK : SecurityStatus.Warning),
				Description = "Safe Browsing protège contre les sites d'hameçonnage, les logiciels malveillants et les téléchargements dangereux. Le niveau 1 active la protection standard et le niveau 2 la protection renforcée. Le niveau 0 (ou l'absence de réglage) désactive cette protection.",
				Recommendation = (enabled ? "Safe Browsing est activé." : "Définir SafeBrowsingProtectionLevel=1 (ou 2) dans " + ChromePolicyPath + " via GPO."),
				Reference = ChromeReference
			};
		});

		// --- Extensions bloquées (blocklist "*" + allowlist/forcelist) ---
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string blockFirst = RegString(ChromePolicyPath + "\\ExtensionInstallBlocklist", "1");
			bool blockAll = string.Equals(blockFirst, "*", StringComparison.Ordinal);
			bool hasAllowlist = KeyExists(ChromePolicyPath + "\\ExtensionInstallAllowlist");
			bool hasForcelist = KeyExists(ChromePolicyPath + "\\ExtensionInstallForcelist");
			bool hasAllowOrForce = hasAllowlist || hasForcelist;
			bool hardened = blockAll && hasAllowOrForce;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Chrome: Contrôle des extensions (blocklist/allowlist)",
				CurrentValue = $"ExtensionInstallBlocklist\\1={(blockFirst ?? "Non défini")}, Allowlist={(hasAllowlist ? "présente" : "absente")}, Forcelist={(hasForcelist ? "présente" : "absente")}",
				ExpectedValue = "Blocklist\\1=\"*\" (tout bloqué) + Allowlist ou Forcelist",
				Status = (hardened ? SecurityStatus.OK : SecurityStatus.Warning),
				Description = "Bloquer toutes les extensions par défaut (ExtensionInstallBlocklist\\1=\"*\") puis n'autoriser explicitement que celles validées (ExtensionInstallAllowlist) ou les imposer (ExtensionInstallForcelist) empêche l'installation d'extensions malveillantes ou d'exfiltration de données.",
				Recommendation = (hardened ? "Le contrôle des extensions est correctement durci (deny-all + liste d'autorisation)." : (blockAll ? "Blocklist \"*\" présente mais aucune Allowlist/Forcelist : définir la liste des extensions autorisées." : "Définir ExtensionInstallBlocklist\\1=\"*\" pour bloquer toutes les extensions par défaut, puis renseigner ExtensionInstallAllowlist/Forcelist.")),
				Reference = ChromeReference
			};
		});

		// --- Restrictions de téléchargement (DownloadRestrictions) ---
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int downloadRestrictions = RegInt(ChromePolicyPath, "DownloadRestrictions");
			bool restricted = downloadRestrictions >= 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Chrome: Restrictions de téléchargement",
				CurrentValue = FormatInt(downloadRestrictions),
				ExpectedValue = ">= 1 (bloquer les téléchargements dangereux)",
				Status = (restricted ? SecurityStatus.OK : SecurityStatus.Warning),
				Description = "DownloadRestrictions contrôle le blocage des téléchargements jugés dangereux par Safe Browsing. La valeur 1 bloque les téléchargements malveillants, 2 les dangereux et 3 tout téléchargement dangereux. La valeur 0 (ou absence) n'applique aucune restriction.",
				Recommendation = (restricted ? "Les restrictions de téléchargement sont actives." : "Définir DownloadRestrictions >= 1 dans " + ChromePolicyPath + " pour bloquer les téléchargements dangereux."),
				Reference = ChromeReference
			};
		});

		// --- Gestionnaire de mots de passe (PasswordManagerEnabled) ---
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int pwdManager = RegInt(ChromePolicyPath, "PasswordManagerEnabled");
			bool disabled = pwdManager == 0;
			bool notConfigured = pwdManager == -1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Chrome: Gestionnaire de mots de passe intégré",
				CurrentValue = FormatInt(pwdManager),
				ExpectedValue = "0 (désactivé) en environnement géré",
				Status = (disabled ? SecurityStatus.OK : (notConfigured ? SecurityStatus.Info : SecurityStatus.Warning)),
				Description = "Le gestionnaire de mots de passe intégré à Chrome stocke les identifiants dans le profil. En environnement géré, il est recommandé de le désactiver (PasswordManagerEnabled=0) au profit d'un coffre-fort d'entreprise centralisé et audité.",
				Recommendation = (disabled ? "Le gestionnaire de mots de passe intégré est désactivé." : (notConfigured ? "Réglage non configuré : définir explicitement PasswordManagerEnabled selon la politique (0 recommandé si un coffre d'entreprise est utilisé)." : "PasswordManagerEnabled=1 : le stockage des mots de passe dans le navigateur est actif. Envisager PasswordManagerEnabled=0 si un coffre d'entreprise est en place.")),
				Reference = ChromeReference
			};
		});
	}

	// ------------------------------------------------------------------
	// Helpers de lecture registre HKLM (vue 64 bits)
	// ------------------------------------------------------------------

	// Lit une valeur DWORD dans HKLM\<path>\<valueName>. Retourne def (-1 par défaut) si absente/erreur.
	private static int RegInt(string path, string valueName, int def = -1)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			object value = subKey?.GetValue(valueName);
			return (value != null && !(value is DBNull)) ? Convert.ToInt32(value) : def;
		}
		catch
		{
			return def;
		}
	}

	// Lit une valeur chaîne dans HKLM\<path>\<valueName>. Retourne null si absente/erreur.
	private static string? RegString(string path, string valueName)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			return subKey?.GetValue(valueName)?.ToString();
		}
		catch
		{
			return null;
		}
	}

	// Indique si la clé HKLM\<path> existe (utilisé pour distinguer « non géré » de « configuré »).
	private static bool KeyExists(string path)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			return subKey != null;
		}
		catch
		{
			return false;
		}
	}

	// Formate un entier lu au registre pour l'affichage (-1 => « Non configuré »).
	private static string FormatInt(int value)
	{
		return (value == -1) ? "Non configuré" : value.ToString();
	}

	// Enveloppe chaque check : en cas d'exception, un résultat d'erreur isolé est ajouté
	// sans interrompre les autres vérifications.
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
				Category = "Navigateurs",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}
}
