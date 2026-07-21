using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class ScreenLockCollector : ISecurityCollector
{
	public string Name => "Verrouillage & Accès Physique";

	public string Category => "Contrôle d'Accès";

	public async Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		Stopwatch sw = Stopwatch.StartNew();
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		try
		{
			await Task.Run(delegate
			{
				ct.ThrowIfCancellationRequested();
				CheckScreenSaver(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckInactivityLock(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckLegalBanner(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckSmartCardPolicy(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckPowerAndHibernate(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckWindowsHelloPin(report.Results);
			}, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			report.ErrorMessage = "Erreur générale ScreenLockCollector : " + ex2.Message;
		}
		finally
		{
			sw.Stop();
			report.Duration = sw.Elapsed;
		}
		return report;
	}

	private void CheckScreenSaver(List<SecurityResult> results)
	{
		object ssActiveHkcu = ReadRegHkcu("Control Panel\\Desktop", "ScreenSaveActive");
		object ssSecureHkcu = ReadRegHkcu("Control Panel\\Desktop", "ScreenSaverIsSecure");
		object ssTimeoutHkcu = ReadRegHkcu("Control Panel\\Desktop", "ScreenSaveTimeOut");
		object? ssActiveGpo = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop", "ScreenSaveActive");
		object ssSecureGpo = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop", "ScreenSaverIsSecure");
		object ssTimeoutGpo = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop", "ScreenSaveTimeOut");
		string activeStr = (ssActiveGpo ?? ssActiveHkcu)?.ToString() ?? "0";
		string secureStr = (ssSecureGpo ?? ssSecureHkcu)?.ToString() ?? "0";
		string timeoutStr = (ssTimeoutGpo ?? ssTimeoutHkcu)?.ToString() ?? "0";
		bool active = activeStr.Trim() == "1";
		bool secure = secureStr.Trim() == "1";
		int parsedTimeout;
		int timeout = (int.TryParse(timeoutStr.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsedTimeout) ? parsedTimeout : 0);
		bool gpoImposed = ssActiveGpo != null || ssSecureGpo != null || ssTimeoutGpo != null;
		string gpoNote = (gpoImposed ? " [Valeur(s) imposée(s) par GPO]" : "");
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "Économiseur d'écran - Mot de passe à la reprise",
			CurrentValue = "ScreenSaverIsSecure=" + secureStr + gpoNote,
			ExpectedValue = "1 (mot de passe requis à la reprise)",
			Status = ((!active || !secure) ? SecurityStatus.Critical : SecurityStatus.OK),
			Description = ((secure && active) ? "L'économiseur d'écran est actif et protégé par mot de passe. Le poste se verrouille automatiquement après inactivité." : ((!active) ? "L'économiseur d'écran est désactivé. Le poste ne se verrouille pas automatiquement." : "L'économiseur d'écran est actif mais ne requiert PAS de mot de passe à la reprise — le poste est accessible sans authentification après inactivité.")),
			Recommendation = ((secure && active) ? "Configuration correcte. Vérifier également le délai d'activation." : "Activer l'économiseur d'écran avec protection par mot de passe via : Paramètres > Personnalisation > Écran de veille. Ou configurer via GPO : Computer Configuration > Policies > Administrative Templates > Control Panel > Personalization."),
			Reference = "CIS Benchmark Windows - 18.9.13 | ANSSI Hygiène Informatique R30",
			CollectedAt = DateTime.Now
		});
		TryAdd(results, delegate
		{
			int timeoutMinutes = ((timeout > 0) ? (timeout / 60) : 0);
			bool timeoutNonCompliant = timeout == 0 || timeout > 900;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Économiseur d'écran - Délai d'activation",
				CurrentValue = ((timeout == 0) ? "Non défini ou 0" : $"{timeout} secondes ({timeoutMinutes} min){gpoNote}"),
				ExpectedValue = "≤ 900 secondes (15 minutes)",
				Status = (timeoutNonCompliant ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = ((timeout == 0) ? "Le délai de l'économiseur d'écran n'est pas défini ou vaut zéro — le verrouillage automatique ne se déclenchera pas." : ((timeout <= 900) ? $"Le délai d'activation est de {timeout}s ({timeoutMinutes} min) — conforme à la recommandation de 15 minutes maximum." : $"Le délai d'activation est de {timeout}s ({timeoutMinutes} min) — supérieur aux 15 minutes recommandées. Un poste laissé sans surveillance est vulnérable.")),
				Recommendation = (timeoutNonCompliant ? "Configurer ScreenSaveTimeOut ≤ 900 secondes (15 minutes) via GPO ou les paramètres de personnalisation Windows." : "Délai conforme. Aucune action requise."),
				Reference = "CIS Benchmark Windows - 18.9.13.1",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CheckInactivityLock(List<SecurityResult> results)
	{
		TryAdd(results, delegate
		{
			object inactivityValue = ReadRegHklm("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "InactivityTimeoutSecs") ?? ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows\\System", "InactivityTimeoutSecs");
			int timeoutSecs = ((inactivityValue is int parsedInactivity) ? parsedInactivity : ((inactivityValue != null) ? Convert.ToInt32(inactivityValue) : 0));
			bool configured = inactivityValue != null && timeoutSecs > 0;
			bool exceedsLimit = configured && timeoutSecs > 900;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Verrouillage par inactivité - InactivityTimeoutSecs",
				CurrentValue = (configured ? $"{timeoutSecs} secondes ({timeoutSecs / 60} min)" : "Non configuré (0 = pas de verrouillage auto)"),
				ExpectedValue = "≤ 900 secondes (15 minutes)",
				Status = ((!configured) ? SecurityStatus.Warning : (exceedsLimit ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = ((!configured) ? "InactivityTimeoutSecs n'est pas configuré. Windows ne verrouillera pas automatiquement la session interactive après inactivité (hors économiseur d'écran)." : (exceedsLimit ? $"Le délai de verrouillage interactif est de {timeoutSecs}s ({timeoutSecs / 60} min) — supérieur à la recommandation de 15 minutes." : $"Verrouillage interactif configuré à {timeoutSecs}s ({timeoutSecs / 60} min) — conforme.")),
				Recommendation = ((!configured || exceedsLimit) ? "Configurer InactivityTimeoutSecs ≤ 900 via GPO : Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > 'Interactive logon: Machine inactivity limit'." : "Aucune action requise."),
				Reference = "CIS Benchmark Windows - 2.3.7.3 | ANSSI R29",
				CollectedAt = DateTime.Now
			};
		});
		TryAdd(results, delegate
		{
			string autoAdminLogon = ReadRegHklm("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "AutoAdminLogon")?.ToString() ?? "0";
			bool autoLogonEnabled = autoAdminLogon.Trim() == "1";
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Ouverture de session automatique (AutoAdminLogon)",
				CurrentValue = "AutoAdminLogon=" + autoAdminLogon,
				ExpectedValue = "0 (désactivé)",
				Status = (autoLogonEnabled ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = (autoLogonEnabled ? "CRITIQUE : AutoAdminLogon=1. Le système démarre et ouvre une session Windows automatiquement sans interaction utilisateur. Quiconque peut démarrer la machine accède directement au bureau sans aucune authentification." : "AutoAdminLogon est désactivé — aucune ouverture de session automatique configurée."),
				Recommendation = (autoLogonEnabled ? "Désactiver immédiatement AutoAdminLogon : définir HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AutoAdminLogon = 0. Supprimer également DefaultPassword et DefaultUserName de cette clé de registre." : "Aucune action requise."),
				Reference = "CIS Benchmark Windows - 2.3.7 | ANSSI Hygiène R31",
				CollectedAt = DateTime.Now
			};
		});
		TryAdd(results, delegate
		{
			bool hasDefaultPassword = !string.IsNullOrEmpty(ReadRegHklm("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultPassword")?.ToString() ?? string.Empty);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Mot de passe en clair - DefaultPassword (Winlogon)",
				CurrentValue = (hasDefaultPassword ? "Présent et non vide (valeur masquée)" : "Absent ou vide"),
				ExpectedValue = "Absent ou vide",
				Status = (hasDefaultPassword ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = (hasDefaultPassword ? "CRITIQUE : Un mot de passe est stocké en clair dans HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\DefaultPassword. Ce mot de passe est lisible par tout administrateur local et tout outil d'extraction de registre (ex : Mimikatz, reg.exe)." : "Aucun mot de passe en clair détecté dans la clé Winlogon DefaultPassword."),
				Recommendation = (hasDefaultPassword ? "Supprimer immédiatement la valeur DefaultPassword du registre. Modifier le mot de passe du compte concerné. Ne jamais utiliser AutoAdminLogon sur un système sensible." : "Aucune action requise."),
				Reference = "MITRE ATT&CK T1552.002 | CIS Benchmark Windows",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CheckLegalBanner(List<SecurityResult> results)
	{
		TryAdd(results, delegate
		{
			string captionWinlogon = (ReadRegHklm("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "LegalNoticeCaption") as string) ?? string.Empty;
			string legalText = (ReadRegHklm("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "LegalNoticeText") as string) ?? string.Empty;
			string captionGpo = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows\\System", "legalnoticecaption") as string;
			string caption = captionGpo ?? captionWinlogon;
			bool hasCaption = !string.IsNullOrWhiteSpace(caption);
			bool hasText = !string.IsNullOrWhiteSpace(legalText);
			bool bannerConfigured = hasCaption && hasText;
			string gpoTag = ((captionGpo != null) ? " [GPO]" : "");
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Message légal à l'ouverture de session (Legal Banner)",
				CurrentValue = (bannerConfigured ? $"Titre : '{TruncateStr(caption, 60)}'{gpoTag} | Texte : {(hasText ? "Présent" : "Absent")}" : "Non configuré (titre et/ou texte vides)"),
				ExpectedValue = "Titre et texte de message légal définis",
				Status = ((!bannerConfigured) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = (bannerConfigured ? ("Un message légal est affiché à l'ouverture de session. Titre : '" + TruncateStr(caption, 80) + "'. Ce message informe les utilisateurs des conditions d'utilisation et a une valeur juridique.") : "Aucun message légal n'est configuré pour l'ouverture de session. L'absence de Legal Banner peut affaiblir la position juridique de l'organisation en cas d'incident."),
				Recommendation = ((!bannerConfigured) ? "Configurer un message légal via GPO : Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > 'Interactive logon: Message title/text for users attempting to log on'. Exemple de texte : 'Système informatique réservé aux utilisateurs autorisés. Toute utilisation non autorisée est interdite et peut faire l'objet de poursuites.'" : "Message légal configuré. Vérifier que le texte est validé par le service juridique."),
				Reference = "CIS Benchmark Windows - 2.3.7.1 / 2.3.7.2 | ISO 27001 A.9.4.2",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CheckSmartCardPolicy(List<SecurityResult> results)
	{
		TryAdd(results, delegate
		{
			object scForceValue = ReadRegHklm("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "ScForceOption");
			object forceSmartCardValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows\\SmartCardCredentialProvider", "ForceSmartCardLogon");
			int scForceOption = ((scForceValue is int parsedScForce) ? parsedScForce : ((scForceValue != null) ? Convert.ToInt32(scForceValue) : 0));
			int forceSmartCardLogon = ((forceSmartCardValue is int parsedForce) ? parsedForce : ((forceSmartCardValue != null) ? Convert.ToInt32(forceSmartCardValue) : 0));
			bool smartCardForced = scForceOption == 1 || forceSmartCardLogon == 1;
			string source = ((forceSmartCardLogon == 1) ? "ForceSmartCardLogon [GPO]" : ((scForceOption == 1) ? "ScForceOption [Policies\\System]" : "Non configuré"));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Connexion par carte à puce (Smart Card)",
				CurrentValue = $"ScForceOption={scForceOption} | ForceSmartCardLogon={forceSmartCardLogon} | Source={source}",
				ExpectedValue = "Dépend de la politique de l'organisation",
				Status = SecurityStatus.Info,
				Description = (smartCardForced ? ("La connexion par carte à puce est obligatoire sur ce système (configurée via " + source + "). Ce niveau d'authentification forte renforce significativement la sécurité des accès.") : "La connexion par carte à puce n'est pas imposée sur ce système. Pour les environnements sensibles (données classifiées, finances, administration), l'authentification forte est recommandée."),
				Recommendation = (smartCardForced ? "Vérifier que les utilisateurs ont bien des cartes à puce valides et que les certificats sont à jour." : "Évaluer la mise en place de l'authentification forte (smart card ou Windows Hello for Business) selon le niveau de sensibilité du système."),
				Reference = "ANSSI - Recommandation MFA | CIS Benchmark Windows - 2.3.7.4",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CheckPowerAndHibernate(List<SecurityResult> results)
	{
		TryAdd(results, delegate
		{
			object hibernateValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Control\\Power", "HibernateEnabled");
			object hibernateDefaultValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Control\\Power", "HibernateEnabledDefault");
			int hibernateState = ((hibernateValue is int parsedHibernate) ? parsedHibernate : ((hibernateDefaultValue is int parsedDefault) ? parsedDefault : (-1)));
			bool hibernateEnabled = hibernateState != 0;
			bool hibernateUnknown = hibernateState == -1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Hibernation - État",
				CurrentValue = (hibernateUnknown ? "Valeur absente (état inconnu)" : (hibernateEnabled ? "Activée" : "Désactivée")),
				ExpectedValue = "Désactivée (si fichier hiberfil.sys non chiffré) ou chiffrée via BitLocker",
				Status = (hibernateUnknown ? SecurityStatus.Info : (hibernateEnabled ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = (hibernateEnabled ? "L'hibernation est activée. Le fichier hiberfil.sys contient une image complète de la RAM — y compris des clés de chiffrement, des mots de passe et des données sensibles. Si le disque n'est pas chiffré par BitLocker, ce fichier peut être exploité hors ligne." : (hibernateUnknown ? "L'état de l'hibernation n'a pas pu être déterminé depuis le registre." : "L'hibernation est désactivée — aucun fichier hiberfil.sys créé.")),
				Recommendation = (hibernateEnabled ? "Si BitLocker est actif sur le volume système, le risque est limité. Sinon, désactiver l'hibernation via : powercfg /hibernate off. Vérifier également que le fichier hiberfil.sys n'est pas accessible à des utilisateurs non autorisés." : "Aucune action requise."),
				Reference = "ANSSI Hygiène R38 | CIS Benchmark BitLocker",
				CollectedAt = DateTime.Now
			};
		});
		TryAdd(results, delegate
		{
			object acSettingValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e", "ACSettingIndex");
			int acSettingIndex = ((acSettingValue is int parsedAcSetting) ? parsedAcSetting : ((acSettingValue != null) ? Convert.ToInt32(acSettingValue) : (-1)));
			bool screenNeverOff = acSettingIndex == 0;
			bool notConfiguredByGpo = acSettingIndex < 0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Plan d'alimentation - Extinction d'écran (AC, GPO)",
				CurrentValue = (notConfiguredByGpo ? "Non configuré par GPO" : (screenNeverOff ? "Jamais (0)" : $"{acSettingIndex} secondes ({acSettingIndex / 60} min)")),
				ExpectedValue = "> 0 secondes (extinction activée)",
				Status = (screenNeverOff ? SecurityStatus.Warning : SecurityStatus.Info),
				Description = (screenNeverOff ? "Le plan d'alimentation GPO configure l'écran pour ne jamais s'éteindre sur secteur. Un écran toujours allumé signale un poste actif et peut permettre une consultation visuelle des données." : (notConfiguredByGpo ? "Le délai d'extinction d'écran n'est pas imposé par GPO. Le paramètre local s'applique." : $"L'écran s'éteint après {acSettingIndex}s ({acSettingIndex / 60} min) selon la GPO.")),
				Recommendation = (screenNeverOff ? "Configurer un délai d'extinction d'écran approprié via GPO Power Management pour réduire la surface d'exposition physique." : "Vérifier le paramètre local via Paramètres > Alimentation et mise en veille si la GPO ne l'impose pas."),
				Reference = "ANSSI Hygiène Informatique | CIS Benchmark Windows",
				CollectedAt = DateTime.Now
			};
		});
		TryAdd(results, delegate
		{
			string powercfgOutput = RunPowercfg();
			bool powercfgAvailable = !string.IsNullOrWhiteSpace(powercfgOutput);
			string screenTimeout = ExtractPowercfgScreenTimeout(powercfgOutput);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Plan d'alimentation actif - Mise en veille écran",
				CurrentValue = ((!powercfgAvailable) ? "Impossible d'exécuter powercfg" : (string.IsNullOrEmpty(screenTimeout) ? "Paramètre écran non identifié dans la sortie powercfg" : screenTimeout)),
				ExpectedValue = "Délai d'écran configuré (non nul)",
				Status = SecurityStatus.Info,
				Description = (powercfgAvailable ? ("Lecture du plan d'alimentation actif via 'powercfg /query SCHEME_CURRENT'. " + (string.IsNullOrEmpty(screenTimeout) ? "Le délai d'extinction d'écran n'a pas pu être extrait automatiquement — vérification manuelle recommandée." : ("Délai d'extinction d'écran détecté : " + screenTimeout + "."))) : "La commande powercfg n'a pas pu être exécutée (droits insuffisants ou service désactivé)."),
				Recommendation = "Utiliser 'powercfg /query SCHEME_CURRENT' pour auditer les paramètres d'alimentation complets.",
				Reference = "powercfg /query SCHEME_CURRENT",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CheckWindowsHelloPin(List<SecurityResult> results)
	{
		TryAdd(results, delegate
		{
			object pinLogonValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows\\System", "AllowDomainPINLogon");
			int pinLogon = ((pinLogonValue is int parsedPin) ? parsedPin : ((pinLogonValue != null) ? Convert.ToInt32(pinLogonValue) : (-1)));
			bool pinConfigured = pinLogon >= 0;
			bool pinAllowed = pinLogon == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows Hello - AllowDomainPINLogon",
				CurrentValue = ((!pinConfigured) ? "Non configuré" : (pinAllowed ? "1 - Connexion PIN autorisée" : "0 - Connexion PIN désactivée")),
				ExpectedValue = "Configurable selon politique de l'organisation",
				Status = SecurityStatus.Info,
				Description = (pinAllowed ? "La connexion par PIN sur un domaine Windows est autorisée. Le PIN est lié au périphérique (Trusted Platform Module) et ne transite pas sur le réseau." : (pinConfigured ? "La connexion par PIN de domaine est explicitement désactivée." : "La connexion par PIN de domaine n'est pas configurée explicitement — comportement par défaut du système.")),
				Recommendation = "La connexion par PIN Windows Hello est considérée plus sécurisée que le mot de passe traditionnel car liée au matériel (TPM). Évaluer son activation dans les environnements compatibles TPM 2.0.",
				Reference = "Microsoft Docs - Windows Hello for Business | CIS Benchmark Windows",
				CollectedAt = DateTime.Now
			};
		});
		TryAdd(results, delegate
		{
			object passportValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\PassportForWork", "Enabled");
			int passportEnabled = ((passportValue is int parsedPassport) ? parsedPassport : ((passportValue != null) ? Convert.ToInt32(passportValue) : (-1)));
			bool passportConfigured = passportEnabled >= 0;
			bool whfbEnabled = passportEnabled == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows Hello for Business - État GPO",
				CurrentValue = ((!passportConfigured) ? "Non configuré par GPO" : (whfbEnabled ? "1 - Activé (GPO)" : "0 - Désactivé (GPO)")),
				ExpectedValue = "Activé dans les environnements compatibles (TPM + AD/AAD)",
				Status = SecurityStatus.Info,
				Description = (whfbEnabled ? "Windows Hello for Business est activé via GPO. Ce mécanisme utilise une paire de clés cryptographiques liée au TPM pour remplacer les mots de passe." : ((passportConfigured && !whfbEnabled) ? "Windows Hello for Business est explicitement désactivé via GPO." : "Windows Hello for Business n'est pas configuré via GPO — le comportement dépend des paramètres par défaut et de l'environnement (AAD, Hybrid Join).")),
				Recommendation = "Windows Hello for Business est recommandé par Microsoft et l'ANSSI pour les organisations souhaitant éliminer les mots de passe. Prérequis : TPM 2.0, Azure AD ou Hybrid Azure AD Join, certificats PKI (si on-premise).",
				Reference = "ANSSI - Authentification forte | Microsoft Docs - WHfB",
				CollectedAt = DateTime.Now
			};
		});
		TryAdd(results, delegate
		{
			object minPinValue = ReadRegHklm("SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\DeviceLock", "MinDevicePasswordLength");
			object maxFailedValue = ReadRegHklm("SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\DeviceLock", "MaxDevicePasswordFailedAttempts");
			object maxInactivityValue = ReadRegHklm("SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\DeviceLock", "MaxInactivityTimeDeviceLock");
			int num6 = ((minPinValue is int num5) ? num5 : ((minPinValue != null) ? Convert.ToInt32(minPinValue) : (-1)));
			int num8 = ((maxFailedValue is int num7) ? num7 : ((maxFailedValue != null) ? Convert.ToInt32(maxFailedValue) : (-1)));
			int num10 = ((maxInactivityValue is int num9) ? num9 : ((maxInactivityValue != null) ? Convert.ToInt32(maxInactivityValue) : (-1)));
			StringBuilder stringBuilder = new StringBuilder();
			if (num6 >= 0)
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder3 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(15, 1, stringBuilder2);
				handler.AppendLiteral("MinPINLength=");
				handler.AppendFormatted(num6);
				handler.AppendLiteral("  ");
				stringBuilder3.Append(ref handler);
			}
			if (num8 >= 0)
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder4 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(15, 1, stringBuilder2);
				handler.AppendLiteral("MaxÉchecsPIN=");
				handler.AppendFormatted(num8);
				handler.AppendLiteral("  ");
				stringBuilder4.Append(ref handler);
			}
			if (num10 >= 0)
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder5 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(17, 1, stringBuilder2);
				handler.AppendLiteral("MaxInactivité=");
				handler.AppendFormatted(num10);
				handler.AppendLiteral("min");
				stringBuilder5.Append(ref handler);
			}
			string summary = ((stringBuilder.Length > 0) ? stringBuilder.ToString().Trim() : "Politiques DeviceLock non configurées");
			bool pinTooShort = num6 >= 0 && num6 < 6;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "DeviceLock - Politiques PIN (PolicyManager)",
				CurrentValue = summary,
				ExpectedValue = "MinPINLength ≥ 6 | MaxÉchecs ≤ 10 | MaxInactivité ≤ 15 min",
				Status = (pinTooShort ? SecurityStatus.Warning : SecurityStatus.Info),
				Description = ((stringBuilder.Length > 0) ? ("Politiques DeviceLock détectées via PolicyManager : " + summary + ". " + (pinTooShort ? $"La longueur minimale du PIN ({num6}) est inférieure à 6 caractères — vulnérable aux attaques par force brute." : "")) : "Aucune politique DeviceLock configurée via le gestionnaire de politiques Windows (MDM/PolicyManager). Cela ne signifie pas nécessairement l'absence de politique — vérifier via Intune ou ADMX locales."),
				Recommendation = (pinTooShort ? "Augmenter MinDevicePasswordLength à 6 minimum (8 recommandé) via MDM/Intune ou GPO." : ((stringBuilder.Length > 0) ? "Vérifier que les valeurs sont conformes à la politique de sécurité de l'organisation." : "Configurer les politiques de verrouillage via GPO ou Intune selon les besoins.")),
				Reference = "CIS Benchmark Windows | ANSSI Hygiène Informatique",
				CollectedAt = DateTime.Now
			};
		});
	}

	private static object? ReadRegHklm(string subKey, string valueName)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey subKeyHandle = baseKey.OpenSubKey(subKey, writable: false);
			return subKeyHandle?.GetValue(valueName);
		}
		catch (Exception)
		{
			return null;
		}
	}

	private static object? ReadRegHkcu(string subKey, string valueName)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
			using RegistryKey subKeyHandle = baseKey.OpenSubKey(subKey, writable: false);
			return subKeyHandle?.GetValue(valueName);
		}
		catch (Exception)
		{
			return null;
		}
	}

	private static int WmiInt(ManagementBaseObject obj, string prop, int def = -1)
	{
		object value = obj[prop];
		if (value == null || value is DBNull)
		{
			return def;
		}
		return Convert.ToInt32(value);
	}

	private static string RunPowercfg()
	{
		try
		{
			using Process process = Process.Start(new ProcessStartInfo
			{
				FileName = "powercfg.exe",
				Arguments = "/query SCHEME_CURRENT",
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			});
			if (process == null)
			{
				return string.Empty;
			}
			string stderr = "";
			process.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e)
			{
				if (e.Data != null)
				{
					stderr += e.Data;
				}
			};
			process.BeginErrorReadLine();
			string output = process.StandardOutput.ReadToEnd();
			if (!process.WaitForExit(10000))
			{
				try
				{
					process.Kill();
				}
				catch
				{
				}
			}
			return output;
		}
		catch (Exception)
		{
			return string.Empty;
		}
	}

	private static string ExtractPowercfgScreenTimeout(string powercfgOutput)
	{
		if (string.IsNullOrWhiteSpace(powercfgOutput))
		{
			return string.Empty;
		}
		bool inMonitorSubgroup = false;
		bool inScreenTimeoutSetting = false;
		string[] lines = powercfgOutput.Split('\n');
		for (int i = 0; i < lines.Length; i++)
		{
			string line = lines[i].Trim();
			if (line.IndexOf("7516b95f-f776-4464-8c53-06167f40cc99", StringComparison.OrdinalIgnoreCase) >= 0)
			{
				inMonitorSubgroup = true;
			}
			if (inMonitorSubgroup && line.IndexOf("3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e", StringComparison.OrdinalIgnoreCase) >= 0)
			{
				inScreenTimeoutSetting = true;
			}
			if (inScreenTimeoutSetting && line.StartsWith("Current AC Power Setting Index:", StringComparison.OrdinalIgnoreCase))
			{
				int colonIndex = line.IndexOf(':');
				if (colonIndex >= 0)
				{
					string rawValue = line.Substring(colonIndex + 1).Trim();
					uint decimalSeconds;
					if (rawValue.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
					{
						if (uint.TryParse(rawValue.Substring(2), NumberStyles.HexNumber, null, out var hexSeconds))
						{
							if (hexSeconds != 0)
							{
								return $"{hexSeconds} secondes ({hexSeconds / 60} min)";
							}
							return "Jamais (0)";
						}
					}
					else if (uint.TryParse(rawValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out decimalSeconds))
					{
						if (decimalSeconds != 0)
						{
							return $"{decimalSeconds} secondes ({decimalSeconds / 60} min)";
						}
						return "Jamais (0)";
					}
				}
			}
			if (inMonitorSubgroup && line.StartsWith("Subgroup GUID:", StringComparison.OrdinalIgnoreCase) && line.IndexOf("7516b95f-f776-4464-8c53-06167f40cc99", StringComparison.OrdinalIgnoreCase) < 0)
			{
				inMonitorSubgroup = false;
				inScreenTimeoutSetting = false;
			}
		}
		return string.Empty;
	}

	private static string TruncateStr(string s, int maxLen)
	{
		if (s.Length > maxLen)
		{
			return s.Substring(0, maxLen) + "…";
		}
		return s;
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
				Category = "Contrôle d'Accès",
				CheckName = "Erreur de vérification",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Échec d'une vérification verrouillage écran : " + ex.Message,
				CollectedAt = DateTime.Now
			});
		}
	}
}
