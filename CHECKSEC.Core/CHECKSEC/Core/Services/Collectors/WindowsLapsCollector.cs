using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur CHECKSEC : audite Windows LAPS NATIF (Local Administrator Password Solution integree).
// Il complete le collecteur LAPS legacy (AdmPwd / Microsoft LAPS GPO) traite ailleurs :
// ici on cible LAPS natif, disponible sur Windows 11 / Windows Server 2019+ apres la mise a jour
// d'avril 2023, gere via les strategies HKLM\SOFTWARE\Microsoft\Policies\LAPS et l'etat effectif
// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State.
// Reference : documentation Microsoft Windows LAPS.
public class WindowsLapsCollector : ISecurityCollector
{
	public string Name => "Windows LAPS (natif)";

	public string Category => "Comptes";

	// Cle de STRATEGIE (definie par GPO / MDM) : prioritaire.
	private const string PolicyKeyPath = "SOFTWARE\\Microsoft\\Policies\\LAPS";

	// Cle d'ETAT effectif applique par le CSE LAPS natif.
	private const string StateKeyPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS\\State";

	// Cle de presence du composant LAPS natif (Client Side Extension).
	private const string CseKeyPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS";

	public Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch stopwatch = Stopwatch.StartNew();
		try
		{
			ct.ThrowIfCancellationRequested();
			CollectLapsConfiguration(report.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			report.ErrorMessage = "WindowsLapsCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			report.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(report);
	}

	private void CollectLapsConfiguration(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// --- BackupDirectory : coeur de la configuration LAPS natif ---
		TryAdd(results, delegate
		{
			// La strategie (Policies\LAPS) prime ; a defaut on lit l'etat effectif.
			int? backupDir = ReadDword(PolicyKeyPath, "BackupDirectory") ?? ReadDword(StateKeyPath, "BackupDirectory");
			// Detection du LAPS legacy (AdmPwd) pour ne pas alerter a tort si un LAPS existe deja.
			bool legacyAdmPwd = IsLegacyAdmPwdConfigured();

			string currentValue;
			SecurityStatus status;
			string recommendation;
			switch (backupDir)
			{
				case 1:
					currentValue = "1 - Azure AD (Entra ID)";
					status = SecurityStatus.OK;
					recommendation = "LAPS natif est configure pour sauvegarder le mot de passe dans Entra ID.";
					break;
				case 2:
					currentValue = "2 - Active Directory";
					status = SecurityStatus.OK;
					recommendation = "LAPS natif est configure pour sauvegarder le mot de passe dans Active Directory.";
					break;
				case 0:
				case null:
					currentValue = (backupDir == 0) ? "0 - Desactive" : "Non configure";
					// Non configure ET aucun LAPS legacy => avertissement (aucune gestion du mot de passe admin local).
					status = legacyAdmPwd ? SecurityStatus.Info : SecurityStatus.Warning;
					recommendation = legacyAdmPwd
						? "LAPS natif inactif mais LAPS legacy (AdmPwd) detecte. Envisager la migration vers LAPS natif."
						: "Aucune gestion de mot de passe administrateur local : activer Windows LAPS natif (BackupDirectory = 1 Entra ID ou 2 Active Directory).";
					break;
				default:
					currentValue = backupDir.Value + " - Valeur inconnue";
					status = SecurityStatus.Warning;
					recommendation = "Valeur BackupDirectory inattendue. Verifier la strategie LAPS.";
					break;
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows LAPS: BackupDirectory",
				CurrentValue = currentValue,
				ExpectedValue = "1 (Entra ID) ou 2 (Active Directory)",
				Status = status,
				Description = "BackupDirectory determine ou Windows LAPS natif sauvegarde le mot de passe de l'administrateur local (0=desactive, 1=Azure AD/Entra ID, 2=Active Directory). Sans LAPS, le mot de passe admin local est souvent identique sur tout le parc, facilitant le mouvement lateral (Pass-the-Hash).",
				Recommendation = recommendation,
				Reference = "https://learn.microsoft.com/windows-server/identity/laps/laps-overview"
			};
		});

		// --- PasswordComplexity ---
		TryAdd(results, delegate
		{
			int? complexity = ReadDword(PolicyKeyPath, "PasswordComplexity") ?? ReadDword(StateKeyPath, "PasswordComplexity");
			string label = complexity switch
			{
				1 => "1 - Majuscules uniquement",
				2 => "2 - Majuscules + minuscules",
				3 => "3 - Majuscules + minuscules + chiffres",
				4 => "4 - Majuscules + minuscules + chiffres + symboles",
				null => "Non configure",
				_ => complexity.Value + " - Inconnu"
			};
			bool strong = complexity.HasValue && complexity.Value >= 4;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows LAPS: PasswordComplexity",
				CurrentValue = label,
				ExpectedValue = "4 (tous les jeux de caracteres)",
				Status = (!complexity.HasValue) ? SecurityStatus.Info : (strong ? SecurityStatus.OK : SecurityStatus.Warning),
				Description = "PasswordComplexity definit les jeux de caracteres utilises pour generer le mot de passe LAPS. La valeur 4 (majuscules, minuscules, chiffres, symboles) offre l'entropie maximale.",
				Recommendation = strong ? "Complexite du mot de passe LAPS maximale." : "Definir PasswordComplexity = 4 pour la complexite maximale.",
				Reference = "https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings"
			};
		});

		// --- PasswordLength (>= 14 attendu) ---
		TryAdd(results, delegate
		{
			int? length = ReadDword(PolicyKeyPath, "PasswordLength") ?? ReadDword(StateKeyPath, "PasswordLength");
			bool adequate = length.HasValue && length.Value >= 14;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows LAPS: PasswordLength",
				CurrentValue = length.HasValue ? length.Value.ToString() + " caracteres" : "Non configure (defaut 14)",
				ExpectedValue = ">= 14 caracteres",
				Status = (!length.HasValue) ? SecurityStatus.Info : (adequate ? SecurityStatus.OK : SecurityStatus.Warning),
				Description = "PasswordLength definit la longueur du mot de passe genere par LAPS. Une longueur d'au moins 14 caracteres est attendue pour resister au cassage hors ligne.",
				Recommendation = adequate ? "Longueur du mot de passe LAPS conforme." : "Definir PasswordLength >= 14 (une valeur plus elevee, ex. 20+, est recommandee).",
				Reference = "https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings"
			};
		});

		// --- PasswordAgeDays (<= 30 attendu) ---
		TryAdd(results, delegate
		{
			int? ageDays = ReadDword(PolicyKeyPath, "PasswordAgeDays") ?? ReadDword(StateKeyPath, "PasswordAgeDays");
			bool adequate = ageDays.HasValue && ageDays.Value > 0 && ageDays.Value <= 30;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows LAPS: PasswordAgeDays",
				CurrentValue = ageDays.HasValue ? ageDays.Value.ToString() + " jours" : "Non configure (defaut 30)",
				ExpectedValue = "<= 30 jours",
				Status = (!ageDays.HasValue) ? SecurityStatus.Info : (adequate ? SecurityStatus.OK : SecurityStatus.Warning),
				Description = "PasswordAgeDays definit la duree de vie du mot de passe LAPS avant rotation automatique. Une rotation au moins tous les 30 jours limite la fenetre d'exploitation d'un mot de passe compromis.",
				Recommendation = adequate ? "Frequence de rotation du mot de passe LAPS conforme." : "Definir PasswordAgeDays <= 30 pour une rotation reguliere.",
				Reference = "https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings"
			};
		});

		// --- AdministratorAccountName ---
		TryAdd(results, delegate
		{
			string acctName = ReadString(PolicyKeyPath, "AdministratorAccountName") ?? ReadString(StateKeyPath, "AdministratorAccountName");
			bool configured = !string.IsNullOrWhiteSpace(acctName);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows LAPS: AdministratorAccountName",
				CurrentValue = configured ? acctName : "Non defini (compte administrateur integre SID-500 gere par defaut)",
				ExpectedValue = "Compte administrateur local cible (personnalise recommande)",
				Status = SecurityStatus.Info,
				Description = "AdministratorAccountName designe le compte administrateur local dont LAPS gere le mot de passe. Si non defini, LAPS gere le compte administrateur integre (SID-500). Un compte administrateur local dedie et renomme est recommande.",
				Recommendation = configured ? "Compte administrateur local cible explicitement defini." : "Envisager de cibler un compte administrateur local dedie et renomme plutot que le compte integre.",
				Reference = "https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings"
			};
		});

		// --- PostAuthenticationActions ---
		TryAdd(results, delegate
		{
			int? paa = ReadDword(PolicyKeyPath, "PostAuthenticationActions") ?? ReadDword(StateKeyPath, "PostAuthenticationActions");
			string label = paa switch
			{
				0 => "0 - Aucune action",
				1 => "1 - Reinitialiser le mot de passe",
				3 => "3 - Reinitialiser le mot de passe et fermer les sessions",
				5 => "5 - Reinitialiser le mot de passe et redemarrer",
				null => "Non configure (defaut : reinitialiser + fermer les sessions)",
				_ => paa.Value + " - Combinaison"
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows LAPS: PostAuthenticationActions",
				CurrentValue = label,
				ExpectedValue = "Reinitialisation post-authentification activee (>= 1)",
				Status = (paa == 0) ? SecurityStatus.Warning : SecurityStatus.Info,
				Description = "PostAuthenticationActions declenche une rotation du mot de passe (et eventuellement la fermeture des sessions ou un redemarrage) apres l'utilisation authentifiee du compte, limitant la persistance apres une intervention.",
				Recommendation = (paa == 0) ? "Activer une action post-authentification pour forcer la rotation apres usage du compte." : "Action post-authentification active.",
				Reference = "https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings"
			};
		});

		// --- ADPasswordEncryptionEnabled (pertinent pour BackupDirectory = 2 / Active Directory) ---
		TryAdd(results, delegate
		{
			int? encEnabled = ReadDword(PolicyKeyPath, "ADPasswordEncryptionEnabled") ?? ReadDword(StateKeyPath, "ADPasswordEncryptionEnabled");
			bool enabled = encEnabled.HasValue && encEnabled.Value == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows LAPS: ADPasswordEncryptionEnabled",
				CurrentValue = encEnabled.HasValue ? (enabled ? "1 - Chiffrement active" : "0 - Chiffrement desactive") : "Non configure (defaut : active)",
				ExpectedValue = "1 (chiffrement du mot de passe dans AD active)",
				Status = (encEnabled.HasValue && !enabled) ? SecurityStatus.Warning : SecurityStatus.Info,
				Description = "ADPasswordEncryptionEnabled active le chiffrement du mot de passe LAPS stocke dans Active Directory (necessite un niveau fonctionnel de domaine Windows Server 2016+). Sans chiffrement, le mot de passe est stocke en clair dans l'attribut AD.",
				Recommendation = (encEnabled.HasValue && !enabled) ? "Activer ADPasswordEncryptionEnabled lorsque BackupDirectory = 2 (Active Directory)." : "Chiffrement du mot de passe AD conforme (par defaut).",
				Reference = "https://learn.microsoft.com/windows-server/identity/laps/laps-concepts"
			};
		});

		// --- Presence du CSE LAPS natif ---
		TryAdd(results, delegate
		{
			bool csePresent = KeyExists(CseKeyPath);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows LAPS: Presence du composant (CSE)",
				CurrentValue = csePresent ? "Present (cle CurrentVersion\\LAPS detectee)" : "Absent",
				ExpectedValue = "Present (Windows 11 / Server 2019+ post avril 2023)",
				Status = SecurityStatus.Info,
				Description = "Presence du composant Windows LAPS natif (Client Side Extension) sous HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS. Son absence indique un systeme trop ancien ou non a jour pour LAPS natif.",
				Recommendation = csePresent ? "Le composant LAPS natif est present." : "Mettre a jour Windows (avril 2023+) pour disposer de LAPS natif, ou utiliser LAPS legacy.",
				Reference = "https://learn.microsoft.com/windows-server/identity/laps/laps-overview"
			};
		});

		// --- Service LAPS ---
		TryAdd(results, delegate
		{
			// Le service LAPS natif s'appuie sur le Task Scheduler / le CSE ; on verifie la cle de service si presente.
			bool serviceKey = KeyExists("SYSTEM\\CurrentControlSet\\Services\\LAPS");
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Windows LAPS: Service",
				CurrentValue = serviceKey ? "Cle de service LAPS presente" : "Cle de service LAPS non detectee",
				ExpectedValue = "Service LAPS disponible",
				Status = SecurityStatus.Info,
				Description = "Verification de la presence du service LAPS natif. Sur les versions recentes, la gestion LAPS est portee par le CSE et le planificateur de taches ; l'absence de cle de service n'est pas necessairement un defaut.",
				Recommendation = "Verifier l'application effective de la strategie LAPS via les journaux LAPS (Applications and Services Logs > Microsoft > Windows > LAPS).",
				Reference = "https://learn.microsoft.com/windows-server/identity/laps/laps-management-event-log"
			};
		});
	}

	// Lecture d'une valeur DWORD sous HKLM (vue 64 bits). Retourne null si la cle ou la valeur est absente.
	private static int? ReadDword(string subKeyPath, string valueName)
	{
		using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
		using RegistryKey key = baseKey.OpenSubKey(subKeyPath);
		object raw = key?.GetValue(valueName);
		if (raw == null)
		{
			return null;
		}
		try
		{
			return Convert.ToInt32(raw);
		}
		catch
		{
			return null;
		}
	}

	// Lecture d'une valeur chaine sous HKLM (vue 64 bits). Retourne null si absente.
	private static string ReadString(string subKeyPath, string valueName)
	{
		using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
		using RegistryKey key = baseKey.OpenSubKey(subKeyPath);
		return key?.GetValue(valueName)?.ToString();
	}

	// Teste l'existence d'une cle sous HKLM (vue 64 bits).
	private static bool KeyExists(string subKeyPath)
	{
		using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
		using RegistryKey key = baseKey.OpenSubKey(subKeyPath);
		return key != null;
	}

	// Detecte la presence d'une configuration LAPS legacy (AdmPwd / Microsoft LAPS) pour eviter une fausse alerte
	// "aucune gestion de mot de passe" quand un LAPS ancien existe deja.
	private static bool IsLegacyAdmPwdConfigured()
	{
		try
		{
			// Strategie AdmPwd (Microsoft LAPS legacy).
			int? admPwdEnabled = ReadDword("SOFTWARE\\Policies\\Microsoft Services\\AdmPwd", "AdmPwdEnabled");
			if (admPwdEnabled.HasValue && admPwdEnabled.Value == 1)
			{
				return true;
			}
			// Presence du composant/GPO CSE AdmPwd.
			if (KeyExists("SOFTWARE\\Policies\\Microsoft Services\\AdmPwd"))
			{
				return true;
			}
		}
		catch (Exception)
		{
		}
		return false;
	}

	// Ajout defensif : ne jamais interrompre le collecteur sur l'echec d'un seul controle.
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
				Category = "Comptes",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Le controle a echoue : " + ex.Message,
				Recommendation = "Verifier l'acces au registre (droits administrateur).",
				Reference = ""
			});
		}
	}
}
