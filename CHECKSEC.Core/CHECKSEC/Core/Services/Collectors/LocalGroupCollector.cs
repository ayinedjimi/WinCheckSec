using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur des groupes et comptes locaux.
// Repose sur WMI (Win32_Group / Win32_GroupUser / Win32_UserAccount / Win32_NetworkLoginProfile).
// La résolution du groupe Administrateurs se fait par SID bien connu (S-1-5-32-544)
// afin d'être INDÉPENDANTE de la locale (Administrateurs, Administrators, Administradores, ...).
public class LocalGroupCollector : ISecurityCollector
{
	// SID bien connu du groupe local Administrateurs (identique sur toutes les locales).
	private const string AdministratorsGroupSid = "S-1-5-32-544";

	// Seuil d'inactivité (en jours) au-delà duquel un compte est considéré comme dormant.
	private const int DormantThresholdDays = 90;

	public string Name => "Groupes & comptes locaux";

	public string Category => "Comptes";

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
			CollectAdministratorsMembers(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectGuestAccount(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectPasswordNeverExpires(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectDormantAccounts(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "LocalGroupCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// ------------------------------------------------------------------
	// 1) Membres du groupe Administrateurs local (résolu par SID S-1-5-32-544).
	// ------------------------------------------------------------------
	private void CollectAdministratorsMembers(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			// Résolution du groupe par SID (locale-indépendante) afin de récupérer Domain + Name.
			string groupDomain = null;
			string groupName = null;
			ManagementObjectSearcher groupSearcher = new ManagementObjectSearcher("SELECT Domain,Name FROM Win32_Group WHERE SID='" + AdministratorsGroupSid + "'");
			try
			{
				using ManagementObjectCollection groupCollection = groupSearcher.Get();
				foreach (ManagementObject groupObject in groupCollection)
				{
					ManagementObject groupToDispose = groupObject;
					try
					{
						ct.ThrowIfCancellationRequested();
						groupDomain = groupObject["Domain"]?.ToString();
						groupName = groupObject["Name"]?.ToString();
					}
					finally
					{
						((IDisposable)groupToDispose)?.Dispose();
					}
				}
			}
			finally
			{
				((IDisposable)groupSearcher)?.Dispose();
			}

			if (string.IsNullOrEmpty(groupName))
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Groupe Administrateurs local : résolution",
					CurrentValue = "Groupe SID " + AdministratorsGroupSid + " introuvable via WMI",
					ExpectedValue = "Groupe résolu par SID",
					Status = SecurityStatus.Error,
					Description = "Impossible de résoudre le groupe Administrateurs local par son SID bien connu (S-1-5-32-544) via WMI.",
					Recommendation = "Exécuter CHECKSEC en tant qu'administrateur et vérifier le bon fonctionnement de WMI.",
					Reference = ""
				});
				return;
			}

			// Énumération des membres via la requête ASSOCIATORS OF (Win32_GroupUser).
			// Le nom du groupe est échappé (apostrophes) pour la construction de la requête WQL.
			List<string> members = new List<string>();
			string escapedDomain = (groupDomain ?? "").Replace("\\", "\\\\").Replace("'", "\\'");
			string escapedName = groupName.Replace("\\", "\\\\").Replace("'", "\\'");
			string associatorsQuery = "ASSOCIATORS OF {Win32_Group.Domain='" + escapedDomain + "',Name='" + escapedName + "'} WHERE AssocClass=Win32_GroupUser";
			ManagementObjectSearcher memberSearcher = new ManagementObjectSearcher(associatorsQuery);
			try
			{
				using ManagementObjectCollection memberCollection = memberSearcher.Get();
				foreach (ManagementObject memberObject in memberCollection)
				{
					ManagementObject memberToDispose = memberObject;
					try
					{
						ct.ThrowIfCancellationRequested();
						// Un membre peut être un compte (Win32_UserAccount) ou un groupe (Win32_Group).
						string memberDomain = SafeGet(memberObject, "Domain");
						string memberAccountName = SafeGet(memberObject, "Name");
						string memberClass = memberObject.ClassPath?.ClassName ?? "";
						string memberKind = memberClass.IndexOf("Group", StringComparison.OrdinalIgnoreCase) >= 0 ? "groupe" : "compte";
						string display = (string.IsNullOrEmpty(memberDomain) ? "" : memberDomain + "\\") + (memberAccountName ?? "?");
						members.Add(display + " (" + memberKind + ")");
					}
					finally
					{
						((IDisposable)memberToDispose)?.Dispose();
					}
				}
			}
			finally
			{
				((IDisposable)memberSearcher)?.Dispose();
			}

			int directMembers = members.Count;
			// Surface d'attaque : plus il y a de membres directs, plus le risque est élevé.
			bool tooManyMembers = directMembers > 2;
			string groupLabel = (string.IsNullOrEmpty(groupDomain) ? "" : groupDomain + "\\") + groupName;
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Membres du groupe Administrateurs local",
				CurrentValue = $"{groupLabel} (SID {AdministratorsGroupSid}) — {directMembers} membre(s) direct(s) : " + (directMembers == 0 ? "aucun" : string.Join(", ", members)),
				ExpectedValue = "<= 2 membres directs (surface d'attaque minimale)",
				Status = (tooManyMembers ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Le groupe Administrateurs local (résolu par SID S-1-5-32-544, indépendamment de la locale) confère un contrôle total sur la machine. Un nombre élevé de membres directs élargit la surface d'attaque et augmente le risque de mouvement latéral en cas de compromission d'un de ces comptes.",
				Recommendation = (tooManyMembers ? "Réduire le nombre de membres directs du groupe Administrateurs local au strict nécessaire. Privilégier des groupes de sécurité gérés et l'accès à privilèges juste-à-temps (JIT/PAM)." : "Le nombre de membres du groupe Administrateurs local est maîtrisé."),
				Reference = "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models"
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
				CheckName = "Membres du groupe Administrateurs local",
				CurrentValue = "Erreur : " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Échec de l'énumération des membres du groupe Administrateurs local via WMI.",
				Recommendation = "Exécuter en tant qu'administrateur et vérifier WMI.",
				Reference = ""
			});
		}
	}

	// ------------------------------------------------------------------
	// 2) Compte Invité (Guest), résolu par SID se terminant par -501.
	// ------------------------------------------------------------------
	private void CollectGuestAccount(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			bool guestFound = false;
			bool guestEnabled = false;
			string guestName = null;
			ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Name,SID,Disabled FROM Win32_UserAccount WHERE LocalAccount=True");
			try
			{
				using ManagementObjectCollection collection = searcher.Get();
				foreach (ManagementObject userAccount in collection)
				{
					ManagementObject userToDispose = userAccount;
					try
					{
						ct.ThrowIfCancellationRequested();
						string sid = userAccount["SID"]?.ToString() ?? "";
						// Le compte Invité est identifié par son RID 501 (locale-indépendant).
						if (sid.EndsWith("-501"))
						{
							guestFound = true;
							guestName = userAccount["Name"]?.ToString() ?? "Guest";
							bool disabled = Convert.ToBoolean(userAccount["Disabled"] ?? ((object)true));
							if (!disabled)
							{
								guestEnabled = true;
							}
						}
					}
					finally
					{
						((IDisposable)userToDispose)?.Dispose();
					}
				}
			}
			finally
			{
				((IDisposable)searcher)?.Dispose();
			}

			bool foundCapture = guestFound;
			bool enabledCapture = guestEnabled;
			string nameCapture = guestName ?? "Invité";
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Compte Invité (Guest, RID 501)",
				CurrentValue = (!foundCapture ? "Compte Invité introuvable (supprimé ?)" : (enabledCapture ? ("Activé : " + nameCapture) : ("Désactivé : " + nameCapture))),
				ExpectedValue = "Désactivé",
				Status = (enabledCapture ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Le compte Invité (identifié par le RID 501, indépendamment de la locale) fournit un accès non authentifié au système. Il doit impérativement rester désactivé.",
				Recommendation = (enabledCapture ? "Désactiver immédiatement le compte Invité : net user \"" + nameCapture + "\" /active:no" : "Le compte Invité est désactivé."),
				Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status"
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
				CheckName = "Compte Invité (Guest, RID 501)",
				CurrentValue = "Erreur : " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Échec de la résolution du compte Invité via WMI.",
				Recommendation = "Exécuter en tant qu'administrateur et vérifier WMI.",
				Reference = ""
			});
		}
	}

	// ------------------------------------------------------------------
	// 3) Comptes locaux « mot de passe n'expire jamais » (agrégat).
	// ------------------------------------------------------------------
	private void CollectPasswordNeverExpires(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			List<string> neverExpireAccounts = new List<string>();
			// Comptes locaux activés dont le mot de passe n'expire jamais.
			ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Name,SID,Disabled,PasswordExpires FROM Win32_UserAccount WHERE LocalAccount=True AND Disabled=False AND PasswordExpires=False");
			try
			{
				using ManagementObjectCollection collection = searcher.Get();
				foreach (ManagementObject userAccount in collection)
				{
					ManagementObject userToDispose = userAccount;
					try
					{
						ct.ThrowIfCancellationRequested();
						string name = userAccount["Name"]?.ToString() ?? "Unknown";
						string sid = userAccount["SID"]?.ToString() ?? "";
						// On ignore les comptes système bien connus (RID < 1000) tels que
						// DefaultAccount (503), WDAGUtilityAccount (504), Invité (501)...
						// Le compte administrateur intégré (500) est également non-standard.
						if (IsSystemAccountSid(sid))
						{
							continue;
						}
						neverExpireAccounts.Add(name);
					}
					finally
					{
						((IDisposable)userToDispose)?.Dispose();
					}
				}
			}
			finally
			{
				((IDisposable)searcher)?.Dispose();
			}

			int count = neverExpireAccounts.Count;
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Comptes locaux : mot de passe qui n'expire jamais",
				CurrentValue = (count == 0 ? "Aucun compte local activé avec mot de passe non expirable" : $"{count} compte(s) : " + string.Join(", ", neverExpireAccounts)),
				ExpectedValue = "0 (hors comptes de service justifiés)",
				Status = (count > 0 ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Les comptes locaux activés dont le mot de passe n'expire jamais (PasswordExpires=False) présentent un risque : un mot de passe compromis reste valide indéfiniment. Certains comptes de service peuvent légitimement avoir cette configuration, mais ils doivent être justifiés et documentés.",
				Recommendation = (count > 0 ? "Vérifier chaque compte listé. Pour les comptes interactifs, activer l'expiration du mot de passe. Pour les comptes de service justifiés, utiliser des comptes de service gérés de groupe (gMSA) ou une rotation régulière via LAPS/PAM." : "Aucun compte local activé n'a de mot de passe non expirable non justifié."),
				Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/maximum-password-age"
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
				CheckName = "Comptes locaux : mot de passe qui n'expire jamais",
				CurrentValue = "Erreur : " + ex.Message,
				Status = SecurityStatus.Error,
				Description = "Échec de l'énumération des comptes locaux via WMI.",
				Recommendation = "Exécuter en tant qu'administrateur et vérifier WMI.",
				Reference = ""
			});
		}
	}

	// ------------------------------------------------------------------
	// 4) Comptes locaux dormants (best-effort via Win32_NetworkLoginProfile).
	//    Isolé dans son propre try/catch pour ne pas casser le reste du collecteur.
	// ------------------------------------------------------------------
	private void CollectDormantAccounts(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			// Ensemble des comptes locaux activés (jointure par Name, insensible à la casse).
			HashSet<string> enabledLocalAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			ManagementObjectSearcher userSearcher = new ManagementObjectSearcher("SELECT Name,SID FROM Win32_UserAccount WHERE LocalAccount=True AND Disabled=False");
			try
			{
				using ManagementObjectCollection userCollection = userSearcher.Get();
				foreach (ManagementObject userAccount in userCollection)
				{
					ManagementObject userToDispose = userAccount;
					try
					{
						ct.ThrowIfCancellationRequested();
						string sid = userAccount["SID"]?.ToString() ?? "";
						if (IsSystemAccountSid(sid))
						{
							continue;
						}
						string name = userAccount["Name"]?.ToString();
						if (!string.IsNullOrEmpty(name))
						{
							enabledLocalAccounts.Add(name);
						}
					}
					finally
					{
						((IDisposable)userToDispose)?.Dispose();
					}
				}
			}
			finally
			{
				((IDisposable)userSearcher)?.Dispose();
			}

			// Récupération des dernières connexions via Win32_NetworkLoginProfile (best-effort).
			List<string> dormantAccounts = new List<string>();
			bool anyLastLogonAvailable = false;
			DateTime now = DateTime.Now;
			ManagementObjectSearcher profileSearcher = new ManagementObjectSearcher("SELECT Name,LastLogon FROM Win32_NetworkLoginProfile");
			try
			{
				using ManagementObjectCollection profileCollection = profileSearcher.Get();
				foreach (ManagementObject profile in profileCollection)
				{
					ManagementObject profileToDispose = profile;
					try
					{
						ct.ThrowIfCancellationRequested();
						string profileName = profile["Name"]?.ToString() ?? "";
						// Le champ Name peut être « DOMAINE\\Utilisateur » : on isole le nom court.
						string shortName = profileName;
						int backslashIndex = profileName.LastIndexOf('\\');
						if (backslashIndex >= 0 && backslashIndex + 1 < profileName.Length)
						{
							shortName = profileName.Substring(backslashIndex + 1);
						}
						if (!enabledLocalAccounts.Contains(shortName))
						{
							continue;
						}
						object lastLogonRaw = profile["LastLogon"];
						string lastLogonStr = lastLogonRaw?.ToString();
						// La valeur CIM_DATETIME « ***... » indique « jamais connecté ».
						if (string.IsNullOrEmpty(lastLogonStr) || lastLogonStr.StartsWith("***"))
						{
							continue;
						}
						DateTime lastLogon;
						try
						{
							lastLogon = ManagementDateTimeConverter.ToDateTime(lastLogonStr);
						}
						catch
						{
							continue;
						}
						anyLastLogonAvailable = true;
						double inactiveDays = (now - lastLogon).TotalDays;
						if (inactiveDays > DormantThresholdDays)
						{
							dormantAccounts.Add($"{shortName} (dernière connexion {lastLogon.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}, {(int)inactiveDays} j)");
						}
					}
					finally
					{
						((IDisposable)profileToDispose)?.Dispose();
					}
				}
			}
			finally
			{
				((IDisposable)profileSearcher)?.Dispose();
			}

			if (!anyLastLogonAvailable)
			{
				// LastLogon indisponible (Win32_NetworkLoginProfile n'est renseigné que pour
				// certains scénarios de logon réseau) : on produit un Info non bloquant.
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Comptes locaux dormants",
					CurrentValue = "Inactivité non déterminable (LastLogon indisponible via Win32_NetworkLoginProfile)",
					ExpectedValue = "Aucun compte inactif > " + DormantThresholdDays + " jours",
					Status = SecurityStatus.Info,
					Description = "La classe WMI Win32_NetworkLoginProfile n'a fourni aucune date de dernière connexion exploitable pour les comptes locaux activés. La détection des comptes dormants n'est pas possible par cette méthode sur ce système.",
					Recommendation = "Auditer manuellement les dernières connexions (par ex. via les journaux d'événements Security 4624/4634 ou 'net user <nom>') et désactiver les comptes locaux inutilisés.",
					Reference = "https://learn.microsoft.com/windows/win32/cimwin32prov/win32-networkloginprofile"
				});
				return;
			}

			int dormantCount = dormantAccounts.Count;
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Comptes locaux dormants",
				CurrentValue = (dormantCount == 0 ? "Aucun compte local activé inactif au-delà du seuil" : $"{dormantCount} compte(s) inactif(s) > {DormantThresholdDays} j : " + string.Join(", ", dormantAccounts)),
				ExpectedValue = "Aucun compte inactif > " + DormantThresholdDays + " jours",
				Status = (dormantCount > 0 ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Les comptes locaux activés mais inutilisés depuis plus de " + DormantThresholdDays + " jours (comptes dormants) élargissent inutilement la surface d'attaque : ils peuvent être compromis sans être détectés par un utilisateur légitime.",
				Recommendation = (dormantCount > 0 ? "Vérifier la nécessité de chaque compte dormant listé et désactiver ceux qui ne sont plus utilisés." : "Aucun compte local dormant détecté au-delà du seuil."),
				Reference = "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models"
			});
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			// La détection des comptes dormants est best-effort : on ne casse pas le collecteur.
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Comptes locaux dormants",
				CurrentValue = "Inactivité non déterminable (" + ex.Message + ")",
				Status = SecurityStatus.Info,
				Description = "La détection des comptes locaux dormants a échoué (best-effort). Le reste du collecteur n'est pas affecté.",
				Recommendation = "Auditer manuellement les dernières connexions et désactiver les comptes locaux inutilisés.",
				Reference = ""
			});
		}
	}

	// Détermine si un SID correspond à un compte système bien connu (RID < 1000).
	private static bool IsSystemAccountSid(string sid)
	{
		if (string.IsNullOrEmpty(sid))
		{
			return false;
		}
		int lastDash = sid.LastIndexOf('-');
		if (lastDash < 0 || lastDash + 1 >= sid.Length)
		{
			return false;
		}
		string ridPart = sid.Substring(lastDash + 1);
		if (int.TryParse(ridPart, NumberStyles.Integer, CultureInfo.InvariantCulture, out int rid))
		{
			return rid < 1000;
		}
		return false;
	}

	// Lecture défensive d'une propriété WMI en chaîne (null-safe).
	private static string SafeGet(ManagementBaseObject mo, string property)
	{
		try
		{
			return mo[property]?.ToString();
		}
		catch
		{
			return null;
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
				Category = "Comptes",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les accès WMI et les permissions.",
				Reference = ""
			});
		}
	}
}
