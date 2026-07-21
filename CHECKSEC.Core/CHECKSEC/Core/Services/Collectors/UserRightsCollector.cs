using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur CHECKSEC : audite les attributions de droits utilisateur (User Rights Assignment) locaux.
// Objectif : reperer les privileges sensibles attribues a des titulaires inattendus (vecteurs d'elevation
// de privileges, contournement d'ACL, BYOVD, Potato, etc.).
// Methode : export locale-independant via secedit.exe /areas USER_RIGHTS, puis parsing de la section
// [Privilege Rights]. Les noms de privileges (Se...Privilege) sont INVARIANTS de la langue de Windows,
// contrairement aux libelles affiches dans secpol.msc. Les SID (*S-1-5-...) sont resolus en noms de comptes.
public class UserRightsCollector : ISecurityCollector
{
	public string Name => "Droits utilisateur (User Rights)";

	public string Category => "Comptes";

	// SID bien connus utilises pour l'evaluation des titulaires attendus.
	private const string SidAdministrators = "S-1-5-32-544"; // BUILTIN\Administrateurs
	private const string SidBackupOperators = "S-1-5-32-551"; // BUILTIN\Operateurs de sauvegarde
	private const string SidServerOperators = "S-1-5-32-549"; // BUILTIN\Operateurs de serveur
	private const string SidLocalSystem = "S-1-5-18"; // LocalSystem
	private const string SidLocalService = "S-1-5-19"; // LocalService
	private const string SidNetworkService = "S-1-5-20"; // NetworkService
	private const string SidServiceGroup = "S-1-5-6"; // Groupe SERVICE
	private const string SidGuests = "S-1-5-32-546"; // BUILTIN\Invites

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
			// Recuperation des attributions via secedit (necessite les droits administrateur).
			Dictionary<string, List<string>> privileges = ExportUserRights(report.Results, ct);
			if (privileges != null)
			{
				ct.ThrowIfCancellationRequested();
				EvaluatePrivileges(report.Results, privileges, ct);
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			report.ErrorMessage = "UserRightsCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			report.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(report);
	}

	// Exporte la zone USER_RIGHTS via secedit dans un fichier INF temporaire (dossier GUID unique),
	// lit le contenu en Unicode (secedit ecrit en UTF-16), et parse la section [Privilege Rights].
	// Retourne null (et ajoute un resultat Error) si secedit echoue.
	private Dictionary<string, List<string>> ExportUserRights(List<SecurityResult> results, CancellationToken ct)
	{
		// Dossier temporaire unique pour isoler l'export et faciliter le nettoyage.
		string tempDir = Path.Combine(Path.GetTempPath(), "checksec_userrights_" + Guid.NewGuid().ToString("N"));
		string cfgPath = Path.Combine(tempDir, "userrights.inf");
		try
		{
			Directory.CreateDirectory(tempDir);
			int exitCode = -1;
			string stdErr = string.Empty;
			try
			{
				ProcessStartInfo startInfo = new ProcessStartInfo("secedit.exe", "/export /areas USER_RIGHTS /cfg \"" + cfgPath + "\" /quiet")
				{
					UseShellExecute = false,
					CreateNoWindow = true,
					RedirectStandardOutput = true,
					RedirectStandardError = true
				};
				// Timeout borne et lie au jeton d'annulation appelant (ct).
				using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
				timeoutCts.CancelAfter(TimeSpan.FromSeconds(20L));
				using Process process = Process.Start(startInfo);
				if (process != null)
				{
					stdErr = process.StandardError.ReadToEnd();
					if (!process.WaitForExit(20000))
					{
						try
						{
							process.Kill();
						}
						catch
						{
						}
					}
					ct.ThrowIfCancellationRequested();
					exitCode = process.ExitCode;
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				// Echec au lancement de secedit : resultat Error explicite (pas de silence).
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "User Rights: Export secedit",
					CurrentValue = "Echec du lancement de secedit.exe : " + ex.Message,
					ExpectedValue = "Export USER_RIGHTS reussi",
					Status = SecurityStatus.Error,
					Description = "Impossible de lancer secedit.exe pour exporter les attributions de droits utilisateur.",
					Recommendation = "Executer CHECKSEC en tant qu'administrateur et verifier la disponibilite de secedit.exe.",
					Reference = "https://learn.microsoft.com/windows-server/administration/windows-commands/secedit"
				});
				return null;
			}
			if (exitCode != 0 || !File.Exists(cfgPath))
			{
				// secedit a echoue ou n'a produit aucun fichier : resultat Error explicite.
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "User Rights: Export secedit",
					CurrentValue = "secedit code " + exitCode + (string.IsNullOrWhiteSpace(stdErr) ? "" : (" - " + stdErr.Trim())),
					ExpectedValue = "Export USER_RIGHTS reussi",
					Status = SecurityStatus.Error,
					Description = "L'export des droits utilisateur via secedit a echoue. secedit necessite des privileges administrateur.",
					Recommendation = "Relancer CHECKSEC avec une elevation de privileges (administrateur).",
					Reference = "https://learn.microsoft.com/windows-server/administration/windows-commands/secedit"
				});
				return null;
			}
			// Lecture Unicode (secedit ecrit le fichier INF en UTF-16).
			string[] lines = File.ReadAllLines(cfgPath, Encoding.Unicode);
			Dictionary<string, List<string>> privileges = ParsePrivilegeRights(lines);
			return privileges;
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
				CheckName = "User Rights: Export secedit",
				CurrentValue = "Erreur : " + ex.Message,
				ExpectedValue = "Export USER_RIGHTS reussi",
				Status = SecurityStatus.Error,
				Description = "Erreur inattendue lors de l'export/lecture des droits utilisateur via secedit.",
				Recommendation = "Executer CHECKSEC en tant qu'administrateur.",
				Reference = "https://learn.microsoft.com/windows-server/administration/windows-commands/secedit"
			});
			return null;
		}
		finally
		{
			// Nettoyage : suppression du dossier temporaire quoi qu'il arrive.
			try
			{
				if (Directory.Exists(tempDir))
				{
					Directory.Delete(tempDir, recursive: true);
				}
			}
			catch (Exception)
			{
			}
		}
	}

	// Parse la section [Privilege Rights] : chaque ligne a la forme "SeXxxPrivilege = *S-1-5-..,*S-1-5-32-544,...".
	// Retourne un dictionnaire { nom de privilege -> liste des SID (sans le prefixe '*') }.
	private static Dictionary<string, List<string>> ParsePrivilegeRights(string[] lines)
	{
		Dictionary<string, List<string>> privileges = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
		bool inSection = false;
		foreach (string rawLine in lines)
		{
			string line = rawLine.Trim();
			if (line.Length == 0 || line.StartsWith(";"))
			{
				continue;
			}
			if (line.StartsWith("["))
			{
				// Entree/sortie de la section pertinente.
				inSection = line.Equals("[Privilege Rights]", StringComparison.OrdinalIgnoreCase);
				continue;
			}
			if (!inSection)
			{
				continue;
			}
			int sep = line.IndexOf('=');
			if (sep <= 0)
			{
				continue;
			}
			string privName = line.Substring(0, sep).Trim();
			string valuePart = line.Substring(sep + 1).Trim();
			List<string> sids = new List<string>();
			if (valuePart.Length > 0)
			{
				string[] tokens = valuePart.Split(',');
				foreach (string token in tokens)
				{
					string sid = token.Trim();
					if (sid.StartsWith("*"))
					{
						// secedit prefixe les SID d'une etoile ; on la retire.
						sid = sid.Substring(1);
					}
					if (sid.Length > 0)
					{
						sids.Add(sid);
					}
				}
			}
			privileges[privName] = sids;
		}
		return privileges;
	}

	// Resout un SID en nom de compte/groupe lisible (DOMAINE\Nom). En cas d'echec (SID orphelin,
	// compte supprime), retourne le SID brut : certains SID ne se resolvent pas.
	private static string ResolveSid(string sid)
	{
		try
		{
			SecurityIdentifier identifier = new SecurityIdentifier(sid);
			NTAccount account = (NTAccount)identifier.Translate(typeof(NTAccount));
			return account.Value;
		}
		catch (Exception)
		{
			return sid;
		}
	}

	// Construit une chaine lisible "Nom (SID), Nom (SID)" pour la liste des titulaires.
	private static string FormatHolders(List<string> sids)
	{
		if (sids == null || sids.Count == 0)
		{
			return "(aucun titulaire)";
		}
		return string.Join(", ", sids.Select((string s) => ResolveSid(s) + " [" + s + "]"));
	}

	// Evalue chaque privilege sensible et produit un SecurityResult par privilege avec la severite adaptee.
	private void EvaluatePrivileges(List<SecurityResult> results, Dictionary<string, List<string>> privileges, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// --- SeDebugPrivilege : attendu = Administrateurs uniquement ---
		AddPrivilegeCheck(results, privileges, "SeDebugPrivilege", "Deboguer les programmes",
			delegate (List<string> sids)
			{
				// Attendu : uniquement S-1-5-32-544. Tout autre titulaire est un probleme.
				bool onlyAdmins = sids.Count > 0 && sids.All((string s) => string.Equals(s, SidAdministrators, StringComparison.OrdinalIgnoreCase));
				bool hasNonAdmin = sids.Any((string s) => !string.Equals(s, SidAdministrators, StringComparison.OrdinalIgnoreCase));
				// Un compte utilisateur (SID de type S-1-5-21-...-RID >= 1000) est particulierement critique.
				bool hasUserAccount = sids.Any(IsLikelyUserOrCustomGroup);
				SecurityStatus status = (onlyAdmins || sids.Count == 0) ? SecurityStatus.OK : (hasUserAccount ? SecurityStatus.Critical : (hasNonAdmin ? SecurityStatus.Warning : SecurityStatus.OK));
				return status;
			},
			"Administrateurs uniquement (S-1-5-32-544)",
			"SeDebugPrivilege permet d'ouvrir n'importe quel processus (y compris LSASS) et de manipuler sa memoire. C'est un vecteur direct de vol de credentials (Mimikatz) et d'elevation vers SYSTEM.",
			"Restreindre SeDebugPrivilege aux Administrateurs uniquement. Retirer tout utilisateur ou groupe personnalise.",
			"https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/debug-programs");

		// --- SeImpersonatePrivilege : attendu = comptes de service systeme ---
		AddPrivilegeCheck(results, privileges, "SeImpersonatePrivilege", "Empprunter l'identite d'un client apres authentification",
			delegate (List<string> sids)
			{
				bool hasUser = sids.Any(IsLikelyUserOrCustomGroup);
				return hasUser ? SecurityStatus.Warning : SecurityStatus.OK;
			},
			"Comptes de service systeme (LocalSystem, LocalService, NetworkService, SERVICE)",
			"SeImpersonatePrivilege permet a un processus d'emprunter l'identite d'un client. Attribue a un utilisateur ou groupe standard, il ouvre la voie aux attaques 'Potato' (JuicyPotato, PrintSpoofer, RoguePotato) menant a une elevation vers SYSTEM.",
			"Ne conserver ce privilege que pour les comptes de service systeme. Retirer tout utilisateur/groupe standard.",
			"https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication");

		// --- SeAssignPrimaryTokenPrivilege : attendu = comptes de service systeme ---
		AddPrivilegeCheck(results, privileges, "SeAssignPrimaryTokenPrivilege", "Remplacer un jeton de niveau processus",
			delegate (List<string> sids)
			{
				bool hasUser = sids.Any(IsLikelyUserOrCustomGroup);
				return hasUser ? SecurityStatus.Warning : SecurityStatus.OK;
			},
			"Comptes de service systeme (LocalService, NetworkService)",
			"SeAssignPrimaryTokenPrivilege permet d'assigner le jeton primaire d'un processus. Combine a l'impersonation, c'est un vecteur d'elevation de privileges (EoP) exploite par les techniques 'Potato'.",
			"Reserver ce privilege aux comptes de service systeme. Retirer tout utilisateur/groupe standard.",
			"https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/replace-a-process-level-token");

		// --- SeTcbPrivilege : ne devrait etre attribue a PERSONNE ---
		AddPrivilegeCheck(results, privileges, "SeTcbPrivilege", "Agir en tant que partie du systeme d'exploitation",
			delegate (List<string> sids)
			{
				// Normalement vide. Tout titulaire => Critical.
				return (sids.Count == 0) ? SecurityStatus.OK : SecurityStatus.Critical;
			},
			"Aucun titulaire",
			"SeTcbPrivilege ('Act as part of the operating system') permet a un processus d'usurper n'importe quelle identite et d'obtenir les privileges du systeme. Il ne devrait etre attribue a aucun compte.",
			"Retirer tous les titulaires de SeTcbPrivilege. Aucun compte ne doit posseder ce privilege.",
			"https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system");

		// --- SeCreateTokenPrivilege : ne devrait etre attribue a PERSONNE ---
		AddPrivilegeCheck(results, privileges, "SeCreateTokenPrivilege", "Creer un objet-jeton",
			delegate (List<string> sids)
			{
				return (sids.Count == 0) ? SecurityStatus.OK : SecurityStatus.Critical;
			},
			"Aucun titulaire",
			"SeCreateTokenPrivilege permet de forger des jetons d'acces arbitraires, donc d'obtenir n'importe quelle appartenance de groupe (y compris SYSTEM). Il ne devrait etre attribue a aucun compte.",
			"Retirer tous les titulaires de SeCreateTokenPrivilege.",
			"https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/create-a-token-object");

		// --- SeLoadDriverPrivilege : Administrateurs uniquement (BYOVD) ---
		AddPrivilegeCheck(results, privileges, "SeLoadDriverPrivilege", "Charger et decharger des pilotes de peripheriques",
			delegate (List<string> sids)
			{
				bool nonAdmin = sids.Any((string s) => !string.Equals(s, SidAdministrators, StringComparison.OrdinalIgnoreCase));
				return nonAdmin ? SecurityStatus.Warning : SecurityStatus.OK;
			},
			"Administrateurs uniquement (S-1-5-32-544)",
			"SeLoadDriverPrivilege permet de charger des pilotes en mode noyau. C'est le vecteur des attaques BYOVD (Bring Your Own Vulnerable Driver) permettant de desactiver l'EDR et d'executer du code noyau.",
			"Restreindre SeLoadDriverPrivilege aux Administrateurs uniquement.",
			"https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/load-and-unload-device-drivers");

		// --- Privileges de contournement d'ACL : Administrateurs (+ Operators) ---
		AddPrivilegeCheck(results, privileges, "SeBackupPrivilege", "Sauvegarder des fichiers et des repertoires",
			CheckBackupRestoreClass,
			"Administrateurs (+ Operateurs de sauvegarde)",
			"SeBackupPrivilege permet de lire n'importe quel fichier en ignorant les ACL (contournement des permissions NTFS). Un utilisateur standard peut ainsi extraire des donnees sensibles (SAM, ruches).",
			"Limiter SeBackupPrivilege aux Administrateurs et Operateurs de sauvegarde. Retirer tout utilisateur standard.",
			"https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories");

		AddPrivilegeCheck(results, privileges, "SeRestorePrivilege", "Restaurer des fichiers et des repertoires",
			CheckBackupRestoreClass,
			"Administrateurs (+ Operateurs de sauvegarde)",
			"SeRestorePrivilege permet d'ecrire n'importe quel fichier en ignorant les ACL et de changer les proprietaires. Vecteur d'elevation de privileges (remplacement de binaires proteges).",
			"Limiter SeRestorePrivilege aux Administrateurs et Operateurs de sauvegarde.",
			"https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/restore-files-and-directories");

		AddPrivilegeCheck(results, privileges, "SeTakeOwnershipPrivilege", "Prendre possession de fichiers ou d'autres objets",
			delegate (List<string> sids)
			{
				bool hasUser = sids.Any(IsLikelyUserOrCustomGroup);
				return hasUser ? SecurityStatus.Warning : SecurityStatus.OK;
			},
			"Administrateurs uniquement",
			"SeTakeOwnershipPrivilege permet de prendre possession de n'importe quel objet securisable, donc de contourner les ACL et d'acceder a des ressources protegees.",
			"Limiter SeTakeOwnershipPrivilege aux Administrateurs.",
			"https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects");

		// --- Logon rights : verification de la presence des comptes sensibles dans les Deny ---
		AddLogonRightCheck(results, privileges, "SeDenyInteractiveLogonRight", "Interdire l'ouverture de session locale",
			"Doit inclure les comptes sensibles (Invites, comptes de service)",
			"Ce droit interdit l'ouverture de session locale. Y placer les Invites et les comptes de service reduit la surface d'attaque en cas de compromission.",
			"S'assurer que les Invites (S-1-5-32-546) et les comptes a risque figurent dans 'Interdire l'ouverture de session locale'.");

		AddLogonRightCheck(results, privileges, "SeDenyRemoteInteractiveLogonRight", "Interdire l'ouverture de session par les services Bureau a distance",
			"Doit inclure les comptes sensibles (Invites, compte administrateur local si non utilise en RDP)",
			"Ce droit interdit l'ouverture de session RDP. Y placer les Invites et les comptes locaux sensibles limite le mouvement lateral via RDP.",
			"S'assurer que les Invites et comptes locaux sensibles figurent dans 'Interdire l'ouverture de session par les services Bureau a distance'.");

		// --- Logon rights informatifs : lister les titulaires ---
		AddLogonRightInfo(results, privileges, "SeServiceLogonRight", "Ouvrir une session en tant que service",
			"Ce droit autorise l'ouverture de session en tant que service. La liste des titulaires doit correspondre aux comptes de service legitimes.");

		AddLogonRightInfo(results, privileges, "SeBatchLogonRight", "Ouvrir une session en tant que tache",
			"Ce droit autorise l'ouverture de session par lot (taches planifiees). Passer en revue les titulaires pour detecter des comptes inattendus.");
	}

	// Evaluateur commun aux privileges de la classe Backup/Restore : Administrateurs + Operateurs (sauvegarde/serveur)
	// sont tolerables ; un utilisateur ou groupe personnalise standard => Warning.
	private static SecurityStatus CheckBackupRestoreClass(List<string> sids)
	{
		bool hasUser = sids.Any((string s) =>
			!string.Equals(s, SidAdministrators, StringComparison.OrdinalIgnoreCase)
			&& !string.Equals(s, SidBackupOperators, StringComparison.OrdinalIgnoreCase)
			&& !string.Equals(s, SidServerOperators, StringComparison.OrdinalIgnoreCase)
			&& IsLikelyUserOrCustomGroup(s));
		return hasUser ? SecurityStatus.Warning : SecurityStatus.OK;
	}

	// Heuristique : un SID represente probablement un compte utilisateur ou un groupe personnalise
	// (donc pas un principal systeme/BUILTIN de confiance) si :
	//  - il n'est pas un compte de service systeme connu, ni un groupe BUILTIN standard, et
	//  - il ressemble a un SID de domaine/local avec RID >= 1000 (comptes crees), ou n'est pas reconnu.
	private static bool IsLikelyUserOrCustomGroup(string sid)
	{
		if (string.IsNullOrEmpty(sid))
		{
			return false;
		}
		// Comptes de service systeme et groupes systeme de confiance.
		string[] trustedWellKnown = new string[]
		{
			SidLocalSystem, SidLocalService, SidNetworkService, SidServiceGroup,
			SidAdministrators, SidBackupOperators, SidServerOperators
		};
		if (trustedWellKnown.Any((string t) => string.Equals(t, sid, StringComparison.OrdinalIgnoreCase)))
		{
			return false;
		}
		// Comptes/groupes du domaine ou locaux (S-1-5-21-...) avec RID utilisateur (>= 1000).
		if (sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase))
		{
			int lastDash = sid.LastIndexOf('-');
			if (lastDash > 0 && int.TryParse(sid.Substring(lastDash + 1), out int rid))
			{
				return rid >= 1000;
			}
			return true;
		}
		// Utilisateurs authentifies (S-1-5-11), Tout le monde (S-1-1-0), Utilisateurs (S-1-5-32-545) :
		// attribuer un privilege sensible a ces groupes larges est anormal.
		if (string.Equals(sid, "S-1-5-11", StringComparison.OrdinalIgnoreCase)
			|| string.Equals(sid, "S-1-1-0", StringComparison.OrdinalIgnoreCase)
			|| string.Equals(sid, "S-1-5-32-545", StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}
		return false;
	}

	// Produit un resultat pour un privilege sensible avec la liste des titulaires et la severite calculee.
	private void AddPrivilegeCheck(List<SecurityResult> results, Dictionary<string, List<string>> privileges,
		string privilegeName, string frenchLabel, Func<List<string>, SecurityStatus> severityEvaluator,
		string expected, string description, string recommendation, string reference)
	{
		TryAdd(results, delegate
		{
			// Un privilege absent de l'export signifie "aucun titulaire".
			List<string> sids = privileges.TryGetValue(privilegeName, out List<string> found) ? found : new List<string>();
			SecurityStatus status = severityEvaluator(sids);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Privilege: " + privilegeName + " (" + frenchLabel + ")",
				CurrentValue = FormatHolders(sids),
				ExpectedValue = expected,
				Status = status,
				Description = description,
				Recommendation = (status == SecurityStatus.OK) ? "Attribution conforme." : recommendation,
				Reference = reference
			};
		});
	}

	// Produit un resultat pour un droit de deni de logon : Info/OK si les comptes sensibles y figurent.
	private void AddLogonRightCheck(List<SecurityResult> results, Dictionary<string, List<string>> privileges,
		string privilegeName, string frenchLabel, string expected, string description, string recommendation)
	{
		TryAdd(results, delegate
		{
			List<string> sids = privileges.TryGetValue(privilegeName, out List<string> found) ? found : new List<string>();
			bool includesGuests = sids.Any((string s) => string.Equals(s, SidGuests, StringComparison.OrdinalIgnoreCase));
			// Presence des Invites dans le deny => bonne pratique (OK), sinon Info a passer en revue.
			SecurityStatus status = includesGuests ? SecurityStatus.OK : SecurityStatus.Info;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Logon Right: " + privilegeName + " (" + frenchLabel + ")",
				CurrentValue = FormatHolders(sids),
				ExpectedValue = expected,
				Status = status,
				Description = description,
				Recommendation = includesGuests ? "Les Invites figurent bien dans ce droit de deni." : recommendation,
				Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/user-rights-assignment"
			};
		});
	}

	// Produit un resultat informatif listant les titulaires d'un droit de logon (Service/Batch).
	private void AddLogonRightInfo(List<SecurityResult> results, Dictionary<string, List<string>> privileges,
		string privilegeName, string frenchLabel, string description)
	{
		TryAdd(results, delegate
		{
			List<string> sids = privileges.TryGetValue(privilegeName, out List<string> found) ? found : new List<string>();
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Logon Right: " + privilegeName + " (" + frenchLabel + ")",
				CurrentValue = FormatHolders(sids),
				ExpectedValue = "Comptes legitimes uniquement (revue manuelle)",
				Status = SecurityStatus.Info,
				Description = description,
				Recommendation = "Passer en revue la liste des titulaires et retirer les comptes inattendus.",
				Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/user-rights-assignment"
			};
		});
	}

	// Ajout defensif : encapsule la fabrique d'un resultat pour ne jamais interrompre le collecteur
	// sur l'echec d'un seul controle.
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
				Recommendation = "Verifier l'acces a secedit et la resolution des SID (droits administrateur).",
				Reference = ""
			});
		}
	}
}
