using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur d'analyse des tâches planifiées Windows sous l'angle sécurité.
// Objectif : détecter deux familles de risques -
//   1) des ACL (listes de contrôle d'accès) faibles sur le dossier et les fichiers de
//      définition des tâches (C:\Windows\System32\Tasks), permettant à un utilisateur NON
//      privilégié de modifier la définition d'une tâche exécutée en SYSTEM (élévation de
//      privilèges / EoP) ;
//   2) des tâches pointant vers un binaire situé dans un chemin « utilisateur » modifiable
//      (Temp, AppData, Users, Public, ProgramData) - vecteur classique de persistance.
// Méthode : lecture DIRECTE des fichiers XML de définition et de leurs ACL (invariant, non
// localisé). On n'utilise volontairement PAS 'schtasks' (sortie localisée / fragile).
// ATTENTION : lecture seule - ce collecteur ne modifie JAMAIS aucune ACL ni aucun fichier.
public class ScheduledTaskAclCollector : ISecurityCollector
{
	// SID des principals NON privilégiés à surveiller (résolution par SID = indépendante de la locale).
	private static readonly SecurityIdentifier UsersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);                       // S-1-5-32-545
	private static readonly SecurityIdentifier EveryoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);                          // S-1-1-0
	private static readonly SecurityIdentifier AuthenticatedUsersSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);    // S-1-5-11

	// Droits réellement dangereux pour un principal non privilégié sur les tâches planifiées.
	// IMPORTANT (bug review, vérifié sur système réel) : le dossier System32\Tasks accorde PAR
	// DÉFAUT « Write » (WriteData/AppendData/WriteAttributes/WriteExtendedAttributes) à
	// « Utilisateurs authentifiés » — comportement STANDARD de Windows, pas une faille. Inclure
	// ces bits provoque un faux Critical sur toute machine. On ne garde donc que les droits de
	// TAMPERING réels ABSENTS du défaut : supprimer/remplacer une définition de tâche (Delete),
	// ou réattribuer ses permissions (ChangePermissions/TakeOwnership) → EoP réel.
	private const FileSystemRights DangerousFileRights =
		FileSystemRights.Delete |
		FileSystemRights.DeleteSubdirectoriesAndFiles |
		FileSystemRights.ChangePermissions |
		FileSystemRights.TakeOwnership;

	// Bornes de parcours pour éviter toute explosion de coût sur un poste chargé.
	private const int MaxFilesInspected = 200;   // Cap global de fichiers de définition inspectés.
	private const int MaxDepth = 1;              // Dossier racine + 1 niveau de sous-dossiers.

	public string Name => "Tâches planifiées — ACL & risques";

	public string Category => "Autoruns & Persistance";

	public Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport collectorReport = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch stopwatch = Stopwatch.StartNew();
		// Compteurs de synthèse.
		int tasksInspected = 0;
		int tasksAtRisk = 0;
		try
		{
			ct.ThrowIfCancellationRequested();

			string tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");

			// 1) ACL du dossier des tâches (racine + sous-dossiers bornés).
			CollectFolderAcls(collectorReport.Results, tasksRoot, ct);
			ct.ThrowIfCancellationRequested();

			// 2) + 3) ACL des fichiers de définition ET analyse du contenu XML (chemins utilisateur).
			CollectTaskFiles(collectorReport.Results, tasksRoot, ct, ref tasksInspected, ref tasksAtRisk);
			ct.ThrowIfCancellationRequested();

			// 4) Synthèse globale.
			AddSummary(collectorReport.Results, tasksInspected, tasksAtRisk);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "ScheduledTaskAclCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// =====================================================================
	//  1) ACL DU DOSSIER DES TÂCHES (racine + sous-dossiers, parcours borné)
	// =====================================================================
	private void CollectFolderAcls(List<SecurityResult> results, string tasksRoot, CancellationToken ct)
	{
		if (!Directory.Exists(tasksRoot))
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "ACL dossier des tâches : " + tasksRoot,
				CurrentValue = "Dossier introuvable",
				ExpectedValue = "N/A",
				Status = SecurityStatus.Info,
				Description = "Le dossier des tâches planifiées n'existe pas sur ce système.",
				Recommendation = "Aucune action.",
				Reference = ""
			});
			return;
		}

		// Dossier racine.
		AddFolderAclResult(results, tasksRoot);

		// Sous-dossiers (1 niveau).
		List<string> subFolders = SafeEnumerateDirectories(tasksRoot, MaxDepth);
		foreach (string sub in subFolders)
		{
			ct.ThrowIfCancellationRequested();
			AddFolderAclResult(results, sub);
		}
	}

	// Évalue l'ACL d'un dossier de tâches. Écriture non privilégiée → Critical (EoP).
	private void AddFolderAclResult(List<SecurityResult> results, string folderPath)
	{
		string checkName = "ACL dossier des tâches : " + folderPath;
		try
		{
			DirectoryInfo dirInfo = new DirectoryInfo(folderPath);
			// GetAccessControl peut lever UnauthorizedAccessException → géré plus bas (non fatal).
			DirectorySecurity security = dirInfo.GetAccessControl(AccessControlSections.Access);
			List<string> offenders = FindDangerousFileSystemGrants(security);

			bool vulnerable = offenders.Count > 0;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = checkName,
				CurrentValue = (vulnerable
					? "Droits d'écriture accordés à : " + string.Join(", ", offenders)
					: "Aucun droit d'écriture pour les utilisateurs standard"),
				ExpectedValue = "Aucun droit d'écriture pour Users/Everyone/Authenticated Users",
				// Écriture par un utilisateur standard dans le dossier des tâches → EoP → Critical.
				Status = (vulnerable ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Un utilisateur non privilégié disposant de droits d'écriture sur le dossier des tâches planifiées (ou d'y créer/remplacer des fichiers) peut modifier ou déposer une définition de tâche exécutée dans le contexte SYSTEM. Cela permet une élévation de privilèges (EoP) et une persistance furtive.",
				Recommendation = (vulnerable
					? "CRITIQUE : retirer les droits d'écriture des principals non privilégiés sur ce dossier. Restaurer les ACL par défaut (SYSTEM et Administrateurs en contrôle total ; Users en lecture seule). Auditer les définitions de tâches présentes pour détecter une éventuelle altération."
					: "Permissions correctes : aucun droit d'écriture non privilégié détecté sur ce dossier de tâches."),
				Reference = "https://learn.microsoft.com/windows/win32/taskschd/task-scheduler-security-contexts"
			});
		}
		catch (UnauthorizedAccessException)
		{
			AddAclUnreadable(results, checkName, folderPath);
		}
		catch (Exception ex)
		{
			AddAclUnreadable(results, checkName, folderPath, ex.Message);
		}
	}

	// =====================================================================
	//  2) ACL DES FICHIERS DE DÉFINITION + 3) CHEMINS UTILISATEUR
	// =====================================================================
	private void CollectTaskFiles(List<SecurityResult> results, string tasksRoot, CancellationToken ct,
		ref int tasksInspected, ref int tasksAtRisk)
	{
		if (!Directory.Exists(tasksRoot))
		{
			return;
		}

		List<string> files = SafeEnumerateTaskFiles(tasksRoot, MaxDepth, MaxFilesInspected);
		foreach (string file in files)
		{
			ct.ThrowIfCancellationRequested();
			tasksInspected++;

			// Nom de la tâche = chemin relatif dans Tasks (ex. « Microsoft\Windows\... »).
			string relativeName = GetRelativeTaskName(tasksRoot, file);

			bool fileAtRisk = false;

			// 2) ACL du fichier de définition.
			if (InspectFileAcl(results, file, relativeName))
			{
				fileAtRisk = true;
			}

			// 3) Analyse du contenu XML : commande pointant vers un chemin utilisateur.
			if (InspectTaskCommandPath(results, file, relativeName))
			{
				fileAtRisk = true;
			}

			if (fileAtRisk)
			{
				tasksAtRisk++;
			}
		}
	}

	// Évalue l'ACL d'un fichier de définition. Écriture non privilégiée → Critical (EoP).
	// Retourne true si le fichier est jugé à risque.
	private bool InspectFileAcl(List<SecurityResult> results, string filePath, string relativeName)
	{
		string checkName = "ACL définition de tâche : " + relativeName;
		try
		{
			FileInfo fileInfo = new FileInfo(filePath);
			FileSecurity security = fileInfo.GetAccessControl(AccessControlSections.Access);
			List<string> offenders = FindDangerousFileSystemGrants(security);

			bool vulnerable = offenders.Count > 0;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = checkName,
				CurrentValue = (vulnerable
					? "Droits d'écriture accordés à : " + string.Join(", ", offenders)
					: "Aucun droit d'écriture pour les utilisateurs standard"),
				ExpectedValue = "Aucun droit d'écriture pour Users/Everyone/Authenticated Users",
				// Écriture par un utilisateur standard sur une définition de tâche → EoP → Critical.
				Status = (vulnerable ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Le fichier XML définit l'action, le compte d'exécution et le déclencheur d'une tâche planifiée. Un utilisateur non privilégié pouvant l'écrire peut remplacer la commande exécutée par la tâche (souvent SYSTEM), obtenant une élévation de privilèges.",
				Recommendation = (vulnerable
					? "CRITIQUE : retirer les droits d'écriture des principals non privilégiés sur ce fichier de définition. Restaurer les ACL par défaut et vérifier que la définition n'a pas déjà été altérée."
					: "Permissions correctes : la définition n'est pas modifiable par un utilisateur standard."),
				Reference = "https://learn.microsoft.com/windows/win32/taskschd/task-scheduler-security-contexts"
			});
			return vulnerable;
		}
		catch (UnauthorizedAccessException)
		{
			AddAclUnreadable(results, checkName, relativeName);
			return false;
		}
		catch (Exception ex)
		{
			AddAclUnreadable(results, checkName, relativeName, ex.Message);
			return false;
		}
	}

	// Analyse le contenu XML de la tâche : si une action <Exec><Command> pointe vers un chemin
	// utilisateur modifiable (hors Microsoft), on lève un Warning. Retourne true si à risque.
	private bool InspectTaskCommandPath(List<SecurityResult> results, string filePath, string relativeName)
	{
		string checkName = "Tâche vers chemin utilisateur : " + relativeName;
		List<string> riskyCommands = new List<string>();
		try
		{
			XDocument doc = XDocument.Load(filePath);
			XElement root = doc.Root;
			if (root == null)
			{
				return false;
			}

			// Parsing namespace-agnostique via LocalName (les XML de tâches utilisent un namespace).
			IEnumerable<XElement> commands = root
				.Descendants()
				.Where(e => e.Name.LocalName.Equals("Command", StringComparison.OrdinalIgnoreCase));

			foreach (XElement cmd in commands)
			{
				string raw = cmd.Value?.Trim();
				if (string.IsNullOrEmpty(raw))
				{
					continue;
				}
				string expanded = SafeExpand(raw);
				if (IsUserWritablePath(expanded))
				{
					riskyCommands.Add(raw);
				}
			}
		}
		catch (Exception)
		{
			// Parsing / lecture impossible pour ce fichier → on ignore silencieusement (non fatal).
			return false;
		}

		if (riskyCommands.Count == 0)
		{
			return false;
		}

		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = checkName,
			CurrentValue = "Commande(s) en chemin utilisateur : " + string.Join(" | ", riskyCommands),
			ExpectedValue = "Binaire situé dans un emplacement protégé (System32, Program Files, Microsoft)",
			// Tâche exécutant un binaire dans un emplacement modifiable par l'utilisateur → Warning.
			Status = SecurityStatus.Warning,
			Description = "Cette tâche planifiée exécute un binaire situé dans un chemin utilisateur (Temp, AppData, Users, Public ou ProgramData). Ces emplacements sont généralement modifiables par des comptes non privilégiés : un attaquant peut y remplacer le binaire pour détourner l'exécution de la tâche (persistance, voire EoP si la tâche s'exécute avec des privilèges élevés).",
			Recommendation = "Vérifier la légitimité de la tâche et de son binaire. Déplacer l'exécutable dans un emplacement protégé (Program Files / System32) avec des ACL restrictives, ou supprimer la tâche si elle est illégitime. Contrôler le compte d'exécution (Principal) de la tâche.",
			Reference = "https://attack.mitre.org/techniques/T1053/005/"
		});
		return true;
	}

	// =====================================================================
	//  4) SYNTHÈSE
	// =====================================================================
	private void AddSummary(List<SecurityResult> results, int tasksInspected, int tasksAtRisk)
	{
		bool clean = tasksAtRisk == 0;
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "Synthèse — tâches planifiées inspectées",
			CurrentValue = $"{tasksInspected} tâche(s) inspectée(s), {tasksAtRisk} à risque",
			ExpectedValue = "0 tâche à risque",
			Status = (clean ? SecurityStatus.OK : SecurityStatus.Warning),
			Description = "Synthèse de l'analyse des tâches planifiées (ACL des définitions et chemins d'exécution). Le parcours est borné (dossier racine + 1 niveau, cap de " + MaxFilesInspected + " fichiers) pour maîtriser le coût de collecte.",
			Recommendation = (clean
				? "Aucune tâche planifiée à risque détectée parmi celles inspectées."
				: "Examiner en priorité les résultats Critical (ACL faibles = EoP) puis les Warning (binaires en chemin utilisateur)."),
			Reference = "https://learn.microsoft.com/windows/win32/taskschd/task-scheduler-start-page"
		});
	}

	// =====================================================================
	//  ANALYSE DES ACL
	// =====================================================================
	// Retourne la liste des principals non privilégiés disposant de droits d'écriture (fichiers/dossiers).
	private List<string> FindDangerousFileSystemGrants(FileSystemSecurity security)
	{
		List<string> offenders = new List<string>();
		AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
		foreach (AuthorizationRule rule in rules)
		{
			if (rule is not FileSystemAccessRule ace)
			{
				continue;
			}
			// Seules les règles d'AUTORISATION (Allow) nous intéressent.
			if (ace.AccessControlType != AccessControlType.Allow)
			{
				continue;
			}
			if (!IsUnprivilegedSid(ace.IdentityReference as SecurityIdentifier))
			{
				continue;
			}
			// La règle accorde-t-elle un droit d'écriture dangereux ?
			if ((ace.FileSystemRights & DangerousFileRights) != 0)
			{
				string label = ResolveSidLabel(ace.IdentityReference as SecurityIdentifier);
				offenders.Add($"{label} ({ace.FileSystemRights & DangerousFileRights})");
			}
		}
		return offenders;
	}

	// Vrai si le SID correspond à Users, Everyone ou Authenticated Users (comparaison par SID = locale-indépendante).
	private static bool IsUnprivilegedSid(SecurityIdentifier sid)
	{
		if (sid == null)
		{
			return false;
		}
		return sid.Equals(UsersSid) || sid.Equals(EveryoneSid) || sid.Equals(AuthenticatedUsersSid);
	}

	// Libellé lisible pour le SID surveillé.
	private static string ResolveSidLabel(SecurityIdentifier sid)
	{
		if (sid == null)
		{
			return "Inconnu";
		}
		if (sid.Equals(UsersSid))
		{
			return "Users (S-1-5-32-545)";
		}
		if (sid.Equals(EveryoneSid))
		{
			return "Everyone (S-1-1-0)";
		}
		if (sid.Equals(AuthenticatedUsersSid))
		{
			return "Authenticated Users (S-1-5-11)";
		}
		return sid.Value;
	}

	// Résultat standard « ACL non lisible » (non fatal).
	private void AddAclUnreadable(List<SecurityResult> results, string checkName, string target, string detail = null)
	{
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = checkName,
			CurrentValue = "ACL non lisible" + (string.IsNullOrEmpty(detail) ? " (accès refusé)" : " : " + detail),
			ExpectedValue = "ACL lisible",
			Status = SecurityStatus.Info,
			Description = "L'ACL de « " + target + " » n'a pas pu être lue (accès refusé ou droits insuffisants). Il ne s'agit pas d'une erreur de sécurité mais d'une limite de collecte.",
			Recommendation = "Relancer l'analyse avec des privilèges administrateur/SYSTEM pour évaluer cette ACL.",
			Reference = ""
		});
	}

	// =====================================================================
	//  DÉTECTION DES CHEMINS UTILISATEUR MODIFIABLES
	// =====================================================================
	// Vrai si le chemin pointe vers Temp/AppData/Users/Public/ProgramData (hors Microsoft),
	// c.-à-d. un emplacement typiquement modifiable par un compte non privilégié.
	private static bool IsUserWritablePath(string commandPath)
	{
		if (string.IsNullOrWhiteSpace(commandPath))
		{
			return false;
		}

		string normalized = commandPath.Replace('/', '\\').Trim().Trim('"');
		string lower = normalized.ToLowerInvariant();

		// Marqueurs d'emplacements « utilisateur » (comparaison insensible à la casse).
		string[] userMarkers = new[]
		{
			"\\temp\\",
			"\\appdata\\",
			"\\users\\",
			"\\public\\",
			"\\programdata\\",
		};

		bool matches = false;
		for (int i = 0; i < userMarkers.Length; i++)
		{
			if (lower.Contains(userMarkers[i]))
			{
				matches = true;
				break;
			}
		}
		if (!matches)
		{
			return false;
		}

		// Exclusion : les binaires légitimes signés Microsoft déposés sous ProgramData\Microsoft, etc.
		// On considère « Microsoft » comme un composant de chemin de confiance relative.
		if (lower.Contains("\\microsoft\\"))
		{
			return false;
		}

		return true;
	}

	// Expansion des variables d'environnement présentes dans la commande (%TEMP%, %APPDATA%, ...),
	// avec repli sûr en cas d'échec.
	private static string SafeExpand(string raw)
	{
		try
		{
			return Environment.ExpandEnvironmentVariables(raw);
		}
		catch
		{
			return raw;
		}
	}

	// =====================================================================
	//  PARCOURS BORNÉ DU SYSTÈME DE FICHIERS
	// =====================================================================
	// Énumère les sous-dossiers jusqu'à la profondeur donnée (racine exclue), en ignorant
	// silencieusement les dossiers inaccessibles.
	private static List<string> SafeEnumerateDirectories(string root, int maxDepth)
	{
		List<string> result = new List<string>();
		EnumerateDirectoriesRecursive(root, maxDepth, 0, result);
		return result;
	}

	private static void EnumerateDirectoriesRecursive(string dir, int maxDepth, int depth, List<string> acc)
	{
		if (depth >= maxDepth)
		{
			return;
		}
		string[] subs;
		try
		{
			subs = Directory.GetDirectories(dir);
		}
		catch
		{
			return;
		}
		foreach (string sub in subs)
		{
			acc.Add(sub);
			EnumerateDirectoriesRecursive(sub, maxDepth, depth + 1, acc);
		}
	}

	// Énumère les fichiers de définition (racine + maxDepth niveaux), plafonnés à 'cap' fichiers.
	// Les dossiers inaccessibles sont ignorés silencieusement.
	private static List<string> SafeEnumerateTaskFiles(string root, int maxDepth, int cap)
	{
		List<string> files = new List<string>();

		// Fichiers directement dans la racine.
		AddFilesFrom(root, files, cap);

		// Fichiers dans les sous-dossiers bornés.
		List<string> subFolders = SafeEnumerateDirectories(root, maxDepth);
		foreach (string sub in subFolders)
		{
			if (files.Count >= cap)
			{
				break;
			}
			AddFilesFrom(sub, files, cap);
		}

		return files;
	}

	private static void AddFilesFrom(string dir, List<string> acc, int cap)
	{
		if (acc.Count >= cap)
		{
			return;
		}
		string[] found;
		try
		{
			found = Directory.GetFiles(dir);
		}
		catch
		{
			return;
		}
		foreach (string f in found)
		{
			if (acc.Count >= cap)
			{
				break;
			}
			acc.Add(f);
		}
	}

	// Nom de tâche = chemin relatif du fichier dans le dossier Tasks (séparateurs Windows).
	private static string GetRelativeTaskName(string tasksRoot, string filePath)
	{
		try
		{
			string rel = Path.GetRelativePath(tasksRoot, filePath);
			return string.IsNullOrWhiteSpace(rel) ? filePath : rel;
		}
		catch
		{
			return filePath;
		}
	}
}
