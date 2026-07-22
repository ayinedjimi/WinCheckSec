using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur d'analyse des ACL (listes de contrôle d'accès) du système de fichiers et du registre.
// Objectif : détecter les faiblesses de permissions permettant une élévation de privilèges (EoP),
// c.-à-d. les emplacements sensibles où un utilisateur NON privilégié dispose de droits d'ÉCRITURE.
// ATTENTION : lecture seule — ce collecteur ne modifie JAMAIS aucune ACL.
public class FileSystemAclCollector : ISecurityCollector
{
	// SID des principals NON privilégiés à surveiller (résolution par SID = indépendante de la locale).
	private static readonly SecurityIdentifier UsersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);          // S-1-5-32-545
	private static readonly SecurityIdentifier EveryoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);             // S-1-1-0
	private static readonly SecurityIdentifier AuthenticatedUsersSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null); // S-1-5-11

	// Droits d'ÉCRITURE réels dangereux pour un principal non privilégié.
	// IMPORTANT (bug review) : ne PAS inclure Modify/FullControl (valeurs composites contenant
	// les bits de lecture/exécution → collapse sur FullControl → faux Critical sur tout droit de
	// lecture, ex. ReadAndExecute accordé par défaut à Users sur System32/Program Files).
	// WriteData/AppendData = une vraie anomalie sur System32/Program Files (le défaut n'accorde
	// PAS l'écriture à Users). On exclut WriteAttributes/WriteExtendedAttributes (bénins, parfois
	// accordés par défaut) pour éviter de faux positifs.
	private const FileSystemRights DangerousFileRights =
		FileSystemRights.WriteData |                        // = CreateFiles
		FileSystemRights.AppendData |                       // = CreateDirectories
		FileSystemRights.Delete |
		FileSystemRights.DeleteSubdirectoriesAndFiles |
		FileSystemRights.ChangePermissions |
		FileSystemRights.TakeOwnership;

	// Droits d'écriture sur clé de registre considérés comme dangereux.
	// Droits registre d'ÉCRITURE réels. Exclure WriteKey et FullControl (composites partageant
	// des bits avec ReadKey/StandardRightsRead → sinon faux Critical sur toute ACE de lecture,
	// ex. ReadKey accordé par défaut à Users sur les clés Run).
	private const RegistryRights DangerousRegistryRights =
		RegistryRights.SetValue |
		RegistryRights.CreateSubKey |
		RegistryRights.Delete |
		RegistryRights.ChangePermissions |
		RegistryRights.TakeOwnership;

	public string Name => "ACL Système de fichiers & Registre";

	public string Category => "Durcissement";

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
			// 1) Dossiers système critiques.
			CollectSystemFolderAcls(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			// 2) Clés Run/RunOnce du registre.
			CollectRegistryRunKeyAcls(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			// 3) Fichier hosts (permission, pas contenu).
			CollectHostsFileAcl(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "FileSystemAclCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// =====================================================================
	//  1) DOSSIERS SYSTÈME
	// =====================================================================
	private void CollectSystemFolderAcls(List<SecurityResult> results, CancellationToken ct)
	{
		// Emplacements dont l'écriture par un utilisateur standard permet une EoP
		// (remplacement de binaire chargé par un processus privilégié / SYSTEM).
		string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
		string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
		string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
		string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

		string[] systemFolders = new[]
		{
			system32,
			windir,
			programFiles,
			programFilesX86,
		};

		foreach (string folder in systemFolders)
		{
			ct.ThrowIfCancellationRequested();
			if (string.IsNullOrWhiteSpace(folder))
			{
				continue;
			}
			AddFolderAclResult(results, folder);
		}
	}

	private void AddFolderAclResult(List<SecurityResult> results, string folderPath)
	{
		string checkName = "ACL dossier système : " + folderPath;
		try
		{
			if (!Directory.Exists(folderPath))
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = checkName,
					CurrentValue = "Dossier introuvable",
					ExpectedValue = "N/A",
					Status = SecurityStatus.Info,
					Description = "Le dossier n'existe pas sur ce système.",
					Recommendation = "Aucune action.",
					Reference = ""
				});
				return;
			}

			DirectoryInfo dirInfo = new DirectoryInfo(folderPath);
			// GetAccessControl peut lever UnauthorizedAccessException → géré plus bas.
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
				// Écriture par un utilisateur standard sur un dossier système → EoP → Critical.
				Status = (vulnerable ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Un utilisateur non privilégié disposant de droits d'écriture dans un dossier système peut remplacer ou déposer un binaire (DLL/EXE) qui sera ensuite chargé par un processus privilégié ou SYSTEM, permettant une élévation de privilèges (EoP).",
				Recommendation = (vulnerable
					? "CRITIQUE : retirer les droits d'écriture des principals non privilégiés sur ce dossier système. Vérifier qu'aucune ACL n'a été modifiée par un installateur défaillant ou un attaquant. Restaurer les ACL par défaut si nécessaire (icacls /reset avec précaution)."
					: "Permissions correctes : aucun droit d'écriture non privilégié détecté."),
				Reference = "https://learn.microsoft.com/windows/security/identity-protection/access-control/access-control"
			});
		}
		catch (UnauthorizedAccessException)
		{
			// Lecture d'ACL refusée → Info, non fatal.
			AddAclUnreadable(results, checkName, folderPath);
		}
		catch (Exception ex)
		{
			AddAclUnreadable(results, checkName, folderPath, ex.Message);
		}
	}

	// =====================================================================
	//  2) CLÉS RUN / RUNONCE
	// =====================================================================
	private void CollectRegistryRunKeyAcls(List<SecurityResult> results, CancellationToken ct)
	{
		string[] runKeys = new[]
		{
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		};

		foreach (string subKey in runKeys)
		{
			ct.ThrowIfCancellationRequested();
			AddRegistryRunKeyAclResult(results, subKey);
		}
	}

	private void AddRegistryRunKeyAclResult(List<SecurityResult> results, string subKeyPath)
	{
		string checkName = "ACL clé registre : HKLM\\" + subKeyPath;
		RegistryKey baseKey = null;
		RegistryKey key = null;
		try
		{
			baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			// Ouverture en lecture des droits (ReadPermissions) uniquement.
			key = baseKey.OpenSubKey(subKeyPath, RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadPermissions);
			if (key == null)
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = checkName,
					CurrentValue = "Clé introuvable",
					ExpectedValue = "N/A",
					Status = SecurityStatus.Info,
					Description = "La clé de registre n'existe pas sur ce système.",
					Recommendation = "Aucune action.",
					Reference = ""
				});
				return;
			}

			RegistrySecurity security = key.GetAccessControl(AccessControlSections.Access);
			List<string> offenders = FindDangerousRegistryGrants(security);

			bool vulnerable = offenders.Count > 0;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = checkName,
				CurrentValue = (vulnerable
					? "Droits d'écriture accordés à : " + string.Join(", ", offenders)
					: "Aucun droit d'écriture pour les utilisateurs standard"),
				ExpectedValue = "Aucun droit SetValue/CreateSubKey pour Users/Everyone/Authenticated Users",
				// SetValue/CreateSubKey par un utilisateur standard sur Run/RunOnce → persistance/EoP → Critical.
				Status = (vulnerable ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = "Les clés Run/RunOnce lancent des programmes au démarrage. Si un utilisateur non privilégié peut y écrire une valeur, il peut y inscrire une charge utile qui s'exécutera dans le contexte de tout utilisateur ouvrant une session (persistance et potentielle élévation de privilèges).",
				Recommendation = (vulnerable
					? "CRITIQUE : retirer les droits SetValue/CreateSubKey des principals non privilégiés sur cette clé. Auditer les valeurs actuelles pour détecter une persistance malveillante déjà en place."
					: "Permissions correctes : seuls les comptes privilégiés peuvent écrire dans cette clé."),
				Reference = "https://learn.microsoft.com/windows/win32/setupapi/run-and-runonce-registry-keys"
			});
		}
		catch (UnauthorizedAccessException)
		{
			AddAclUnreadable(results, checkName, "HKLM\\" + subKeyPath);
		}
		catch (Exception ex)
		{
			AddAclUnreadable(results, checkName, "HKLM\\" + subKeyPath, ex.Message);
		}
		finally
		{
			key?.Dispose();
			baseKey?.Dispose();
		}
	}

	// =====================================================================
	//  3) FICHIER HOSTS (permission, pas contenu)
	// =====================================================================
	private void CollectHostsFileAcl(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers\\etc\\hosts");
		string checkName = "ACL fichier hosts : " + hostsPath;
		try
		{
			if (!File.Exists(hostsPath))
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = checkName,
					CurrentValue = "Fichier introuvable",
					ExpectedValue = "N/A",
					Status = SecurityStatus.Info,
					Description = "Le fichier hosts n'existe pas.",
					Recommendation = "Aucune action.",
					Reference = ""
				});
				return;
			}

			FileInfo fileInfo = new FileInfo(hostsPath);
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
				// Ici on évalue la PERMISSION (l'intégrité du CONTENU est vérifiée ailleurs) → Warning.
				Status = (vulnerable ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Un droit d'écriture sur le fichier hosts accordé à un utilisateur standard permet de rediriger silencieusement le trafic (pharming), de bloquer des mises à jour de sécurité ou de contourner des filtres DNS. Cette vérification porte sur la PERMISSION, pas sur le contenu du fichier.",
				Recommendation = (vulnerable
					? "Retirer les droits d'écriture des principals non privilégiés sur le fichier hosts. Seuls Administrateurs et SYSTEM doivent pouvoir le modifier."
					: "Permissions correctes : le fichier hosts n'est pas modifiable par un utilisateur standard."),
				Reference = "https://learn.microsoft.com/troubleshoot/windows-client/networking/configure-tcpip-networking"
			});
		}
		catch (UnauthorizedAccessException)
		{
			AddAclUnreadable(results, checkName, hostsPath);
		}
		catch (Exception ex)
		{
			AddAclUnreadable(results, checkName, hostsPath, ex.Message);
		}
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

	// Retourne la liste des principals non privilégiés disposant de droits d'écriture (registre).
	private List<string> FindDangerousRegistryGrants(RegistrySecurity security)
	{
		List<string> offenders = new List<string>();
		AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
		foreach (AuthorizationRule rule in rules)
		{
			if (rule is not RegistryAccessRule ace)
			{
				continue;
			}
			if (ace.AccessControlType != AccessControlType.Allow)
			{
				continue;
			}
			if (!IsUnprivilegedSid(ace.IdentityReference as SecurityIdentifier))
			{
				continue;
			}
			if ((ace.RegistryRights & DangerousRegistryRights) != 0)
			{
				string label = ResolveSidLabel(ace.IdentityReference as SecurityIdentifier);
				offenders.Add($"{label} ({ace.RegistryRights & DangerousRegistryRights})");
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

	// Résultat standard « permissions non lisibles » (non fatal).
	private void AddAclUnreadable(List<SecurityResult> results, string checkName, string target, string detail = null)
	{
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = checkName,
			CurrentValue = "Permissions non lisibles" + (string.IsNullOrEmpty(detail) ? " (accès refusé)" : " : " + detail),
			ExpectedValue = "ACL lisible",
			Status = SecurityStatus.Info,
			Description = "L'ACL de « " + target + " » n'a pas pu être lue (accès refusé ou droits insuffisants). Il ne s'agit pas d'une erreur de sécurité mais d'une limite de collecte.",
			Recommendation = "Relancer l'analyse avec des privilèges administrateur/SYSTEM pour évaluer cette ACL.",
			Reference = ""
		});
	}
}
