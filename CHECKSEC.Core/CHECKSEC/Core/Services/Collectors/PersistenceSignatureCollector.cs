using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services.Helpers;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur CHECKSEC — vérifie la signature Authenticode des binaires référencés par les
// mécanismes de persistance (Run keys, services non-Microsoft, Winlogon) et détecte les
// « ghost binaries » (entrée de persistance pointant vers un fichier absent du disque).
//
// La vérification s'appuie sur WinVerifyTrust (wintrust.dll) avec l'action générique
// WINTRUST_ACTION_GENERIC_VERIFY_V2 : cette approche couvre AUSSI les fichiers signés par
// catalogue de sécurité (composants Windows signés indirectement), contrairement à une simple
// lecture du certificat embarqué.
public class PersistenceSignatureCollector : ISecurityCollector
{
	// ----------------------------------------------------------------------------------------
	// Résultat de la vérification de signature d'un fichier.
	// ----------------------------------------------------------------------------------------
	private enum SignatureStatus
	{
		Trusted,   // Signature valide et de confiance (embarquée ou catalogue)
		Untrusted, // Non signé, ou signature non fiable / non valide
		Error      // Impossible de vérifier (erreur d'accès, fichier verrouillé, etc.)
	}

	// Plafond global : au plus ce nombre de binaires DISTINCTS sont vérifiés (perf).
	private const int MaxBinaries = 150;

	// ----------------------------------------------------------------------------------------
	// P/Invoke WinVerifyTrust
	// ----------------------------------------------------------------------------------------

	// GUID {00AAC56B-CD44-11d0-8CC2-00C04FC295EE} = WINTRUST_ACTION_GENERIC_VERIFY_V2
	private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

	// Choix d'interface utilisateur : aucune (mode silencieux).
	private const uint WTD_UI_NONE = 2u;

	// Aucune vérification de révocation (perf ; évite les appels réseau bloquants).
	private const uint WTD_REVOKE_NONE = 0u;

	// L'objet à vérifier est un fichier.
	private const uint WTD_CHOICE_FILE = 1u;

	// Actions d'état : VERIFY effectue la vérification, CLOSE libère l'état alloué.
	private const uint WTD_STATEACTION_VERIFY = 1u;
	private const uint WTD_STATEACTION_CLOSE = 2u;

	// Utilise la politique SAFER lors de la vérification.
	private const uint WTD_SAFER_FLAG = 0x100u;

	// Codes de retour notables de WinVerifyTrust (HRESULT).
	private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
	private const int TRUST_E_SUBJECT_NOT_TRUSTED = unchecked((int)0x800B0004);
	private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
	private const int TRUST_E_ACTION_UNKNOWN = unchecked((int)0x800B0002);
	private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
	private const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
	private const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
	private const int CERT_E_CHAINING = unchecked((int)0x800B010A);
	private const int CERT_E_REVOKED = unchecked((int)0x800B010C);
	private const int CERT_E_WRONG_USAGE = unchecked((int)0x800B0110);

	// WINTRUST_FILE_INFO : décrit le fichier à vérifier.
	[StructLayout(LayoutKind.Sequential)]
	private struct WINTRUST_FILE_INFO
	{
		public uint cbStruct;
		[MarshalAs(UnmanagedType.LPWStr)]
		public string pcwszFilePath;
		public IntPtr hFile;
		public IntPtr pgKnownSubject;
	}

	// WINTRUST_DATA : paramètres généraux de l'appel WinVerifyTrust.
	[StructLayout(LayoutKind.Sequential)]
	private struct WINTRUST_DATA
	{
		public uint cbStruct;
		public IntPtr pPolicyCallbackData;
		public IntPtr pSIPClientData;
		public uint dwUIChoice;
		public uint fdwRevocationChecks;
		public uint dwUnionChoice;
		public IntPtr pFile; // pointeur vers WINTRUST_FILE_INFO
		public uint dwStateAction;
		public IntPtr hWVTStateData;
		[MarshalAs(UnmanagedType.LPWStr)]
		public string pwszURLReference;
		public uint dwProvFlags;
		public uint dwUIContext;
		public IntPtr pSignatureSettings;
	}

	[DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
	private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);

	public string Name => "Signatures de persistance";

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

			// 1) Collecte des chemins de binaires référencés par les mécanismes de persistance.
			//    On déduplique par chemin (insensible à la casse) et on borne à MaxBinaries.
			Dictionary<string, string> binaries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			bool capReached = false;

			CollectRunKeys(binaries, ref capReached, ct);
			ct.ThrowIfCancellationRequested();
			CollectNonMicrosoftServices(binaries, ref capReached, ct);
			ct.ThrowIfCancellationRequested();
			CollectWinlogon(binaries, ref capReached, ct);
			ct.ThrowIfCancellationRequested();

			// 2) Vérification de chaque binaire distinct.
			int verified = 0;
			int unsignedCount = 0;
			int ghostCount = 0;

			foreach (KeyValuePair<string, string> entry in binaries)
			{
				ct.ThrowIfCancellationRequested();
				string path = entry.Key;
				string source = entry.Value;
				verified++;

				// (a) Ghost binary : la persistance pointe vers un fichier qui n'existe plus.
				if (!File.Exists(path))
				{
					// Correctif bug #4 : un chemin NON enraciné (ex : « rundll32 X.dll,Entry » → « X.dll »)
					// n'est pas une preuve d'absence — Windows le résout via l'ordre de recherche.
					// On tente de le résoudre contre les répertoires système avant toute conclusion.
					if (!Path.IsPathRooted(path))
					{
						string resolved = TryResolveAgainstSystemDirs(path);
						if (string.IsNullOrEmpty(resolved))
						{
							// Non enraciné et introuvable dans les répertoires système : un simple nom
							// de fichier non enraciné ne prouve PAS l'absence → Info, pas Critical.
							collectorReport.Results.Add(new SecurityResult
							{
								Category = Category,
								CheckName = "Cible non résolue : " + path,
								CurrentValue = path + " (source : " + source + ")",
								ExpectedValue = "Le binaire référencé existe sur le disque",
								Status = SecurityStatus.Info,
								Description = "La cible de persistance '" + path + "' (source : " + source + ") est un nom de fichier non enraciné qui n'a pu être résolu ni tel quel ni dans les répertoires système. Un chemin relatif n'étant pas une preuve d'absence du binaire, cette entrée n'est pas classée « ghost binary ».",
								Recommendation = "Vérifier manuellement la cible réellement chargée (ordre de recherche des DLL/EXE, répertoire de travail du processus) pour confirmer la présence et la légitimité du binaire.",
								Reference = "https://attack.mitre.org/techniques/T1547/001/"
							});
							continue;
						}
						// Résolu dans un répertoire système : on poursuit la vérification de signature.
						path = resolved;
					}
					else
					{
						// Chemin enraciné réellement absent du disque → véritable « ghost binary ».
						ghostCount++;
						collectorReport.Results.Add(new SecurityResult
						{
							Category = Category,
							CheckName = "Ghost binary : " + path,
						CurrentValue = path + " (source : " + source + ")",
						ExpectedValue = "Le binaire référencé existe sur le disque",
						Status = SecurityStatus.Critical,
						Description = "Persistance vers un binaire absent du disque. Une entrée de persistance (" + source + ") référence '" + path + "' qui n'existe pas. Ce motif de « ghost binary » est typique d'un mécanisme de persistance orphelin, d'un malware supprimé/incomplet, ou d'un détournement d'ordre de recherche (DLL/EXE hijacking) préparant un remplacement ultérieur.",
						Recommendation = "Vérifier l'entrée de persistance à l'origine de la référence (" + source + "). Si le binaire n'est plus légitimement attendu, supprimer l'entrée de persistance. Surveiller le chemin '" + path + "' : le dépôt ultérieur d'un fichier à cet emplacement entraînerait son exécution automatique.",
						Reference = "https://attack.mitre.org/techniques/T1547/001/"
					});
					continue;
					}
				}

				// (b) Vérification de la signature Authenticode via WinVerifyTrust.
				SignatureStatus sig = VerifyFile(path);
				if (sig == SignatureStatus.Trusted)
				{
					// Signé et de confiance → pas de résultat individuel (réduction du bruit), simplement compté.
					continue;
				}
				if (sig == SignatureStatus.Error)
				{
					// Impossible de vérifier : on le signale en Info, sans le compter comme non signé.
					collectorReport.Results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "Signature non vérifiable : " + Path.GetFileName(path),
						CurrentValue = path + " (source : " + source + ")",
						ExpectedValue = "Signature Authenticode valide et de confiance",
						Status = SecurityStatus.Info,
						Description = "La signature Authenticode du binaire de persistance '" + path + "' n'a pas pu être vérifiée (accès refusé, fichier verrouillé ou fournisseur indisponible).",
						Recommendation = "Vérifier manuellement la signature du fichier (clic droit > Propriétés > Signatures numériques) et les permissions d'accès.",
						Reference = "https://attack.mitre.org/techniques/T1553/002/"
					});
					continue;
				}

				// sig == Untrusted → non signé ou non fiable.
				unsignedCount++;
				string publisher = TryGetPublisher(path);
				bool suspicious = IsSuspiciousPath(path);
				collectorReport.Results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Binaire non signé/non fiable : " + Path.GetFileName(path),
					CurrentValue = path + " (source : " + source + ")" + (string.IsNullOrEmpty(publisher) ? "" : ", éditeur : " + publisher),
					ExpectedValue = "Signature Authenticode valide et de confiance",
					Status = (suspicious ? SecurityStatus.Critical : SecurityStatus.Warning),
					Description = "Le binaire de persistance '" + path + "' (référencé par " + source + ") n'est pas signé numériquement ou sa signature n'est pas de confiance (racine non fiable, certificat révoqué/expiré ou sujet non fiable)." + (suspicious ? " De plus, il réside dans un emplacement inscriptible par l'utilisateur (Temp/AppData/Users/Public/ProgramData hors Microsoft), ce qui est fortement caractéristique d'un malware." : ""),
					Recommendation = (suspicious ? "URGENT : investiguer immédiatement ce binaire non signé exécuté automatiquement depuis un emplacement utilisateur suspect. Analyser le fichier (hash, sandbox), identifier l'entrée de persistance (" + source + ") et la supprimer si non autorisée." : "Vérifier l'origine et la légitimité de ce binaire non signé lancé par " + source + ". Un logiciel légitime installé dans Program Files/Windows devrait normalement être signé."),
					Reference = "https://attack.mitre.org/techniques/T1553/002/"
				});
			}

			// 3) Synthèse globale.
			SecurityStatus summaryStatus;
			if (ghostCount > 0)
			{
				summaryStatus = SecurityStatus.Critical;
			}
			else if (unsignedCount > 0)
			{
				// Critical si au moins un non signé est en emplacement suspect, sinon Warning.
				summaryStatus = collectorReport.Results.Any((SecurityResult r) => r.Status == SecurityStatus.Critical) ? SecurityStatus.Critical : SecurityStatus.Warning;
			}
			else
			{
				summaryStatus = SecurityStatus.OK;
			}

			string capNote = capReached ? $" (limité à {MaxBinaries} binaires distincts)" : "";
			collectorReport.Results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Synthèse : signatures des binaires de persistance",
				CurrentValue = $"{verified} binaires de persistance vérifiés — {unsignedCount} non signés/non fiables, {ghostCount} ghost{capNote}",
				ExpectedValue = "Tous les binaires de persistance signés et présents sur le disque",
				Status = summaryStatus,
				Description = "Vérification de la signature Authenticode (via WinVerifyTrust, couvrant les signatures embarquées et par catalogue) des binaires référencés par les mécanismes de persistance : clés Run/RunOnce (HKLM/HKCU + Wow6432Node), services non-Microsoft (hors C:\\Windows) et valeurs Winlogon (Shell/Userinit). Les binaires manquants sont signalés comme « ghost binaries ».",
				Recommendation = (summaryStatus == SecurityStatus.OK) ? "Tous les binaires de persistance vérifiés sont présents et signés de confiance." : "Examiner les résultats individuels : les ghost binaries (Critical) et les binaires non signés en emplacement suspect (Critical) sont prioritaires.",
				Reference = "https://attack.mitre.org/techniques/T1547/001/"
			});
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			collectorReport.ErrorMessage = "PersistenceSignatureCollector fatal error: " + ex2.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// ----------------------------------------------------------------------------------------
	// Vérification de signature — helper principal via WinVerifyTrust.
	// ----------------------------------------------------------------------------------------
	private SignatureStatus VerifyFile(string path)
	{
		if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
		{
			return SignatureStatus.Error;
		}

		IntPtr pFile = IntPtr.Zero;
		IntPtr pData = IntPtr.Zero;
		Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		try
		{
			// Prépare la structure décrivant le fichier.
			WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO
			{
				cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
				pcwszFilePath = path,
				hFile = IntPtr.Zero,
				pgKnownSubject = IntPtr.Zero
			};
			pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
			Marshal.StructureToPtr(fileInfo, pFile, false);

			// Prépare la structure de données ; on commence par l'action VERIFY.
			WINTRUST_DATA data = new WINTRUST_DATA
			{
				cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
				pPolicyCallbackData = IntPtr.Zero,
				pSIPClientData = IntPtr.Zero,
				dwUIChoice = WTD_UI_NONE,
				fdwRevocationChecks = WTD_REVOKE_NONE,
				dwUnionChoice = WTD_CHOICE_FILE,
				pFile = pFile,
				dwStateAction = WTD_STATEACTION_VERIFY,
				hWVTStateData = IntPtr.Zero,
				pwszURLReference = null,
				dwProvFlags = WTD_SAFER_FLAG,
				dwUIContext = 0u,
				pSignatureSettings = IntPtr.Zero
			};
			pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
			Marshal.StructureToPtr(data, pData, false);

			// Appel VERIFY : c'est ce code de retour qui détermine le statut.
			int result = WinVerifyTrust(IntPtr.Zero, ref action, pData);

			// Appel CLOSE : libère impérativement l'état alloué en interne par WinVerifyTrust.
			try
			{
				// Relit la structure pour récupérer hWVTStateData mis à jour par l'appel VERIFY.
				WINTRUST_DATA closeData = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
				closeData.dwStateAction = WTD_STATEACTION_CLOSE;
				Marshal.StructureToPtr(closeData, pData, false);
				WinVerifyTrust(IntPtr.Zero, ref action, pData);
			}
			catch
			{
				// Best-effort : l'échec du CLOSE ne doit pas masquer le résultat du VERIFY.
			}

			// Interprétation du code de retour du VERIFY.
			if (result == 0)
			{
				return SignatureStatus.Trusted;
			}
			switch (result)
			{
				case TRUST_E_NOSIGNATURE:
				case TRUST_E_SUBJECT_NOT_TRUSTED:
				case TRUST_E_PROVIDER_UNKNOWN:
				case TRUST_E_ACTION_UNKNOWN:
				case TRUST_E_SUBJECT_FORM_UNKNOWN:
				case CERT_E_EXPIRED:
				case CERT_E_UNTRUSTEDROOT:
				case CERT_E_CHAINING:
				case CERT_E_REVOKED:
				case CERT_E_WRONG_USAGE:
					return SignatureStatus.Untrusted;
				default:
					// Correctif bug #3 : les HRESULT de facilité FACILITY_WIN32 (motif 0x8007xxxx)
					// traduisent une erreur d'accès/E-S (ACCESS_DENIED, SHARING_VIOLATION,
					// FILE_NOT_FOUND…), PAS un défaut de confiance. Les classer « Untrusted »
					// produisait un faux « non signé » → on retourne Error (signalé en Info).
					if ((result & unchecked((int)0xFFFF0000)) == unchecked((int)0x80070000))
					{
						return SignatureStatus.Error;
					}
					// Tout autre HRESULT négatif est traité comme « non fiable » par prudence.
					return SignatureStatus.Untrusted;
			}
		}
		catch
		{
			return SignatureStatus.Error;
		}
		finally
		{
			if (pFile != IntPtr.Zero)
			{
				// Correctif bug #6 : StructureToPtr a alloué la chaîne LPWStr (pcwszFilePath) ;
				// DestroyStructure la libère AVANT FreeHGlobal, sinon fuite mémoire par fichier.
				Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO));
				Marshal.FreeHGlobal(pFile);
			}
			if (pData != IntPtr.Zero)
			{
				// Symétrie : libère les éventuels champs marshalés de WINTRUST_DATA avant FreeHGlobal.
				Marshal.DestroyStructure(pData, typeof(WINTRUST_DATA));
				Marshal.FreeHGlobal(pData);
			}
		}
	}

	// Récupération best-effort de l'éditeur via le certificat embarqué.
	// Échoue (retourne "") pour les fichiers signés par catalogue, ce qui est acceptable : cette
	// information n'est utilisée qu'à titre indicatif dans les résultats.
	private static string TryGetPublisher(string path)
	{
		try
		{
			X509Certificate cert = X509Certificate.CreateFromSignedFile(path);
			X509Certificate2 cert2 = new X509Certificate2(cert);
			string subject = cert2.GetNameInfo(X509NameType.SimpleName, false);
			return string.IsNullOrEmpty(subject) ? cert2.Subject : subject;
		}
		catch
		{
			return string.Empty;
		}
	}

	// ----------------------------------------------------------------------------------------
	// Sources de persistance (bornées pour la performance).
	// ----------------------------------------------------------------------------------------

	// 1) Clés Run / RunOnce (HKLM, HKCU, + Wow6432Node).
	private void CollectRunKeys(Dictionary<string, string> binaries, ref bool capReached, CancellationToken ct)
	{
		(RegistryHive, string, string)[] runKeyLocations = new(RegistryHive, string, string)[6]
		{
			(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run"),
			(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM RunOnce"),
			(RegistryHive.CurrentUser, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU Run"),
			(RegistryHive.CurrentUser, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU RunOnce"),
			(RegistryHive.LocalMachine, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Wow6432Node Run"),
			(RegistryHive.LocalMachine, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM Wow6432Node RunOnce")
		};
		for (int i = 0; i < runKeyLocations.Length; i++)
		{
			if (capReached)
			{
				return;
			}
			var (hive, subPath, label) = runKeyLocations[i];
			ct.ThrowIfCancellationRequested();
			try
			{
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
				using RegistryKey runKey = baseKey.OpenSubKey(subPath);
				if (runKey == null)
				{
					continue;
				}
				string[] valueNames = runKey.GetValueNames();
				foreach (string valueName in valueNames)
				{
					ct.ThrowIfCancellationRequested();
					string commandLine = runKey.GetValue(valueName)?.ToString() ?? string.Empty;
					string exePath = ExtractExecutablePath(commandLine);
					if (!string.IsNullOrEmpty(exePath) && !AddBinary(binaries, exePath, label + " : " + valueName))
					{
						capReached = true;
						return;
					}
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch
			{
				// Clé illisible : on ignore et on poursuit.
			}
		}
	}

	// 2) Services non-Microsoft dont le PathName est hors C:\Windows\ (on limite aux chemins non-System32).
	private void CollectNonMicrosoftServices(Dictionary<string, string> binaries, ref bool capReached, CancellationToken ct)
	{
		if (capReached)
		{
			return;
		}
		try
		{
			ManagementObjectSearcher searcher = new ManagementObjectSearcher(WmiHelper.GetScope(), new ObjectQuery("SELECT Name, PathName FROM Win32_Service"));
			try
			{
				using ManagementObjectCollection services = searcher.Get();
				foreach (ManagementObject svc in services)
				{
					ManagementObject mo = svc;
					try
					{
						ct.ThrowIfCancellationRequested();
						string svcName = svc["Name"]?.ToString() ?? "(service)";
						string pathName = svc["PathName"]?.ToString() ?? string.Empty;
						string exePath = ExtractExecutablePath(pathName);
						if (string.IsNullOrEmpty(exePath))
						{
							continue;
						}
						// Exclut les services Microsoft/OS résidant dans C:\Windows\ (dont System32).
						if (exePath.IndexOf("\\Windows\\", StringComparison.OrdinalIgnoreCase) >= 0)
						{
							continue;
						}
						if (!AddBinary(binaries, exePath, "Service non-Microsoft : " + svcName))
						{
							capReached = true;
							return;
						}
					}
					finally
					{
						((IDisposable)mo)?.Dispose();
					}
				}
			}
			finally
			{
				((IDisposable)searcher)?.Dispose();
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch
		{
			// WMI indisponible : on ignore cette source.
		}
	}

	// 3) Winlogon : valeurs Shell et Userinit.
	private void CollectWinlogon(Dictionary<string, string> binaries, ref bool capReached, CancellationToken ct)
	{
		if (capReached)
		{
			return;
		}
		ct.ThrowIfCancellationRequested();
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey winlogonKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
			if (winlogonKey == null)
			{
				return;
			}
			string[] valueNames = new string[2] { "Shell", "Userinit" };
			foreach (string valueName in valueNames)
			{
				ct.ThrowIfCancellationRequested();
				string raw = winlogonKey.GetValue(valueName)?.ToString() ?? string.Empty;
				if (string.IsNullOrWhiteSpace(raw))
				{
					continue;
				}
				// Shell/Userinit peuvent contenir plusieurs binaires séparés par des virgules.
				string[] parts = raw.Split(new char[1] { ',' }, StringSplitOptions.RemoveEmptyEntries);
				foreach (string part in parts)
				{
					string exePath = ExtractExecutablePath(part);
					if (!string.IsNullOrEmpty(exePath) && !AddBinary(binaries, exePath, "Winlogon " + valueName))
					{
						capReached = true;
						return;
					}
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch
		{
			// Winlogon illisible : on ignore.
		}
	}

	// Ajoute un binaire à l'ensemble dédupliqué. Retourne false si le plafond MaxBinaries est atteint.
	private static bool AddBinary(Dictionary<string, string> binaries, string path, string source)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return true;
		}
		if (binaries.ContainsKey(path))
		{
			return true;
		}
		if (binaries.Count >= MaxBinaries)
		{
			return false;
		}
		binaries[path] = source;
		return true;
	}

	// ----------------------------------------------------------------------------------------
	// Résolution du chemin d'exécutable à partir d'une ligne de commande.
	// Gère : guillemets, arguments, variables d'environnement (%SystemRoot%…),
	// et le cas rundll32.exe X.dll,Entrée (on extrait alors la DLL cible).
	// ----------------------------------------------------------------------------------------
	private static string ExtractExecutablePath(string commandLine)
	{
		if (string.IsNullOrWhiteSpace(commandLine))
		{
			return string.Empty;
		}
		string cmd = Environment.ExpandEnvironmentVariables(commandLine.Trim());

		// Cas rundll32 : la « vraie » cible est la DLL passée en argument.
		int rundllIdx = cmd.IndexOf("rundll32", StringComparison.OrdinalIgnoreCase);
		if (rundllIdx >= 0)
		{
			string dll = ExtractRundllTarget(cmd, rundllIdx);
			if (!string.IsNullOrEmpty(dll))
			{
				return NormalizePath(dll);
			}
			// À défaut de DLL identifiable, on retombe sur l'extraction générique ci-dessous.
		}

		string exe;
		if (cmd.StartsWith("\""))
		{
			// Chemin entre guillemets : on prend ce qui est entre les deux premiers guillemets.
			int end = cmd.IndexOf('"', 1);
			exe = (end > 1) ? cmd.Substring(1, end - 1) : cmd.Trim('"');
		}
		else
		{
			// Pas de guillemets : le chemin s'arrête au premier espace… sauf si le chemin lui-même
			// contient des espaces. Heuristique : on cherche le premier segment se terminant par
			// une extension exécutable connue, sinon on coupe au premier espace.
			exe = ExtractUnquotedPath(cmd);
		}
		return NormalizePath(exe);
	}

	// Extrait la DLL cible d'une commande rundll32 (ex : rundll32.exe C:\x\evil.dll,Entry).
	private static string ExtractRundllTarget(string cmd, int rundllIdx)
	{
		// Repère la fin du token « rundll32(.exe) », puis récupère l'argument suivant jusqu'à la virgule.
		int after = rundllIdx;
		// Avance jusqu'au premier espace après rundll32.
		while (after < cmd.Length && !char.IsWhiteSpace(cmd[after]))
		{
			after++;
		}
		string rest = (after < cmd.Length) ? cmd.Substring(after).Trim() : string.Empty;
		if (string.IsNullOrEmpty(rest))
		{
			return string.Empty;
		}
		// L'argument DLL se termine à la virgule (avant le point d'entrée) ou au premier espace.
		if (rest.StartsWith("\""))
		{
			int end = rest.IndexOf('"', 1);
			return (end > 1) ? rest.Substring(1, end - 1) : string.Empty;
		}
		int commaIdx = rest.IndexOf(',');
		int spaceIdx = rest.IndexOf(' ');
		int cut = -1;
		if (commaIdx >= 0 && spaceIdx >= 0)
		{
			cut = Math.Min(commaIdx, spaceIdx);
		}
		else if (commaIdx >= 0)
		{
			cut = commaIdx;
		}
		else if (spaceIdx >= 0)
		{
			cut = spaceIdx;
		}
		return (cut > 0) ? rest.Substring(0, cut).Trim() : rest.Trim();
	}

	// Extraction d'un chemin non quoté : gère les chemins avec espaces se terminant par une
	// extension exécutable connue, sinon coupe au premier espace.
	private static string ExtractUnquotedPath(string cmd)
	{
		string[] exts = new string[6] { ".exe", ".dll", ".com", ".bat", ".cmd", ".scr" };
		foreach (string ext in exts)
		{
			int idx = cmd.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
			if (idx >= 0)
			{
				// Fin du chemin = juste après l'extension.
				return cmd.Substring(0, idx + ext.Length).Trim();
			}
		}
		// Pas d'extension reconnue : on coupe au premier espace.
		int space = cmd.IndexOf(' ');
		return (space > 0) ? cmd.Substring(0, space) : cmd;
	}

	// Nettoie/normalise un chemin extrait (guillemets résiduels, espaces).
	private static string NormalizePath(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return string.Empty;
		}
		string p = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"').Trim());
		return p;
	}

	// Correctif bug #4 : tente de résoudre un nom de fichier NON enraciné (ex : « X.dll » issu
	// d'un « rundll32 X.dll,Entry ») contre les répertoires système, comme le ferait l'ordre de
	// recherche de Windows. Retourne le chemin complet du premier fichier existant, sinon "".
	private static string TryResolveAgainstSystemDirs(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return string.Empty;
		}
		string systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
		string[] searchDirs = new string[3]
		{
			Path.Combine(systemRoot, "System32"),
			Path.Combine(systemRoot, "SysWOW64"),
			systemRoot
		};
		for (int i = 0; i < searchDirs.Length; i++)
		{
			try
			{
				string candidate = Path.Combine(searchDirs[i], path);
				if (File.Exists(candidate))
				{
					return candidate;
				}
			}
			catch
			{
				// Chemin invalide pour la combinaison : on ignore et on essaie le répertoire suivant.
			}
		}
		return string.Empty;
	}

	// Détermine si un chemin réside dans un emplacement inscriptible/suspect
	// (Temp/AppData/Users/Public/ProgramData hors Microsoft).
	private static bool IsSuspiciousPath(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return false;
		}
		string lower = path.ToLowerInvariant();
		if (lower.Contains("\\temp\\") || lower.Contains("\\appdata\\") || lower.Contains("\\users\\") || lower.Contains("\\public\\"))
		{
			return true;
		}
		if (lower.Contains("\\programdata\\") && !lower.Contains("\\programdata\\microsoft\\"))
		{
			return true;
		}
		return false;
	}
}
