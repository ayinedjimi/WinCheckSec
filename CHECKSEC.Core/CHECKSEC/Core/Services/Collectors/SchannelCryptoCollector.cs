using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur CHECKSEC : Schannel & Cryptographie (TLS / Cryptography).
// Complète le collecteur TLS existant (protocoles + cipher suites par protocole) en se concentrant
// sur les réglages cryptographiques globaux :
//  - Mode FIPS (neutre : Info) ;
//  - ordre des cipher suites SSL (SSL Cipher Suite Order) ;
//  - cache de session Schannel (Client/ServerCacheTime) ;
//  - désactivation des algorithmes faibles globaux Schannel (Ciphers/Hashes/KeyExchangeAlgorithms) ;
//  - certificats faibles ou expirés dans les magasins machine (Root / My).
// Remarque : les protocoles TLS eux-mêmes sont couverts par le collecteur TLS — on ne les duplique pas ici.
public class SchannelCryptoCollector : ISecurityCollector
{
	private const string SchannelRoot = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL";

	public string Name => "Schannel & Cryptographie";

	public string Category => "TLS / Cryptography";

	public Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch sw = Stopwatch.StartNew();
		try
		{
			ct.ThrowIfCancellationRequested();
			CollectFipsMode(report.Results, ct);

			ct.ThrowIfCancellationRequested();
			CollectCipherSuiteOrder(report.Results, ct);

			ct.ThrowIfCancellationRequested();
			CollectSessionCache(report.Results, ct);

			ct.ThrowIfCancellationRequested();
			CollectWeakAlgorithms(report.Results, ct);

			ct.ThrowIfCancellationRequested();
			CollectWeakCertificates(report.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			report.ErrorMessage = "SchannelCryptoCollector fatal error: " + ex2.Message;
		}
		finally
		{
			sw.Stop();
			report.Duration = sw.Elapsed;
		}
		return Task.FromResult(report);
	}

	// --- Mode FIPS ----------------------------------------------------------------------------

	private void CollectFipsMode(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int fips = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy", "Enabled");
			bool enabled = fips == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Mode FIPS (FipsAlgorithmPolicy)",
				CurrentValue = ((fips == -1) ? "Non configuré (désactivé par défaut)" : (enabled ? "1 (Activé)" : "0 (Désactivé)")),
				ExpectedValue = "Selon politique de conformité (neutre)",
				// FIPS n'est pas systématiquement recommandé : on reste neutre (Info dans les deux cas).
				Status = SecurityStatus.Info,
				Description = "Le mode FIPS (FipsAlgorithmPolicy) force l'utilisation exclusive d'algorithmes cryptographiques validés FIPS 140. Il est requis dans certains contextes réglementaires (gouvernement, défense) mais peut désactiver des algorithmes modernes non validés et créer des incompatibilités. Il n'est donc pas universellement recommandé.",
				Recommendation = (enabled
					? "Le mode FIPS est activé. S'assurer que cette exigence provient bien d'une contrainte de conformité et que les applications restent compatibles."
					: "Le mode FIPS est désactivé (configuration par défaut). L'activer uniquement si une exigence réglementaire l'impose (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy\\Enabled = 1)."),
				Reference = "https://learn.microsoft.com/windows/security/security-foundations/certification/fips-140-validation"
			};
		});
	}

	// --- Ordre des cipher suites --------------------------------------------------------------

	private void CollectCipherSuiteOrder(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			string order = RegString("HKLM", "SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002", "Functions");
			bool configured = !string.IsNullOrWhiteSpace(order);
			int count = 0;
			if (configured)
			{
				count = order.Split(new char[] { ',', '\r', '\n', ';' }, StringSplitOptions.RemoveEmptyEntries).Length;
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Ordre des cipher suites (SSL Cipher Suite Order)",
				CurrentValue = (configured ? $"Configuré via GPO ({count} suites définies)" : "Non configuré (ordre par défaut Windows)"),
				ExpectedValue = "Ordre explicite maîtrisé (GPO)",
				Status = (configured ? SecurityStatus.OK : SecurityStatus.Info),
				Description = "L'ordre des cipher suites SSL/TLS détermine la préférence de négociation côté serveur/client. Un ordre explicitement défini via GPO permet de privilégier les suites fortes (AEAD, forward secrecy) et de reléguer/exclure les suites faibles. Sans configuration, Windows applique son ordre par défaut, qui évolue selon la version.",
				Recommendation = (configured
					? "L'ordre des cipher suites est maîtrisé via GPO. Vérifier périodiquement que la liste privilégie les suites AEAD (GCM/CHACHA20) avec forward secrecy (ECDHE) et exclut les suites faibles (RC4, 3DES, CBC obsolètes)."
					: "Définir un ordre explicite via GPO : Computer Configuration > Administrative Templates > Network > SSL Configuration Settings > SSL Cipher Suite Order (clé HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002\\Functions)."),
				Reference = "https://learn.microsoft.com/windows-server/security/tls/manage-tls"
			};
		});
	}

	// --- Cache de session Schannel ------------------------------------------------------------

	private void CollectSessionCache(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int clientCache = RegInt("HKLM", SchannelRoot, "ClientCacheTime");
			int serverCache = RegInt("HKLM", SchannelRoot, "ServerCacheTime");
			string clientText = (clientCache == -1) ? "Non configuré (défaut)" : $"{clientCache} ms";
			string serverText = (serverCache == -1) ? "Non configuré (défaut)" : $"{serverCache} ms";
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Cache de session Schannel (Client/ServerCacheTime)",
				CurrentValue = "ClientCacheTime=" + clientText + ", ServerCacheTime=" + serverText,
				ExpectedValue = "Valeurs par défaut ou ajustées selon la politique",
				Status = SecurityStatus.Info,
				Description = "ClientCacheTime et ServerCacheTime contrôlent la durée de conservation des éléments de session TLS (reprise de session) dans le cache Schannel. Des valeurs élevées améliorent les performances mais prolongent la durée de vie du matériel de session en mémoire ; une valeur de 0 désactive la mise en cache. Ce réglage est informatif.",
				Recommendation = "Conserver les valeurs par défaut sauf besoin spécifique. Pour limiter la durée de vie des sessions en mémoire (durcissement), réduire ServerCacheTime ; pour désactiver le cache, définir la valeur à 0.",
				Reference = "https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings"
			};
		});
	}

	// --- Algorithmes faibles globaux Schannel -------------------------------------------------

	private void CollectWeakAlgorithms(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// (sous-clé Schannel, nom de l'algorithme, statut si non désactivé, description).
		// On se concentre sur Ciphers / Hashes / KeyExchangeAlgorithms — PAS sur les protocoles TLS
		// (déjà couverts par le collecteur TLS) afin d'éviter la duplication.
		(string, string, SecurityStatus, string)[] weakAlgos = new (string, string, SecurityStatus, string)[10]
		{
			("Ciphers", "RC4 40/128",  SecurityStatus.Warning, "RC4 40/128 est un chiffrement de flux obsolète et cassé (biais statistiques). Il doit être explicitement désactivé."),
			("Ciphers", "RC4 56/128",  SecurityStatus.Warning, "RC4 56/128 est un chiffrement de flux obsolète et cassé. Il doit être explicitement désactivé."),
			("Ciphers", "RC4 64/128",  SecurityStatus.Warning, "RC4 64/128 est un chiffrement de flux obsolète et cassé. Il doit être explicitement désactivé."),
			("Ciphers", "RC4 128/128", SecurityStatus.Warning, "RC4 128/128 est un chiffrement de flux obsolète et déconseillé (RFC 7465). Il doit être explicitement désactivé."),
			("Ciphers", "DES 56/56",   SecurityStatus.Warning, "DES 56 bits offre une clé trop courte, cassable par force brute. Il doit être explicitement désactivé."),
			("Ciphers", "Triple DES 168", SecurityStatus.Warning, "Triple DES (3DES) 168 bits est déprécié (attaque Sweet32 sur blocs 64 bits). Il doit être explicitement désactivé."),
			("Hashes", "MD5", SecurityStatus.Warning, "MD5 est une fonction de hachage cassée (collisions). Elle doit être explicitement désactivée pour Schannel."),
			("Hashes", "SHA", SecurityStatus.Warning, "SHA-1 (clé 'SHA') est déprécié pour les signatures (collisions pratiques). Il doit être explicitement désactivé lorsque la compatibilité le permet."),
			("KeyExchangeAlgorithms", "Diffie-Hellman", SecurityStatus.Warning, "Un échange Diffie-Hellman avec des paramètres faibles (< 2048 bits) est vulnérable (Logjam). Vérifier la taille minimale (ServerMinKeyBitLength >= 2048) et désactiver si non maîtrisé."),
			("KeyExchangeAlgorithms", "PKCS", SecurityStatus.Warning, "L'échange de clés PKCS (RSA key transport, sans forward secrecy) est à éviter au profit d'ECDHE. Signaler s'il n'est pas explicitement désactivé.")
		};

		foreach ((string, string, SecurityStatus, string) algo in weakAlgos)
		{
			ct.ThrowIfCancellationRequested();
			string subKey = algo.Item1;
			string algoName = algo.Item2;
			SecurityStatus weakStatus = algo.Item3;
			string desc = algo.Item4;
			TryAdd(results, delegate
			{
				// Chemin : ...\SCHANNEL\<subKey>\<algoName> valeur "Enabled".
				// Enabled = 0 (ou 0xFFFFFFFF traité en négatif) => désactivé (OK).
				// Enabled absent OU != 0 => algorithme faible actif (Warning).
				string fullPath = SchannelRoot + "\\" + subKey + "\\" + algoName;
				bool keyExists = RegKeyExists("HKLM", fullPath);
				int enabled = RegInt("HKLM", fullPath, "Enabled", int.MinValue);

				// Considéré désactivé uniquement si Enabled est présent et vaut 0.
				bool explicitlyDisabled = keyExists && enabled == 0;
				bool valuePresent = enabled != int.MinValue;

				string currentValue;
				if (!keyExists)
				{
					currentValue = "Sous-clé absente (algorithme non désactivé explicitement)";
				}
				else if (!valuePresent)
				{
					currentValue = "Sous-clé présente sans 'Enabled' (non désactivé)";
				}
				else
				{
					currentValue = explicitlyDisabled ? "Enabled=0 (désactivé)" : $"Enabled={enabled} (actif)";
				}

				return new SecurityResult
				{
					Category = Category,
					CheckName = "Schannel " + subKey + " : " + algoName + " désactivé",
					CurrentValue = currentValue,
					ExpectedValue = "Enabled=0 (algorithme faible désactivé)",
					Status = (explicitlyDisabled ? SecurityStatus.OK : weakStatus),
					Description = desc,
					Recommendation = (explicitlyDisabled
						? (algoName + " est explicitement désactivé dans Schannel — bon état.")
						: ("Désactiver explicitement l'algorithme faible : créer HKLM\\" + fullPath + " et définir la valeur DWORD 'Enabled' = 0 (0x00000000). Un redémarrage est nécessaire pour appliquer.")),
					Reference = "https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings"
				};
			});
		}
	}

	// --- Certificats faibles dans les magasins machine ----------------------------------------

	private void CollectWeakCertificates(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		StoreName[] storeNames = new StoreName[2] { StoreName.Root, StoreName.My };
		foreach (StoreName storeName in storeNames)
		{
			ct.ThrowIfCancellationRequested();
			StoreName sn = storeName;
			TryAdd(results, delegate
			{
				int total = 0;
				int weakSignature = 0;
				int weakKey = 0;
				int expired = 0;
				List<string> examples = new List<string>();
				string scanError = null;

				try
				{
					using X509Store store = new X509Store(sn, StoreLocation.LocalMachine);
					store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
					DateTime now = DateTime.Now;
					foreach (X509Certificate2 cert in store.Certificates)
					{
						try
						{
							total++;
							bool isWeak = false;
							List<string> reasons = new List<string>();

							// Algorithme de signature faible : SHA1 / MD5.
							string sigOid = cert.SignatureAlgorithm?.Value ?? "";
							string sigName = cert.SignatureAlgorithm?.FriendlyName ?? "";
							if (IsWeakSignatureAlgorithm(sigOid, sigName))
							{
								weakSignature++;
								isWeak = true;
								reasons.Add("signature " + (string.IsNullOrEmpty(sigName) ? sigOid : sigName));
							}

							// Clé RSA < 2048 bits.
							int rsaBits = GetRsaKeySize(cert);
							if (rsaBits > 0 && rsaBits < 2048)
							{
								weakKey++;
								isWeak = true;
								reasons.Add($"clé RSA {rsaBits} bits");
							}

							// Certificat expiré.
							if (cert.NotAfter < now)
							{
								expired++;
								isWeak = true;
								reasons.Add("expiré le " + cert.NotAfter.ToString("yyyy-MM-dd"));
							}

							if (isWeak && examples.Count < 5)
							{
								string subject = string.IsNullOrEmpty(cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false))
									? cert.Subject
									: cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
								if (subject.Length > 48)
								{
									subject = subject.Substring(0, 48) + "...";
								}
								examples.Add(subject + " (" + string.Join(", ", reasons) + ")");
							}
						}
						finally
						{
							cert.Dispose();
						}
					}
				}
				catch (Exception ex)
				{
					scanError = ex.Message;
				}

				int problems = weakSignature + weakKey + expired;
				string storeLabel = (sn == StoreName.Root) ? "Root (racines de confiance)" : "My (certificats personnels/machine)";

				if (scanError != null)
				{
					return new SecurityResult
					{
						Category = Category,
						CheckName = "Certificats faibles : magasin " + sn,
						CurrentValue = "Analyse impossible : " + scanError,
						ExpectedValue = "Aucun certificat faible/expiré",
						Status = SecurityStatus.Info,
						Description = "Analyse du magasin de certificats machine " + storeLabel + " pour détecter des certificats à signature faible (SHA1/MD5), à clé RSA < 2048 bits ou expirés. Le magasin n'a pas pu être lu.",
						Recommendation = "Vérifier les permissions d'accès au magasin de certificats machine et l'exécution en administrateur.",
						Reference = "https://learn.microsoft.com/windows/win32/seccrypto/certificate-stores"
					};
				}

				bool hasProblems = problems > 0;
				string summary = hasProblems
					? $"{problems} certificat(s) faible(s) sur {total} (signature faible={weakSignature}, clé faible={weakKey}, expiré={expired})"
						+ ((examples.Count > 0) ? " — ex. : " + string.Join(" ; ", examples) : "")
					: $"Aucun certificat faible détecté ({total} analysés)";

				return new SecurityResult
				{
					Category = Category,
					CheckName = "Certificats faibles : magasin " + sn,
					CurrentValue = summary,
					ExpectedValue = "Aucun certificat SHA1/MD5, RSA < 2048 ou expiré",
					Status = (hasProblems ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = "Le magasin de certificats machine " + storeLabel + " est analysé à la recherche de certificats à algorithme de signature obsolète (SHA1/MD5), à clé RSA inférieure à 2048 bits, ou expirés. De tels certificats affaiblissent la confiance TLS/PKI : un certificat racine faible ou un certificat serveur obsolète peut faciliter des attaques d'usurpation ou d'interception.",
					Recommendation = (hasProblems
						? "Examiner et remplacer/révoquer les certificats faibles ou expirés. Retirer du magasin Root toute racine SHA1/MD5 inutile, et renouveler les certificats machine avec SHA-256 et des clés RSA >= 2048 bits (ou ECDSA)."
						: "Aucun certificat faible détecté dans ce magasin — bon état. Réévaluer périodiquement."),
					Reference = "https://learn.microsoft.com/security/sdl/cryptographic-recommendations"
				};
			});
		}
	}

	private static bool IsWeakSignatureAlgorithm(string oid, string friendlyName)
	{
		string name = (friendlyName ?? "").ToUpperInvariant();
		// OID connus des signatures faibles.
		// 1.2.840.113549.1.1.4 = md5RSA ; 1.2.840.113549.1.1.5 = sha1RSA ;
		// 1.2.840.10040.4.3 = sha1DSA ; 1.2.840.10045.4.1 = sha1ECDSA ; 1.3.14.3.2.29 = sha1RSA (ancien).
		switch (oid)
		{
			case "1.2.840.113549.1.1.4": // md5RSA
			case "1.2.840.113549.1.1.5": // sha1RSA
			case "1.2.840.10040.4.3":    // sha1DSA
			case "1.2.840.10045.4.1":    // sha1ECDSA
			case "1.3.14.3.2.29":        // sha1RSA (obsolète)
			case "1.2.840.113549.2.5":   // md5
			case "1.3.14.3.2.26":        // sha1
				return true;
		}
		// Repli par nom convivial (locale-invariant pour ces algos).
		return name.Contains("MD5") || name.Contains("SHA1") || name.Contains("SHA-1");
	}

	private static int GetRsaKeySize(X509Certificate2 cert)
	{
		try
		{
			using RSA rsa = cert.GetRSAPublicKey();
			return (rsa != null) ? rsa.KeySize : 0;
		}
		catch
		{
			return 0;
		}
	}

	// --- Helpers registre ---------------------------------------------------------------------

	private static bool RegKeyExists(string hive, string path)
	{
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine);
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			return subKey != null;
		}
		catch
		{
			return false;
		}
	}

	private static int RegInt(string hive, string path, string valueName, int def = -1)
	{
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine);
			// Vue 64 bits explicite pour éviter la redirection WOW64.
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

	private static string RegString(string hive, string path, string valueName)
	{
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine);
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			object value = subKey?.GetValue(valueName);
			if (value == null || value is DBNull)
			{
				return null;
			}
			// La valeur Functions peut être un REG_MULTI_SZ (string[]) ou un REG_SZ.
			if (value is string[] multi)
			{
				return string.Join(",", multi);
			}
			return value.ToString();
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
				Category = "TLS / Cryptography",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les permissions d'accès au registre et aux magasins de certificats.",
				Reference = ""
			});
		}
	}
}
