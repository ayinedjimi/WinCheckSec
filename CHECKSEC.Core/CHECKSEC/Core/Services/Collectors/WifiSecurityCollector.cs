using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

/// <summary>
/// Collecteur de sécurité des réseaux sans fil (WiFi).
///
/// Stratégie robuste à la locale :
///  - Source PRIMAIRE : export XML des profils WLAN via
///    « netsh wlan export profile key=clear folder="&lt;dir temp&gt;" ».
///    Les noms d'éléments XML sont INVARIANTS de langue (name, authentication,
///    encryption, connectionMode, nonBroadcast, MacRandomization, EAP, etc.),
///    contrairement aux libellés localisés de « netsh show » que l'on ne parse JAMAIS.
///  - FALLBACK : « netsh wlan show profiles » pour au moins énumérer les noms.
///  - Registre (chemins invariants) pour le service WLAN AutoConfig et les
///    politiques d'auto-connexion (WiFi Sense / OEM).
///
/// ⚠️ SÉCURITÉ : « key=clear » écrit la PSK en clair sur disque. On utilise donc un
/// dossier temporaire unique (GUID) supprimé INCONDITIONNELLEMENT dans un finally,
/// et on ne remonte JAMAIS la clé/PSK dans un SecurityResult — uniquement le FAIT
/// d'un chiffrement/authentification faible.
///
/// La classe possède un constructeur SANS paramètre (instanciation via new T()).
/// </summary>
public class WifiSecurityCollector : ISecurityCollector
{
	// Clés de registre (invariantes de langue).
	private const string WlansvcServiceKey = "SYSTEM\\CurrentControlSet\\Services\\Wlansvc";

	private const string WifiSenseHotspotsKey = "Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowAutoConnectToWiFiSenseHotspots";

	private const string WcmSvcConfigKey = "Software\\Microsoft\\WcmSvc\\wifinetworkmanager\\config";

	private const string PolicyReference = "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-wifi";

	// Délai maximal accordé à chaque invocation de netsh.
	private static readonly TimeSpan NetshTimeout = TimeSpan.FromSeconds(20.0);

	public string Name => "Sécurité WiFi";

	public string Category => "Réseau sans fil";

	public async Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch stopwatch = Stopwatch.StartNew();
		try
		{
			ct.ThrowIfCancellationRequested();

			// C1 — Service WLAN AutoConfig (Wlansvc). Détermine aussi la présence du sous-système WiFi.
			bool wlansvcPresent = CollectWlanAutoConfigService(report.Results, ct);

			// Détection de présence d'une carte WiFi via « netsh wlan show interfaces ».
			bool hasWifiInterface = await DetectWifiInterfaceAsync(ct).ConfigureAwait(false);

			// Absence de carte WiFi ET service absent → un seul résultat NotApplicable, retour anticipé.
			if (!hasWifiInterface && !wlansvcPresent)
			{
				report.Results.Clear();
				report.Results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "WiFi — Carte réseau",
					CurrentValue = "Aucune carte WiFi détectée",
					ExpectedValue = "N/A",
					Status = SecurityStatus.NotApplicable,
					Description = "Aucune interface WiFi ni service WLAN AutoConfig n'a été détecté sur cette machine. Les vérifications WiFi ne s'appliquent pas.",
					Recommendation = "Aucune action nécessaire.",
					Reference = PolicyReference
				});
				return report;
			}

			// Profils WiFi enregistrés — source primaire : export XML « key=clear ».
			await CollectWifiProfilesAsync(report.Results, ct).ConfigureAwait(false);

			// C12 / C13 — Politiques d'auto-connexion (registre).
			CollectAutoConnectPolicies(report.Results, ct);
		}
		catch (OperationCanceledException)
		{
			// L'annulation coopérative n'est pas une erreur fatale : on remonte ce qui a été collecté.
			report.ErrorMessage = "WifiSecurityCollector: opération annulée.";
		}
		catch (Exception ex)
		{
			report.ErrorMessage = "WifiSecurityCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			report.Duration = stopwatch.Elapsed;
		}
		return report;
	}

	// ------------------------------------------------------------------
	// C1 — Service WLAN AutoConfig (Wlansvc)
	// ------------------------------------------------------------------
	/// <summary>Analyse le service Wlansvc. Retourne true si le service est présent.</summary>
	private bool CollectWlanAutoConfigService(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey serviceKey = Registry.LocalMachine.OpenSubKey(WlansvcServiceKey);
			if (serviceKey == null)
			{
				// Service non installé : signalé, sans marquer comme présent.
				return false;
			}
			object startRaw = serviceKey.GetValue("Start");
			int startType = (startRaw != null) ? Convert.ToInt32(startRaw) : -1;
			string startLabel = startType switch
			{
				0 => "Boot (0)",
				1 => "System (1)",
				2 => "Automatique (2)",
				3 => "Manuel (3)",
				4 => "Désactivé (4)",
				_ => $"Inconnu ({startType})",
			};
			// Auto (2) ou Manuel (3) sont normaux ; Désactivé (4) peut être voulu sur poste sans WiFi.
			SecurityStatus status = startType switch
			{
				2 => SecurityStatus.OK,
				3 => SecurityStatus.OK,
				4 => SecurityStatus.Info,
				_ => SecurityStatus.Info,
			};
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WiFi — Service WLAN AutoConfig (Wlansvc)",
				CurrentValue = startLabel,
				ExpectedValue = "Automatique (2) ou Manuel (3) si WiFi utilisé, Désactivé (4) sinon",
				Status = status,
				Description = "Le service WLAN AutoConfig gère la découverte et la connexion aux réseaux WiFi. Mode de démarrage : " + startLabel + ".",
				Recommendation = ((startType == 4) ? "Service désactivé : correct sur les machines sans WiFi. Réactivez-le si le WiFi est requis." : "Sur les machines sans besoin de WiFi (serveurs, postes filaires), désactivez ce service pour réduire la surface d'attaque."),
				Reference = PolicyReference
			});
			return true;
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			results.Add(BuildErrorResult("WiFi — Service WLAN AutoConfig — Erreur", ex));
			return false;
		}
	}

	// ------------------------------------------------------------------
	// Détection d'une interface WiFi
	// ------------------------------------------------------------------
	/// <summary>
	/// Tente « netsh wlan show interfaces ». Renvoie true si la sortie mentionne au moins
	/// une interface. La détection ne parse pas de libellés localisés : elle se contente
	/// de vérifier qu'une sortie non triviale a été produite avec un code de sortie 0.
	/// </summary>
	private async Task<bool> DetectWifiInterfaceAsync(CancellationToken ct)
	{
		try
		{
			(int exitCode, string stdout) = await RunNetshAsync("wlan show interfaces", ct).ConfigureAwait(false);
			if (exitCode != 0 || string.IsNullOrWhiteSpace(stdout))
			{
				return false;
			}
			// Si aucune interface n'est présente, netsh renvoie typiquement un message court
			// (« There is no wireless interface... »). On considère la présence d'une interface
			// dès lors que la sortie contient une adresse MAC (motif invariant xx:xx:xx:xx:xx:xx).
			if (System.Text.RegularExpressions.Regex.IsMatch(stdout, "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"))
			{
				return true;
			}
			// Heuristique de repli : sortie « riche » (plusieurs lignes de détails).
			int nonEmptyLines = stdout.Split('\n').Count((string l) => !string.IsNullOrWhiteSpace(l));
			return nonEmptyLines > 4;
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch
		{
			return false;
		}
	}

	// ------------------------------------------------------------------
	// Profils WiFi — source primaire : export XML « key=clear »
	// ------------------------------------------------------------------
	private async Task CollectWifiProfilesAsync(List<SecurityResult> results, CancellationToken ct)
	{
		// Dossier temporaire UNIQUE pour l'export (contient la PSK en clair).
		string exportDir = Path.Combine(Path.GetTempPath(), "CHECKSEC_wlan_" + Guid.NewGuid().ToString("N"));
		bool exportOk = false;
		List<XDocument> profileDocs = new List<XDocument>();
		try
		{
			Directory.CreateDirectory(exportDir);
			try
			{
				// L'export écrit un fichier XML par profil dans exportDir.
				(int exitCode, string _) = await RunNetshAsync(
					"wlan export profile key=clear folder=\"" + exportDir + "\"", ct).ConfigureAwait(false);
				if (exitCode == 0)
				{
					foreach (string file in Directory.EnumerateFiles(exportDir, "*.xml"))
					{
						ct.ThrowIfCancellationRequested();
						try
						{
							profileDocs.Add(XDocument.Load(file));
						}
						catch
						{
							// Fichier XML illisible : NE PAS l'avaler silencieusement → Warning.
							string label = Path.GetFileNameWithoutExtension(file);
							results.Add(BuildUnparsableResult(string.IsNullOrEmpty(label) ? "(fichier illisible)" : label));
						}
					}
					exportOk = true;
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch
			{
				exportOk = false;
			}

			if (exportOk && profileDocs.Count > 0)
			{
				AnalyzeProfileDocuments(results, profileDocs, ct);
			}
			else if (exportOk && profileDocs.Count == 0)
			{
				// Export réussi mais aucun profil enregistré.
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "WiFi — Profils enregistrés",
					CurrentValue = "0",
					ExpectedValue = "N/A",
					Status = SecurityStatus.Info,
					Description = "Aucun profil WiFi n'est enregistré sur cette machine.",
					Recommendation = "Aucune action nécessaire.",
					Reference = PolicyReference
				});
			}
			else
			{
				// FALLBACK : au moins énumérer les noms de profils.
				await CollectProfilesFallbackAsync(results, ct).ConfigureAwait(false);
			}
		}
		finally
		{
			// ⚠️ Suppression INCONDITIONNELLE du dossier contenant les PSK en clair.
			try
			{
				if (Directory.Exists(exportDir))
				{
					Directory.Delete(exportDir, recursive: true);
				}
			}
			catch
			{
				// Dernier recours : tenter d'effacer le contenu des fichiers puis les supprimer.
				try
				{
					foreach (string file in Directory.EnumerateFiles(exportDir))
					{
						try
						{
							File.WriteAllText(file, string.Empty);
							File.Delete(file);
						}
						catch
						{
						}
					}
					Directory.Delete(exportDir, recursive: true);
				}
				catch
				{
					// On ne peut pas faire mieux sans risquer de propager une exception depuis finally.
				}
			}
		}
	}

	/// <summary>Analyse tous les documents XML de profils et produit checks par profil + agrégats.</summary>
	private void AnalyzeProfileDocuments(List<SecurityResult> results, List<XDocument> docs, CancellationToken ct)
	{
		int openCount = 0;       // Réseaux ouverts (authentication=open).
		int wepCount = 0;        // WEP (auth ou chiffrement).
		int tkipCount = 0;       // Chiffrement TKIP.
		int total = 0;

		foreach (XDocument doc in docs)
		{
			ct.ThrowIfCancellationRequested();
			total++;
			ProfileAnalysis analysis = AnalyzeSingleProfile(results, doc);
			if (analysis.IsOpen)
			{
				openCount++;
			}
			if (analysis.IsWep)
			{
				wepCount++;
			}
			if (analysis.IsTkip)
			{
				tkipCount++;
			}
		}

		// ---- Agrégats ----
		// Réseaux ouverts enregistrés.
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "WiFi — Réseaux ouverts enregistrés",
			CurrentValue = openCount.ToString(CultureInfo.InvariantCulture),
			ExpectedValue = "0",
			Status = ((openCount >= 1) ? SecurityStatus.Critical : SecurityStatus.OK),
			Description = ((openCount >= 1)
				? $"{openCount} profil(s) WiFi ouvert(s) (sans authentification) enregistré(s). Un tel profil peut se reconnecter automatiquement à un point d'accès malveillant (evil twin)."
				: "Aucun profil WiFi ouvert enregistré."),
			Recommendation = ((openCount >= 1) ? "Supprimez les profils de réseaux ouverts et évitez de vous connecter à des réseaux WiFi non chiffrés." : "Configuration correcte."),
			Reference = PolicyReference
		});

		// WEP (auth ou chiffrement).
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "WiFi — Profils WEP",
			CurrentValue = wepCount.ToString(CultureInfo.InvariantCulture),
			ExpectedValue = "0",
			Status = ((wepCount >= 1) ? SecurityStatus.Critical : SecurityStatus.OK),
			Description = ((wepCount >= 1)
				? $"{wepCount} profil(s) utilisant WEP. WEP est cryptographiquement cassé et peut être déchiffré en quelques minutes."
				: "Aucun profil WEP enregistré."),
			Recommendation = ((wepCount >= 1) ? "Supprimez immédiatement les profils WEP et reconfigurez les points d'accès en WPA2/WPA3." : "Configuration correcte."),
			Reference = PolicyReference
		});

		// TKIP.
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "WiFi — Profils TKIP",
			CurrentValue = tkipCount.ToString(CultureInfo.InvariantCulture),
			ExpectedValue = "0",
			Status = ((tkipCount >= 1) ? SecurityStatus.Warning : SecurityStatus.OK),
			Description = ((tkipCount >= 1)
				? $"{tkipCount} profil(s) utilisant le chiffrement TKIP, obsolète et vulnérable."
				: "Aucun profil TKIP enregistré."),
			Recommendation = ((tkipCount >= 1) ? "Reconfigurez les points d'accès pour utiliser AES (CCMP) / GCMP à la place de TKIP." : "Configuration correcte."),
			Reference = PolicyReference
		});

		// Nombre total de profils (Info).
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "WiFi — Nombre total de profils",
			CurrentValue = total.ToString(CultureInfo.InvariantCulture),
			ExpectedValue = "N/A",
			Status = SecurityStatus.Info,
			Description = $"{total} profil(s) WiFi enregistré(s) sur cette machine.",
			Recommendation = "Supprimez les profils WiFi inutilisés pour limiter les reconnexions automatiques indésirables.",
			Reference = PolicyReference
		});
	}

	/// <summary>Résultat d'analyse d'un profil, pour l'agrégation.</summary>
	private struct ProfileAnalysis
	{
		public bool IsOpen;
		public bool IsWep;
		public bool IsTkip;
	}

	/// <summary>
	/// Analyse un profil WiFi (XML invariant de langue) et produit les SecurityResult détaillés.
	/// </summary>
	private ProfileAnalysis AnalyzeSingleProfile(List<SecurityResult> results, XDocument doc)
	{
		ProfileAnalysis analysis = default(ProfileAnalysis);
		string profileName = "(sans nom)";
		try
		{
			XElement root = doc.Root;
			if (root == null)
			{
				// Document vide/illisible : NE PAS avaler silencieusement → Warning.
				results.Add(BuildUnparsableResult(profileName));
				return analysis;
			}
			// Résolution 100 % par nom LOCAL (namespace ignoré). Le premier <name> du document
			// est le nom du profil (un second <name> peut apparaître sous SSIDConfig/SSID).
			profileName = Val(root, "name") ?? "(sans nom)";

			// --- Authentification / chiffrement (éléments invariants de langue) ---
			// ⚠️ On cible authentication/encryption SOUS le PREMIER <authEncryption> pour éviter
			// de capter un élément homonyme situé dans un sous-bloc EAP.
			XElement authEnc = Elem(root, "authEncryption");
			string auth = (Val(authEnc, "authentication") ?? string.Empty).Trim();
			string enc = (Val(authEnc, "encryption") ?? string.Empty).Trim();
			bool useOneX = string.Equals(Val(authEnc, "useOneX"), "true", StringComparison.OrdinalIgnoreCase);
			bool isEap = useOneX || auth.IndexOf("EAP", StringComparison.OrdinalIgnoreCase) >= 0;

			bool isOpen = auth.Equals("open", StringComparison.OrdinalIgnoreCase);
			bool isNoneEnc = enc.Equals("none", StringComparison.OrdinalIgnoreCase);
			bool isWepAuth = auth.Equals("WEP", StringComparison.OrdinalIgnoreCase) || auth.Equals("shared", StringComparison.OrdinalIgnoreCase);
			bool isWepEnc = enc.Equals("WEP", StringComparison.OrdinalIgnoreCase);
			bool isTkip = enc.Equals("TKIP", StringComparison.OrdinalIgnoreCase);
			// Un réseau est « ouvert » (risque n°1) si auth=open OU encryption=none.
			analysis.IsOpen = isOpen || isNoneEnc;
			analysis.IsWep = isWepAuth || isWepEnc;
			analysis.IsTkip = isTkip;

			// Authentification (classification normalisée, insensible à la casse).
			(SecurityStatus authStatus, string authLabel) = ClassifyAuthentication(auth, useOneX);
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = $"WiFi [{profileName}] — Authentification",
				CurrentValue = (string.IsNullOrEmpty(auth) ? "(inconnue)" : auth) + " — " + authLabel,
				ExpectedValue = "WPA2PSK ou WPA3SAE (ou 802.1X/EAP)",
				Status = authStatus,
				Description = $"Méthode d'authentification du profil « {profileName} » : {(string.IsNullOrEmpty(auth) ? "inconnue" : auth)} ({authLabel}).",
				Recommendation = authStatus switch
				{
					SecurityStatus.Critical => "Réseau non sécurisé : reconfigurez le point d'accès en WPA2-PSK au minimum, idéalement WPA3-SAE, et supprimez ce profil.",
					SecurityStatus.Warning => "Migrez vers WPA2-PSK (AES) ou WPA3-SAE ; les protocoles WPA d'origine sont obsolètes.",
					_ => "Configuration correcte.",
				},
				Reference = PolicyReference
			});

			// Chiffrement.
			// none→Critical, WEP→Critical, TKIP→Warning, AES/GCMP→OK.
			(SecurityStatus encStatus, string encLabel) = ClassifyEncryption(enc);
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = $"WiFi [{profileName}] — Chiffrement",
				CurrentValue = (string.IsNullOrEmpty(enc) ? "(inconnu)" : enc) + " — " + encLabel,
				ExpectedValue = "AES (CCMP) ou GCMP",
				Status = encStatus,
				Description = $"Algorithme de chiffrement du profil « {profileName} » : {(string.IsNullOrEmpty(enc) ? "inconnu" : enc)} ({encLabel}).",
				Recommendation = encStatus switch
				{
					SecurityStatus.Critical => "Chiffrement absent ou cassé : reconfigurez le réseau avec AES/GCMP (WPA2/WPA3).",
					SecurityStatus.Warning => "Remplacez TKIP par AES (CCMP) / GCMP.",
					_ => "Configuration correcte.",
				},
				Reference = PolicyReference
			});

			// --- Connexion automatique (connectionMode = auto|manual) ---
			string connectionMode = (Val(root, "connectionMode") ?? string.Empty).Trim();
			bool isAuto = connectionMode.Equals("auto", StringComparison.OrdinalIgnoreCase);
			// Auto-connexion sur réseau ouvert → Warning ; sinon Info.
			if (!string.IsNullOrEmpty(connectionMode))
			{
				SecurityStatus connStatus = (isAuto && analysis.IsOpen) ? SecurityStatus.Warning : SecurityStatus.Info;
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = $"WiFi [{profileName}] — Connexion automatique",
					CurrentValue = (isAuto ? "Automatique" : "Manuelle"),
					ExpectedValue = "Manuelle pour les réseaux ouverts",
					Status = connStatus,
					Description = $"Le profil « {profileName} » se connecte en mode {(isAuto ? "automatique" : "manuel")}." + (connStatus == SecurityStatus.Warning ? " Combinée à un réseau ouvert, l'auto-connexion expose à des points d'accès malveillants (evil twin)." : string.Empty),
					Recommendation = (connStatus == SecurityStatus.Warning) ? "Désactivez l'auto-connexion pour ce réseau ouvert ou supprimez le profil." : "Aucune action particulière.",
					Reference = PolicyReference
				});
			}

			// --- Réseau masqué (nonBroadcast = true|false) ---
			string nonBroadcast = (Val(root, "nonBroadcast") ?? string.Empty).Trim();
			if (nonBroadcast.Equals("true", StringComparison.OrdinalIgnoreCase))
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = $"WiFi [{profileName}] — Réseau masqué (SSID caché)",
					CurrentValue = "SSID masqué (nonBroadcast=true)",
					ExpectedValue = "Information",
					Status = SecurityStatus.Info,
					Description = $"Le profil « {profileName} » cible un réseau à SSID masqué. Le masquage du SSID n'apporte pas de sécurité réelle et provoque des sondes actives révélant le SSID recherché.",
					Recommendation = "Ne comptez pas sur le masquage du SSID comme mesure de sécurité ; privilégiez WPA3 et un mot de passe robuste.",
					Reference = PolicyReference
				});
			}

			// --- Randomisation d'adresse MAC (élément dans le namespace v3) ---
			XElement macRand = Elem(root, "MacRandomization");
			if (macRand != null)
			{
				string enableRand = (Val(macRand, "enableRandomization") ?? string.Empty).Trim();
				bool randOff = enableRand.Equals("false", StringComparison.OrdinalIgnoreCase);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = $"WiFi [{profileName}] — Randomisation MAC",
					CurrentValue = (randOff ? "Désactivée" : "Activée"),
					ExpectedValue = "Activée (protection anti-pistage)",
					Status = (randOff ? SecurityStatus.Info : SecurityStatus.OK),
					Description = $"Randomisation de l'adresse MAC pour le profil « {profileName} » : {(randOff ? "désactivée" : "activée")}. La randomisation limite le pistage de l'appareil entre réseaux.",
					Recommendation = (randOff ? "Activez la randomisation MAC (aléatoire) pour limiter le pistage de l'appareil." : "Configuration correcte."),
					Reference = PolicyReference
				});
			}

			// --- 802.1X / EAP ---
			// Déclenché si useOneX==true OU si l'auth contient « EAP ».
			if (isEap)
			{
				AnalyzeEap(results, root, profileName);
			}
		}
		catch
		{
			// Un profil illisible ne doit JAMAIS être avalé silencieusement : on alerte.
			results.Add(BuildUnparsableResult(profileName));
		}
		return analysis;
	}

	/// <summary>Analyse la configuration 802.1X / EAP d'un profil (validation du certificat serveur, méthode EAP).</summary>
	private void AnalyzeEap(List<SecurityResult> results, XElement root, string profileName)
	{
		// La présence d'une config EAP (OneX / EAPConfig) précise le 802.1X ; en son absence,
		// on reste sur le bloc <security> (useOneX=true sans détail EAP explicite).
		XElement eapConfig = Elems(root, "EAPConfig").FirstOrDefault()
			?? Elems(root, "OneX").FirstOrDefault()
			?? Elems(root, "security").FirstOrDefault()
			?? root;

		// Type EAP racine (invariant) : 13=TLS, 25=PEAP, 21=TTLS, etc.
		string eapType = Elems(eapConfig, "Type")
			.Select((XElement e) => e.Value.Trim())
			.FirstOrDefault((string v) => !string.IsNullOrEmpty(v)) ?? string.Empty;
		string eapLabel = eapType switch
		{
			"13" => "EAP-TLS (certificat client)",
			"25" => "PEAP",
			"21" => "EAP-TTLS",
			"43" => "EAP-FAST",
			"18" => "EAP-SIM",
			"23" => "EAP-AKA",
			_ => (string.IsNullOrEmpty(eapType) ? "inconnue" : "type " + eapType),
		};
		// Méthode EAP (Info ; TLS est la plus robuste).
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = $"WiFi [{profileName}] — Méthode 802.1X/EAP",
			CurrentValue = eapLabel,
			ExpectedValue = "EAP-TLS de préférence",
			Status = SecurityStatus.Info,
			Description = $"Le profil d'entreprise « {profileName} » utilise l'authentification 802.1X ({eapLabel}).",
			Recommendation = "Privilégiez EAP-TLS (authentification mutuelle par certificats) et validez toujours le certificat du serveur RADIUS.",
			Reference = PolicyReference
		});

		// Validation du certificat serveur.
		// Indices invariants : ServerValidation, DisableUserPromptForServerValidation, TrustedRootCA.
		bool hasServerValidation = Elems(eapConfig, "ServerValidation").Any();
		bool hasTrustedRoot = Elems(eapConfig, "TrustedRootCA").Any(e => !string.IsNullOrWhiteSpace(e.Value));

		// « DisableUserPromptForServerValidation = true » sans TrustedRootCA = acceptation aveugle du serveur.
		string disablePrompt = Elems(eapConfig, "DisableUserPromptForServerValidation")
			.Select((XElement e) => e.Value.Trim())
			.FirstOrDefault((string v) => !string.IsNullOrEmpty(v)) ?? string.Empty;
		bool promptDisabled = disablePrompt.Equals("true", StringComparison.OrdinalIgnoreCase);

		// Config critique si : invite de validation désactivée, OU pas de bloc de validation serveur,
		// OU aucun TrustedRootCA défini (acceptation aveugle possible d'un faux serveur RADIUS).
		bool validationWeak = promptDisabled || !hasServerValidation || !hasTrustedRoot;

		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = $"WiFi [{profileName}] — Validation du certificat serveur (802.1X)",
			CurrentValue = (validationWeak
				? "Validation absente / incomplète" + (promptDisabled ? " (invite désactivée)" : string.Empty)
				: "Validation configurée (CA racine de confiance)"),
			ExpectedValue = "Validation activée + autorité racine (TrustedRootCA) fixée",
			Status = (validationWeak ? SecurityStatus.Critical : SecurityStatus.OK),
			Description = (validationWeak
				? $"Le profil 802.1X « {profileName} » ne valide pas correctement le certificat du serveur RADIUS (bloc ServerValidation manquant ou aucune autorité racine de confiance déclarée). Un attaquant peut monter un faux serveur RADIUS et capturer les identifiants."
				: $"Le profil 802.1X « {profileName} » valide le certificat du serveur RADIUS contre une autorité racine de confiance."),
			Recommendation = (validationWeak
				? "Activez la validation du certificat serveur, fixez la ou les autorités racines de confiance (TrustedRootCA) et exigez le nom du serveur RADIUS attendu."
				: "Configuration correcte."),
			Reference = PolicyReference
		});
	}

	/// <summary>
	/// Classe la méthode d'authentification (valeur brute invariante de langue), insensible à la casse.
	/// Règle de fiabilité : une valeur vide OU non reconnue N'est JAMAIS silencieuse (Info) — elle
	/// remonte en Warning « non déterminée », car un profil non analysable doit alerter.
	/// </summary>
	private static (SecurityStatus, string) ClassifyAuthentication(string auth, bool useOneX)
	{
		string a = (auth ?? string.Empty).Trim();

		// Réseau ouvert : risque n°1.
		if (a.Equals("open", StringComparison.OrdinalIgnoreCase))
		{
			return (SecurityStatus.Critical, "réseau ouvert, sans authentification");
		}
		// WEP / clé partagée : cassé.
		if (a.Equals("WEP", StringComparison.OrdinalIgnoreCase) || a.Equals("shared", StringComparison.OrdinalIgnoreCase))
		{
			return (SecurityStatus.Critical, "WEP / clé partagée, cassé");
		}
		// 802.1X / entreprise (EAP) : correct au niveau authentification (la validation du
		// certificat serveur est évaluée séparément dans AnalyzeEap).
		if (useOneX || a.IndexOf("EAP", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return (SecurityStatus.OK, "802.1X / entreprise (EAP)");
		}
		// WPA3 / SAE : recommandé.
		if (a.IndexOf("WPA3", StringComparison.OrdinalIgnoreCase) >= 0 || a.IndexOf("SAE", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return (SecurityStatus.OK, "WPA3 (recommandé)");
		}
		// WPA2 (PSK ou entreprise) : correct.
		if (a.IndexOf("WPA2", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return (SecurityStatus.OK, "WPA2");
		}
		// WPA d'origine (WPA1 / WPAPSK) : obsolète.
		if (a.Equals("WPAPSK", StringComparison.OrdinalIgnoreCase)
			|| a.Equals("WPA", StringComparison.OrdinalIgnoreCase)
			|| a.IndexOf("WPA", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			return (SecurityStatus.Warning, "WPA d'origine (obsolète)");
		}
		// Vide ou non reconnue → alerte (jamais OK/Info silencieux).
		return (SecurityStatus.Warning, "non déterminée");
	}

	/// <summary>
	/// Classe l'algorithme de chiffrement (valeur brute invariante), insensible à la casse.
	/// Une valeur vide remonte en Warning (jamais Info silencieux).
	/// </summary>
	private static (SecurityStatus, string) ClassifyEncryption(string enc)
	{
		string e = (enc ?? string.Empty).Trim();
		if (e.Equals("none", StringComparison.OrdinalIgnoreCase))
		{
			return (SecurityStatus.Critical, "aucun chiffrement");
		}
		if (e.Equals("WEP", StringComparison.OrdinalIgnoreCase))
		{
			return (SecurityStatus.Critical, "WEP, cassé");
		}
		if (e.Equals("TKIP", StringComparison.OrdinalIgnoreCase))
		{
			return (SecurityStatus.Warning, "TKIP, obsolète");
		}
		if (e.Equals("AES", StringComparison.OrdinalIgnoreCase)
			|| e.Equals("CCMP", StringComparison.OrdinalIgnoreCase)
			|| e.Equals("GCMP", StringComparison.OrdinalIgnoreCase))
		{
			return (SecurityStatus.OK, "AES/GCMP (robuste)");
		}
		// Vide ou non reconnu → alerte.
		return (SecurityStatus.Warning, "non déterminé");
	}

	// ------------------------------------------------------------------
	// FALLBACK : énumération des noms de profils via « netsh wlan show profiles »
	// ------------------------------------------------------------------
	private async Task CollectProfilesFallbackAsync(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			(int exitCode, string stdout) = await RunNetshAsync("wlan show profiles", ct).ConfigureAwait(false);
			// On ne parse PAS de libellés localisés pour la sécurité : on extrait uniquement
			// les noms de profils après le séparateur « : » (présent quelle que soit la langue).
			List<string> names = new List<string>();
			if (!string.IsNullOrWhiteSpace(stdout))
			{
				foreach (string line in stdout.Split('\n'))
				{
					int idx = line.IndexOf(':');
					if (idx > 0 && idx < line.Length - 1)
					{
						string candidate = line.Substring(idx + 1).Trim();
						// Filtre grossier : un nom de profil ne contient pas de longues phrases.
						if (!string.IsNullOrWhiteSpace(candidate) && candidate.Length <= 64 && !candidate.Contains(':'))
						{
							names.Add(candidate);
						}
					}
				}
			}
			int count = names.Distinct(StringComparer.OrdinalIgnoreCase).Count();
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WiFi — Profils enregistrés (mode dégradé)",
				CurrentValue = (exitCode == 0 ? count.ToString(CultureInfo.InvariantCulture) + " profil(s)" : "Indéterminé"),
				ExpectedValue = "N/A",
				Status = SecurityStatus.Warning,
				Description = "L'export XML des profils WiFi (analyse détaillée) a échoué. Seule l'énumération des noms de profils a pu être réalisée ; l'authentification et le chiffrement n'ont pas pu être vérifiés.",
				Recommendation = "Exécutez CHECKSEC avec des privilèges administrateur pour permettre l'export détaillé des profils WiFi (« netsh wlan export profile »).",
				Reference = PolicyReference
			});
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			results.Add(BuildErrorResult("WiFi — Profils (fallback) — Erreur", ex));
		}
	}

	// ------------------------------------------------------------------
	// C12 / C13 — Politiques d'auto-connexion (registre)
	// ------------------------------------------------------------------
	private void CollectAutoConnectPolicies(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// C12 — WiFi Sense : auto-connexion aux hotspots (valeur attendue 0).
		try
		{
			using RegistryKey senseKey = Registry.LocalMachine.OpenSubKey(WifiSenseHotspotsKey);
			object raw = senseKey?.GetValue("value");
			if (raw != null)
			{
				int v = Convert.ToInt32(raw);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "WiFi — Auto-connexion hotspots WiFi Sense",
					CurrentValue = (v == 0 ? "Désactivée (0)" : $"Activée ({v})"),
					ExpectedValue = "Désactivée (0)",
					Status = (v == 0 ? SecurityStatus.OK : SecurityStatus.Warning),
					Description = "Politique WiFi Sense d'auto-connexion aux hotspots partagés. Activée, elle connecte automatiquement l'appareil à des réseaux publics non fiables.",
					Recommendation = (v == 0 ? "Configuration correcte." : "Désactivez l'auto-connexion aux hotspots WiFi Sense (valeur 0)."),
					Reference = PolicyReference
				});
			}
			else
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "WiFi — Auto-connexion hotspots WiFi Sense",
					CurrentValue = "Non configurée",
					ExpectedValue = "Désactivée (0)",
					Status = SecurityStatus.Info,
					Description = "La politique WiFi Sense n'est pas explicitement configurée. WiFi Sense est obsolète sur les versions récentes de Windows mais la valeur devrait être forcée à 0.",
					Recommendation = "Forcez la politique AllowAutoConnectToWiFiSenseHotspots à 0 par GPO/MDM.",
					Reference = PolicyReference
				});
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			results.Add(BuildErrorResult("WiFi — WiFi Sense — Erreur", ex));
		}

		// C13 — Auto-connexion OEM (valeur attendue 0).
		try
		{
			using RegistryKey cfgKey = Registry.LocalMachine.OpenSubKey(WcmSvcConfigKey);
			object raw = cfgKey?.GetValue("AutoConnectAllowedOEM");
			if (raw != null)
			{
				int v = Convert.ToInt32(raw);
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "WiFi — Auto-connexion OEM",
					CurrentValue = (v == 0 ? "Désactivée (0)" : $"Activée ({v})"),
					ExpectedValue = "Désactivée (0)",
					Status = (v == 0 ? SecurityStatus.OK : SecurityStatus.Warning),
					Description = "Paramètre AutoConnectAllowedOEM : autorise l'auto-connexion à des réseaux préconfigurés par le fabricant (OEM), potentiellement non maîtrisés.",
					Recommendation = (v == 0 ? "Configuration correcte." : "Positionnez AutoConnectAllowedOEM à 0 pour empêcher l'auto-connexion aux réseaux OEM."),
					Reference = PolicyReference
				});
			}
			else
			{
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "WiFi — Auto-connexion OEM",
					CurrentValue = "Non configurée",
					ExpectedValue = "Désactivée (0)",
					Status = SecurityStatus.Info,
					Description = "Le paramètre AutoConnectAllowedOEM n'est pas défini ; le comportement par défaut s'applique.",
					Recommendation = "Positionnez AutoConnectAllowedOEM à 0 pour désactiver l'auto-connexion aux réseaux OEM.",
					Reference = PolicyReference
				});
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			results.Add(BuildErrorResult("WiFi — Auto-connexion OEM — Erreur", ex));
		}
	}

	// ------------------------------------------------------------------
	// Helpers XML (résolution par nom local, indépendante du namespace)
	// ------------------------------------------------------------------
	/// <summary>
	/// Énumère TOUS les descendants (à n'importe quelle profondeur) dont le nom LOCAL correspond,
	/// en ignorant totalement le namespace XML. C'est le cœur de la fiabilité namespace-agnostique :
	/// les exports « netsh » mélangent au moins deux namespaces par défaut (profile/v1 et
	/// MacRandomization profile/v3) ; naviguer par nom qualifié échouerait silencieusement.
	/// </summary>
	private static IEnumerable<XElement> Elems(XElement parent, string localName)
	{
		if (parent == null)
		{
			return Enumerable.Empty<XElement>();
		}
		return parent.Descendants().Where((XElement e) => e.Name.LocalName.Equals(localName, StringComparison.OrdinalIgnoreCase));
	}

	/// <summary>Valeur (trimée) du PREMIER descendant portant ce nom local, ou null s'il est absent.</summary>
	private static string Val(XElement root, string localName)
	{
		XElement el = Elems(root, localName).FirstOrDefault();
		return el?.Value?.Trim();
	}

	/// <summary>Premier descendant portant ce nom local (namespace ignoré), ou null.</summary>
	private static XElement Elem(XElement parent, string localName)
	{
		return Elems(parent, localName).FirstOrDefault();
	}

	// ------------------------------------------------------------------
	// Exécution de netsh (encodage OEM, timeout, annulation)
	// ------------------------------------------------------------------
	/// <summary>
	/// Exécute « netsh.exe &lt;args&gt; » avec redirection de la sortie standard en encodage OEM,
	/// un timeout de 20 s (lié au CancellationToken), et Kill() en cas d'annulation/timeout.
	/// Retourne (code de sortie, stdout). Un code -1 signale un échec de lancement.
	/// </summary>
	private static async Task<(int ExitCode, string StdOut)> RunNetshAsync(string args, CancellationToken ct)
	{
		Encoding oemEncoding;
		try
		{
			oemEncoding = Encoding.GetEncoding(CultureInfo.InstalledUICulture.TextInfo.OEMCodePage);
		}
		catch
		{
			oemEncoding = Encoding.UTF8;
		}

		using CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		linkedCts.CancelAfter(NetshTimeout);

		ProcessStartInfo psi = new ProcessStartInfo("netsh.exe", args)
		{
			RedirectStandardOutput = true,
			RedirectStandardError = true,
			UseShellExecute = false,
			CreateNoWindow = true,
			StandardOutputEncoding = oemEncoding,
			StandardErrorEncoding = oemEncoding
		};

		using Process process = new Process { StartInfo = psi };
		try
		{
			if (!process.Start())
			{
				return (-1, string.Empty);
			}
		}
		catch
		{
			return (-1, string.Empty);
		}

		// Lecture asynchrone de la sortie.
		Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
		try
		{
			await process.WaitForExitAsync(linkedCts.Token).ConfigureAwait(false);
			string output = await stdoutTask.ConfigureAwait(false);
			return (process.ExitCode, output);
		}
		catch (OperationCanceledException)
		{
			// Timeout ou annulation : on tue le processus pour ne pas laisser de netsh orphelin.
			try
			{
				if (!process.HasExited)
				{
					process.Kill(entireProcessTree: true);
				}
			}
			catch
			{
			}
			// Si c'est le token appelant qui a annulé, on propage ; si c'est le timeout, on renvoie un échec.
			if (ct.IsCancellationRequested)
			{
				throw;
			}
			return (-1, string.Empty);
		}
	}

	// ------------------------------------------------------------------
	// Helper commun de résultat d'erreur
	// ------------------------------------------------------------------
	/// <summary>Résultat Warning pour un profil dont le parsing a échoué (jamais avalé silencieusement).</summary>
	private SecurityResult BuildUnparsableResult(string profileName)
	{
		return new SecurityResult
		{
			Category = Category,
			CheckName = $"WiFi [{profileName}] — Profil non analysable",
			CurrentValue = "Analyse impossible",
			ExpectedValue = "Profil analysable (authentification/chiffrement déterminés)",
			Status = SecurityStatus.Warning,
			Description = $"Le profil WiFi « {profileName} » n'a pas pu être analysé (XML absent, illisible ou structure inattendue). Son niveau de sécurité (authentification/chiffrement) n'a pas pu être vérifié.",
			Recommendation = "Vérifiez ce profil manuellement (« netsh wlan show profile name=... key=clear ») et exécutez CHECKSEC avec des privilèges administrateur.",
			Reference = PolicyReference
		};
	}

	private SecurityResult BuildErrorResult(string checkName, Exception ex)
	{
		return new SecurityResult
		{
			Category = Category,
			CheckName = checkName,
			CurrentValue = "Erreur",
			ExpectedValue = "N/A",
			Status = SecurityStatus.Error,
			Description = "Erreur lors de la collecte : " + ex.Message,
			Recommendation = "Vérifiez les permissions et la disponibilité du sous-système WLAN.",
			Reference = PolicyReference
		};
	}
}
