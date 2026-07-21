using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur Proxy & Résolution réseau.
// Inspecte la configuration proxy (WinINET utilisateur/machine, WinHTTP), les politiques de
// résolution de noms (NRPT) et l'état des services réseau associés (WinHttpAutoProxySvc, Dnscache).
// Contrat ISecurityCollector : constructeur sans paramètre.
public class ProxyNetworkCollector : ISecurityCollector
{
	public string Name => "Proxy & Résolution réseau";

	public string Category => "Réseau";

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
			// Proxy système WinINET (HKCU + HKLM), y compris PAC (AutoConfigURL).
			CollectWinInetProxy(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			// Proxy WinHTTP machine (blob binaire).
			CollectWinHttpProxy(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			// Règles NRPT (Name Resolution Policy Table).
			CollectNrptRules(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			// Services réseau : WinHttpAutoProxySvc et Dnscache.
			CollectNetworkServices(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "ProxyNetworkCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// Proxy WinINET : ProxyEnable / ProxyServer / AutoConfigURL (PAC), sous HKCU puis HKLM.
	private void CollectWinInetProxy(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		const string internetSettingsPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

		// 1) Proxy statique (ProxyEnable + ProxyServer).
		TryAdd(results, delegate
		{
			int proxyEnableHkcu = RegInt("HKCU", internetSettingsPath, "ProxyEnable");
			string proxyServerHkcu = RegString("HKCU", internetSettingsPath, "ProxyServer");
			int proxyEnableHklm = RegInt("HKLM", internetSettingsPath, "ProxyEnable");
			string proxyServerHklm = RegString("HKLM", internetSettingsPath, "ProxyServer");

			bool hkcuEnabled = proxyEnableHkcu == 1 && !string.IsNullOrEmpty(proxyServerHkcu);
			bool hklmEnabled = proxyEnableHklm == 1 && !string.IsNullOrEmpty(proxyServerHklm);
			bool proxyConfigured = hkcuEnabled || hklmEnabled;

			string details = "HKCU: " + (hkcuEnabled ? ("activé -> " + proxyServerHkcu) : "non configuré")
				+ " | HKLM: " + (hklmEnabled ? ("activé -> " + proxyServerHklm) : "non configuré");

			return new SecurityResult
			{
				Category = Category,
				CheckName = "Proxy WinINET (ProxyServer)",
				CurrentValue = details,
				ExpectedValue = "Conforme à la politique réseau de l'organisation",
				// Un proxy configuré n'est pas une faille en soi : Info (contexte).
				Status = (proxyConfigured ? SecurityStatus.Info : SecurityStatus.OK),
				Description = "Le proxy WinINET (Internet Settings) est utilisé par Internet Explorer, Edge (mode hérité) et de nombreuses applications. Un proxy configuré route le trafic HTTP(S) via un serveur intermédiaire. Un proxy inattendu ou pointant vers une adresse non maîtrisée peut détourner ou espionner le trafic (MITM).",
				Recommendation = (proxyConfigured
					? "Un proxy WinINET est configuré. Vérifier que le serveur (" + (hkcuEnabled ? proxyServerHkcu : proxyServerHklm) + ") est légitime et approuvé par l'organisation."
					: "Aucun proxy WinINET statique configuré."),
				Reference = "https://learn.microsoft.com/windows/win32/wininet/enabling-internet-functionality"
			};
		});

		// 2) Configuration automatique par PAC (AutoConfigURL).
		TryAdd(results, delegate
		{
			string pacHkcu = RegString("HKCU", internetSettingsPath, "AutoConfigURL");
			string pacHklm = RegString("HKLM", internetSettingsPath, "AutoConfigURL");
			string pacUrl = (!string.IsNullOrEmpty(pacHkcu) ? pacHkcu : pacHklm);
			bool pacConfigured = !string.IsNullOrEmpty(pacUrl);

			// Une URL PAC non-locale (http externe) présente un risque de détournement.
			bool pacIsNonLocal = pacConfigured && IsNonLocalUrl(pacUrl);

			return new SecurityResult
			{
				Category = Category,
				CheckName = "Proxy auto-configuration (PAC / AutoConfigURL)",
				CurrentValue = (pacConfigured ? pacUrl : "Non configuré"),
				ExpectedValue = "Non configuré, ou URL PAC interne/approuvée",
				// PAC non-local = Warning (risque de détournement), PAC local = Info.
				Status = (pacIsNonLocal ? SecurityStatus.Warning : (pacConfigured ? SecurityStatus.Info : SecurityStatus.OK)),
				Description = "AutoConfigURL désigne un fichier PAC (Proxy Auto-Config) qui détermine dynamiquement le proxy à utiliser par destination. Un fichier PAC hébergé sur une URL externe non maîtrisée peut être modifié par un attaquant pour rediriger tout le trafic web (détournement de proxy). Les fichiers PAC locaux (file://, http://<intranet>) sont plus sûrs.",
				Recommendation = (pacIsNonLocal
					? "Une URL PAC pointe vers une ressource externe/non-locale (" + pacUrl + "). Vérifier qu'elle est légitime, servie en HTTPS depuis un hôte de confiance, et non détournée. Un PAC malveillant peut rediriger tout le trafic."
					: (pacConfigured
						? "Un fichier PAC local/interne est configuré (" + pacUrl + "). Confirmer qu'il correspond à la politique de l'organisation."
						: "Aucune configuration automatique par PAC.")),
				Reference = "https://learn.microsoft.com/windows/win32/winhttp/proxy-autoconfig-cache"
			};
		});
	}

	// Proxy WinHTTP machine : blob binaire sous Connections\WinHttpSettings.
	private void CollectWinHttpProxy(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			byte[] blob = RegBinary("HKLM",
				"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections",
				"WinHttpSettings");

			// Interprétation minimale du blob WinHttpSettings :
			// offset 0-3 : version, 4-7 : compteur, 8-11 : flags de configuration.
			// flags : 1 = direct, 2 = proxy explicite, 4 = auto-detect/PAC.
			bool proxyConfigured = false;
			string decoded = "Non lisible";
			if (blob != null && blob.Length >= 12)
			{
				int flags = BitConverter.ToInt32(blob, 8);
				bool hasProxy = (flags & 0x2) != 0;
				bool hasAutoDetect = (flags & 0x4) != 0;
				proxyConfigured = hasProxy || hasAutoDetect;
				decoded = $"flags=0x{flags:X} (proxy explicite={hasProxy}, auto-detect/PAC={hasAutoDetect})";
			}
			else if (blob != null)
			{
				decoded = $"blob de {blob.Length} octet(s) (format inattendu)";
			}

			bool present = blob != null;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Proxy WinHTTP machine (WinHttpSettings)",
				CurrentValue = (present ? decoded : "Non configuré (accès direct par défaut)"),
				ExpectedValue = "Conforme à la politique réseau de l'organisation",
				Status = SecurityStatus.Info,
				Description = "WinHTTP est utilisé par les services Windows, les tâches système et de nombreuses applications serveur (mises à jour, télémétrie, etc.). Contrairement à WinINET (par utilisateur), le proxy WinHTTP est défini au niveau machine via 'netsh winhttp set proxy' et stocké en binaire dans WinHttpSettings. Un proxy WinHTTP inattendu peut détourner le trafic des services système.",
				Recommendation = (proxyConfigured
					? "Un proxy WinHTTP machine est configuré. Vérifier avec 'netsh winhttp show proxy' qu'il correspond à la configuration attendue et pointe vers un serveur approuvé."
					: (present
						? "WinHttpSettings présent mais configuré en accès direct (pas de proxy machine)."
						: "Aucun proxy WinHTTP machine configuré (accès direct).")),
				Reference = "https://learn.microsoft.com/windows/win32/winhttp/netsh-exe-commands"
			};
		});
	}

	// NRPT : présence de règles sous ...\DNSClient\DnsPolicyConfig (sous-clés).
	private void CollectNrptRules(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int ruleCount = 0;
			bool readError = false;
			try
			{
				using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				using RegistryKey nrptKey = baseKey.OpenSubKey(
					"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig");
				if (nrptKey != null)
				{
					ruleCount = nrptKey.SubKeyCount;
				}
			}
			catch
			{
				readError = true;
			}

			bool hasRules = ruleCount > 0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "NRPT (Name Resolution Policy Table)",
				CurrentValue = (readError ? "Erreur de lecture" : (hasRules ? $"{ruleCount} règle(s) NRPT définie(s)" : "Aucune règle NRPT")),
				ExpectedValue = "Conforme à la politique de résolution de noms",
				Status = (readError ? SecurityStatus.Error : SecurityStatus.Info),
				Description = "La NRPT (Name Resolution Policy Table) définit des règles de résolution DNS spécifiques par suffixe/namespace (serveurs DNS dédiés, DNSSEC, DNS over HTTPS, DirectAccess). Les règles sont stockées comme sous-clés de HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig. Des règles NRPT inattendues peuvent rediriger la résolution de certains domaines vers des serveurs contrôlés par un attaquant.",
				Recommendation = (hasRules
					? "Des règles NRPT sont présentes. Vérifier avec 'Get-DnsClientNrptPolicy' qu'elles sont légitimes (DoH, DirectAccess, DNSSEC) et non un détournement de résolution."
					: "Aucune règle NRPT définie."),
				Reference = "https://learn.microsoft.com/powershell/module/dnsclient/get-dnsclientnrptpolicy"
			};
		});
	}

	// État des services réseau via WMI Win32_Service : WinHttpAutoProxySvc et Dnscache.
	private void CollectNetworkServices(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// WinHTTP Web Proxy Auto-Discovery Service (WPAD).
		TryAdd(results, delegate
		{
			ServiceInfo svc = QueryService("WinHttpAutoProxySvc");
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Service WinHTTP Auto Proxy (WinHttpAutoProxySvc)",
				CurrentValue = svc.ToDisplayString(),
				ExpectedValue = "Selon usage (WPAD peut être une surface d'attaque)",
				Status = SecurityStatus.Info,
				Description = "WinHttpAutoProxySvc implémente la découverte automatique de proxy (WPAD/PAC). WPAD est historiquement une surface d'attaque (empoisonnement WPAD, MITM via réponses DNS/LLMNR malveillantes). Son état est fourni ici à titre de contexte.",
				Recommendation = (svc.Found
					? ("Service WPAD à l'état '" + svc.State + "'. Si la découverte automatique de proxy n'est pas nécessaire, envisager de désactiver WPAD pour réduire la surface d'attaque.")
					: "Service WinHttpAutoProxySvc introuvable via WMI."),
				Reference = "https://learn.microsoft.com/windows-server/networking/technologies/wpad"
			};
		});

		ct.ThrowIfCancellationRequested();

		// DNS Client Cache (Dnscache).
		TryAdd(results, delegate
		{
			ServiceInfo svc = QueryService("Dnscache");
			bool running = string.Equals(svc.State, "Running", StringComparison.OrdinalIgnoreCase);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Service DNS Client Cache (Dnscache)",
				CurrentValue = svc.ToDisplayString(),
				ExpectedValue = "Running (actif)",
				Status = SecurityStatus.Info,
				Description = "Le service Dnscache (DNS Client) gère le cache de résolution DNS de la machine et applique la NRPT. Il est normalement actif. Un service Dnscache arrêté peut dégrader la résolution et neutraliser certaines politiques DNS (NRPT, DoH).",
				Recommendation = (running
					? "Le service DNS Client (Dnscache) est actif."
					: (svc.Found
						? ("Le service Dnscache est à l'état '" + svc.State + "'. Vérifier pourquoi il n'est pas en cours d'exécution.")
						: "Service Dnscache introuvable via WMI.")),
				Reference = "https://learn.microsoft.com/windows-server/networking/dns/dns-top"
			};
		});
	}

	// --- Helpers WMI service ---

	private static ServiceInfo QueryService(string serviceName)
	{
		ServiceInfo info = new ServiceInfo
		{
			Name = serviceName
		};
		try
		{
			using ManagementObjectSearcher searcher = new ManagementObjectSearcher(
				"SELECT State, StartMode, Status FROM Win32_Service WHERE Name='" + serviceName + "'");
			using ManagementObjectCollection collection = searcher.Get();
			foreach (ManagementObject serviceObject in collection)
			{
				using (serviceObject)
				{
					info.Found = true;
					info.State = serviceObject["State"]?.ToString() ?? "Unknown";
					info.StartMode = serviceObject["StartMode"]?.ToString() ?? "Unknown";
				}
			}
		}
		catch
		{
			// Lecture WMI best-effort.
		}
		return info;
	}

	// --- Helpers registre (style AdditionalSecurityCollector) ---

	private static int RegInt(string hive, string path, string valueName, int def = -1)
	{
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKLM") ? RegistryHive.LocalMachine : ((!(hiveName == "HKCU")) ? RegistryHive.LocalMachine : RegistryHive.CurrentUser));
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

	private static string? RegString(string hive, string path, string valueName)
	{
		string result;
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKLM") ? RegistryHive.LocalMachine : ((!(hiveName == "HKCU")) ? RegistryHive.LocalMachine : RegistryHive.CurrentUser));
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			result = subKey?.GetValue(valueName)?.ToString();
		}
		catch
		{
			result = null;
		}
		return result;
	}

	private static byte[]? RegBinary(string hive, string path, string valueName)
	{
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKLM") ? RegistryHive.LocalMachine : ((!(hiveName == "HKCU")) ? RegistryHive.LocalMachine : RegistryHive.CurrentUser));
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			return subKey?.GetValue(valueName) as byte[];
		}
		catch
		{
			return null;
		}
	}

	// Détermine si une URL (PAC) pointe vers une ressource non-locale (risque de détournement).
	private static bool IsNonLocalUrl(string url)
	{
		if (string.IsNullOrEmpty(url))
		{
			return false;
		}
		string lower = url.ToLowerInvariant();
		// Un PAC servi via file:// local est considéré comme local/sûr.
		if (lower.StartsWith("file:"))
		{
			return false;
		}
		// Références à la boucle locale = local.
		if (lower.Contains("localhost") || lower.Contains("127.0.0.1") || lower.Contains("::1"))
		{
			return false;
		}
		// URL http/https vers un hôte distant = non-locale.
		return lower.StartsWith("http:") || lower.StartsWith("https:");
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
				Category = "Réseau",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les permissions d'accès au registre et WMI.",
				Reference = ""
			});
		}
	}

	// Représentation interne de l'état d'un service Windows.
	private sealed class ServiceInfo
	{
		public string Name { get; set; } = "";

		public bool Found { get; set; }

		public string State { get; set; } = "Unknown";

		public string StartMode { get; set; } = "Unknown";

		public string ToDisplayString()
		{
			return Found
				? ("State=" + State + ", StartMode=" + StartMode)
				: "Service introuvable";
		}
	}
}
