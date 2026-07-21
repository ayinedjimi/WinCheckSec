using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur "extra" d'accès distant : vérifications complémentaires sur
// l'Assistance à distance (Remote Assistance) et WinRM (authentification Basic,
// état du service). Chaque vérification est isolée via TryAdd.
public class RemoteAccessExtraCollector : ISecurityCollector
{
	public string Name => "Accès distant (extra)";

	public string Category => "Accès Distant";

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
			CollectRemoteAssistance(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectWinRmBasicAuth(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectWinRmService(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			// Annulation demandée : on propage sans polluer le rapport.
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "RemoteAccessExtraCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// --- Assistance à distance (Remote Assistance) ---
	// fAllowToGetHelp : 0 attendu (désactivé). fAllowFullControl / fAllowUnsolicited :
	// 0 attendu (pas de contrôle total, pas de sessions non sollicitées).
	private void CollectRemoteAssistance(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int allowToGetHelp = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", "fAllowToGetHelp");
			bool enabled = allowToGetHelp == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Assistance à distance (fAllowToGetHelp)",
				CurrentValue = ((allowToGetHelp == -1) ? "Non configuré (désactivé par défaut sur la plupart des éditions)" : (enabled ? "1 - Activé" : "0 - Désactivé")),
				ExpectedValue = "0 (désactivé)",
				Status = (enabled ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "L'Assistance à distance (Remote Assistance) permet à un tiers de se connecter au poste pour apporter de l'aide. Activée (fAllowToGetHelp=1), elle augmente la surface d'attaque et peut être détournée pour obtenir un accès interactif. Elle doit être désactivée sauf besoin opérationnel explicite.",
				Recommendation = (enabled ? "Désactiver l'Assistance à distance : HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance\\fAllowToGetHelp = 0, ou via GPO : Configuration ordinateur > Modèles d'administration > Système > Assistance à distance > Proposer l'assistance à distance / Demander l'assistance à distance = Désactivé." : "L'Assistance à distance est désactivée — bonne configuration."),
				Reference = "https://learn.microsoft.com/troubleshoot/windows-server/remote/remote-assistance-overview"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int allowFullControl = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", "fAllowFullControl");
			int allowUnsolicited = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", "fAllowUnsolicited");
			bool fullControlOn = allowFullControl == 1;
			bool unsolicitedOn = allowUnsolicited == 1;
			bool anyRisky = fullControlOn || unsolicitedOn;
			string fullText = ((allowFullControl == -1) ? "Non configuré" : (fullControlOn ? "1 - Contrôle total autorisé" : "0 - Contrôle total refusé"));
			string unsolText = ((allowUnsolicited == -1) ? "Non configuré" : (unsolicitedOn ? "1 - Sessions non sollicitées autorisées" : "0 - Sessions non sollicitées refusées"));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Assistance à distance — contrôle total / non sollicité",
				CurrentValue = "fAllowFullControl=" + fullText + ", fAllowUnsolicited=" + unsolText,
				ExpectedValue = "0 pour les deux (pas de contrôle total, pas de session non sollicitée)",
				Status = (anyRisky ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "fAllowFullControl=1 autorise l'assistant distant à prendre le contrôle total du poste (clavier/souris), et non une simple visualisation. fAllowUnsolicited=1 autorise l'assistance non sollicitée (l'assistant initie la connexion sans demande de l'utilisateur). Ces deux options élargissent fortement les possibilités d'accès distant interactif et doivent rester désactivées.",
				Recommendation = (anyRisky ? "Refuser le contrôle total et les sessions non sollicitées : définir fAllowFullControl = 0 et fAllowUnsolicited = 0 sous HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance, ou désactiver entièrement l'Assistance à distance via GPO." : "Ni le contrôle total ni les sessions non sollicitées ne sont autorisés — bonne configuration."),
				Reference = "https://learn.microsoft.com/troubleshoot/windows-server/remote/remote-assistance-overview"
			};
		});
	}

	// --- WinRM Basic Auth (client et service) ---
	// AllowBasic : 0 attendu. L'auth Basic transmet les identifiants faiblement
	// protégés (base64), à proscrire.
	private void CollectWinRmBasicAuth(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int clientBasic = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client", "AllowBasic");
			bool enabled = clientBasic == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "WinRM Client — Basic Auth (AllowBasic)",
				CurrentValue = ((clientBasic == -1) ? "Non configuré (Basic autorisé par défaut côté client)" : (enabled ? "1 - Basic autorisé" : "0 - Basic refusé")),
				ExpectedValue = "0 (Basic refusé)",
				Status = (enabled ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "L'authentification Basic de WinRM (Windows Remote Management) transmet les identifiants encodés en base64, faiblement protégés — en clair si le transport n'est pas chiffré (HTTP). Côté client, AllowBasic=1 autorise l'envoi d'identifiants via Basic, exposant au vol de credentials. NTLM/Kerberos doivent être privilégiés.",
				Recommendation = (enabled ? "Désactiver l'auth Basic côté client WinRM : HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\AllowBasic = 0, ou via GPO : Configuration ordinateur > Modèles d'administration > Composants Windows > Gestion à distance de Windows (WinRM) > Client WinRM > Autoriser l'authentification Basic = Désactivé." : "L'auth Basic du client WinRM est désactivée — bonne configuration."),
				Reference = "https://learn.microsoft.com/windows/win32/winrm/authentication-for-remote-connections"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			int serviceBasic = RegInt("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service", "AllowBasic");
			bool enabled = serviceBasic == 1;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "WinRM Service — Basic Auth (AllowBasic)",
				CurrentValue = ((serviceBasic == -1) ? "Non configuré (Basic autorisé par défaut côté service)" : (enabled ? "1 - Basic autorisé" : "0 - Basic refusé")),
				ExpectedValue = "0 (Basic refusé)",
				Status = (enabled ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Côté service WinRM, AllowBasic=1 accepte les connexions entrantes authentifiées en Basic, où les identifiants transitent faiblement protégés (base64), en clair sur un transport HTTP non chiffré. Cela facilite l'interception d'identifiants et les attaques par relais. L'auth Basic doit être refusée au profit de NTLM/Kerberos.",
				Recommendation = (enabled ? "Désactiver l'auth Basic côté service WinRM : HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\AllowBasic = 0, ou via GPO : Configuration ordinateur > Modèles d'administration > Composants Windows > Gestion à distance de Windows (WinRM) > Service WinRM > Autoriser l'authentification Basic = Désactivé." : "L'auth Basic du service WinRM est désactivée — bonne configuration."),
				Reference = "https://learn.microsoft.com/windows/win32/winrm/authentication-for-remote-connections"
			};
		});
	}

	// --- WinRM service : état de démarrage (contexte, Info) ---
	private void CollectWinRmService(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			// Start du service : 2 = Automatique, 3 = Manuel, 4 = Désactivé.
			int startValue = RegInt("HKLM", "SYSTEM\\CurrentControlSet\\Services\\WinRM", "Start");
			string serviceState = "Inconnu";
			try
			{
				ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT State FROM Win32_Service WHERE Name='WinRM'");
				try
				{
					foreach (ManagementObject serviceObject in searcher.Get())
					{
						ManagementObject mo = serviceObject;
						try
						{
							serviceState = serviceObject["State"]?.ToString() ?? "Inconnu";
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
			catch
			{
				// WMI indisponible : on se contente de l'information registre.
			}
			string startLabel;
			switch (startValue)
			{
			case 2:
				startLabel = "2 - Automatique";
				break;
			case 3:
				startLabel = "3 - Manuel";
				break;
			case 4:
				startLabel = "4 - Désactivé";
				break;
			case -1:
				startLabel = "Non trouvé";
				break;
			default:
				startLabel = startValue.ToString();
				break;
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Service WinRM — état de démarrage (contexte)",
				CurrentValue = "Start=" + startLabel + ", State=" + serviceState,
				ExpectedValue = "Désactivé si la gestion à distance WinRM n'est pas requise",
				Status = SecurityStatus.Info,
				Description = "Le service WinRM (Gestion à distance de Windows) expose une interface d'administration à distance (PowerShell Remoting, WS-Management). Information de contexte : un service WinRM actif n'est pas un problème en soi s'il est correctement authentifié (NTLM/Kerberos, Basic désactivé) et filtré, mais il constitue une surface d'attaque à désactiver lorsqu'il n'est pas nécessaire.",
				Recommendation = "Si la gestion à distance WinRM n'est pas requise sur ce poste, désactiver le service : Stop-Service WinRM; Set-Service WinRM -StartupType Disabled. Sinon, s'assurer que l'auth Basic est refusée et que l'accès est restreint (HTTPS, filtrage réseau).",
				Reference = "https://learn.microsoft.com/windows/win32/winrm/portal"
			};
		});
	}

	// --- Helpers d'accès registre (vue 64 bits explicite) ---

	private static int RegInt(string hive, string path, string valueName, int def = -1)
	{
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine);
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
		string? result;
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine);
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

	// Isole chaque vérification : une exception unitaire produit un résultat Error
	// sans interrompre les autres checks.
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
				Category = "Accès Distant",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les permissions d'accès au registre et WMI.",
				Reference = ""
			});
		}
	}
}
