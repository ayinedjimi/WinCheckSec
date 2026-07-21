using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur de durcissement des services de découverte réseau (WSD / SSDP / UPnP).
// Ces services élargissent la surface d'attaque sur les postes qui n'ont pas besoin
// de partage/découverte réseau. Il s'agit de durcissements OPTIONNELS :
// les statuts restent nuancés (Info / Warning), jamais Critical.
public class NetworkServicesHardeningCollector : ISecurityCollector
{
	// Représente l'état d'un service résolu par son nom invariant (pas le DisplayName localisé).
	private sealed class ServiceState
	{
		public bool Found;

		public string StartMode = "Inconnu";

		public string State = "Inconnu";

		// Valeur affichée : "StartMode / State".
		public string Display => StartMode + " / " + State;
	}

	public string Name => "Services de découverte réseau";

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
			CollectFunctionDiscovery(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectSsdpDiscovery(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectUpnpDeviceHost(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception exception)
		{
			collectorReport.ErrorMessage = "NetworkServicesHardeningCollector fatal error: " + exception.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// FDResPub — Function Discovery Resource Publication (publication WSD).
	// Sur un poste non-partage, un démarrage Manuel ou Désactivé est attendu.
	// Automatique + Running => durcissement recommandé (Info/Warning).
	private void CollectFunctionDiscovery(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			ServiceState svc = QueryService("FDResPub");
			if (!svc.Found)
			{
				return AbsentResult(
					"FDResPub (Function Discovery Resource Publication)",
					"Le service de publication des ressources de découverte de fonctions (WSD) n'est pas présent sur ce système.",
					"https://learn.microsoft.com/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server");
			}
			bool isRunning = IsRunning(svc.State);
			bool isAuto = IsAuto(svc.StartMode);
			// Automatique + en cours => Warning (surface réseau active) ; en cours seul => Info ; sinon OK.
			SecurityStatus status = ((isAuto && isRunning) ? SecurityStatus.Warning : (isRunning ? SecurityStatus.Info : SecurityStatus.OK));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Service FDResPub (Function Discovery / WSD)",
				CurrentValue = svc.Display,
				ExpectedValue = "Désactivé ou Manuel (postes non-partage)",
				Status = status,
				Description = "FDResPub publie ce poste et ses ressources sur le réseau local via WSD (Web Services for Devices). Sur un poste qui ne partage ni imprimante ni fichier, ce service augmente inutilement la surface d'exposition réseau.",
				Recommendation = ((isAuto && isRunning) ? "Durcissement recommandé : passer FDResPub en Manuel ou Désactivé sur les postes non-partage : Set-Service FDResPub -StartupType Manual (ou Disabled)." : (isRunning ? "FDResPub est en cours d'exécution. Sur un poste non-partage, envisager de le passer en Manuel." : "Configuration conforme au durcissement : le service n'est pas démarré automatiquement.")),
				Reference = "https://learn.microsoft.com/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server"
			};
		});
	}

	// SSDPSRV — SSDP Discovery (découverte des périphériques UPnP).
	// À désactiver si UPnP n'est pas requis. Running => Info/Warning.
	private void CollectSsdpDiscovery(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			ServiceState svc = QueryService("SSDPSRV");
			if (!svc.Found)
			{
				return AbsentResult(
					"SSDPSRV (SSDP Discovery / UPnP)",
					"Le service de découverte SSDP (protocole UPnP) n'est pas présent sur ce système.",
					"https://learn.microsoft.com/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server");
			}
			bool isRunning = IsRunning(svc.State);
			bool isAuto = IsAuto(svc.StartMode);
			// SSDP est un service de découverte ; s'il tourne en Automatique => Warning, sinon Info.
			SecurityStatus status = ((isAuto && isRunning) ? SecurityStatus.Warning : (isRunning ? SecurityStatus.Info : SecurityStatus.OK));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Service SSDPSRV (SSDP Discovery / UPnP)",
				CurrentValue = svc.Display,
				ExpectedValue = "Désactivé si UPnP non requis",
				Status = status,
				Description = "SSDPSRV découvre les périphériques et services réseau utilisant le protocole SSDP (base d'UPnP). Ce protocole a historiquement servi de vecteur d'amplification (attaques DDoS) et d'exposition de services. Il est recommandé de le désactiver quand UPnP n'est pas nécessaire.",
				Recommendation = ((isAuto && isRunning) ? "Durcissement recommandé : désactiver SSDPSRV si UPnP n'est pas requis : Set-Service SSDPSRV -StartupType Disabled (désactive aussi upnphost qui en dépend)." : (isRunning ? "SSDPSRV est en cours d'exécution. Envisager de le désactiver si UPnP n'est pas nécessaire." : "Configuration conforme au durcissement : le service n'est pas démarré automatiquement.")),
				Reference = "https://learn.microsoft.com/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server"
			};
		});
	}

	// upnphost — UPnP Device Host (hébergement de périphériques UPnP).
	// Désactivé attendu ; Running => Warning (ce poste héberge des services UPnP).
	private void CollectUpnpDeviceHost(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			ServiceState svc = QueryService("upnphost");
			if (!svc.Found)
			{
				return AbsentResult(
					"upnphost (UPnP Device Host)",
					"Le service d'hébergement de périphériques UPnP n'est pas présent sur ce système.",
					"https://learn.microsoft.com/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server");
			}
			bool isRunning = IsRunning(svc.State);
			// upnphost héberge activement des services UPnP : s'il tourne => Warning.
			SecurityStatus status = (isRunning ? SecurityStatus.Warning : SecurityStatus.OK);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Service upnphost (UPnP Device Host)",
				CurrentValue = svc.Display,
				ExpectedValue = "Désactivé",
				Status = status,
				Description = "upnphost héberge des périphériques UPnP sur ce poste, exposant potentiellement des services au réseau local sans authentification. Sur un poste de travail, ce service devrait normalement être désactivé.",
				Recommendation = (isRunning ? "Durcissement recommandé : désactiver upnphost s'il n'est pas requis : Set-Service upnphost -StartupType Disabled." : "Configuration conforme au durcissement : le service UPnP Device Host n'est pas démarré."),
				Reference = "https://learn.microsoft.com/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server"
			};
		});
	}

	// Interroge WMI Win32_Service par nom de service invariant (Name), pas le DisplayName localisé.
	private static ServiceState QueryService(string serviceName)
	{
		ServiceState state = new ServiceState();
		try
		{
			// Le nom de service est un identifiant invariant : sûr à injecter (valeurs codées en dur).
			ManagementObjectSearcher searcher = new ManagementObjectSearcher(
				"SELECT State, StartMode FROM Win32_Service WHERE Name='" + serviceName + "'");
			try
			{
				foreach (ManagementObject serviceObject in searcher.Get())
				{
					ManagementObject disposableWmiObject = serviceObject;
					try
					{
						state.Found = true;
						state.State = serviceObject["State"]?.ToString() ?? "Inconnu";
						state.StartMode = serviceObject["StartMode"]?.ToString() ?? "Inconnu";
					}
					finally
					{
						((IDisposable)disposableWmiObject)?.Dispose();
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
			// En cas d'échec WMI, on laisse Found=false : traité comme « service absent ».
		}
		return state;
	}

	// Vrai si l'état WMI indique un service en cours d'exécution.
	private static bool IsRunning(string state)
	{
		return string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase);
	}

	// Vrai si le mode de démarrage WMI est Automatique.
	private static bool IsAuto(string startMode)
	{
		return string.Equals(startMode, "Auto", StringComparison.OrdinalIgnoreCase)
			|| string.Equals(startMode, "Automatic", StringComparison.OrdinalIgnoreCase);
	}

	// Résultat standard pour un service absent : Info (non-configuré / non-installé, pas un défaut).
	private SecurityResult AbsentResult(string checkName, string description, string reference)
	{
		return new SecurityResult
		{
			Category = Category,
			CheckName = checkName,
			CurrentValue = "Service absent",
			ExpectedValue = "Désactivé ou absent",
			Status = SecurityStatus.Info,
			Description = description + " Son absence réduit d'autant la surface d'attaque réseau.",
			Recommendation = "Aucune action requise : le service n'est pas installé sur ce poste.",
			Reference = reference
		};
	}

	private void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			SecurityResult result = factory();
			if (result != null)
			{
				results.Add(result);
			}
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier l'accès WMI et exécuter en tant qu'administrateur.",
				Reference = ""
			});
		}
	}
}
