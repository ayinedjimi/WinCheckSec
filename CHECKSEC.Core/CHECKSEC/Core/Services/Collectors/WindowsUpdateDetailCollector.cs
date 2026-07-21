using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services.Helpers;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class WindowsUpdateDetailCollector : ISecurityCollector
{
	private const string WuAuKey = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU";

	private const string WuPolicyKey = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate";

	private const string WuResultsInstall = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Install";

	private const string WuResultsDetect = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Detect";

	private const string WuRebootKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired";

	private const string CbsRebootKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending";

	private const string CbsPkgPending = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\PackagesPending";

	private const string PendingFileRen = "SYSTEM\\CurrentControlSet\\Control\\Session Manager";

	private const string WinNtKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

	private const string WuUxSettings = "SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings";

	private static readonly (string Version, DateTime EolDate, string Label)[] EolDates = new(string, DateTime, string)[4]
	{
		("22H2", new DateTime(2024, 10, 14), "Windows 11 22H2"),
		("23H2", new DateTime(2025, 11, 11), "Windows 11 23H2"),
		("24H2", new DateTime(2026, 10, 13), "Windows 11 24H2"),
		("21H2", new DateTime(2024, 6, 11), "Windows 10 21H2")
	};

	private static readonly DateTime Win10_22H2_Eol = new DateTime(2025, 10, 14);

	public string Name => "Windows Update";

	public string Category => "Gestion des Patchs";

	public Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		Stopwatch stopwatch = Stopwatch.StartNew();
		CollectorReport collectorReport = new CollectorReport
		{
			CollectorName = Name
		};
		try
		{
			ct.ThrowIfCancellationRequested();
			CollectUpdateServiceStatus(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectUpdateConfiguration(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectLastUpdateActivity(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectPendingReboots(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectWindowsVersionAndEol(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectUpdateHistory(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectUpdatePauseStatus(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "WindowsUpdateDetailCollector erreur fatale : " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectUpdateServiceStatus(List<SecurityResult> results, CancellationToken ct)
	{
		(string, string, bool)[] serviceDefinitions = new(string, string, bool)[3]
		{
			("wuauserv", "Windows Update Service — Service principal de mise à jour", true),
			("UsoSvc", "Update Orchestrator Service — Orchestration des mises à jour", false),
			("WaaSMedicSvc", "Windows Update Medic — Service auto-réparateur (ne peut pas être arrêté manuellement)", false)
		};
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.AppendLine("=== SERVICES WINDOWS UPDATE ===");
		stringBuilder.AppendLine();
		bool isWuauservDisabled = false;
		int stoppedCount = 0;
		(string, string, bool)[] services = serviceDefinitions;
		for (int i = 0; i < services.Length; i++)
		{
			(string, string, bool) service = services[i];
			ct.ThrowIfCancellationRequested();
			(string State, string StartMode) serviceStatus = QueryServiceWmi(service.Item1);
			string state = serviceStatus.State;
			string startMode = serviceStatus.StartMode;
			bool isRunning = state.Equals("Running", StringComparison.OrdinalIgnoreCase);
			bool isDisabled = startMode.Equals("Disabled", StringComparison.OrdinalIgnoreCase);
			string statusTag = (isRunning ? "[OK]" : (service.Item3 ? "[CRITIQUE]" : "[AVERT.]"));
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(22, 4, stringBuilder2);
			handler.AppendLiteral("  ");
			handler.AppendFormatted<string>(statusTag, -12);
			handler.AppendLiteral(" ");
			handler.AppendFormatted<string>(service.Item1, -20);
			handler.AppendLiteral(" État: ");
			handler.AppendFormatted<string>(state, -14);
			handler.AppendLiteral(" Démarrage: ");
			handler.AppendFormatted(startMode);
			stringBuilder3.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(15, 1, stringBuilder2);
			handler.AppendLiteral("             → ");
			handler.AppendFormatted(service.Item2);
			stringBuilder4.AppendLine(ref handler);
			stringBuilder.AppendLine();
			if (service.Item1 == "wuauserv" && isDisabled)
			{
				isWuauservDisabled = true;
			}
			if (!isRunning)
			{
				stoppedCount++;
			}
		}
		if (isWuauservDisabled)
		{
			stringBuilder.AppendLine("  [CRITIQUE] Le service Windows Update (wuauserv) est DÉSACTIVÉ. Les mises à jour automatiques sont impossibles !");
		}
		else if (stoppedCount > 0)
		{
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder5 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(55, 1, stringBuilder2);
			handler.AppendLiteral("  [AVERTISSEMENT] ");
			handler.AppendFormatted(stoppedCount);
			handler.AppendLiteral(" service(s) de mise à jour arrêté(s).");
			stringBuilder5.AppendLine(ref handler);
		}
		else
		{
			stringBuilder.AppendLine("  [OK] Tous les services Windows Update sont opérationnels.");
		}
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "A. Services Windows Update",
			CurrentValue = (isWuauservDisabled ? "wuauserv DÉSACTIVÉ" : $"{stoppedCount} service(s) arrêté(s)"),
			ExpectedValue = "wuauserv actif, UsoSvc actif",
			Status = (isWuauservDisabled ? SecurityStatus.Critical : ((stoppedCount > 0) ? SecurityStatus.Warning : SecurityStatus.OK)),
			Description = stringBuilder.ToString().TrimEnd(),
			Recommendation = (isWuauservDisabled ? "CRITIQUE : Activer le service Windows Update immédiatement : 'sc config wuauserv start=auto && sc start wuauserv'." : ((stoppedCount > 0) ? "Certains services de mise à jour sont arrêtés. Vérifier et redémarrer si nécessaire." : "Services Windows Update opérationnels.")),
			Reference = "https://learn.microsoft.com/windows/deployment/update/windows-update-troubleshooting",
			CollectedAt = DateTime.Now
		});
	}

	private void CollectUpdateConfiguration(List<SecurityResult> results, CancellationToken ct)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey auKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", writable: false);
			using RegistryKey policyKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate", writable: false);
			int noAutoUpdate = ((auKey != null) ? Convert.ToInt32(auKey.GetValue("NoAutoUpdate", 0)) : 0);
			int auOptions = ((auKey != null) ? Convert.ToInt32(auKey.GetValue("AUOptions", 4)) : 4);
			int noAutoRebootWithLoggedOnUsers = ((auKey != null) ? Convert.ToInt32(auKey.GetValue("NoAutoRebootWithLoggedOnUsers", 0)) : 0);
			int scheduledInstallDay = ((auKey != null) ? Convert.ToInt32(auKey.GetValue("ScheduledInstallDay", 0)) : 0);
			int scheduledInstallTime = ((auKey != null) ? Convert.ToInt32(auKey.GetValue("ScheduledInstallTime", 3)) : 3);
			int disableWuAccess = ((policyKey != null) ? Convert.ToInt32(policyKey.GetValue("DisableWindowsUpdateAccess", 0)) : 0);
			string wuServer = policyKey?.GetValue("WUServer", null)?.ToString() ?? string.Empty;
			string wuStatusServer = policyKey?.GetValue("WUStatusServer", null)?.ToString() ?? string.Empty;
			bool isAutoUpdateDisabled = noAutoUpdate == 1;
			bool isWuAccessBlocked = disableWuAccess == 1;
			bool hasWsusServer = !string.IsNullOrEmpty(wuServer);
			string auOptionsLabel = auOptions switch
			{
				2 => "2 — Notification uniquement (téléchargement et installation manuels)",
				3 => "3 — Téléchargement auto + notification pour installation",
				4 => "4 — Téléchargement et installation automatiques (RECOMMANDÉ)",
				5 => "5 — Installation planifiée",
				_ => $"{auOptions} — Valeur inconnue",
			};
			string[] dayNames = new string[8] { "Tous les jours", "Dimanche", "Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi" };
			string scheduledDayLabel = ((scheduledInstallDay >= 0 && scheduledInstallDay <= 7) ? dayNames[scheduledInstallDay] : scheduledInstallDay.ToString());
			string scheduledTimeLabel = $"{scheduledInstallTime:00}:00";
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.AppendLine("=== CONFIGURATION WINDOWS UPDATE (STRATÉGIE) ===");
			stringBuilder.AppendLine();
			stringBuilder.AppendLine("  ─── Clé AU (Mise à jour automatique) ───");
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(32, 2, stringBuilder2);
			handler.AppendLiteral("  NoAutoUpdate             : ");
			handler.AppendFormatted(noAutoUpdate);
			handler.AppendLiteral(" (");
			handler.AppendFormatted(isAutoUpdateDisabled ? "DÉSACTIVÉ ✗" : "Auto activé ✓");
			handler.AppendLiteral(")");
			stringBuilder3.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(29, 1, stringBuilder2);
			handler.AppendLiteral("  AUOptions                : ");
			handler.AppendFormatted(auOptionsLabel);
			stringBuilder4.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder5 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(32, 2, stringBuilder2);
			handler.AppendLiteral("  NoAutoRebootWithLoggedOn : ");
			handler.AppendFormatted(noAutoRebootWithLoggedOnUsers);
			handler.AppendLiteral(" (");
			handler.AppendFormatted((noAutoRebootWithLoggedOnUsers == 1) ? "Redémarrage différé (peut retarder les patchs)" : "Redémarrage auto");
			handler.AppendLiteral(")");
			stringBuilder5.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder6 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(32, 2, stringBuilder2);
			handler.AppendLiteral("  Installation planifiée   : ");
			handler.AppendFormatted(scheduledDayLabel);
			handler.AppendLiteral(" à ");
			handler.AppendFormatted(scheduledTimeLabel);
			stringBuilder6.AppendLine(ref handler);
			stringBuilder.AppendLine();
			stringBuilder.AppendLine("  ─── Clé WindowsUpdate (Stratégie globale) ───");
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder7 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(34, 2, stringBuilder2);
			handler.AppendLiteral("  DisableWindowsUpdateAccess : ");
			handler.AppendFormatted(disableWuAccess);
			handler.AppendLiteral(" (");
			handler.AppendFormatted(isWuAccessBlocked ? "ACCÈS BLOQUÉ ✗" : "Accessible ✓");
			handler.AppendLiteral(")");
			stringBuilder7.AppendLine(ref handler);
			if (hasWsusServer)
			{
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder8 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(27, 1, stringBuilder2);
				handler.AppendLiteral("  WUServer (WSUS)        : ");
				handler.AppendFormatted(wuServer);
				stringBuilder8.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder9 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(27, 1, stringBuilder2);
				handler.AppendLiteral("  WUStatusServer         : ");
				handler.AppendFormatted(wuStatusServer);
				stringBuilder9.AppendLine(ref handler);
				stringBuilder.AppendLine("  [INFO] WSUS détecté — les mises à jour passent par un serveur interne.");
			}
			else
			{
				stringBuilder.AppendLine("  WUServer               : (non configuré — mises à jour directes depuis Microsoft)");
			}
			if (noAutoRebootWithLoggedOnUsers == 1)
			{
				stringBuilder.AppendLine("\n  [AVERTISSEMENT] NoAutoRebootWithLoggedOnUsers = 1. Les redémarrages automatiques sont désactivés pour les sessions actives. Cela peut retarder l'application des patchs critiques.");
			}
			SecurityStatus status = ((isAutoUpdateDisabled || isWuAccessBlocked) ? SecurityStatus.Critical : ((noAutoRebootWithLoggedOnUsers == 1 || auOptions == 2) ? SecurityStatus.Warning : SecurityStatus.OK));
			string recommendation = (isAutoUpdateDisabled ? "CRITIQUE : Les mises à jour automatiques sont désactivées (NoAutoUpdate=1). Activer via : Paramètres > Windows Update > Options avancées, ou GPO 'Configurer les mises à jour automatiques'." : (isWuAccessBlocked ? "CRITIQUE : L'accès à Windows Update est bloqué par stratégie (DisableWindowsUpdateAccess=1). Réviser la GPO." : ((auOptions != 2) ? (hasWsusServer ? "WSUS détecté. Vérifier que le serveur WSUS est bien à jour et qu'il approuve les patchs critiques en temps opportun." : "Configuration Windows Update correcte.") : "Les mises à jour nécessitent une action manuelle (AUOptions=2). Configurer en mode 4 (auto download+install) pour les patchs critiques.")));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "B. Configuration Windows Update",
				CurrentValue = (isAutoUpdateDisabled ? "AUTO UPDATE DÉSACTIVÉ" : (isWuAccessBlocked ? "ACCÈS WU BLOQUÉ" : $"AUOptions={auOptions} | WSUS: {(hasWsusServer ? "Oui" : "Non")}")),
				ExpectedValue = "NoAutoUpdate=0, AUOptions=4, DisableWindowsUpdateAccess=0",
				Status = status,
				Description = stringBuilder.ToString().TrimEnd(),
				Recommendation = recommendation,
				Reference = "https://learn.microsoft.com/windows/deployment/update/waas-wu-settings",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CollectLastUpdateActivity(List<SecurityResult> results, CancellationToken ct)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey installKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Install", writable: false);
			using RegistryKey detectKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Detect", writable: false);
			string lastInstallText = installKey?.GetValue("LastSuccessTime", string.Empty)?.ToString() ?? string.Empty;
			string lastDetectText = detectKey?.GetValue("LastSuccessTime", string.Empty)?.ToString() ?? string.Empty;
			DateTime lastInstallDate = DateTime.MinValue;
			DateTime lastDetectDate = DateTime.MinValue;
			int installAgeDays = -1;
			int detectAgeDays = -1;
			if (!string.IsNullOrEmpty(lastInstallText) && DateTime.TryParse(lastInstallText, out var parsedInstallDate))
			{
				lastInstallDate = parsedInstallDate;
				installAgeDays = (int)(DateTime.Now - lastInstallDate).TotalDays;
			}
			if (!string.IsNullOrEmpty(lastDetectText) && DateTime.TryParse(lastDetectText, out var parsedDetectDate))
			{
				lastDetectDate = parsedDetectDate;
				detectAgeDays = (int)(DateTime.Now - lastDetectDate).TotalDays;
			}
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.AppendLine("=== DERNIÈRE ACTIVITÉ WINDOWS UPDATE ===");
			stringBuilder.AppendLine();
			stringBuilder.AppendLine("  ─── Dernière installation réussie ───");
			if (lastInstallDate != DateTime.MinValue)
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder3 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(19, 1, stringBuilder2);
				handler.AppendLiteral("  Date           : ");
				handler.AppendFormatted(lastInstallDate, "yyyy-MM-dd HH:mm:ss");
				stringBuilder3.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder4 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(27, 1, stringBuilder2);
				handler.AppendLiteral("  Âge            : ");
				handler.AppendFormatted(installAgeDays);
				handler.AppendLiteral(" jour(s)");
				stringBuilder4.AppendLine(ref handler);
			}
			else
			{
				stringBuilder.AppendLine("  Date           : Inconnue (clé de registre absente ou vide)");
			}
			stringBuilder.AppendLine();
			stringBuilder.AppendLine("  ─── Dernière vérification de mises à jour ───");
			if (lastDetectDate != DateTime.MinValue)
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder5 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(19, 1, stringBuilder2);
				handler.AppendLiteral("  Date           : ");
				handler.AppendFormatted(lastDetectDate, "yyyy-MM-dd HH:mm:ss");
				stringBuilder5.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder6 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(27, 1, stringBuilder2);
				handler.AppendLiteral("  Âge            : ");
				handler.AppendFormatted(detectAgeDays);
				handler.AppendLiteral(" jour(s)");
				stringBuilder6.AppendLine(ref handler);
			}
			else
			{
				stringBuilder.AppendLine("  Date           : Inconnue (clé de registre absente ou vide)");
			}
			stringBuilder.AppendLine();
			if (installAgeDays > 90)
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder7 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(109, 1, stringBuilder2);
				handler.AppendLiteral("  [CRITIQUE URGENT] Aucune mise à jour installée depuis ");
				handler.AppendFormatted(installAgeDays);
				handler.AppendLiteral(" jours (> 90 jours) ! La machine est très vulnérable.");
				stringBuilder7.AppendLine(ref handler);
			}
			else if (installAgeDays > 60)
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder8 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(69, 1, stringBuilder2);
				handler.AppendLiteral("  [CRITIQUE] Aucune mise à jour installée depuis ");
				handler.AppendFormatted(installAgeDays);
				handler.AppendLiteral(" jours (> 60 jours).");
				stringBuilder8.AppendLine(ref handler);
			}
			else if (installAgeDays > 30)
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder9 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(74, 1, stringBuilder2);
				handler.AppendLiteral("  [AVERTISSEMENT] Aucune mise à jour installée depuis ");
				handler.AppendFormatted(installAgeDays);
				handler.AppendLiteral(" jours (> 30 jours).");
				stringBuilder9.AppendLine(ref handler);
			}
			else if (installAgeDays >= 0)
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder10 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(52, 1, stringBuilder2);
				handler.AppendLiteral("  [OK] Dernière mise à jour installée il y a ");
				handler.AppendFormatted(installAgeDays);
				handler.AppendLiteral(" jours.");
				stringBuilder10.AppendLine(ref handler);
			}
			else
			{
				stringBuilder.AppendLine("  [INFO] Impossible de déterminer la date de dernière mise à jour.");
			}
			SecurityStatus status = ((installAgeDays < 0) ? SecurityStatus.Info : ((installAgeDays > 90) ? SecurityStatus.Critical : ((installAgeDays > 60) ? SecurityStatus.Critical : ((installAgeDays > 30) ? SecurityStatus.Warning : SecurityStatus.OK))));
			string recommendation = ((installAgeDays > 90) ? $"URGENT : Aucune mise à jour depuis {installAgeDays} jours. De nombreuses CVEs critiques ne sont pas corrigées. Appliquer les mises à jour immédiatement." : ((installAgeDays > 60) ? $"CRITIQUE : {installAgeDays} jours sans mise à jour. Appliquer les mises à jour de sécurité dès que possible." : ((installAgeDays > 30) ? $"Planifier les mises à jour Windows. {installAgeDays} jours sans patch est excessif pour un environnement sécurisé." : ((installAgeDays < 0) ? "Vérifier manuellement l'historique des mises à jour dans Paramètres > Windows Update > Afficher l'historique des mises à jour." : "Mises à jour récentes. Maintenir le cycle de patching mensuel (Patch Tuesday)."))));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "C. Dernière Activité de Mise à Jour",
				CurrentValue = ((installAgeDays >= 0) ? $"Dernière installation : {installAgeDays} jour(s)" : "Date inconnue"),
				ExpectedValue = "Installation < 30 jours",
				Status = status,
				Description = stringBuilder.ToString().TrimEnd(),
				Recommendation = recommendation,
				Reference = "https://learn.microsoft.com/windows/deployment/update/windows-update-logs",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CollectPendingReboots(List<SecurityResult> results, CancellationToken ct)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey wuRebootKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired", writable: false);
			using RegistryKey cbsRebootKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending", writable: false);
			using RegistryKey cbsPackagesKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\PackagesPending", writable: false);
			bool wuRebootRequired = wuRebootKey != null;
			bool cbsRebootPending = cbsRebootKey != null;
			bool cbsPackagesPending = cbsPackagesKey != null;
			bool pendingFileRename = false;
			using (RegistryKey sessionManagerKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Session Manager", writable: false))
			{
				if (sessionManagerKey != null)
				{
					pendingFileRename = sessionManagerKey.GetValue("PendingFileRenameOperations") != null;
				}
			}
			bool rebootPending = wuRebootRequired || cbsRebootPending || cbsPackagesPending || pendingFileRename;
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.AppendLine("=== REDÉMARRAGES EN ATTENTE ===");
			stringBuilder.AppendLine();
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(41, 1, stringBuilder2);
			handler.AppendLiteral("  WindowsUpdate\\RebootRequired         : ");
			handler.AppendFormatted(wuRebootRequired ? "OUI — Redémarrage requis pour WU" : "non");
			stringBuilder3.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(41, 1, stringBuilder2);
			handler.AppendLiteral("  CBS\\RebootPending                    : ");
			handler.AppendFormatted(cbsRebootPending ? "OUI — Composant système en attente" : "non");
			stringBuilder4.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder5 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(41, 1, stringBuilder2);
			handler.AppendLiteral("  CBS\\PackagesPending                  : ");
			handler.AppendFormatted(cbsPackagesPending ? "OUI — Packages CBS en attente" : "non");
			stringBuilder5.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder6 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(42, 1, stringBuilder2);
			handler.AppendLiteral("  PendingFileRenameOperations           : ");
			handler.AppendFormatted(pendingFileRename ? "OUI — Renommage de fichiers au prochain démarrage" : "non");
			stringBuilder6.AppendLine(ref handler);
			stringBuilder.AppendLine();
			if (rebootPending)
			{
				stringBuilder.AppendLine("  [AVERTISSEMENT] Un ou plusieurs indicateurs de redémarrage en attente sont présents.");
				stringBuilder.AppendLine("  Les patchs de sécurité ne sont PAS entièrement appliqués avant le prochain redémarrage.");
			}
			else
			{
				stringBuilder.AppendLine("  [OK] Aucun redémarrage en attente détecté.");
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "D. Redémarrages en Attente",
				CurrentValue = (rebootPending ? "Redémarrage en attente détecté" : "Aucun redémarrage en attente"),
				ExpectedValue = "Aucun redémarrage en attente",
				Status = (rebootPending ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = stringBuilder.ToString().TrimEnd(),
				Recommendation = (rebootPending ? "Planifier un redémarrage de la machine pour finaliser l'application des mises à jour de sécurité. Ne pas différer inutilement." : "Aucun redémarrage en attente."),
				Reference = "https://learn.microsoft.com/windows/deployment/update/waas-restart",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CollectWindowsVersionAndEol(List<SecurityResult> results, CancellationToken ct)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey winNtKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", writable: false);
			string? currentBuild = winNtKey?.GetValue("CurrentBuild", "?")?.ToString() ?? "?";
			string ubr = winNtKey?.GetValue("UBR", "?")?.ToString() ?? "?";
			string displayVersion = winNtKey?.GetValue("DisplayVersion", "?")?.ToString() ?? "?";
			string productName = winNtKey?.GetValue("ProductName", "?")?.ToString() ?? "?";
			string releaseId = winNtKey?.GetValue("ReleaseId", "?")?.ToString() ?? "?";
			long installDateUnix = Convert.ToInt64(winNtKey?.GetValue("InstallDate", 0L) ?? ((object)0L));
			DateTime installDate = ((installDateUnix > 0) ? DateTimeOffset.FromUnixTimeSeconds(installDateUnix).LocalDateTime : DateTime.MinValue);
			string fullBuild = currentBuild + "." + ubr;
			DateTime today = DateTime.Today;
			DateTime eolDate = DateTime.MaxValue;
			string eolLabel = "Non déterminé";
			bool isWindows10 = productName.Contains("Windows 10", StringComparison.OrdinalIgnoreCase);
			productName.Contains("Windows 11", StringComparison.OrdinalIgnoreCase);
			// Correctif M4 : Windows 10 22H2 doit utiliser sa propre date EOL (2025-10-14) et non l'entrée Windows 11 22H2 (2024-10-14)
			if (isWindows10 && displayVersion.Equals("22H2", StringComparison.OrdinalIgnoreCase))
			{
				eolDate = Win10_22H2_Eol;
				eolLabel = "Windows 10 22H2";
			}
			else
			{
				(string, DateTime, string)[] eolDates = EolDates;
				for (int i = 0; i < eolDates.Length; i++)
				{
					var (eolVersion, eolEntryDate, eolEntryLabel) = eolDates[i];
					if (displayVersion.Equals(eolVersion, StringComparison.OrdinalIgnoreCase))
					{
						eolDate = eolEntryDate;
						eolLabel = eolEntryLabel;
						break;
					}
				}
			}
			bool isEol = eolDate < today && eolDate != DateTime.MaxValue;
			int daysToEol = ((eolDate != DateTime.MaxValue) ? ((int)(eolDate - today).TotalDays) : (-1));
			bool isEolSoon = daysToEol >= 0 && daysToEol <= 90;
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.AppendLine("=== VERSION WINDOWS ET FIN DE VIE (EOL) ===");
			stringBuilder.AppendLine();
			StringBuilder stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder3 = stringBuilder2;
			StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(27, 1, stringBuilder2);
			handler.AppendLiteral("  Système d'exploitation : ");
			handler.AppendFormatted(productName);
			stringBuilder3.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(27, 1, stringBuilder2);
			handler.AppendLiteral("  Version Display        : ");
			handler.AppendFormatted(displayVersion);
			stringBuilder4.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder5 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(27, 1, stringBuilder2);
			handler.AppendLiteral("  Build complet          : ");
			handler.AppendFormatted(fullBuild);
			stringBuilder5.AppendLine(ref handler);
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder6 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(27, 1, stringBuilder2);
			handler.AppendLiteral("  ReleaseId              : ");
			handler.AppendFormatted(releaseId);
			stringBuilder6.AppendLine(ref handler);
			if (installDate != DateTime.MinValue)
			{
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder7 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(27, 1, stringBuilder2);
				handler.AppendLiteral("  Date d'installation    : ");
				handler.AppendFormatted(installDate, "yyyy-MM-dd");
				stringBuilder7.AppendLine(ref handler);
			}
			stringBuilder.AppendLine();
			stringBuilder.AppendLine("  ─── Fin de vie (EOL) ───");
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder8 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(27, 1, stringBuilder2);
			handler.AppendLiteral("  Label EOL              : ");
			handler.AppendFormatted(eolLabel);
			stringBuilder8.AppendLine(ref handler);
			if (eolDate != DateTime.MaxValue)
			{
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder9 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(27, 1, stringBuilder2);
				handler.AppendLiteral("  Date EOL               : ");
				handler.AppendFormatted(eolDate, "yyyy-MM-dd");
				stringBuilder9.AppendLine(ref handler);
				if (isEol)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder10 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(109, 1, stringBuilder2);
					handler.AppendLiteral("  Statut EOL             : [CRITIQUE] DÉPASSÉE depuis ");
					handler.AppendFormatted(-daysToEol);
					handler.AppendLiteral(" jour(s) — Plus de mises à jour de sécurité Microsoft !");
					stringBuilder10.AppendLine(ref handler);
				}
				else if (isEolSoon)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder11 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(86, 1, stringBuilder2);
					handler.AppendLiteral("  Statut EOL             : [AVERTISSEMENT] Dans ");
					handler.AppendFormatted(daysToEol);
					handler.AppendLiteral(" jour(s) — Planifier la mise à niveau.");
					stringBuilder11.AppendLine(ref handler);
				}
				else
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder12 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(46, 1, stringBuilder2);
					handler.AppendLiteral("  Statut EOL             : [OK] Dans ");
					handler.AppendFormatted(daysToEol);
					handler.AppendLiteral(" jour(s).");
					stringBuilder12.AppendLine(ref handler);
				}
			}
			else
			{
				stringBuilder.AppendLine("  Date EOL               : Non déterminée pour cette version.");
			}
			SecurityStatus status = (isEol ? SecurityStatus.Critical : (isEolSoon ? SecurityStatus.Warning : ((eolDate == DateTime.MaxValue) ? SecurityStatus.Info : SecurityStatus.OK)));
			string recommendation = (isEol ? ($"CRITIQUE : {eolLabel} a atteint sa fin de vie le {eolDate:yyyy-MM-dd}. " + "Plus aucune mise à jour de sécurité n'est publiée par Microsoft. Mettre à niveau vers une version supportée immédiatement.") : ((!isEolSoon) ? $"Version {displayVersion} actuellement supportée jusqu'au {eolDate:yyyy-MM-dd}. Planifier la mise à niveau avant l'EOL." : $"La version {eolLabel} atteindra sa fin de vie dans {daysToEol} jours ({eolDate:yyyy-MM-dd}). Planifier la mise à niveau."));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "E. Version Windows et EOL",
				CurrentValue = $"{productName} {displayVersion} (Build {fullBuild})",
				ExpectedValue = "Version Windows actuellement supportée",
				Status = status,
				Description = stringBuilder.ToString().TrimEnd(),
				Recommendation = recommendation,
				Reference = "https://learn.microsoft.com/windows/release-health/release-information",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CollectUpdateHistory(List<SecurityResult> results, CancellationToken ct)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			List<(string, string, string)> updateEntries = new List<(string, string, string)>();
			DateTime latestDate = DateTime.MinValue;
			try
			{
				ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(WmiHelper.GetScope(), new ObjectQuery("SELECT HotFixID, InstalledOn, Description, FixComments FROM Win32_QuickFixEngineering"));
				try
				{
					List<(string, DateTime, string, string)> hotfixes = new List<(string, DateTime, string, string)>();
					using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
					foreach (ManagementObject hotfixObject in managementObjectCollection)
					{
						ManagementObject managementObject2 = hotfixObject;
						try
						{
							ct.ThrowIfCancellationRequested();
							string hotFixId = hotfixObject["HotFixID"]?.ToString() ?? "?";
							string description = hotfixObject["Description"]?.ToString() ?? string.Empty;
							string installedOnText = hotfixObject["InstalledOn"]?.ToString() ?? string.Empty;
							DateTime installedOnDate = DateTime.MinValue;
							if (!string.IsNullOrEmpty(installedOnText) && !DateTime.TryParse(installedOnText, CultureInfo.InvariantCulture, DateTimeStyles.None, out installedOnDate))
							{
								DateTime.TryParse(installedOnText, out installedOnDate);
							}
							hotfixes.Add((hotFixId, installedOnDate, installedOnText, description));
						}
						finally
						{
							((IDisposable)managementObject2)?.Dispose();
						}
					}
					foreach (var recentHotfix in hotfixes.OrderByDescending<(string, DateTime, string, string), DateTime>(((string HotFixId, DateTime Date, string InstalledOn, string Description) hotfix) => hotfix.Date).Take(20).ToList())
					{
						updateEntries.Add((recentHotfix.Item1, recentHotfix.Item3, recentHotfix.Item4));
						if (recentHotfix.Item2 != DateTime.MinValue && recentHotfix.Item2 > latestDate)
						{
							latestDate = recentHotfix.Item2;
						}
					}
				}
				finally
				{
					((IDisposable)managementObjectSearcher)?.Dispose();
				}
			}
			catch (Exception ex)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "F. Historique des Mises à Jour (KBs)",
					CurrentValue = "Erreur WMI",
					Status = SecurityStatus.Error,
					Description = "Erreur lors de la lecture de Win32_QuickFixEngineering : " + ex.Message,
					Recommendation = "Vérifier les permissions WMI.",
					Reference = ""
				};
			}
			int latestAgeDays = ((latestDate != DateTime.MinValue) ? ((int)(DateTime.Now - latestDate).TotalDays) : (-1));
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.AppendLine("=== HISTORIQUE DES MISES À JOUR RÉCENTES (20 DERNIÈRES) ===");
			stringBuilder.AppendLine();
			if (updateEntries.Count == 0)
			{
				stringBuilder.AppendLine("  Aucun KB trouvé via Win32_QuickFixEngineering.");
				stringBuilder.AppendLine("  Note : Les mises à jour Windows 10/11 modernes peuvent ne pas apparaître ici.");
				stringBuilder.AppendLine("  Vérifier via : Paramètres > Windows Update > Afficher l'historique des mises à jour.");
			}
			else
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder3 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(15, 2, stringBuilder2);
				handler.AppendLiteral("  ");
				handler.AppendFormatted<string>("KB / HotFix", -18);
				handler.AppendLiteral(" ");
				handler.AppendFormatted<string>("Date", -14);
				handler.AppendLiteral(" Description");
				stringBuilder3.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder4 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(37, 2, stringBuilder2);
				handler.AppendLiteral("  ");
				handler.AppendFormatted<string>("─────────────────", -18);
				handler.AppendLiteral(" ");
				handler.AppendFormatted<string>("──────────────", -14);
				handler.AppendLiteral(" ─────────────────────────────────");
				stringBuilder4.AppendLine(ref handler);
				foreach (var entry in updateEntries)
				{
					string kbId = entry.Item1;
					string dateText = entry.Item2;
					string descriptionText = entry.Item3;
					string descriptionDisplay = (string.IsNullOrEmpty(descriptionText) ? "(aucune description)" : descriptionText);
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder5 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(4, 3, stringBuilder2);
					handler.AppendLiteral("  ");
					handler.AppendFormatted<string>(kbId, -18);
					handler.AppendLiteral(" ");
					handler.AppendFormatted<string>(dateText, -14);
					handler.AppendLiteral(" ");
					handler.AppendFormatted(descriptionDisplay);
					stringBuilder5.AppendLine(ref handler);
				}
				stringBuilder.AppendLine();
				if (latestAgeDays > 30)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder6 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(60, 1, stringBuilder2);
					handler.AppendLiteral("  [CRITIQUE] Dernier KB installé il y a ");
					handler.AppendFormatted(latestAgeDays);
					handler.AppendLiteral(" jours (> 30 jours).");
					stringBuilder6.AppendLine(ref handler);
				}
				else if (latestAgeDays >= 0)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder7 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(41, 1, stringBuilder2);
					handler.AppendLiteral("  [OK] Dernier KB installé il y a ");
					handler.AppendFormatted(latestAgeDays);
					handler.AppendLiteral(" jours.");
					stringBuilder7.AppendLine(ref handler);
				}
			}
			SecurityStatus status = ((updateEntries.Count == 0 || latestAgeDays > 30) ? SecurityStatus.Critical : ((latestAgeDays > 14) ? SecurityStatus.Warning : SecurityStatus.OK));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "F. Historique des Mises à Jour (KBs)",
				CurrentValue = ((updateEntries.Count > 0) ? $"{updateEntries.Count} KB(s) trouvé(s) | Dernier : {latestAgeDays} jour(s)" : "Aucun KB détecté"),
				ExpectedValue = "Au moins 1 KB installé dans les 30 derniers jours",
				Status = status,
				Description = stringBuilder.ToString().TrimEnd(),
				Recommendation = ((updateEntries.Count == 0) ? "Aucun KB détecté. Vérifier l'historique des mises à jour dans les Paramètres Windows et s'assurer que les patchs mensuels sont installés." : ((latestAgeDays > 30) ? $"Dernier KB installé il y a {latestAgeDays} jours. Appliquer les mises à jour de sécurité (Patch Tuesday) immédiatement." : "Historique de patchs à jour.")),
				Reference = "https://support.microsoft.com/topic/windows-update-history",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CollectUpdatePauseStatus(List<SecurityResult> results, CancellationToken ct)
	{
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey uxSettingsKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings", writable: false);
			string featurePauseText = uxSettingsKey?.GetValue("PauseFeatureUpdatesStartTime", null)?.ToString() ?? string.Empty;
			string qualityPauseText = uxSettingsKey?.GetValue("PauseQualityUpdatesStartTime", null)?.ToString() ?? string.Empty;
			DateTime featurePauseDate = DateTime.MinValue;
			DateTime qualityPauseDate = DateTime.MinValue;
			int featurePauseDays = -1;
			int qualityPauseDays = -1;
			if (!string.IsNullOrEmpty(featurePauseText) && DateTime.TryParse(featurePauseText, out var parsedFeatureDate))
			{
				featurePauseDate = parsedFeatureDate;
				featurePauseDays = (int)(DateTime.Now - featurePauseDate).TotalDays;
			}
			if (!string.IsNullOrEmpty(qualityPauseText) && DateTime.TryParse(qualityPauseText, out var parsedQualityDate))
			{
				qualityPauseDate = parsedQualityDate;
				qualityPauseDays = (int)(DateTime.Now - qualityPauseDate).TotalDays;
			}
			bool isFeaturePaused = featurePauseDays >= 0;
			bool isQualityPaused = qualityPauseDays >= 0;
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.AppendLine("=== PAUSES DES MISES À JOUR WINDOWS ===");
			stringBuilder.AppendLine();
			stringBuilder.AppendLine("  ─── Mises à jour de qualité (patchs de sécurité) ───");
			if (isQualityPaused)
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder3 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(43, 2, stringBuilder2);
				handler.AppendLiteral("  État           : PAUSÉES depuis ");
				handler.AppendFormatted(qualityPauseDate, "yyyy-MM-dd");
				handler.AppendLiteral(" (");
				handler.AppendFormatted(qualityPauseDays);
				handler.AppendLiteral(" jours)");
				stringBuilder3.AppendLine(ref handler);
				if (qualityPauseDays > 30)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder4 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(95, 1, stringBuilder2);
					handler.AppendLiteral("  [CRITIQUE] Mises à jour de qualité pausées depuis ");
					handler.AppendFormatted(qualityPauseDays);
					handler.AppendLiteral(" jours — Patchs de sécurité NON appliqués !");
					stringBuilder4.AppendLine(ref handler);
				}
				else if (qualityPauseDays > 7)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder5 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(64, 1, stringBuilder2);
					handler.AppendLiteral("  [AVERTISSEMENT] Mises à jour de qualité pausées depuis ");
					handler.AppendFormatted(qualityPauseDays);
					handler.AppendLiteral(" jours.");
					stringBuilder5.AppendLine(ref handler);
				}
			}
			else
			{
				stringBuilder.AppendLine("  État           : Actives (non pausées)");
			}
			stringBuilder.AppendLine();
			stringBuilder.AppendLine("  ─── Mises à jour de fonctionnalités (Feature Updates) ───");
			if (isFeaturePaused)
			{
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder6 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(43, 2, stringBuilder2);
				handler.AppendLiteral("  État           : PAUSÉES depuis ");
				handler.AppendFormatted(featurePauseDate, "yyyy-MM-dd");
				handler.AppendLiteral(" (");
				handler.AppendFormatted(featurePauseDays);
				handler.AppendLiteral(" jours)");
				stringBuilder6.AppendLine(ref handler);
				if (featurePauseDays > 60)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder7 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(85, 1, stringBuilder2);
					handler.AppendLiteral("  [AVERTISSEMENT] Mises à jour de fonctionnalités pausées depuis ");
					handler.AppendFormatted(featurePauseDays);
					handler.AppendLiteral(" jours (> 60 jours).");
					stringBuilder7.AppendLine(ref handler);
				}
			}
			else
			{
				stringBuilder.AppendLine("  État           : Actives (non pausées)");
			}
			SecurityStatus status = ((isQualityPaused && qualityPauseDays > 30) ? SecurityStatus.Critical : ((isQualityPaused && qualityPauseDays > 7) ? SecurityStatus.Warning : ((isFeaturePaused && featurePauseDays > 60) ? SecurityStatus.Warning : ((isQualityPaused || isFeaturePaused) ? SecurityStatus.Info : SecurityStatus.OK))));
			string currentValue;
			if (!isQualityPaused && !isFeaturePaused)
			{
				currentValue = "Aucune pause active";
			}
			else
			{
				List<string> pauseParts = new List<string>();
				if (isQualityPaused)
				{
					pauseParts.Add($"Qualité pausée {qualityPauseDays}j");
				}
				if (isFeaturePaused)
				{
					pauseParts.Add($"Fonctionnalités pausées {featurePauseDays}j");
				}
				currentValue = string.Join(" | ", pauseParts);
			}
			string recommendation = ((isQualityPaused && qualityPauseDays > 30) ? $"CRITIQUE : Les mises à jour de sécurité (qualité) sont pausées depuis {qualityPauseDays} jours. Reprendre immédiatement dans Paramètres > Windows Update." : (isQualityPaused ? $"Les mises à jour de qualité sont pausées depuis {qualityPauseDays} jours. Reprendre pour recevoir les patchs de sécurité." : ((!isFeaturePaused || featurePauseDays <= 60) ? "Aucune pause problématique détectée sur les mises à jour Windows." : $"Les mises à jour de fonctionnalités sont pausées depuis {featurePauseDays} jours. Envisager de reprendre pour rester sur une version supportée.")));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "G. Pauses des Mises à Jour",
				CurrentValue = currentValue,
				ExpectedValue = "Aucune pause > 7 jours pour les mises à jour de qualité",
				Status = status,
				Description = stringBuilder.ToString().TrimEnd(),
				Recommendation = recommendation,
				Reference = "https://learn.microsoft.com/windows/deployment/update/waas-configure-wufb",
				CollectedAt = DateTime.Now
			};
		});
	}

	private static (string State, string StartMode) QueryServiceWmi(string serviceName)
	{
		try
		{
			ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(WmiHelper.GetScope(), new ObjectQuery("SELECT State, StartMode FROM Win32_Service WHERE Name='" + serviceName + "'"));
			try
			{
				using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
				using (ManagementObjectCollection.ManagementObjectEnumerator managementObjectEnumerator = managementObjectCollection.GetEnumerator())
				{
					if (managementObjectEnumerator.MoveNext())
					{
						ManagementObject managementObject = (ManagementObject)managementObjectEnumerator.Current;
						ManagementObject managementObject2 = managementObject;
						try
						{
							string? state = managementObject["State"]?.ToString() ?? "Unknown";
							string startMode = managementObject["StartMode"]?.ToString() ?? "Unknown";
							return (State: state, StartMode: startMode);
						}
						finally
						{
							((IDisposable)managementObject2)?.Dispose();
						}
					}
				}
				return (State: "Not Found", StartMode: "N/A");
			}
			finally
			{
				((IDisposable)managementObjectSearcher)?.Dispose();
			}
		}
		catch (ManagementException)
		{
			return (State: "Erreur WMI", StartMode: "N/A");
		}
		catch (Exception)
		{
			return (State: "Erreur WMI", StartMode: "N/A");
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
				Category = "Gestion des Patchs",
				CheckName = "Erreur de vérification",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Vérification Windows Update échouée : " + ex.Message,
				Recommendation = "Vérifier les accès WMI et registre (exécuter en tant qu'administrateur).",
				Reference = ""
			});
		}
	}
}
