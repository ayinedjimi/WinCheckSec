using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services;
using CHECKSEC.Core.Services.Analysis;
using CHECKSEC.Core.Services.Collectors;
using EventLogEntry = CHECKSEC.Core.Models.EventLogEntry;

namespace CHECKSEC.Services;

public sealed class AnalysisService
{
	private CancellationTokenSource? _cts;

	private readonly SettingsService _settings;

	private readonly object _runLock = new object();

	public List<CollectorReport> Reports { get; private set; } = new List<CollectorReport>();

	public List<ComplianceGap> Gaps { get; private set; } = new List<ComplianceGap>();

	public List<SecurityResult> AllResults { get; private set; } = new List<SecurityResult>();

	public List<CisBenchmarkItem> CisItems { get; private set; } = new List<CisBenchmarkItem>();

	public List<SecurityScore> CategoryScores { get; private set; } = new List<SecurityScore>();

	public List<SecureCoreItem> SecureCoreItems { get; private set; } = new List<SecureCoreItem>();

	public List<EventLogEntry> EventLogEntries { get; private set; } = new List<EventLogEntry>();

	public string ResultText { get; private set; } = string.Empty;

	public string EventLogText { get; private set; } = string.Empty;

	public double GlobalScore { get; private set; }

	public string GlobalGrade { get; private set; } = "—";

	public int TotalOK { get; private set; }

	public int TotalWarning { get; private set; }

	public int TotalCritical { get; private set; }

	public int TotalError { get; private set; }

	public bool IsRunning { get; private set; }

	public DateTimeOffset? AnalysisStartUtc { get; private set; }

	public DateTimeOffset? AnalysisEndUtc { get; private set; }

	public TimeSpan AnalysisDuration { get; private set; }

	public event Action<int, int, string>? ProgressChanged;

	public event Action<CollectorReport>? CollectorCompleted;

	public AnalysisService(SettingsService settings)
	{
		_settings = settings;
	}

	public void Cancel()
	{
		CancellationTokenSource cts;
		lock (_runLock)
		{
			cts = _cts;
		}
		try
		{
			cts?.Cancel();
		}
		catch (ObjectDisposedException)
		{
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Warning, "[Cancel] " + ex.Message, ex);
		}
	}

	public async Task RunAsync()
	{
		lock (_runLock)
		{
			if (IsRunning)
			{
				return;
			}
			IsRunning = true;
		}
		Reports.Clear();
		Gaps.Clear();
		AllResults.Clear();
		lock (_runLock)
		{
			_cts?.Dispose();
			_cts = new CancellationTokenSource(TimeSpan.FromMinutes(_settings.Current.AnalysisTimeoutMinutes));
		}
		CancellationToken ct;
		lock (_runLock)
		{
			ct = _cts.Token;
		}
		AnalysisStartUtc = DateTimeOffset.UtcNow;
		try
		{
			this.ProgressChanged?.Invoke(0, 1, "Initialisation des collecteurs…");
			List<ISecurityCollector> collectors = BuildCollectors();
			int total = collectors.Count + 2;
			int done = 0;
			this.ProgressChanged?.Invoke(done, total, "Analyse MSCT Toolkit (350+ policies)…");
			List<ComplianceGap> complianceGaps;
			try
			{
				List<BaselinePolicy> policies = await new MsctToolkitParser(_settings.Current.MsctToolkitPath).ParseAsync(ct);
				complianceGaps = new GapAnalyzer().Analyze(policies, ct);
			}
			catch (Exception ex)
			{
				complianceGaps = new List<ComplianceGap>();
				ErrorLogger.AddError("[MSCT] " + ex.Message);
			}
			Interlocked.Increment(ref done);
			this.ProgressChanged?.Invoke(done, total, "Analyse des écarts de conformité…");
			Gaps.AddRange(complianceGaps);
			Interlocked.Increment(ref done);
			this.ProgressChanged?.Invoke(done, total, $"Collecte en cours — 0/{collectors.Count} modules…");
			int completedCount = 0;
			object lockObj = new object();
			await Task.WhenAll(collectors.Select((ISecurityCollector c) => Task.Run(async delegate
			{
				using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
				// H1 : 120 s par collecteur (au lieu de 30 s). Les collecteurs s'exécutent en
				// parallèle, donc la borne réelle reste le timeout global d'analyse ; 30 s coupait
				// des collecteurs légitimement lourds (EventLog, SoftwareInventory, WiFi/netsh, AutoRuns).
				timeoutCts.CancelAfter(TimeSpan.FromSeconds(120L));
				CollectorReport collectorReport;
				try
				{
					collectorReport = await RunCollectorSafeAsync(c, timeoutCts.Token);
				}
				catch (OperationCanceledException)
				{
					collectorReport = new CollectorReport
					{
						CollectorName = c.Name,
						ErrorMessage = (ct.IsCancellationRequested ? "Annulé par l'utilisateur." : "Temps d'exécution dépassé (Timeout 30s).")
					};
				}
				catch (Exception ex)
				{
					collectorReport = new CollectorReport
					{
						CollectorName = c.Name,
						ErrorMessage = ex.Message
					};
				}
				lock (lockObj)
				{
					Reports.Add(collectorReport);
				}
				int completed = Interlocked.Increment(ref completedCount);
				int currentDone = Interlocked.Increment(ref done);
				string statusMessage = (collectorReport.Success ? $"✓ {collectorReport.CollectorName} — {completed}/{collectors.Count}" : $"✗ {collectorReport.CollectorName} — {completed}/{collectors.Count}");
				this.ProgressChanged?.Invoke(currentDone, total, statusMessage);
				this.CollectorCompleted?.Invoke(collectorReport);
				return collectorReport;
			}, ct)).ToArray());
			this.ProgressChanged?.Invoke(total, total, "Compilation des résultats…");
			// Correctif B4 : ordre déterministe (tri stable par CollectorName) pour des tuiles reproductibles
			AllResults = Reports.OrderBy((CollectorReport r) => r.CollectorName, StringComparer.Ordinal).SelectMany((CollectorReport r) => r.Results).ToList();
			int okCount = 0;
			int warningCount = 0;
			int criticalCount = 0;
			int errorCount = 0;
			using (List<SecurityResult>.Enumerator enumerator = AllResults.GetEnumerator())
			{
				while (enumerator.MoveNext())
				{
					switch (enumerator.Current.Status)
					{
					case SecurityStatus.OK:
						okCount++;
						break;
					case SecurityStatus.Warning:
						warningCount++;
						break;
					case SecurityStatus.Critical:
						criticalCount++;
						break;
					case SecurityStatus.Error:
						errorCount++;
						break;
					}
				}
			}
			TotalOK = okCount;
			TotalWarning = warningCount;
			TotalCritical = criticalCount;
			TotalError = errorCount;
			CisBenchmarkMapper cisBenchmarkMapper = new CisBenchmarkMapper();
			CisItems = cisBenchmarkMapper.MapResults(AllResults);
			ResultText = FormatResults(Reports);
			EventLogText = FormatEventLogs(Reports);
			EventLogEntries = CollectWindowsEventErrors(ct);
			List<ComplianceGap> gaps = Gaps.OrderByDescending((ComplianceGap g) => g.Severity).ToList();
			Gaps = gaps;
			ComputeSecureCore(AllResults);
			ComputeCategoryScores(AllResults);
			int totalChecks = TotalOK + TotalWarning + TotalCritical + TotalError;
			this.ProgressChanged?.Invoke(total, total, $"✓ Analyse terminée — {totalChecks} vérifications — {TotalOK} OK  {TotalWarning} AVERT.  {TotalCritical} CRITIQUES  {TotalError} ERREURS");
		}
		catch (OperationCanceledException)
		{
			this.ProgressChanged?.Invoke(0, 1, "Analyse annulée.");
		}
		catch (Exception ex)
		{
			this.ProgressChanged?.Invoke(0, 1, "Erreur : " + ex.Message);
			ErrorLogger.AddError($"[RunAnalysis] {ex}");
		}
		finally
		{
			AnalysisEndUtc = DateTimeOffset.UtcNow;
			AnalysisDuration = (AnalysisEndUtc - AnalysisStartUtc) ?? TimeSpan.Zero;
			lock (_runLock)
			{
				IsRunning = false;
				_cts?.Dispose();
				_cts = null;
			}
		}
	}

	private static List<ISecurityCollector> BuildCollectors()
	{
		List<ISecurityCollector> collectors = new List<ISecurityCollector>(40);
		TryAdd<SystemInfoCollector>(collectors);
		TryAdd<VbsSecurityCollector>(collectors);
		TryAdd<DefenderCollector>(collectors);
		TryAdd<SecurityCenterCollector>(collectors);
		TryAdd<FirewallCollector>(collectors);
		TryAdd<BitLockerCollector>(collectors);
		TryAdd<AppControlCollector>(collectors);
		TryAdd<NetworkSecCollector>(collectors);
		TryAdd<EventLogCollector>(collectors);
		TryAdd<AuditPolicyCollector>(collectors);
		TryAdd<UserAccountsCollector>(collectors);
		TryAdd<TlsCollector>(collectors);
		TryAdd<AdditionalSecurityCollector>(collectors);
		TryAdd<AutoRunsCollector>(collectors);
		TryAdd<ProcessDriverCollector>(collectors);
		TryAdd<NetworkSharesCollector>(collectors);
		TryAdd<ScreenLockCollector>(collectors);
		TryAdd<OfficeMacroCollector>(collectors);
		TryAdd<SoftwareInventoryCollector>(collectors);
		TryAdd<KerberosCollector>(collectors);
		TryAdd<EventLogExtendedCollector>(collectors);
		TryAdd<MdeCollector>(collectors);
		TryAdd<WindowsUpdateDetailCollector>(collectors);
		TryAdd<CertificateCollector>(collectors);
		TryAdd<AzureAdCollector>(collectors);
		TryAdd<HardeningCollector>(collectors);
		TryAdd<AsrRulesCollector>(collectors);
		TryAdd<LapsCollector>(collectors);
		TryAdd<DnsOverHttpsCollector>(collectors);
		TryAdd<SmbHardeningCollector>(collectors);
		TryAdd<PrintSpoolerCollector>(collectors);
		TryAdd<WDigestCollector>(collectors);
		TryAdd<LsaProtectionCollector>(collectors);
		TryAdd<ExploitProtectionCollector>(collectors);
		TryAdd<RdpHardeningCollector>(collectors);
		TryAdd<CisFallbackCollector>(collectors);
		TryAdd<UacDetailCollector>(collectors);
		TryAdd<CredentialDelegationCollector>(collectors);
		TryAdd<WindowsSandboxCollector>(collectors);
		TryAdd<BluetoothCollector>(collectors);
		TryAdd<WifiSecurityCollector>(collectors);
		TryAdd<SecureBootPolicyCollector>(collectors);
		TryAdd<BrowserHardeningCollector>(collectors);
		TryAdd<SystemHardeningExtraCollector>(collectors);
		TryAdd<RemoteAccessExtraCollector>(collectors);
		TryAdd<LocalGroupCollector>(collectors);
		TryAdd<LogConfigCollector>(collectors);
		TryAdd<NetworkServicesHardeningCollector>(collectors);
		TryAdd<DomainAuthHardeningCollector>(collectors);
		// Vague 1 — nouveaux collecteurs (roadmap communautaire)
		TryAdd<AmsiCollector>(collectors);
		TryAdd<ProxyNetworkCollector>(collectors);
		TryAdd<UserRightsCollector>(collectors);
		TryAdd<WindowsLapsCollector>(collectors);
		TryAdd<ModernWindowsFeaturesCollector>(collectors);
		TryAdd<AdvancedPersistenceCollector>(collectors);
		TryAdd<DefenderExclusionsCollector>(collectors);
		TryAdd<FileSystemAclCollector>(collectors);
		TryAdd<BootIntegrityCollector>(collectors);
		TryAdd<SchannelCryptoCollector>(collectors);
		return collectors;
	}

	private static void TryAdd<T>(List<ISecurityCollector> list) where T : ISecurityCollector, new()
	{
		try
		{
			list.Add(new T());
		}
		catch (Exception ex)
		{
			ErrorLogger.AddError("[Factory:" + typeof(T).Name + "] " + ex.Message);
		}
	}

	private static async Task<CollectorReport> RunCollectorSafeAsync(ISecurityCollector collector, CancellationToken ct)
	{
		Stopwatch sw = Stopwatch.StartNew();
		try
		{
			CollectorReport report = await collector.CollectAsync(ct);
			report.Duration = sw.Elapsed;
			return report;
		}
		catch (Exception ex)
		{
			return new CollectorReport
			{
				CollectorName = collector.Name,
				ErrorMessage = ex.Message,
				Duration = sw.Elapsed,
				Results = new List<SecurityResult>
				{
					new SecurityResult
					{
						Category = collector.Category,
						CheckName = collector.Name,
						Status = SecurityStatus.Error,
						Description = "Le collecteur a rencontré une erreur : " + ex.Message,
						CurrentValue = ex.GetType().Name
					}
				}
			};
		}
	}

	private void ComputeSecureCore(List<SecurityResult> results)
	{
		SecureCoreItems = new List<SecureCoreItem>(6);
		(SecurityStatus, string) tpmInfo = Find("TPM");
		SecureCoreItems.Add(new SecureCoreItem
		{
			Name = "TPM",
			Icon = "\ue72e",
			Status = tpmInfo.Item1,
			Value = tpmInfo.Item2,
			TechnicalDescription = "Le TPM (Trusted Platform Module) est un processeur cryptographique matériel dédié qui fournit des fonctions de sécurité. Il stocke clés de chiffrement, certificats et mots de passe. TPM 2.0 est requis pour Windows 11 et active BitLocker, Windows Hello, Measured Boot et l'attestation d'intégrité.",
			Impact = "Sans TPM, BitLocker utilise un chiffrement logiciel moins sécurisé, Windows Hello biométrique est indisponible, et l'attestation d'intégrité au démarrage est impossible.",
			Remediation = "1. Vérifiez la présence du TPM : tpm.msc\n2. Activez le TPM dans le BIOS/UEFI (Security > TPM Device)\n3. Si TPM 1.2 : mise à jour firmware vers TPM 2.0\n4. PowerShell : Get-Tpm | Format-List",
			Reference = "https://learn.microsoft.com/windows/security/hardware-security/tpm/tpm-recommendations"
		});
		(SecurityStatus, string) secureBootInfo = Find("Secure Boot");
		SecureCoreItems.Add(new SecureCoreItem
		{
			Name = "Secure Boot",
			Icon = "\ue785",
			Status = secureBootInfo.Item1,
			Value = secureBootInfo.Item2,
			TechnicalDescription = "Secure Boot est une fonctionnalité UEFI qui vérifie la signature numérique de chaque composant chargé au démarrage (bootloader, pilotes, OS). Empêche l'exécution de bootkits et rootkits UEFI.",
			Impact = "Sans Secure Boot, le système est vulnérable aux bootkits/rootkits qui s'exécutent avant l'OS et sont indétectables par les antivirus.",
			Remediation = "1. Accédez au BIOS/UEFI (F2/Del au démarrage)\n2. Section Security/Boot : activez Secure Boot\n3. Mode UEFI requis (pas Legacy/CSM)\n4. Vérification : Confirm-SecureBootUEFI",
			Reference = "https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-secure-boot"
		});
		(SecurityStatus, string) vbsInfo = Find("VBS");
		SecureCoreItems.Add(new SecureCoreItem
		{
			Name = "VBS",
			Icon = "\ue890",
			Status = vbsInfo.Item1,
			Value = vbsInfo.Item2,
			TechnicalDescription = "VBS (Virtualization-Based Security) utilise l'hyperviseur Windows pour créer un environnement mémoire isolé (Virtual Secure Mode). Le noyau normal ne peut pas accéder à cette zone, protégeant secrets cryptographiques et intégrité du code.",
			Impact = "Sans VBS, les secrets en mémoire (tokens NTLM, Kerberos TGT) sont accessibles par des attaques kernel-level type Mimikatz.",
			Remediation = "1. Prérequis : UEFI, Secure Boot, CPU avec SLAT\n2. Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Hypervisor\n3. GPO : Configuration ordinateur > Modèles d'administration > Système > Device Guard\n4. Reg : HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity = 1",
			Reference = "https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity"
		});
		(SecurityStatus, string) credGuardInfo = Find("Credential Guard");
		SecureCoreItems.Add(new SecureCoreItem
		{
			Name = "Credential Guard",
			Icon = "\ue8d7",
			Status = credGuardInfo.Item1,
			Value = credGuardInfo.Item2,
			TechnicalDescription = "Credential Guard utilise VBS pour isoler les dérivés de mots de passe (NTLM hashes, Kerberos TGT/TGS) dans un processus LSA isolé (LsaIso.exe). Même un attaquant SYSTEM ne peut pas extraire ces secrets.",
			Impact = "Sans Credential Guard, un attaquant admin peut utiliser Mimikatz pour extraire hashes NTLM et tickets Kerberos, permettant pass-the-hash et pass-the-ticket.",
			Remediation = "1. Prérequis : VBS activé, UEFI Secure Boot, TPM 2.0\n2. GPO : Configuration ordinateur > Modèles d'administration > Système > Device Guard > Credential Guard : Activé avec verrouillage UEFI\n3. Reg : HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LsaCfgFlags = 1\n4. Vérif : msinfo32 > Services de sécurité basés sur la virtualisation",
			Reference = "https://learn.microsoft.com/windows/security/identity-protection/credential-guard"
		});
		(SecurityStatus, string) hvciInfo = Find("HVCI");
		SecureCoreItems.Add(new SecureCoreItem
		{
			Name = "HVCI",
			Icon = "\ue835",
			Status = hvciInfo.Item1,
			Value = hvciInfo.Item2,
			TechnicalDescription = "HVCI (Hypervisor-protected Code Integrity / Memory Integrity) utilise l'hyperviseur pour vérifier chaque page de code chargée dans le noyau. Seul le code signé et vérifié peut s'exécuter en mode noyau.",
			Impact = "Sans HVCI, des pilotes non signés ou malveillants peuvent être chargés dans le noyau, permettant élévation de privilèges et persistance.",
			Remediation = "1. Prérequis : VBS activé\n2. Paramètres > Sécurité de l'appareil > Isolation du noyau > Intégrité de la mémoire : Activé\n3. Reg : HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled = 1\n4. Attention : certains anciens pilotes incompatibles",
			Reference = "https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity"
		});
		(SecurityStatus, string) dmaInfo = Find("DMA Protection");
		SecureCoreItems.Add(new SecureCoreItem
		{
			Name = "DMA Protection",
			Icon = "\ue83d",
			Status = dmaInfo.Item1,
			Value = dmaInfo.Item2,
			TechnicalDescription = "La protection DMA (Kernel DMA Protection) empêche les attaques DMA drive-by via Thunderbolt/USB4/PCIe externes. Utilise l'IOMMU pour isoler les périphériques et bloquer l'accès mémoire non autorisé.",
			Impact = "Sans protection DMA, un périphérique malveillant Thunderbolt peut lire/écrire directement la mémoire, contournant toutes les protections (BitLocker, login).",
			Remediation = "1. Prérequis : BIOS avec support IOMMU (Intel VT-d / AMD-Vi)\n2. Activez VT-d/AMD-Vi dans le BIOS\n3. GPO : Configuration ordinateur > Modèles d'administration > Système > Protection DMA du noyau\n4. Vérif : msinfo32 > Protection DMA du noyau",
			Reference = "https://learn.microsoft.com/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt"
		});
		(SecurityStatus status, string value) Find(string sub)
		{
			// Correctif B4 : privilégier la ligne "running" (WMI/Running) plutôt que la ligne registre (configuré)
			SecurityResult securityResult = results.FirstOrDefault((SecurityResult r) => r.CheckName.Contains(sub, StringComparison.OrdinalIgnoreCase) && (r.CheckName.Contains("WMI", StringComparison.OrdinalIgnoreCase) || r.CheckName.Contains("Running", StringComparison.OrdinalIgnoreCase)))
				?? results.FirstOrDefault((SecurityResult r) => r.CheckName.Contains(sub, StringComparison.OrdinalIgnoreCase));
			return (status: securityResult?.Status ?? SecurityStatus.Info, value: securityResult?.CurrentValue ?? "N/A");
		}
	}

	private void ComputeCategoryScores(List<SecurityResult> results)
	{
		CategoryScores = new List<SecurityScore>();
		foreach (IGrouping<string, SecurityResult> categoryGroup in from r in results
			group r by r.Category into g
			orderby g.Key
			select g)
		{
			int totalCount = 0;
			int okCount = 0;
			int warningCount = 0;
			int criticalCount = 0;
			int errorCount = 0;
			int infoCount = 0;
			foreach (SecurityResult result in categoryGroup)
			{
				totalCount++;
				switch (result.Status)
				{
				case SecurityStatus.OK:
					okCount++;
					break;
				case SecurityStatus.Warning:
					warningCount++;
					break;
				case SecurityStatus.Critical:
					criticalCount++;
					break;
				case SecurityStatus.Error:
					errorCount++;
					break;
				case SecurityStatus.Info:
				case SecurityStatus.NotApplicable:
					// H5 : NotApplicable est neutre (ex. machine sans WiFi), pas une erreur.
					infoCount++;
					break;
				}
			}
			CategoryScores.Add(new SecurityScore
			{
				Category = categoryGroup.Key,
				Icon = CategoryIcon(categoryGroup.Key),
				TotalChecks = totalCount,
				PassedChecks = okCount,
				WarningChecks = warningCount,
				CriticalChecks = criticalCount,
				ErrorChecks = errorCount,
				InfoChecks = infoCount
			});
		}
		int scoredTotal = 0;
		int scoredOk = 0;
		int scoredWarning = 0;
		int scoredCritical = 0;
		foreach (SecurityResult result in results)
		{
			// H5 : seuls OK/Warning/Critical entrent dans le score. Info, NotApplicable (neutre) et
			// Error (échec technique) sont exclus du dénominateur pour ne pas fausser le score.
			if (result.Status != SecurityStatus.Info && result.Status != SecurityStatus.NotApplicable && result.Status != SecurityStatus.Error && !result.Category.Contains("Journ", StringComparison.OrdinalIgnoreCase) && !result.Category.Contains("Event", StringComparison.OrdinalIgnoreCase))
			{
				scoredTotal++;
				if (result.Status == SecurityStatus.OK)
				{
					scoredOk++;
				}
				else if (result.Status == SecurityStatus.Warning)
				{
					scoredWarning++;
				}
				else if (result.Status == SecurityStatus.Critical)
				{
					scoredCritical++;
				}
			}
		}
		GlobalScore = SecurityScore.ComputeScore(scoredOk, scoredWarning, scoredCritical, scoredTotal);
		GlobalGrade = SecurityScore.ComputeGrade(GlobalScore);
		static string CategoryIcon(string category)
		{
			string lowered = category.ToLowerInvariant();
			if (lowered.Contains("defender") || lowered.Contains("antivirus"))
			{
				return "\ue72e";
			}
			if (lowered.Contains("firewall"))
			{
				return "\ue785";
			}
			if (lowered.Contains("bitlocker") || lowered.Contains("chiffrement"))
			{
				return "\ue785";
			}
			if (lowered.Contains("réseau") || lowered.Contains("network"))
			{
				return "\ue774";
			}
			if (lowered.Contains("tls") || lowered.Contains("crypto"))
			{
				return "\ue8d7";
			}
			if (lowered.Contains("compte") || lowered.Contains("user") || lowered.Contains("account"))
			{
				return "\ue77b";
			}
			if (lowered.Contains("audit") || lowered.Contains("log") || lowered.Contains("event"))
			{
				return "\ue7ba";
			}
			if (lowered.Contains("système") || lowered.Contains("system"))
			{
				return "\ue7f4";
			}
			if (lowered.Contains("vbs") || lowered.Contains("core"))
			{
				return "\ue835";
			}
			if (lowered.Contains("app") || lowered.Contains("control"))
			{
				return "\ue71d";
			}
			if (lowered.Contains("process") || lowered.Contains("driver"))
			{
				return "\ue943";
			}
			if (lowered.Contains("partage") || lowered.Contains("share"))
			{
				return "\ue8b7";
			}
			if (lowered.Contains("office") || lowered.Contains("macro"))
			{
				return "\ue8a5";
			}
			if (lowered.Contains("kerberos"))
			{
				return "\ue8d7";
			}
			if (lowered.Contains("update") || lowered.Contains("mise à jour"))
			{
				return "\ue895";
			}
			if (lowered.Contains("certificat"))
			{
				return "\ue890";
			}
			if (lowered.Contains("azure") || lowered.Contains("entra"))
			{
				return "\ue753";
			}
			return "\ue721";
		}
	}

	private string FormatResults(IReadOnlyList<CollectorReport> reports)
	{
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.AppendLine("═══════════════════════════════════════════════════════════════════════");
		stringBuilder.AppendLine("##  CHECKSEC — RAPPORT D'AUDIT DE SÉCURITÉ WINDOWS 11");
		StringBuilder stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder3 = stringBuilder2;
		StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(16, 1, stringBuilder2);
		handler.AppendLiteral("##  Généré le : ");
		handler.AppendFormatted(DateTime.Now, "dddd dd MMMM yyyy à HH:mm:ss");
		stringBuilder3.AppendLine(ref handler);
		stringBuilder.AppendLine("##  Conformité : Microsoft Security Compliance Toolkit v25H2");
		stringBuilder.AppendLine("═══════════════════════════════════════════════════════════════════════");
		stringBuilder.AppendLine();
		List<SecurityResult> allResults = reports.SelectMany((CollectorReport r) => r.Results).ToList();
		int okCount = 0;
		int warningCount = 0;
		int criticalCount = 0;
		int errorCount = 0;
		using (List<SecurityResult>.Enumerator enumerator = allResults.GetEnumerator())
		{
			while (enumerator.MoveNext())
			{
				switch (enumerator.Current.Status)
				{
				case SecurityStatus.OK:
					okCount++;
					break;
				case SecurityStatus.Warning:
					warningCount++;
					break;
				case SecurityStatus.Critical:
					criticalCount++;
					break;
				case SecurityStatus.Error:
					errorCount++;
					break;
				}
			}
		}
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder4 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(40, 1, stringBuilder2);
		handler.AppendLiteral("ℹ\ufe0f  SYNTHÈSE : ");
		handler.AppendFormatted(allResults.Count);
		handler.AppendLiteral(" vérifications effectuées");
		stringBuilder4.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder5 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(15, 1, stringBuilder2);
		handler.AppendLiteral("✅  OK        : ");
		handler.AppendFormatted(okCount);
		stringBuilder5.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder6 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(16, 1, stringBuilder2);
		handler.AppendLiteral("⚠\ufe0f  AVERTIS.  : ");
		handler.AppendFormatted(warningCount);
		stringBuilder6.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder7 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(15, 1, stringBuilder2);
		handler.AppendLiteral("❌  CRITIQUES : ");
		handler.AppendFormatted(criticalCount);
		stringBuilder7.AppendLine(ref handler);
		stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder8 = stringBuilder2;
		handler = new StringBuilder.AppendInterpolatedStringHandler(16, 1, stringBuilder2);
		handler.AppendLiteral("\ud83d\udd34  ERREURS   : ");
		handler.AppendFormatted(errorCount);
		stringBuilder8.AppendLine(ref handler);
		stringBuilder.AppendLine();
		foreach (IGrouping<string, CollectorReport> categoryGroup in from r in reports
			group r by r.Results.FirstOrDefault()?.Category ?? r.CollectorName into g
			orderby g.Key
			select g)
		{
			stringBuilder.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder9 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
			handler.AppendLiteral("##  ");
			handler.AppendFormatted(categoryGroup.Key.ToUpperInvariant());
			stringBuilder9.AppendLine(ref handler);
			stringBuilder.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
			foreach (CollectorReport report in categoryGroup)
			{
				if (!report.Success)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder10 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(16, 2, stringBuilder2);
					handler.AppendLiteral("\ud83d\udd34  [");
					handler.AppendFormatted(report.CollectorName);
					handler.AppendLiteral("] ERREUR : ");
					handler.AppendFormatted(report.ErrorMessage);
					stringBuilder10.AppendLine(ref handler);
					continue;
				}
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder11 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(18, 2, stringBuilder2);
				handler.AppendLiteral("ℹ\ufe0f  Module : ");
				handler.AppendFormatted(report.CollectorName);
				handler.AppendLiteral("  (");
				handler.AppendFormatted(report.Duration.TotalSeconds, "F2");
				handler.AppendLiteral("s)");
				stringBuilder11.AppendLine(ref handler);
				foreach (SecurityResult result in report.Results.OrderByDescending((SecurityResult x) => (int)x.Status))
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder12 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(2, 2, stringBuilder2);
					handler.AppendFormatted(StatusIcon(result.Status));
					handler.AppendLiteral("  ");
					handler.AppendFormatted(result.CheckName);
					stringBuilder12.AppendLine(ref handler);
					if (!string.IsNullOrWhiteSpace(result.Description))
					{
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder13 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
						handler.AppendLiteral("    ");
						handler.AppendFormatted(result.Description);
						stringBuilder13.AppendLine(ref handler);
					}
					if (!string.IsNullOrWhiteSpace(result.CurrentValue))
					{
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder14 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(22, 1, stringBuilder2);
						handler.AppendLiteral("    Valeur actuelle : ");
						handler.AppendFormatted(result.CurrentValue);
						stringBuilder14.AppendLine(ref handler);
					}
					if (!string.IsNullOrWhiteSpace(result.ExpectedValue))
					{
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder15 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(22, 1, stringBuilder2);
						handler.AppendLiteral("    Valeur attendue : ");
						handler.AppendFormatted(result.ExpectedValue);
						stringBuilder15.AppendLine(ref handler);
					}
					SecurityStatus status = result.Status;
					bool needsRecommendation = (((uint)(status - 1) <= 1u || status == SecurityStatus.Error) ? true : false);
					if (needsRecommendation && !string.IsNullOrWhiteSpace(result.Recommendation))
					{
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder16 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(22, 1, stringBuilder2);
						handler.AppendLiteral("    Recommandation  : ");
						handler.AppendFormatted(result.Recommendation);
						stringBuilder16.AppendLine(ref handler);
					}
					if (!string.IsNullOrWhiteSpace(result.Reference))
					{
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder17 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(22, 1, stringBuilder2);
						handler.AppendLiteral("    Référence       : ");
						handler.AppendFormatted(result.Reference);
						stringBuilder17.AppendLine(ref handler);
					}
					stringBuilder.AppendLine();
				}
			}
		}
		IReadOnlyList<string> errors = ErrorLogger.GetErrors();
		if (errors.Count > 0)
		{
			stringBuilder.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
			stringBuilder.AppendLine("##  ERREURS INTERNES (diagnostics)");
			stringBuilder.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
			foreach (string errorLine in errors.TakeLast(50))
			{
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder18 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
				handler.AppendLiteral("\ud83d\udd34  ");
				handler.AppendFormatted(errorLine);
				stringBuilder18.AppendLine(ref handler);
			}
		}
		stringBuilder.AppendLine("═══════════════════════════════════════════════════════════════════════");
		stringBuilder.AppendLine("##  FIN DU RAPPORT CHECKSEC");
		stringBuilder.AppendLine("═══════════════════════════════════════════════════════════════════════");
		return stringBuilder.ToString();
	}

	private static string FormatEventLogs(IReadOnlyList<CollectorReport> reports)
	{
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.AppendLine("═══════════════════════════════════════════════════════════════════════");
		stringBuilder.AppendLine("##  JOURNAUX D'ÉVÉNEMENTS — ANALYSE SÉCURITÉ");
		StringBuilder stringBuilder2 = stringBuilder;
		StringBuilder stringBuilder3 = stringBuilder2;
		StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(16, 1, stringBuilder2);
		handler.AppendLiteral("##  Généré le : ");
		handler.AppendFormatted(DateTime.Now, "yyyy-MM-dd HH:mm:ss");
		stringBuilder3.AppendLine(ref handler);
		stringBuilder.AppendLine("═══════════════════════════════════════════════════════════════════════");
		stringBuilder.AppendLine();
		List<CollectorReport> logReports = reports.Where((CollectorReport r) => r.CollectorName.Contains("Event", StringComparison.OrdinalIgnoreCase) || r.CollectorName.Contains("Log", StringComparison.OrdinalIgnoreCase) || r.CollectorName.Contains("Audit", StringComparison.OrdinalIgnoreCase)).ToList();
		if (logReports.Count == 0)
		{
			stringBuilder.AppendLine("ℹ\ufe0f  Aucun collecteur de journaux d'événements n'a produit de données.");
			return stringBuilder.ToString();
		}
		foreach (CollectorReport report in logReports)
		{
			stringBuilder.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
			stringBuilder2 = stringBuilder;
			StringBuilder stringBuilder4 = stringBuilder2;
			handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
			handler.AppendLiteral("##  ");
			handler.AppendFormatted(report.CollectorName.ToUpperInvariant());
			stringBuilder4.AppendLine(ref handler);
			stringBuilder.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
			if (!report.Success)
			{
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder5 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(13, 1, stringBuilder2);
				handler.AppendLiteral("\ud83d\udd34  Erreur : ");
				handler.AppendFormatted(report.ErrorMessage);
				stringBuilder5.AppendLine(ref handler);
				continue;
			}
			foreach (SecurityResult result in report.Results)
			{
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder6 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(2, 2, stringBuilder2);
				handler.AppendFormatted(StatusIcon(result.Status));
				handler.AppendLiteral("  ");
				handler.AppendFormatted(result.CheckName);
				stringBuilder6.AppendLine(ref handler);
				if (!string.IsNullOrWhiteSpace(result.Description))
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder7 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
					handler.AppendLiteral("    ");
					handler.AppendFormatted(result.Description);
					stringBuilder7.AppendLine(ref handler);
				}
				if (!string.IsNullOrWhiteSpace(result.CurrentValue))
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder8 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
					handler.AppendLiteral("    ");
					handler.AppendFormatted(result.CurrentValue);
					stringBuilder8.AppendLine(ref handler);
				}
				stringBuilder.AppendLine();
			}
		}
		return stringBuilder.ToString();
	}

	private static string StatusIcon(SecurityStatus s)
	{
		return s switch
		{
			SecurityStatus.OK => "✅", 
			SecurityStatus.Warning => "⚠\ufe0f", 
			SecurityStatus.Critical => "❌", 
			SecurityStatus.Error => "\ud83d\udd34", 
			SecurityStatus.NotApplicable => "ℹ\ufe0f", 
			_ => "ℹ\ufe0f", 
		};
	}

	// Lit les VRAIS événements Windows de niveau Critique/Erreur des journaux System et Application
	// (7 derniers jours), avec EventID, fournisseur, horodatage et message réels — pour l'export forensique.
	private List<EventLogEntry> CollectWindowsEventErrors(CancellationToken ct)
	{
		List<EventLogEntry> entries = new List<EventLogEntry>();
		// Level 1 = Critique, 2 = Erreur ; timediff en millisecondes (7 jours = 604800000).
		const string xpath = "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
		string[] logNames = new string[] { "System", "Application" };

		foreach (string logName in logNames)
		{
			ct.ThrowIfCancellationRequested();
			try
			{
				EventLogQuery query = new EventLogQuery(logName, PathType.LogName, xpath)
				{
					ReverseDirection = true // plus récents d'abord
				};
				using EventLogReader reader = new EventLogReader(query);
				int count = 0;
				for (EventRecord record = reader.ReadEvent(); record != null && count < 150; record = reader.ReadEvent())
				{
					using (record)
					{
						ct.ThrowIfCancellationRequested();
						string message;
						try
						{
							message = record.FormatDescription();
						}
						catch
						{
							message = null;
						}
						if (string.IsNullOrWhiteSpace(message))
						{
							message = "(message indisponible)";
						}
						message = message.Replace("\r", " ").Replace("\n", " ").Trim();
						if (message.Length > 500)
						{
							message = message.Substring(0, 500) + "…";
						}

						entries.Add(new EventLogEntry
						{
							Timestamp = record.TimeCreated ?? DateTime.MinValue,
							Level = (record.Level == 1) ? "Critical" : "Error",
							EventId = record.Id,
							Source = record.ProviderName ?? logName,
							Message = "[" + logName + "] " + message
						});
						count++;
					}
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				ErrorLogger.AddError("[EventErrors:" + logName + "] " + ex.Message);
			}
		}

		entries.Sort((EventLogEntry a, EventLogEntry b) => b.Timestamp.CompareTo(a.Timestamp));
		return entries;
	}

	private List<EventLogEntry> ParseEventLogEntries(List<CollectorReport> reports)
	{
		List<EventLogEntry> entries = new List<EventLogEntry>();
		foreach (CollectorReport report in reports)
		{
			foreach (SecurityResult result in report.Results)
			{
				if (result.Category.Contains("Event", StringComparison.OrdinalIgnoreCase) || result.Category.Contains("Journ", StringComparison.OrdinalIgnoreCase))
				{
					List<EventLogEntry> entriesRef = entries;
					EventLogEntry eventLogEntry = new EventLogEntry();
					eventLogEntry.Timestamp = result.CollectedAt;
					EventLogEntry eventLogEntry2 = eventLogEntry;
					string level;
					switch (result.Status)
					{
					case SecurityStatus.OK:
						level = "Information";
						break;
					case SecurityStatus.Warning:
						level = "Warning";
						break;
					case SecurityStatus.Critical:
					case SecurityStatus.Error:
						level = "Error";
						break;
					default:
						level = "Information";
						break;
					}
					eventLogEntry2.Level = level;
					eventLogEntry.EventId = TryExtractEventId(result.CheckName, result.CurrentValue);
					eventLogEntry.Source = report.CollectorName;
					eventLogEntry.Message = result.CheckName + ": " + result.Description;
					entriesRef.Add(eventLogEntry);
				}
			}
		}
		entries.Sort((EventLogEntry a, EventLogEntry b) => b.Timestamp.CompareTo(a.Timestamp));
		return entries;
	}

	private static int TryExtractEventId(string checkName, string currentValue)
	{
		string[] sources = new string[2] { checkName, currentValue };
		foreach (string source in sources)
		{
			if (!string.IsNullOrEmpty(source))
			{
				Match match = Regex.Match(source, "(?:Event\\s*(?:ID)?[:\\s]*|ID[:\\s]*)(\\d{3,5})", RegexOptions.IgnoreCase);
				if (match.Success && int.TryParse(match.Groups[1].Value, out var eventId))
				{
					return eventId;
				}
			}
		}
		return 0;
	}
}
