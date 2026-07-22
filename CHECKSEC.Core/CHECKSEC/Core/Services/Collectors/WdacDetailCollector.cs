using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

/// <summary>
/// Collecteur WDAC détaillé (Windows Defender Application Control).
///
/// Le collecteur AppControlCollector existant se contente de constater la PRÉSENCE
/// d'une policy (clés de registre, fichiers .p7b). Il ne dit rien du MODE RÉEL
/// d'application. Ce collecteur va plus loin :
///   - distingue les policies « base » des policies « supplemental » ;
///   - détermine si chaque policy tourne en Audit (journalise sans bloquer) ou
///     en Enforce (bloque réellement) ;
///   - sépare les policies système (Microsoft, embarquées) des policies déployées
///     par l'administrateur.
///
/// Sources, par ordre de fiabilité :
///   1. CiTool.exe --list-policies --json  (Windows 11 22H2+, nécessite admin) ;
///   2. Fallback (Windows plus anciens) : énumération des fichiers .cip actifs +
///      registre CI / DeviceGuard.
/// </summary>
public class WdacDetailCollector : ISecurityCollector
{
	/// <summary>Répertoire des policies WDAC actives (fichiers compilés .cip).</summary>
	private const string ActiveCiPoliciesPath = "C:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active";

	/// <summary>Représente une policy WDAC telle que retournée par CiTool ou déduite du fallback.</summary>
	private sealed class WdacPolicy
	{
		public string FriendlyName = "";

		public string PolicyId = "";

		public string BasePolicyId = "";

		public bool IsSystemPolicy;

		public bool IsEnforced;

		public bool IsAuthorized;

		public bool IsOnDisk;

		public string Version = "";

		/// <summary>Une policy est « base » quand son PolicyID est égal à son BasePolicyID.</summary>
		public bool IsBase => !string.IsNullOrEmpty(PolicyId) && string.Equals(PolicyId, BasePolicyId, StringComparison.OrdinalIgnoreCase);
	}

	public string Name => "WDAC (Application Control) — Détail";

	public string Category => "Application Control";

	public async Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch sw = Stopwatch.StartNew();
		try
		{
			ct.ThrowIfCancellationRequested();

			// CiTool.exe se trouve dans System32 sur Windows 11 22H2+.
			string ciToolPath = Path.Combine(Environment.SystemDirectory ?? "C:\\Windows\\System32", "CiTool.exe");
			bool ciToolPresent = File.Exists(ciToolPath);

			if (ciToolPresent)
			{
				// Source privilégiée : CiTool renvoie l'état réel (mode Audit/Enforce inclus).
				await CollectViaCiToolAsync(report.Results, ciToolPath, ct);
			}
			else
			{
				// Fallback pour les versions de Windows sans CiTool.
				CollectViaFallback(report.Results, ct);
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			report.ErrorMessage = "WdacDetailCollector fatal error: " + ex2.Message;
		}
		finally
		{
			sw.Stop();
			report.Duration = sw.Elapsed;
		}
		return report;
	}

	// ============================================================================
	// SOURCE 1 : CiTool.exe --list-policies --json
	// ============================================================================

	private async Task CollectViaCiToolAsync(List<SecurityResult> results, string ciToolPath, CancellationToken ct)
	{
		string json;
		try
		{
			json = await RunCiToolAsync(ciToolPath, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			// Échec d'exécution (le plus souvent droits insuffisants) : on remonte une
			// Error EXPLICITE plutôt qu'un faux « WDAC non déployé ».
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC — Interrogation CiTool",
				CurrentValue = "Erreur : " + ex.Message,
				ExpectedValue = "Sortie JSON de CiTool --list-policies",
				Status = SecurityStatus.Error,
				Description = "CiTool.exe est présent mais son exécution a échoué. L'état WDAC réel n'a pas pu être déterminé.",
				Recommendation = "CiTool indisponible / droits insuffisants. Relancer CHECKSEC en tant qu'administrateur.",
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
			});
			return;
		}

		List<WdacPolicy> policies;
		try
		{
			policies = ParseCiToolJson(json);
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC — Analyse de la sortie CiTool",
				CurrentValue = "Erreur d'analyse JSON : " + ex.Message,
				ExpectedValue = "JSON valide",
				Status = SecurityStatus.Error,
				Description = "La sortie de CiTool.exe n'a pas pu être analysée (format inattendu).",
				Recommendation = "Exécuter manuellement 'CiTool.exe --list-policies --json' pour vérifier la sortie.",
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
			});
			return;
		}

		ProduceResults(results, policies, "CiTool.exe --list-policies --json", ct);
	}

	/// <summary>
	/// Exécute CiTool.exe --list-policies --json et retourne la sortie standard.
	/// Encodage OEM (comme AuditPolicyCollector), timeout via token lié au ct + CancelAfter(20s),
	/// Kill du process si annulation/timeout.
	/// </summary>
	private async Task<string> RunCiToolAsync(string ciToolPath, CancellationToken ct)
	{
		ProcessStartInfo startInfo = new ProcessStartInfo(ciToolPath, "--list-policies --json")
		{
			RedirectStandardOutput = true,
			RedirectStandardError = true,
			UseShellExecute = false,
			CreateNoWindow = true,
			StandardOutputEncoding = GetSafeOemEncoding(),
			StandardErrorEncoding = GetSafeOemEncoding()
		};
		using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		timeoutCts.CancelAfter(TimeSpan.FromSeconds(20L));
		using Process proc = Process.Start(startInfo);
		if (proc == null)
		{
			throw new InvalidOperationException("Impossible de démarrer CiTool.exe.");
		}
		string output;
		try
		{
			// BUG #5 : stdout ET stderr sont redirigés. Il faut lire les DEUX pipes
			// EN PARALLÈLE, sinon un stderr volumineux remplit son pipe et bloque
			// CiTool.exe (deadlock) → timeout/annulation. On démarre donc les deux
			// ReadToEndAsync AVANT WaitForExitAsync, puis on attend les deux lectures.
			Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync(timeoutCts.Token);
			Task<string> stderrTask = proc.StandardError.ReadToEndAsync(timeoutCts.Token);
			await Task.WhenAll(stdoutTask, stderrTask);
			await proc.WaitForExitAsync(timeoutCts.Token);
			output = stdoutTask.Result;
		}
		catch (OperationCanceledException)
		{
			try
			{
				proc.Kill();
			}
			catch
			{
			}
			throw;
		}
		if (proc.ExitCode != 0)
		{
			throw new InvalidOperationException($"CiTool.exe a retourné le code {proc.ExitCode}.");
		}
		return output;
	}

	/// <summary>
	/// Analyse la sortie JSON de CiTool. La structure attendue est un objet racine
	/// contenant un tableau « Policies ». Les noms de propriétés sont comparés sans
	/// tenir compte de la casse pour robustesse.
	/// </summary>
	private static List<WdacPolicy> ParseCiToolJson(string json)
	{
		List<WdacPolicy> list = new List<WdacPolicy>();
		if (string.IsNullOrWhiteSpace(json))
		{
			return list;
		}
		using JsonDocument doc = JsonDocument.Parse(json);
		JsonElement root = doc.RootElement;

		// Localiser le tableau de policies : soit sous la propriété "Policies",
		// soit directement à la racine si CiTool renvoie un tableau.
		JsonElement policiesArray = default;
		bool haveArray = false;
		if (root.ValueKind == JsonValueKind.Array)
		{
			policiesArray = root;
			haveArray = true;
		}
		else if (root.ValueKind == JsonValueKind.Object)
		{
			foreach (JsonProperty prop in root.EnumerateObject())
			{
				if (string.Equals(prop.Name, "Policies", StringComparison.OrdinalIgnoreCase) && prop.Value.ValueKind == JsonValueKind.Array)
				{
					policiesArray = prop.Value;
					haveArray = true;
					break;
				}
			}
			if (!haveArray)
			{
				return list;
			}
		}
		else
		{
			return list;
		}

		if (!haveArray)
		{
			return list;
		}

		foreach (JsonElement policyElem in policiesArray.EnumerateArray())
		{
			if (policyElem.ValueKind != JsonValueKind.Object)
			{
				continue;
			}
			WdacPolicy p = new WdacPolicy
			{
				FriendlyName = GetJsonString(policyElem, "FriendlyName"),
				PolicyId = GetJsonString(policyElem, "PolicyID"),
				BasePolicyId = GetJsonString(policyElem, "BasePolicyID"),
				Version = GetJsonString(policyElem, "Version"),
				IsSystemPolicy = GetJsonBool(policyElem, "IsSystemPolicy"),
				IsEnforced = GetJsonBool(policyElem, "IsEnforced"),
				IsAuthorized = GetJsonBool(policyElem, "IsAuthorized"),
				IsOnDisk = GetJsonBool(policyElem, "IsOnDisk")
			};
			if (string.IsNullOrEmpty(p.FriendlyName))
			{
				p.FriendlyName = string.IsNullOrEmpty(p.PolicyId) ? "(sans nom)" : p.PolicyId;
			}
			list.Add(p);
		}
		return list;
	}

	/// <summary>Lecture tolérante d'une propriété string (insensible à la casse).</summary>
	private static string GetJsonString(JsonElement obj, string name)
	{
		foreach (JsonProperty prop in obj.EnumerateObject())
		{
			if (string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase))
			{
				return prop.Value.ValueKind switch
				{
					JsonValueKind.String => prop.Value.GetString() ?? "",
					JsonValueKind.Number => prop.Value.ToString(),
					JsonValueKind.Null => "",
					_ => prop.Value.ToString()
				};
			}
		}
		return "";
	}

	/// <summary>Lecture tolérante d'une propriété booléenne (accepte true/false, 0/1, "true"/"false").</summary>
	private static bool GetJsonBool(JsonElement obj, string name)
	{
		foreach (JsonProperty prop in obj.EnumerateObject())
		{
			if (string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase))
			{
				switch (prop.Value.ValueKind)
				{
				case JsonValueKind.True:
					return true;
				case JsonValueKind.False:
					return false;
				case JsonValueKind.Number:
					return prop.Value.TryGetInt64(out long n) && n != 0L;
				case JsonValueKind.String:
					string s = prop.Value.GetString() ?? "";
					return s.Equals("true", StringComparison.OrdinalIgnoreCase) || s == "1";
				}
			}
		}
		return false;
	}

	// ============================================================================
	// Production des résultats communs (à partir de la liste de policies)
	// ============================================================================

	private void ProduceResults(List<SecurityResult> results, List<WdacPolicy> policies, string source, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// Séparation policies système (Microsoft) / policies non-système (déployées par l'admin).
		List<WdacPolicy> nonSystem = new List<WdacPolicy>();
		List<WdacPolicy> system = new List<WdacPolicy>();
		foreach (WdacPolicy p in policies)
		{
			if (p.IsSystemPolicy)
			{
				system.Add(p);
			}
			else
			{
				nonSystem.Add(p);
			}
		}

		int baseCount = 0;
		int supplementalCount = 0;
		int enforcedCount = 0;
		int auditCount = 0;
		foreach (WdacPolicy p in nonSystem)
		{
			if (p.IsBase)
			{
				baseCount++;
			}
			else
			{
				supplementalCount++;
			}
			if (p.IsEnforced)
			{
				enforcedCount++;
			}
			else
			{
				auditCount++;
			}
		}

		// ---- Résultat 1 : WDAC — Policies déployées ---------------------------
		ct.ThrowIfCancellationRequested();
		if (nonSystem.Count == 0)
		{
			// Aucune policy non-système : WDAC est un durcissement avancé optionnel,
			// son absence n'est donc PAS Critical mais Info.
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC — Policies déployées",
				CurrentValue = "0 policy non-système déployée",
				ExpectedValue = ">= 1 policy (optionnel — durcissement avancé)",
				Status = SecurityStatus.Info,
				Description = "WDAC non déployé (mode application control non actif). WDAC restreint l'exécution aux applications explicitement autorisées. Source : " + source + ".",
				Recommendation = "WDAC est un durcissement avancé optionnel. Pour un contrôle applicatif strict, déployer une policy WDAC (base) en mode Audit puis Enforce après validation.",
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
			});
		}
		else
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC — Policies déployées",
				CurrentValue = $"{nonSystem.Count} policy(ies) non-système ({baseCount} base, {supplementalCount} supplemental)",
				ExpectedValue = ">= 1 policy base déployée",
				Status = SecurityStatus.Info,
				Description = "Nombre total de policies WDAC déployées par l'administrateur (base + supplemental). Une policy « base » définit le socle des règles ; une policy « supplemental » l'étend. Source : " + source + ".",
				Recommendation = "Vérifier que les policies déployées correspondent à la stratégie de contrôle applicatif attendue.",
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
			});
		}

		// ---- Résultat 2 : WDAC — Mode d'application ---------------------------
		ct.ThrowIfCancellationRequested();
		if (nonSystem.Count == 0)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC — Mode d'application",
				CurrentValue = "Aucune policy non-système",
				ExpectedValue = "Enforce (pour un blocage réel)",
				Status = SecurityStatus.Info,
				Description = "Aucune policy WDAC non-système n'est déployée : il n'y a donc pas de mode d'application à évaluer.",
				Recommendation = "Déployer une policy WDAC pour activer le contrôle applicatif.",
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
			});
		}
		else if (enforcedCount > 0)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC — Mode d'application",
				CurrentValue = $"WDAC en mode Enforce ({enforcedCount} policy(ies) Enforced, {auditCount} en Audit)",
				ExpectedValue = "Au moins une policy en Enforce",
				Status = SecurityStatus.OK,
				Description = "Au moins une policy WDAC non-système est en mode Enforce : les exécutions non autorisées sont réellement bloquées.",
				Recommendation = "Le contrôle applicatif WDAC est actif en mode blocage. Maintenir les règles à jour lors des changements applicatifs.",
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
			});
		}
		else
		{
			// Toutes les policies non-système sont en Audit uniquement.
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC — Mode d'application",
				CurrentValue = $"WDAC en Audit uniquement ({auditCount} policy(ies) en Audit)",
				ExpectedValue = "Au moins une policy en Enforce",
				Status = SecurityStatus.Warning,
				Description = "WDAC en Audit uniquement (ne bloque pas) : les violations sont journalisées mais aucune exécution n'est empêchée. C'est le mode de test avant bascule en Enforce.",
				Recommendation = "Après validation des journaux d'audit (Event ID 3076/3077), basculer les policies en mode Enforce pour un blocage effectif.",
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
			});
		}

		// ---- Résultat 3 : WDAC — Détail par policy (une ligne par policy non-système)
		foreach (WdacPolicy p in nonSystem)
		{
			ct.ThrowIfCancellationRequested();
			WdacPolicy pol = p;
			string kind = pol.IsBase ? "Base" : "Supplemental";
			string mode = pol.IsEnforced ? "Enforced" : "Audit";
			string version = string.IsNullOrEmpty(pol.Version) ? "?" : pol.Version;
			// Contexte informatif, sauf en mode Audit → Warning (ne bloque pas).
			SecurityStatus status = pol.IsEnforced ? SecurityStatus.Info : SecurityStatus.Warning;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC — Policy : " + pol.FriendlyName,
				CurrentValue = $"{kind} / {mode} / v{version}",
				ExpectedValue = "Enforced (pour un blocage réel)",
				Status = status,
				Description = $"Policy WDAC « {pol.FriendlyName} » — type {kind}, mode {mode}, version {version}. " + $"IsAuthorized={pol.IsAuthorized}, IsOnDisk={pol.IsOnDisk}, PolicyID={pol.PolicyId}.",
				Recommendation = (pol.IsEnforced ? "Policy en mode Enforce (blocage actif)." : "Policy en Audit : ne bloque pas. Basculer en Enforce après validation des journaux."),
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
			});
		}

		// ---- Résultat 4 : WDAC — Policies système (Microsoft) -----------------
		ct.ThrowIfCancellationRequested();
		int sysBase = 0;
		int sysSupplemental = 0;
		foreach (WdacPolicy p in system)
		{
			if (p.IsBase)
			{
				sysBase++;
			}
			else
			{
				sysSupplemental++;
			}
		}
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "WDAC — Policies système (Microsoft)",
			CurrentValue = $"{system.Count} policy(ies) système ({sysBase} base, {sysSupplemental} supplemental)",
			ExpectedValue = "Présence normale (policies Microsoft embarquées)",
			Status = SecurityStatus.Info,
			Description = "Policies WDAC système fournies et gérées par Microsoft (ex. WindowsE, WindowsS, Smart App Control). Elles ne reflètent pas la stratégie de l'administrateur.",
			Recommendation = "Aucune action requise : ces policies sont gérées par le système d'exploitation.",
			Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
		});
	}

	// ============================================================================
	// SOURCE 2 : Fallback (pas de CiTool) — fichiers .cip + registre
	// ============================================================================

	private void CollectViaFallback(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// Comptage des policies déployées via les fichiers compilés .cip actifs.
		int cipCount = 0;
		bool activeDirExists = Directory.Exists(ActiveCiPoliciesPath);
		if (activeDirExists)
		{
			try
			{
				cipCount = Directory.GetFiles(ActiveCiPoliciesPath, "*.cip").Length;
			}
			catch (Exception ex) when (ex is UnauthorizedAccessException || ex is IOException)
			{
				// BUG #7 : distinguer l'ÉCHEC DE LECTURE (droits insuffisants /
				// accès refusé) de l'ABSENCE RÉELLE de fichiers. Sans cette
				// distinction, un accès refusé retombait sur « 0 policy » →
				// faux « WDAC non déployé ». On remonte ici une Error EXPLICITE
				// et on n'émet PAS de conclusion « non déployé ».
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "WDAC — Policies déployées",
					CurrentValue = "Impossible d'énumérer " + ActiveCiPoliciesPath + " : " + ex.Message,
					ExpectedValue = "Énumération lisible du répertoire CiPolicies\\Active",
					Status = SecurityStatus.Error,
					Description = "Impossible d'énumérer CiPolicies\\Active — droits insuffisants (exécuter en administrateur). L'état de déploiement WDAC n'a pas pu être déterminé par le fallback ; ceci N'EST PAS un constat de « WDAC non déployé ».",
					Recommendation = "Relancer CHECKSEC en tant qu'administrateur pour permettre l'énumération des policies WDAC actives (.cip).",
					Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
				});
				return;
			}
			catch
			{
			}
		}

		// Mode audit/enforce déductible du registre si disponible.
		// DeployConfigCIPolicy / clés DeviceGuard : présence d'une configuration d'application.
		int deployConfig = RegInt("SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", "DeployConfigCIPolicy");
		int codeIntegrityPoliciesActive = RegInt("SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard", "CodeIntegrityPoliciesActive");
		int userModeCodeIntegrity = RegInt("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", "Enabled");

		// ---- Résultat 1 : Policies déployées (fallback) -----------------------
		ct.ThrowIfCancellationRequested();
		if (cipCount == 0)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC — Policies déployées",
				CurrentValue = (activeDirExists ? "0 fichier .cip actif" : "Répertoire CiPolicies\\Active introuvable"),
				ExpectedValue = ">= 1 policy (optionnel — durcissement avancé)",
				Status = SecurityStatus.Info,
				Description = "WDAC non déployé (mode application control non actif). Détecté via fallback (CiTool.exe absent — Windows antérieur à 11 22H2). Aucun fichier de policy compilé (.cip) trouvé dans " + ActiveCiPoliciesPath + ".",
				Recommendation = "WDAC est un durcissement avancé optionnel. Pour l'activer, déployer une policy WDAC compilée (.cip) via GPO/MDM/SCCM.",
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
			});
		}
		else
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC — Policies déployées",
				CurrentValue = $"{cipCount} fichier(s) .cip actif(s)",
				ExpectedValue = ">= 1 policy base déployée",
				Status = SecurityStatus.Info,
				Description = "Nombre de policies WDAC déployées, déduit des fichiers compilés .cip présents dans " + ActiveCiPoliciesPath + ". Détecté via fallback (CiTool.exe absent). Le détail base/supplemental n'est pas disponible sans CiTool.",
				Recommendation = "Pour un état détaillé (base/supplemental, Audit/Enforce), exécuter sur Windows 11 22H2+ disposant de CiTool.exe.",
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
			});
		}

		// ---- Résultat 2 : Mode d'application (fallback) -----------------------
		ct.ThrowIfCancellationRequested();
		if (cipCount == 0 && codeIntegrityPoliciesActive != 1)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC — Mode d'application",
				CurrentValue = "Aucune policy active détectée",
				ExpectedValue = "Enforce (pour un blocage réel)",
				Status = SecurityStatus.Info,
				Description = "Aucune policy WDAC active détectée via le registre/fichiers .cip : pas de mode d'application à évaluer.",
				Recommendation = "Déployer une policy WDAC pour activer le contrôle applicatif.",
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
			});
		}
		else
		{
			// DeployConfigCIPolicy : 0 = Audit, 1 = Enforce (indication de registre, si présente).
			bool enforce = deployConfig == 1;
			bool audit = deployConfig == 0;
			SecurityStatus status;
			string current;
			string reco;
			if (enforce)
			{
				status = SecurityStatus.OK;
				current = "WDAC en mode Enforce (DeployConfigCIPolicy=1)";
				reco = "Le contrôle applicatif WDAC est actif en mode blocage.";
			}
			else if (audit)
			{
				status = SecurityStatus.Warning;
				current = "WDAC en Audit uniquement (DeployConfigCIPolicy=0, ne bloque pas)";
				reco = "Basculer la policy en mode Enforce après validation des journaux d'audit.";
			}
			else
			{
				// Registre non concluant : on ne peut pas trancher Audit vs Enforce sans CiTool.
				status = SecurityStatus.Info;
				current = "Policy active détectée, mode indéterminé (DeployConfigCIPolicy non défini)";
				reco = "Le mode Audit/Enforce n'est pas déterminable via le registre. Utiliser CiTool.exe (Windows 11 22H2+) pour l'état exact.";
			}
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "WDAC — Mode d'application",
				CurrentValue = current,
				ExpectedValue = "Enforce (pour un blocage réel)",
				Status = status,
				Description = $"Mode d'application WDAC déduit du registre (fallback). Indicateurs : DeployConfigCIPolicy={FmtReg(deployConfig)}, CodeIntegrityPoliciesActive={FmtReg(codeIntegrityPoliciesActive)}, HVCI.Enabled={FmtReg(userModeCodeIntegrity)}.",
				Recommendation = reco,
				Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
			});
		}

		// ---- Résultat 4 (fallback) : indication policies système --------------
		// Sans CiTool, on ne peut pas énumérer précisément les policies système ;
		// on fournit une synthèse Info pour signaler la limite de la source.
		ct.ThrowIfCancellationRequested();
		results.Add(new SecurityResult
		{
			Category = Category,
			CheckName = "WDAC — Policies système (Microsoft)",
			CurrentValue = "Non énumérables sans CiTool.exe",
			ExpectedValue = "Présence normale (policies Microsoft embarquées)",
			Status = SecurityStatus.Info,
			Description = "Le détail des policies système (Microsoft) n'est pas énumérable via le fallback registre/fichiers. CiTool.exe (Windows 11 22H2+) est requis pour cette synthèse.",
			Recommendation = "Aucune action requise. Pour le détail complet, exécuter sur un système disposant de CiTool.exe.",
			Reference = "https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/"
		});
	}

	// ============================================================================
	// Helpers
	// ============================================================================

	/// <summary>Formatte une valeur de registre lue (-1 = absente) pour l'affichage.</summary>
	private static string FmtReg(int value)
	{
		return (value == -1) ? "non défini" : value.ToString(CultureInfo.InvariantCulture);
	}

	/// <summary>Lecture d'un DWORD sous HKLM (vue 64 bits). Retourne -1 si absent/erreur.</summary>
	private static int RegInt(string path, string valueName)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(path);
			object value = subKey?.GetValue(valueName);
			return (value != null && !(value is DBNull)) ? Convert.ToInt32(value) : (-1);
		}
		catch
		{
			return -1;
		}
	}

	/// <summary>Encodage OEM sûr pour lire la sortie d'un process console (repli UTF-8).</summary>
	private static Encoding GetSafeOemEncoding()
	{
		try
		{
			return Encoding.GetEncoding(CultureInfo.InstalledUICulture.TextInfo.OEMCodePage);
		}
		catch
		{
			return Encoding.UTF8;
		}
	}
}
