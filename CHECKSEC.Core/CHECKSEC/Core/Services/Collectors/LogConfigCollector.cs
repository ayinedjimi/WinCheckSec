using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

// Collecteur de la configuration des journaux d'événements Windows.
//
// ATTENTION AUX UNITÉS (point critique) :
//   - Sous la POLICY  HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\<Journal>\MaxSize
//     la valeur MaxSize est exprimée en KILO-OCTETS (Ko).
//   - Sous les SERVICES HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Journal>\MaxSize
//     la valeur MaxSize est exprimée en OCTETS.
// On normalise systématiquement en Ko pour la comparaison aux seuils (exprimés en Ko),
// et on affiche en Mo pour la lisibilité.
public class LogConfigCollector : ISecurityCollector
{
	// Représente un journal à contrôler et son seuil minimal (en Ko).
	private sealed class LogSpec
	{
		public string DisplayName;    // Libellé affiché
		public string RegistryName;   // Nom de la clé sous EventLog (ex. "Security", "Microsoft-Windows-PowerShell/Operational")
		public long ThresholdKo;      // Seuil minimal recommandé, en KILO-octets
		public bool BelowIsInfoOnly;  // true => sous le seuil = Info (au lieu de Warning)
		public bool HasServicesFallback; // true si un repli Services\EventLog existe (journaux classiques)
	}

	// Taille par défaut approximative des journaux classiques Windows (20 Mo = 20480 Ko).
	private const long WindowsDefaultKo = 20480L;

	public string Name => "Configuration des journaux";

	public string Category => "Journaux";

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
			CollectLogSizes(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectRetentionSettings(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "LogConfigCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	// ------------------------------------------------------------------
	// Tailles maximales des journaux (comparaison aux seuils CIS).
	// ------------------------------------------------------------------
	private void CollectLogSizes(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		LogSpec[] specs = new LogSpec[]
		{
			new LogSpec { DisplayName = "Security", RegistryName = "Security", ThresholdKo = 196608L, BelowIsInfoOnly = false, HasServicesFallback = true },
			new LogSpec { DisplayName = "Application", RegistryName = "Application", ThresholdKo = 32768L, BelowIsInfoOnly = false, HasServicesFallback = true },
			new LogSpec { DisplayName = "System", RegistryName = "System", ThresholdKo = 32768L, BelowIsInfoOnly = false, HasServicesFallback = true },
			new LogSpec { DisplayName = "PowerShell/Operational", RegistryName = "Microsoft-Windows-PowerShell/Operational", ThresholdKo = 32768L, BelowIsInfoOnly = true, HasServicesFallback = false }
		};

		foreach (LogSpec spec in specs)
		{
			ct.ThrowIfCancellationRequested();
			LogSpec specCapture = spec;
			TryAdd(results, () => BuildLogSizeResult(specCapture));
		}
	}

	private SecurityResult BuildLogSizeResult(LogSpec spec)
	{
		// 1) Lecture prioritaire sous la POLICY (valeur en KILO-octets).
		long? policyKo = null;
		object policyRaw = ReadMaxSizeRaw("SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\" + spec.RegistryName);
		if (policyRaw != null)
		{
			policyKo = ToInt64Safe(policyRaw); // déjà en Ko
		}

		// 2) Repli sous les SERVICES (valeur en OCTETS -> conversion en Ko).
		long? servicesKo = null;
		if (!policyKo.HasValue && spec.HasServicesFallback)
		{
			object servicesRaw = ReadMaxSizeRaw("SYSTEM\\CurrentControlSet\\Services\\EventLog\\" + spec.RegistryName);
			if (servicesRaw != null)
			{
				long? octets = ToInt64Safe(servicesRaw);
				if (octets.HasValue)
				{
					servicesKo = octets.Value / 1024L; // octets -> Ko
				}
			}
		}

		bool configured;
		long effectiveKo;
		string source;
		if (policyKo.HasValue)
		{
			configured = true;
			effectiveKo = policyKo.Value;
			source = "GPO (Policies, Ko)";
		}
		else if (servicesKo.HasValue)
		{
			configured = true;
			effectiveKo = servicesKo.Value;
			source = "Services\\EventLog (octets normalisés)";
		}
		else
		{
			// Non configuré : Windows applique une taille par défaut (souvent ~20 Mo).
			configured = false;
			effectiveKo = WindowsDefaultKo;
			source = "Non configuré (valeur par défaut Windows)";
		}

		bool meetsThreshold = effectiveKo >= spec.ThresholdKo;
		double effectiveMo = effectiveKo / 1024.0;
		double thresholdMo = spec.ThresholdKo / 1024.0;

		// Sévérité :
		//   - conforme                -> OK
		//   - sous le seuil + Info    -> Info (journal optionnel, ex. PowerShell)
		//   - sous le seuil (défaut)  -> Warning (valeur par défaut)
		//   - sous le seuil (config.) -> Warning
		SecurityStatus status;
		if (meetsThreshold)
		{
			status = SecurityStatus.OK;
		}
		else if (spec.BelowIsInfoOnly)
		{
			status = SecurityStatus.Info;
		}
		else
		{
			status = SecurityStatus.Warning;
		}

		string currentValue = string.Format(CultureInfo.InvariantCulture,
			"{0:0.#} Mo ({1} Ko) — source : {2}",
			effectiveMo, effectiveKo, source)
			+ (configured ? "" : " [valeur par défaut, non configuré explicitement]");

		string expectedValue = string.Format(CultureInfo.InvariantCulture,
			">= {0:0.#} Mo ({1} Ko)", thresholdMo, spec.ThresholdKo);

		string description = "Taille maximale du journal « " + spec.DisplayName + " ». "
			+ "Un journal trop petit provoque l'écrasement rapide des événements (rotation) et la perte de traces essentielles pour la détection et l'investigation. "
			+ "Lecture prioritaire sous la stratégie de groupe (Policies, valeur en Ko) avec repli sous Services\\EventLog (valeur en octets, normalisée en Ko). "
			+ "Seuil issu des recommandations CIS Benchmark.";

		string recommendation;
		if (meetsThreshold)
		{
			recommendation = "La taille du journal « " + spec.DisplayName + " » est conforme au seuil recommandé.";
		}
		else if (!configured)
		{
			recommendation = "Le journal « " + spec.DisplayName + " » utilise la valeur par défaut Windows (~20 Mo). "
				+ string.Format(CultureInfo.InvariantCulture, "Configurer via GPO une taille >= {0:0.#} Mo ({1} Ko) : ", thresholdMo, spec.ThresholdKo)
				+ "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > " + spec.DisplayName + " > Specify the maximum log file size (KB).";
		}
		else
		{
			recommendation = string.Format(CultureInfo.InvariantCulture,
				"Augmenter la taille maximale du journal « {0} » à au moins {1:0.#} Mo ({2} Ko) via GPO ou registre.",
				spec.DisplayName, thresholdMo, spec.ThresholdKo);
		}

		return new SecurityResult
		{
			Category = Category,
			CheckName = "Taille du journal : " + spec.DisplayName,
			CurrentValue = currentValue,
			ExpectedValue = expectedValue,
			Status = status,
			Description = description,
			Recommendation = recommendation,
			Reference = "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-log-policy-settings"
		};
	}

	// ------------------------------------------------------------------
	// Mode de rétention / AutoBackupLogFiles (informatif).
	// ------------------------------------------------------------------
	private void CollectRetentionSettings(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		string[] classicLogs = new string[] { "Security", "Application", "System" };
		foreach (string log in classicLogs)
		{
			ct.ThrowIfCancellationRequested();
			string logCapture = log;
			TryAdd(results, () =>
			{
				// AutoBackupLogFiles : 1 => archivage automatique avant écrasement.
				// Priorité à la policy, repli sur Services\EventLog.
				object autoBackupRaw = ReadValueRaw("SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\" + logCapture, "AutoBackupLogFiles")
					?? ReadValueRaw("SYSTEM\\CurrentControlSet\\Services\\EventLog\\" + logCapture, "AutoBackupLogFiles");
				object retentionRaw = ReadValueRaw("SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\" + logCapture, "Retention")
					?? ReadValueRaw("SYSTEM\\CurrentControlSet\\Services\\EventLog\\" + logCapture, "Retention");

				long? autoBackup = ToInt64Safe(autoBackupRaw);
				bool archiving = autoBackup == 1L;
				string retentionText = retentionRaw == null
					? "Non configuré (écrasement au besoin par défaut)"
					: DescribeRetention(retentionRaw);

				return new SecurityResult
				{
					Category = Category,
					CheckName = "Rétention du journal : " + logCapture,
					CurrentValue = "AutoBackupLogFiles=" + (autoBackup.HasValue ? autoBackup.Value.ToString(CultureInfo.InvariantCulture) : "Non configuré")
						+ (archiving ? " (archivage automatique activé)" : "") + ", Retention=" + retentionText,
					ExpectedValue = "Archivage avant écrasement sur systèmes critiques",
					Status = SecurityStatus.Info,
					Description = "Le mode de rétention détermine le comportement lorsque le journal « " + logCapture + " » est plein. "
						+ "AutoBackupLogFiles=1 force l'archivage du journal (fichier .evtx) avant tout écrasement, évitant la perte d'événements. "
						+ "Ne pas écraser sans archivage sur les systèmes critiques.",
					Recommendation = archiving
						? "L'archivage automatique est activé pour le journal « " + logCapture + " »."
						: "Sur les systèmes critiques, envisager d'activer l'archivage automatique (AutoBackupLogFiles=1) et une taille de journal adaptée, ou une centralisation via une solution SIEM/forwarding.",
					Reference = "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-log-policy-settings"
				};
			});
		}
	}

	// Décrit la valeur de rétention (REG_DWORD) de façon lisible.
	private static string DescribeRetention(object raw)
	{
		long? val = ToInt64Safe(raw);
		if (!val.HasValue)
		{
			return raw?.ToString() ?? "Inconnu";
		}
		return val.Value switch
		{
			0L => "0 (écraser les événements au besoin)",
			-1L => "-1 / 0xFFFFFFFF (ne pas écraser, archivage manuel requis)",
			4294967295L => "0xFFFFFFFF (ne pas écraser, archivage manuel requis)",
			_ => val.Value.ToString(CultureInfo.InvariantCulture) + " (durée de rétention en secondes)"
		};
	}

	// Lit la valeur MaxSize sous le chemin HKLM indiqué (Registry64). Retourne null si absente.
	private static object ReadMaxSizeRaw(string subPath)
	{
		return ReadValueRaw(subPath, "MaxSize");
	}

	// Lecture générique d'une valeur du registre HKLM en vue 64 bits. Retourne null si absente.
	private static object ReadValueRaw(string subPath, string valueName)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey subKey = baseKey.OpenSubKey(subPath);
			object value = subKey?.GetValue(valueName);
			return (value is DBNull) ? null : value;
		}
		catch
		{
			return null;
		}
	}

	// Conversion défensive d'une valeur de registre en Int64.
	private static long? ToInt64Safe(object value)
	{
		if (value == null || value is DBNull)
		{
			return null;
		}
		try
		{
			return Convert.ToInt64(value, CultureInfo.InvariantCulture);
		}
		catch
		{
			// Certaines valeurs REG_DWORD peuvent être stockées en tant que texte.
			if (long.TryParse(value.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsed))
			{
				return parsed;
			}
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
				Category = "Journaux",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}
}
