using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services;

namespace CHECKSEC.Services;

// Service d'export SARIF 2.1.0 (Static Analysis Results Interchange Format).
// Produit un rapport JSON standardisé exploitable par les chaînes CI/CD
// (GitHub code scanning, Azure DevOps) et les SIEM. Même style que CefExportService :
// une classe simple avec une méthode Generate...(AnalysisService) : string.
public class SarifExportService
{
	// Génère le document SARIF 2.1.0 complet à partir des résultats d'analyse.
	// Robuste : n'émet jamais d'exception (renvoie un SARIF vide en cas d'erreur).
	public string GenerateSarif(AnalysisService analysis)
	{
		try
		{
			// Version de l'assembly (repli sur "6.3.0" si indisponible).
			string toolVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "6.3.0";
			if (string.IsNullOrEmpty(toolVersion) || toolVersion == "0.0.0.0")
			{
				toolVersion = "6.3.0";
			}

			// On ne garde que les résultats problématiques (SARIF = liste de problèmes).
			// OK / Info / NotApplicable sont exclus.
			List<SecurityResult> findings = (analysis.AllResults ?? Enumerable.Empty<SecurityResult>())
				.Where(r => r != null && (r.Status == SecurityStatus.Critical
					|| r.Status == SecurityStatus.Warning
					|| r.Status == SecurityStatus.Error))
				.ToList();

			// Construction des règles : une règle par CheckName DISTINCT.
			// Le slug (id de règle) doit être stable et dédupliqué.
			HashSet<string> usedRuleIds = new HashSet<string>(StringComparer.Ordinal);
			Dictionary<string, string> checkNameToRuleId = new Dictionary<string, string>(StringComparer.Ordinal);
			List<object> rules = new List<object>();

			foreach (SecurityResult finding in findings)
			{
				string checkName = finding.CheckName ?? string.Empty;
				if (checkNameToRuleId.ContainsKey(checkName))
				{
					continue;
				}

				string ruleId = MakeStableSlug(checkName, usedRuleIds);
				checkNameToRuleId[checkName] = ruleId;

				// helpUri = la Reference du résultat si disponible.
				object rule;
				string helpUri = finding.Reference ?? string.Empty;
				if (!string.IsNullOrWhiteSpace(helpUri))
				{
					rule = new
					{
						id = ruleId,
						name = string.IsNullOrEmpty(checkName) ? ruleId : checkName,
						shortDescription = new { text = string.IsNullOrEmpty(checkName) ? ruleId : checkName },
						helpUri,
						properties = new { category = finding.Category ?? string.Empty }
					};
				}
				else
				{
					rule = new
					{
						id = ruleId,
						name = string.IsNullOrEmpty(checkName) ? ruleId : checkName,
						shortDescription = new { text = string.IsNullOrEmpty(checkName) ? ruleId : checkName },
						properties = new { category = finding.Category ?? string.Empty }
					};
				}
				rules.Add(rule);
			}

			// Construction des résultats SARIF (un par finding non-OK).
			List<object> results = new List<object>();
			foreach (SecurityResult finding in findings)
			{
				string checkName = finding.CheckName ?? string.Empty;
				string ruleId = checkNameToRuleId.TryGetValue(checkName, out string? mappedId)
					? mappedId
					: MakeStableSlug(checkName, usedRuleIds);

				// Mappage niveau CHECKSEC -> niveau SARIF.
				string level = finding.Status switch
				{
					SecurityStatus.Critical => "error",
					SecurityStatus.Warning => "warning",
					SecurityStatus.Error => "note",
					_ => "note"
				};

				// message.text = CheckName + " : " + CurrentValue + (Recommendation).
				StringBuilder messageBuilder = new StringBuilder();
				messageBuilder.Append(checkName);
				messageBuilder.Append(" : ");
				messageBuilder.Append(finding.CurrentValue ?? string.Empty);
				if (!string.IsNullOrWhiteSpace(finding.Recommendation))
				{
					messageBuilder.Append(" — ");
					messageBuilder.Append(finding.Recommendation);
				}

				// Le registre / WMI n'a pas de fichier : on utilise un logicalLocation
				// (nom de catégorie / collecteur) plutôt qu'une location physique.
				string logicalName = string.IsNullOrWhiteSpace(finding.Category) ? "CHECKSEC" : finding.Category;

				results.Add(new
				{
					ruleId,
					level,
					message = new { text = messageBuilder.ToString() },
					locations = new[]
					{
						new
						{
							logicalLocations = new[]
							{
								new { name = logicalName, kind = "namespace" }
							}
						}
					},
					properties = new
					{
						category = finding.Category ?? string.Empty,
						currentValue = finding.CurrentValue ?? string.Empty,
						expectedValue = finding.ExpectedValue ?? string.Empty,
						status = finding.Status.ToString()
					}
				});
			}

			// Document SARIF 2.1.0 minimal valide.
			object sarif = new
			{
				schema = "https://json.schemastore.org/sarif-2.1.0.json",
				version = "2.1.0",
				runs = new[]
				{
					new
					{
						tool = new
						{
							driver = new
							{
								name = "CHECKSEC",
								version = toolVersion,
								informationUri = "https://github.com/ayinedjimi/CHECKSEC",
								rules
							}
						},
						results
					}
				}
			};

			JsonSerializerOptions options = new JsonSerializerOptions
			{
				WriteIndented = true,
				// Le nom de propriété "$schema" doit être écrit littéralement.
				Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
			};

			// System.Text.Json ne permet pas un nom de propriété commençant par "$"
			// via un type anonyme. On sérialise puis on renomme "schema" -> "$schema".
			string json = JsonSerializer.Serialize(sarif, options);
			// La propriété "schema" est la toute première du document : on ne
			// renomme que sa première occurrence en "$schema" (évite toute
			// collision avec une valeur de champ contenant ce texte).
			int schemaIndex = json.IndexOf("\"schema\":", StringComparison.Ordinal);
			if (schemaIndex >= 0)
			{
				json = json.Substring(0, schemaIndex) + "\"$schema\":" + json.Substring(schemaIndex + "\"schema\":".Length);
			}
			return json;
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "[SarifExport] " + ex.Message, ex);
			// Repli : un document SARIF vide mais valide.
			return "{\n  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n  \"version\": \"2.1.0\",\n  \"runs\": [\n    {\n      \"tool\": { \"driver\": { \"name\": \"CHECKSEC\", \"version\": \"6.3.0\", \"informationUri\": \"https://github.com/ayinedjimi/CHECKSEC\", \"rules\": [] } },\n      \"results\": []\n    }\n  ]\n}";
		}
	}

	// Génère un identifiant de règle stable : slug du CheckName en minuscules,
	// tout caractère non alphanumérique -> "-", dédupliqué au sein du run.
	private static string MakeStableSlug(string checkName, HashSet<string> used)
	{
		StringBuilder slugBuilder = new StringBuilder();
		foreach (char c in (checkName ?? string.Empty).ToLowerInvariant())
		{
			if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
			{
				slugBuilder.Append(c);
			}
			else
			{
				slugBuilder.Append('-');
			}
		}

		// Nettoyage : fusion des tirets consécutifs et rognage des bords.
		string slug = slugBuilder.ToString();
		while (slug.Contains("--"))
		{
			slug = slug.Replace("--", "-");
		}
		slug = slug.Trim('-');
		if (string.IsNullOrEmpty(slug))
		{
			slug = "check";
		}

		// Déduplication : suffixe numérique si collision.
		string candidate = slug;
		int suffix = 2;
		while (!used.Add(candidate))
		{
			candidate = slug + "-" + suffix;
			suffix++;
		}
		return candidate;
	}
}
