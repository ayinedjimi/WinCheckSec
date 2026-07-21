using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services.Analysis;
using CHECKSEC.Core.Services.Helpers;

namespace CHECKSEC.Core.Services.Collectors;

public class CisFallbackCollector : ISecurityCollector
{
	public string Name => "CisFallbackCollector";

	public string Category => "CIS Manual Fallbacks";

	public async Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		try
		{
			await Task.Run(delegate
			{
				foreach (CisBenchmarkMapper.CisMapping mapping in CisBenchmarkMapper.Mappings.Where((CisBenchmarkMapper.CisMapping candidate) => candidate.CheckNameContains != null && candidate.CheckNameContains.Any((string checkName) => checkName.StartsWith("CISFallback_"))).ToList())
				{
					ct.ThrowIfCancellationRequested();
					// Correctif D: libellé explicite au lieu de "(Automated check missing logic)".
					string currentValue = "Vérification manuelle requise";
					bool isCompliant = false;
					// evaluated=true uniquement si une comparaison registre réelle a eu lieu.
					bool evaluated = false;
					bool errored = false;
					if (mapping.Remediation.Contains("Set HKLM\\"))
					{
						try
						{
							int setIndex = mapping.Remediation.IndexOf("Set HKLM\\");
							int equalsIndex = mapping.Remediation.IndexOf('=', setIndex);
							if (setIndex > -1 && equalsIndex > setIndex)
							{
								string registryPath = mapping.Remediation.Substring(setIndex + 9, equalsIndex - (setIndex + 9)).Trim();
								string expectedToken = mapping.Remediation.Substring(equalsIndex + 1).Trim().Split(new char[2] { ' ', '.' }, StringSplitOptions.RemoveEmptyEntries)[0];
								int lastSeparatorIndex = registryPath.LastIndexOf('\\');
								if (lastSeparatorIndex > 0)
								{
									string subKey = registryPath.Substring(0, lastSeparatorIndex);
									string valueName = registryPath.Substring(lastSeparatorIndex + 1);
									string stringValue = RegistryHelper.GetString(subKey, valueName);
									if (stringValue != null)
									{
										currentValue = stringValue;
										isCompliant = currentValue == expectedToken;
										evaluated = true;
									}
									else
									{
										int dwordValue = RegistryHelper.GetDword(subKey, valueName, -999);
										if (dwordValue != -999)
										{
											currentValue = dwordValue.ToString();
											isCompliant = currentValue == expectedToken;
											evaluated = true;
										}
										else
										{
											currentValue = "Non défini (Manquant)";
											evaluated = true;
										}
									}
								}
							}
						}
						catch (Exception exReg)
						{
							// Correctif D: journalise l'erreur au lieu de l'avaler; résultat en erreur explicite.
							ErrorLogger.AddError($"[CisFallback] {mapping.CisId} - Erreur registre: {exReg.GetType().Name}: {exReg.Message}");
							currentValue = "Erreur de vérification";
							evaluated = false;
							errored = true;
						}
					}
					else
					{
						// Correctif D: contrôle NON réellement évalué → Info (n'affecte pas le score).
						currentValue = "Vérification manuelle requise";
					}
					// Status: OK/Warning uniquement pour un contrôle réellement évalué;
					// Error si exception; sinon Info (non évalué, exclu du scoring).
					SecurityStatus status = errored
						? SecurityStatus.Error
						: (evaluated ? (isCompliant ? SecurityStatus.OK : SecurityStatus.Warning) : SecurityStatus.Info);
					report.Results.Add(new SecurityResult
					{
						Category = "CIS Benchmark",
						CheckName = "CISFallback_" + mapping.CisId,
						CurrentValue = currentValue,
						ExpectedValue = mapping.ExpectedValue,
						Status = status,
						Description = "[Automated fallback attempt] " + mapping.Title,
						Recommendation = mapping.Remediation,
						CollectedAt = DateTime.Now
					});
				}
			}, ct);
		}
		catch (Exception ex)
		{
			report.ErrorMessage = ex.Message;
		}
		return report;
	}
}
