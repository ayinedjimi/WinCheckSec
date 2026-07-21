using System;
using System.Collections.Generic;
using System.Linq;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Services;

public class RemediationService
{
	public List<RemediationItem> GeneratePlan(AnalysisService analysis)
	{
		List<RemediationItem> plan = new List<RemediationItem>();
		int priority = 1;
		foreach (SecureCoreItem coreItem in analysis.SecureCoreItems.Where((SecureCoreItem i) => i.Status != SecurityStatus.OK))
		{
			List<RemediationItem> items = plan;
			RemediationItem remediationItem = new RemediationItem();
			remediationItem.Priority = priority++;
			remediationItem.Category = "Secure Core";
			remediationItem.Action = "Activer " + coreItem.Name;
			remediationItem.Detail = coreItem.TechnicalDescription;
			RemediationItem remediationItem2 = remediationItem;
			string name = coreItem.Name;
			bool isComplex = ((name == "TPM" || name == "Secure Boot") ? true : false);
			remediationItem2.Effort = (isComplex ? "Complexe" : "Moyen");
			remediationItem.Command = coreItem.Remediation;
			remediationItem.Severity = ((coreItem.Status == SecurityStatus.Critical) ? "Critical" : "High");
			items.Add(remediationItem);
		}
		foreach (SecurityResult criticalResult in analysis.AllResults.Where((SecurityResult r) => r.Status == SecurityStatus.Critical))
		{
			plan.Add(new RemediationItem
			{
				Priority = priority++,
				Category = criticalResult.Category,
				Action = criticalResult.CheckName,
				Detail = criticalResult.Description,
				Effort = EstimateEffort(criticalResult),
				Command = criticalResult.Recommendation,
				Severity = "Critical"
			});
		}
		foreach (SecurityResult warningResult in analysis.AllResults.Where((SecurityResult r) => r.Status == SecurityStatus.Warning))
		{
			plan.Add(new RemediationItem
			{
				Priority = priority++,
				Category = warningResult.Category,
				Action = warningResult.CheckName,
				Detail = warningResult.Description,
				Effort = EstimateEffort(warningResult),
				Command = warningResult.Recommendation,
				Severity = "Medium"
			});
		}
		foreach (ComplianceGap gap in from g in analysis.Gaps
			where !g.IsCompliant
			orderby g.Severity descending
			select g)
		{
			plan.Add(new RemediationItem
			{
				Priority = priority++,
				Category = "MSCT Compliance",
				Action = gap.PolicyName,
				Detail = gap.Description,
				Effort = "Quick Win",
				Command = "Reg: " + gap.RegistryPath + " = " + gap.BaselineValue,
				Severity = gap.Severity.ToString()
			});
		}
		return plan;
	}

	private static string EstimateEffort(SecurityResult r)
	{
		if (!string.IsNullOrEmpty(r.Recommendation) && r.Recommendation.Contains("reg", StringComparison.OrdinalIgnoreCase))
		{
			return "Quick Win";
		}
		// Correctif M8 : renvoyer un effort spécifique pour les mises à jour (au lieu du no-op qui jetait l'expression)
		if (r.Category.Contains("Update", StringComparison.OrdinalIgnoreCase) || r.Category.Contains("Mise à jour", StringComparison.OrdinalIgnoreCase))
		{
			return "Complexe";
		}
		return "Moyen";
	}
}
