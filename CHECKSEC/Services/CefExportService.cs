using System;
using System.Linq;
using System.Text;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Services;

public class CefExportService
{
	public string GenerateCef(AnalysisService analysis)
	{
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.AppendLine(FormatCef("CHECKSEC", "SecurityAudit", "AuditComplete", "Audit Complete", (analysis.GlobalScore >= 75.0) ? 3 : ((analysis.GlobalScore >= 50.0) ? 6 : 9), $"score={analysis.GlobalScore} grade={analysis.GlobalGrade} ok={analysis.TotalOK} warn={analysis.TotalWarning} crit={analysis.TotalCritical} err={analysis.TotalError} machine={Environment.MachineName}"));
		foreach (SecurityResult criticalResult in analysis.AllResults.Where((SecurityResult r) => r.Status == SecurityStatus.Critical))
		{
			stringBuilder.AppendLine(FormatCef("CHECKSEC", "SecurityCheck", "CriticalFinding", criticalResult.CheckName, 9, $"cat={Esc(criticalResult.Category)} cs1={Esc(criticalResult.CurrentValue)} cs1Label=CurrentValue cs2={Esc(criticalResult.ExpectedValue)} cs2Label=ExpectedValue cs3={Esc(criticalResult.Recommendation)} cs3Label=Recommendation msg={Esc(criticalResult.Description)}"));
		}
		foreach (SecurityResult warningResult in analysis.AllResults.Where((SecurityResult r) => r.Status == SecurityStatus.Warning))
		{
			stringBuilder.AppendLine(FormatCef("CHECKSEC", "SecurityCheck", "WarningFinding", warningResult.CheckName, 5, $"cat={Esc(warningResult.Category)} cs1={Esc(warningResult.CurrentValue)} cs1Label=CurrentValue cs2={Esc(warningResult.ExpectedValue)} cs2Label=ExpectedValue cs3={Esc(warningResult.Recommendation)} cs3Label=Recommendation msg={Esc(warningResult.Description)}"));
		}
		foreach (ComplianceGap gap in analysis.Gaps.Where((ComplianceGap g) => !g.IsCompliant))
		{
			int severity = gap.Severity switch
			{
				GapSeverity.Critical => 9, 
				GapSeverity.High => 7, 
				GapSeverity.Medium => 5, 
				_ => 3, 
			};
			stringBuilder.AppendLine(FormatCef("CHECKSEC", "MSCTCompliance", "ComplianceGap", gap.PolicyName, severity, $"cs1={Esc(gap.RegistryPath)} cs1Label=RegistryPath cs2={Esc(gap.BaselineValue)} cs2Label=ExpectedValue cs3={Esc(gap.CurrentValue)} cs3Label=ActualValue severity={gap.Severity}"));
		}
		return stringBuilder.ToString();
	}

	private static string FormatCef(string vendor, string product, string eventClass, string name, int severity, string extensions)
	{
		string timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
		return $"CEF:0|{vendor}|{product}|6.0|{eventClass}|{EscPipe(name)}|{severity}|rt={timestamp} dvchost={Environment.MachineName} {extensions}";
	}

	private static string Esc(string? s)
	{
		return (s ?? "").Replace("\\", "\\\\").Replace("=", "\\=").Replace("[", "\\[")
			.Replace("]", "\\]")
			.Replace("\n", " ")
			.Replace("\r", "");
	}

	private static string EscPipe(string? s)
	{
		return (s ?? "").Replace("|", "\\|");
	}
}
