using System;
using System.Collections.Generic;

namespace CHECKSEC.Services;

public class AnalysisSnapshot
{
	public string Id { get; set; } = Guid.NewGuid().ToString("N").Substring(0, 8);

	public DateTime Timestamp { get; set; } = DateTime.Now;

	public string MachineName { get; set; } = Environment.MachineName;

	public double GlobalScore { get; set; }

	public string GlobalGrade { get; set; } = "—";

	public int TotalOK { get; set; }

	public int TotalWarning { get; set; }

	public int TotalCritical { get; set; }

	public int TotalError { get; set; }

	public int TotalChecks { get; set; }

	public List<CategoryScoreSnapshot> CategoryScores { get; set; } = new List<CategoryScoreSnapshot>();

	public List<SecureCoreSnapshot> SecureCoreItems { get; set; } = new List<SecureCoreSnapshot>();
}
