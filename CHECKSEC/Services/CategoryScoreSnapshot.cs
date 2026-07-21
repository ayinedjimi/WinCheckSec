namespace CHECKSEC.Services;

public class CategoryScoreSnapshot
{
	public string Category { get; set; } = string.Empty;

	public string Grade { get; set; } = string.Empty;

	public double ScorePercent { get; set; }

	public int PassedChecks { get; set; }

	public int WarningChecks { get; set; }

	public int CriticalChecks { get; set; }
}
