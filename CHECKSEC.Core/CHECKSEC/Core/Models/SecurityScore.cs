using System;

namespace CHECKSEC.Core.Models;

public class SecurityScore
{
	public string Category { get; set; } = string.Empty;

	public string Icon { get; set; } = string.Empty;

	public int TotalChecks { get; set; }

	public int PassedChecks { get; set; }

	public int WarningChecks { get; set; }

	public int CriticalChecks { get; set; }

	public int ErrorChecks { get; set; }

	public int InfoChecks { get; set; }

	public double ScorePercent => ComputeScore(PassedChecks, WarningChecks, CriticalChecks, TotalChecks - InfoChecks);

	public string Grade => ComputeGrade(ScorePercent);

	public string GradeColorHex => Grade switch
	{
		"A" => "#4CAF50", 
		"B" => "#8BC34A", 
		"C" => "#FF9800", 
		"D" => "#FF5722", 
		"F" => "#F44336", 
		_ => "#78909C", 
	};

	public static double ComputeScore(int ok, int warning, int critical, int applicable)
	{
		if (applicable <= 0)
		{
			return (applicable == 0) ? 100 : 0;
		}
		return Math.Clamp(Math.Round(((double)ok * 1.0 + (double)warning * 0.5 + (double)critical * 0.0) / (double)applicable * 100.0, 1), 0.0, 100.0);
	}

	public static string ComputeGrade(double score)
	{
		if (!(score >= 85.0))
		{
			if (!(score >= 70.0))
			{
				if (!(score >= 55.0))
				{
					if (!(score >= 40.0))
					{
						return "F";
					}
					return "D";
				}
				return "C";
			}
			return "B";
		}
		return "A";
	}
}
