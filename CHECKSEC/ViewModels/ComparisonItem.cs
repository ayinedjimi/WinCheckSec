namespace CHECKSEC.ViewModels;

public class ComparisonItem
{
	public string Category { get; set; } = string.Empty;

	public double Before { get; set; }

	public double After { get; set; }

	public double Delta { get; set; }

	public string GradeBefore { get; set; } = "—";

	public string GradeAfter { get; set; } = "—";

	public string DeltaLabel
	{
		get
		{
			if (!(Delta > 0.0))
			{
				if (!(Delta < 0.0))
				{
					return "=";
				}
				return $"{Delta:0.0}%";
			}
			return $"+{Delta:0.0}%";
		}
	}

	public string DeltaColorHex
	{
		get
		{
			if (!(Delta > 0.0))
			{
				if (!(Delta < 0.0))
				{
					return "#78909C";
				}
				return "#F44336";
			}
			return "#4CAF50";
		}
	}
}
