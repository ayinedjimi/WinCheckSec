using System;
using System.Collections.Generic;

namespace CHECKSEC.Core.Models;

public class CollectorReport
{
	public string CollectorName { get; set; } = string.Empty;

	public List<SecurityResult> Results { get; set; } = new List<SecurityResult>();

	public string? ErrorMessage { get; set; }

	public TimeSpan Duration { get; set; }

	public bool Success => ErrorMessage == null;
}
