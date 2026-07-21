using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using CHECKSEC.Core.Models;
using CHECKSEC.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using WinRT;

namespace CHECKSEC.ViewModels;

public partial class GapsViewModel : ObservableObject
{
	private readonly AnalysisService _analysis;

	private List<ComplianceGap> _allGaps = new List<ComplianceGap>();

	[ObservableProperty]
	private bool _hasResults;

	[ObservableProperty]
	private bool _isLoading;

	[ObservableProperty]
	private int _criticalCount;

	[ObservableProperty]
	private int _highCount;

	[ObservableProperty]
	private int _mediumCount;

	[ObservableProperty]
	private int _lowCount;

	[ObservableProperty]
	private int _totalCount;

	[ObservableProperty]
	private string _filterSeverity = "Toutes";

	[ObservableProperty]
	private string _searchText = string.Empty;

	[ObservableProperty]
	private bool _isExporting;

	private bool _dataLoaded;

	public ObservableCollection<ComplianceGap> Gaps { get; } = new ObservableCollection<ComplianceGap>();

	public GapsViewModel(AnalysisService analysis)
	{
		_analysis = analysis;
	}

	public void Refresh()
	{
		IsLoading = true;
		try
		{
			_allGaps = _analysis.Gaps.ToList();
			HasResults = _allGaps.Count > 0;
			TotalCount = _allGaps.Count;
			int criticalCount = 0;
			int highCount = 0;
			int mediumCount = 0;
			int lowCount = 0;
			using (List<ComplianceGap>.Enumerator enumerator = _allGaps.GetEnumerator())
			{
				while (enumerator.MoveNext())
				{
					switch (enumerator.Current.Severity)
					{
					case GapSeverity.Critical:
						criticalCount++;
						break;
					case GapSeverity.High:
						highCount++;
						break;
					case GapSeverity.Medium:
						mediumCount++;
						break;
					case GapSeverity.Low:
						lowCount++;
						break;
					}
				}
			}
			CriticalCount = criticalCount;
			HighCount = highCount;
			MediumCount = mediumCount;
			LowCount = lowCount;
			ApplyFilter();
			_dataLoaded = true;
		}
		finally
		{
			IsLoading = false;
		}
	}

	public void LoadIfNeeded()
	{
		if (!_dataLoaded)
		{
			Refresh();
		}
	}

	public void ApplyFilter()
	{
		Gaps.Clear();
		IEnumerable<ComplianceGap> query = _allGaps.AsEnumerable();
		if (FilterSeverity != "Toutes")
		{
			if (Enum.TryParse<GapSeverity>(FilterSeverity, out var sev))
			{
				query = query.Where((ComplianceGap g) => g.Severity == sev);
			}
		}
		if (!string.IsNullOrWhiteSpace(SearchText))
		{
			string search = SearchText.Trim();
			query = query.Where(delegate(ComplianceGap g)
			{
				string policyName = g.PolicyName;
				if (policyName == null || !policyName.Contains(search, StringComparison.OrdinalIgnoreCase))
				{
					string registryPath = g.RegistryPath;
					if (registryPath == null || !registryPath.Contains(search, StringComparison.OrdinalIgnoreCase))
					{
						string gpoName = g.GpoName;
						if (gpoName == null || !gpoName.Contains(search, StringComparison.OrdinalIgnoreCase))
						{
							return g.Description?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false;
						}
					}
				}
				return true;
			});
		}
		foreach (ComplianceGap item in query)
		{
			Gaps.Add(item);
		}
	}
}
