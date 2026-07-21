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

public partial class CisViewModel : ObservableObject
{
	private readonly AnalysisService _analysis;

	private List<CisBenchmarkItem> _allCisItems = new List<CisBenchmarkItem>();

	[ObservableProperty]
	private bool _hasResults;

	[ObservableProperty]
	private bool _isLoading;

	[ObservableProperty]
	private int _passCount;

	[ObservableProperty]
	private int _failCount;

	[ObservableProperty]
	private int _manualCount;

	[ObservableProperty]
	private int _totalCount;

	[ObservableProperty]
	private string _filterStatus = "Tous";

	[ObservableProperty]
	private string _searchText = string.Empty;

	[ObservableProperty]
	private bool _isExporting;

	private bool _dataLoaded;

	public ObservableCollection<CisBenchmarkItem> CisResults { get; } = new ObservableCollection<CisBenchmarkItem>();

	public CisViewModel(AnalysisService analysis)
	{
		_analysis = analysis;
	}

	public void Refresh()
	{
		IsLoading = true;
		try
		{
			_allCisItems = _analysis.CisItems.ToList();
			HasResults = _allCisItems.Count > 0;
			TotalCount = _allCisItems.Count;
			int passCount = 0;
			int failCount = 0;
			int manualCount = 0;
			using (List<CisBenchmarkItem>.Enumerator enumerator = _allCisItems.GetEnumerator())
			{
				while (enumerator.MoveNext())
				{
					switch (enumerator.Current.Status)
					{
					case "Pass":
						passCount++;
						break;
					case "Fail":
						failCount++;
						break;
					case "Manual":
						manualCount++;
						break;
					}
				}
			}
			PassCount = passCount;
			FailCount = failCount;
			ManualCount = manualCount;
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
		CisResults.Clear();
		IEnumerable<CisBenchmarkItem> query = _allCisItems.AsEnumerable();
		if (FilterStatus != "Tous")
		{
			query = query.Where((CisBenchmarkItem c) => c.Status.Equals(FilterStatus, StringComparison.OrdinalIgnoreCase));
		}
		if (!string.IsNullOrWhiteSpace(SearchText))
		{
			string search = SearchText.Trim();
			query = query.Where(delegate(CisBenchmarkItem c)
			{
				string cisId = c.CisId;
				if (cisId == null || !cisId.Contains(search, StringComparison.OrdinalIgnoreCase))
				{
					string title = c.Title;
					if (title == null || !title.Contains(search, StringComparison.OrdinalIgnoreCase))
					{
						string section = c.Section;
						if (section == null || !section.Contains(search, StringComparison.OrdinalIgnoreCase))
						{
							return c.Remediation?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false;
						}
					}
				}
				return true;
			});
		}
		foreach (CisBenchmarkItem item in query)
		{
			CisResults.Add(item);
		}
	}
}
