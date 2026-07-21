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

public partial class ResultsViewModel : ObservableObject
{
	private readonly AnalysisService _analysis;

	[ObservableProperty]
	private string _resultText = string.Empty;

	[ObservableProperty]
	private bool _hasResults;

	[ObservableProperty]
	private bool _isLoading;

	[ObservableProperty]
	private string _filterStatus = "Tous";

	[ObservableProperty]
	private string _searchText = string.Empty;

	[ObservableProperty]
	private int _totalCount;

	[ObservableProperty]
	private int _okCount;

	[ObservableProperty]
	private int _warningCount;

	[ObservableProperty]
	private int _criticalCount;

	[ObservableProperty]
	private int _errorCount;

	[ObservableProperty]
	private bool _isExporting;

	private List<SecurityResult> _allResults = new List<SecurityResult>();

	private bool _dataLoaded;

	public ObservableCollection<SecurityResult> FilteredResults { get; } = new ObservableCollection<SecurityResult>();

	public ResultsViewModel(AnalysisService analysis)
	{
		_analysis = analysis;
	}

	public void Refresh()
	{
		IsLoading = true;
		try
		{
			ResultText = _analysis.ResultText;
			_allResults = _analysis.AllResults.ToList();
			HasResults = _allResults.Count > 0;
			int okCount = 0;
			int warningCount = 0;
			int criticalCount = 0;
			int errorCount = 0;
			using (List<SecurityResult>.Enumerator enumerator = _allResults.GetEnumerator())
			{
				while (enumerator.MoveNext())
				{
					switch (enumerator.Current.Status)
					{
					case SecurityStatus.OK:
						okCount++;
						break;
					case SecurityStatus.Warning:
						warningCount++;
						break;
					case SecurityStatus.Critical:
						criticalCount++;
						break;
					case SecurityStatus.Error:
					case SecurityStatus.NotApplicable:
						errorCount++;
						break;
					}
				}
			}
			OkCount = okCount;
			WarningCount = warningCount;
			CriticalCount = criticalCount;
			ErrorCount = errorCount;
			// Correctif M9 : TotalCount aligné sur la somme des badges affichés (exclut les Info non comptabilisés)
			TotalCount = okCount + warningCount + criticalCount + errorCount;
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
		IEnumerable<SecurityResult> query = _allResults.AsEnumerable();
		if (FilterStatus != "Tous")
		{
			SecurityStatus status = FilterStatus switch
			{
				"OK" => SecurityStatus.OK,
				"Warning" => SecurityStatus.Warning,
				"Critical" => SecurityStatus.Critical,
				"Error" => SecurityStatus.Error,
				_ => SecurityStatus.Info,
			};
			query = query.Where((SecurityResult r) => r.Status == status);
		}
		if (!string.IsNullOrWhiteSpace(SearchText))
		{
			string term = SearchText;
			query = query.Where(delegate(SecurityResult r)
			{
				string checkName = r.CheckName;
				if (checkName == null || !checkName.Contains(term, StringComparison.OrdinalIgnoreCase))
				{
					string category = r.Category;
					if (category == null || !category.Contains(term, StringComparison.OrdinalIgnoreCase))
					{
						string description = r.Description;
						if (description == null || !description.Contains(term, StringComparison.OrdinalIgnoreCase))
						{
							return r.CurrentValue?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false;
						}
					}
				}
				return true;
			});
		}
		FilteredResults.Clear();
		foreach (SecurityResult item in query)
		{
			FilteredResults.Add(item);
		}
	}
}
