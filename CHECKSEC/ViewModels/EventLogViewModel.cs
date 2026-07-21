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

public partial class EventLogViewModel : ObservableObject
{
	private readonly AnalysisService _analysis;

	[ObservableProperty]
	private string _eventLogText = string.Empty;

	[ObservableProperty]
	private bool _hasResults;

	[ObservableProperty]
	private bool _isLoading;

	[ObservableProperty]
	private int _totalCount;

	[ObservableProperty]
	private int _errorCount;

	[ObservableProperty]
	private int _warningCount;

	[ObservableProperty]
	private int _infoCount;

	[ObservableProperty]
	private string _filterLevel = "Tous";

	[ObservableProperty]
	private string _searchText = string.Empty;

	[ObservableProperty]
	private bool _isExporting;

	private List<EventLogEntry> _allEntries = new List<EventLogEntry>();

	private bool _dataLoaded;

	public ObservableCollection<EventLogEntry> FilteredEntries { get; } = new ObservableCollection<EventLogEntry>();

	public EventLogViewModel(AnalysisService analysis)
	{
		_analysis = analysis;
	}

	public void Refresh()
	{
		IsLoading = true;
		try
		{
			EventLogText = _analysis.EventLogText;
			_allEntries = _analysis.EventLogEntries.ToList();
			HasResults = _allEntries.Count > 0;
			TotalCount = _allEntries.Count;
			int errorCount = 0;
			int warningCount = 0;
			int infoCount = 0;
			foreach (EventLogEntry entry in _allEntries)
			{
				string level = entry.Level;
				if ((level == "Error" || level == "Critical") ? true : false)
				{
					errorCount++;
				}
				else if (entry.Level == "Warning")
				{
					warningCount++;
				}
				else if (entry.Level == "Information")
				{
					infoCount++;
				}
			}
			ErrorCount = errorCount;
			WarningCount = warningCount;
			InfoCount = infoCount;
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
		IEnumerable<EventLogEntry> query = _allEntries.AsEnumerable();
		if (FilterLevel != "Tous")
		{
			query = query.Where((EventLogEntry e) => e.Level == FilterLevel);
		}
		if (!string.IsNullOrWhiteSpace(SearchText))
		{
			string term = SearchText;
			query = query.Where(delegate(EventLogEntry e)
			{
				string source = e.Source;
				return (source != null && source.Contains(term, StringComparison.OrdinalIgnoreCase)) || (e.Message?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false);
			});
		}
		FilteredEntries.Clear();
		foreach (EventLogEntry item in query)
		{
			FilteredEntries.Add(item);
		}
	}
}
