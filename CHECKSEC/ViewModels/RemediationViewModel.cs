using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using CHECKSEC.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using WinRT;

namespace CHECKSEC.ViewModels;

public partial class RemediationViewModel : ObservableObject
{
	private readonly AnalysisService _analysis;

	private readonly RemediationService _remediation;

	[ObservableProperty]
	private bool _hasResults;

	[ObservableProperty]
	private bool _isLoading;

	[ObservableProperty]
	private int _totalActions;

	[ObservableProperty]
	private int _criticalActions;

	[ObservableProperty]
	private int _quickWins;

	private bool _dataLoaded;

	public ObservableCollection<RemediationItem> Items { get; } = new ObservableCollection<RemediationItem>();

	public RemediationViewModel(AnalysisService analysis, RemediationService remediation)
	{
		_analysis = analysis;
		_remediation = remediation;
	}

	public void Refresh()
	{
		IsLoading = true;
		try
		{
			Items.Clear();
			foreach (RemediationItem item in _remediation.GeneratePlan(_analysis))
			{
				Items.Add(item);
			}
			HasResults = Items.Count > 0;
			TotalActions = Items.Count;
			CriticalActions = Items.Count((RemediationItem i) => i.Severity == "Critical");
			QuickWins = Items.Count((RemediationItem i) => i.Effort == "Quick Win");
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
}
