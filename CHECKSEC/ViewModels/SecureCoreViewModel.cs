using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using CHECKSEC.Core.Models;
using CHECKSEC.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using WinRT;

namespace CHECKSEC.ViewModels;

public partial class SecureCoreViewModel : ObservableObject
{
	private readonly AnalysisService _analysis;

	[ObservableProperty]
	private bool _hasResults;

	[ObservableProperty]
	private bool _isLoading;

	private bool _dataLoaded;

	public ObservableCollection<SecureCoreItem> Items { get; } = new ObservableCollection<SecureCoreItem>();

	public SecureCoreViewModel(AnalysisService analysis)
	{
		_analysis = analysis;
	}

	public void Refresh()
	{
		IsLoading = true;
		try
		{
			Items.Clear();
			foreach (SecureCoreItem secureCoreItem in _analysis.SecureCoreItems)
			{
				Items.Add(secureCoreItem);
			}
			HasResults = Items.Count > 0;
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
