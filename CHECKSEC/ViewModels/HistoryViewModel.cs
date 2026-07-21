using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using CHECKSEC.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinRT;

namespace CHECKSEC.ViewModels;

public partial class HistoryViewModel : ObservableObject
{
	private readonly HistoryService _history;

	[ObservableProperty]
	private bool _hasHistory;

	[ObservableProperty]
	private AnalysisSnapshot? _selectedSnapshot1;

	[ObservableProperty]
	private AnalysisSnapshot? _selectedSnapshot2;

	[ObservableProperty]
	private bool _hasComparison;

	[ObservableProperty]
	private string _comparisonSummary = string.Empty;

	[ObservableProperty]
	private double _scoreDelta;

	private bool _dataLoaded;

	public ObservableCollection<AnalysisSnapshot> Snapshots { get; } = new ObservableCollection<AnalysisSnapshot>();

	public ObservableCollection<ComparisonItem> ComparisonItems { get; } = new ObservableCollection<ComparisonItem>();

	public HistoryViewModel(HistoryService history)
	{
		_history = history;
	}

	public void Refresh()
	{
		_history.LoadAll();
		Snapshots.Clear();
		foreach (AnalysisSnapshot snapshot in _history.Snapshots)
		{
			Snapshots.Add(snapshot);
		}
		HasHistory = Snapshots.Count > 0;
		_dataLoaded = true;
	}

	public void LoadIfNeeded()
	{
		if (!_dataLoaded)
		{
			Refresh();
		}
	}

	[RelayCommand]
	private void Delete(AnalysisSnapshot snapshot)
	{
		_history.DeleteSnapshot(snapshot.Id);
		Snapshots.Remove(snapshot);
		HasHistory = Snapshots.Count > 0;
	}

	[RelayCommand]
	private void Compare()
	{
		if (SelectedSnapshot1 == null || SelectedSnapshot2 == null)
		{
			return;
		}
		ComparisonItems.Clear();
		ScoreDelta = SelectedSnapshot2.GlobalScore - SelectedSnapshot1.GlobalScore;
		foreach (CategoryScoreSnapshot categoryAfter in SelectedSnapshot2.CategoryScores)
		{
			CategoryScoreSnapshot categoryBefore = SelectedSnapshot1.CategoryScores.FirstOrDefault((CategoryScoreSnapshot c) => c.Category == categoryAfter.Category);
			ComparisonItems.Add(new ComparisonItem
			{
				Category = categoryAfter.Category,
				Before = (categoryBefore?.ScorePercent ?? 0.0),
				After = categoryAfter.ScorePercent,
				Delta = categoryAfter.ScorePercent - (categoryBefore?.ScorePercent ?? 0.0),
				GradeBefore = (categoryBefore?.Grade ?? "—"),
				GradeAfter = categoryAfter.Grade
			});
		}
		ComparisonSummary = ((ScoreDelta > 0.0) ? $"Amélioration de {ScoreDelta:+0.0}% ({SelectedSnapshot1.GlobalGrade} → {SelectedSnapshot2.GlobalGrade})" : ((ScoreDelta < 0.0) ? $"Régression de {ScoreDelta:0.0}% ({SelectedSnapshot1.GlobalGrade} → {SelectedSnapshot2.GlobalGrade})" : "Aucun changement"));
		HasComparison = true;
	}
}
