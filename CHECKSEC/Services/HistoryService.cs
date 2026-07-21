using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services;

namespace CHECKSEC.Services;

public class HistoryService
{
	private static readonly string HistoryDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CHECKSEC", "history");

	private List<AnalysisSnapshot> _snapshots = new List<AnalysisSnapshot>();

	public IReadOnlyList<AnalysisSnapshot> Snapshots => _snapshots.AsReadOnly();

	public HistoryService()
	{
		Directory.CreateDirectory(HistoryDir);
		LoadAll();
	}

	public void SaveSnapshot(AnalysisService analysis)
	{
		AnalysisSnapshot analysisSnapshot = new AnalysisSnapshot
		{
			GlobalScore = analysis.GlobalScore,
			GlobalGrade = analysis.GlobalGrade,
			TotalOK = analysis.TotalOK,
			TotalWarning = analysis.TotalWarning,
			TotalCritical = analysis.TotalCritical,
			TotalError = analysis.TotalError,
			TotalChecks = analysis.AllResults.Count,
			CategoryScores = analysis.CategoryScores.Select((SecurityScore s) => new CategoryScoreSnapshot
			{
				Category = s.Category,
				Grade = s.Grade,
				ScorePercent = s.ScorePercent,
				PassedChecks = s.PassedChecks,
				WarningChecks = s.WarningChecks,
				CriticalChecks = s.CriticalChecks
			}).ToList(),
			SecureCoreItems = analysis.SecureCoreItems.Select((SecureCoreItem i) => new SecureCoreSnapshot
			{
				Name = i.Name,
				Status = i.Status,
				Value = i.Value
			}).ToList()
		};
		string path = Path.Combine(HistoryDir, $"{analysisSnapshot.Id}_{analysisSnapshot.Timestamp:yyyyMMdd_HHmmss}.json");
		string contents = JsonSerializer.Serialize(analysisSnapshot, new JsonSerializerOptions
		{
			WriteIndented = true
		});
		File.WriteAllText(path, contents);
		_snapshots.Insert(0, analysisSnapshot);
	}

	public void LoadAll()
	{
		_snapshots.Clear();
		if (!Directory.Exists(HistoryDir))
		{
			return;
		}
		string fullPath = Path.GetFullPath(HistoryDir);
		foreach (string file in from f in Directory.GetFiles(HistoryDir, "*.json")
			orderby f descending
			select f)
		{
			try
			{
				string fullPath2 = Path.GetFullPath(file);
				if (fullPath2.StartsWith(fullPath, StringComparison.OrdinalIgnoreCase))
				{
					AnalysisSnapshot analysisSnapshot = JsonSerializer.Deserialize<AnalysisSnapshot>(File.ReadAllText(fullPath2));
					if (analysisSnapshot != null)
					{
						_snapshots.Add(analysisSnapshot);
					}
				}
			}
			catch (Exception ex)
			{
				ErrorLogger.Log(LogLevel.Warning, "Skipping corrupt history file " + file + ": " + ex.Message);
			}
		}
	}

	public void DeleteSnapshot(string id)
	{
		if (string.IsNullOrEmpty(id) || !id.All((char c) => char.IsLetterOrDigit(c)))
		{
			ErrorLogger.Log(LogLevel.Warning, "Invalid snapshot id rejected: '" + id + "'");
			return;
		}
		try
		{
			string[] files = Directory.GetFiles(HistoryDir, id + "_*.json");
			for (int i = 0; i < files.Length; i++)
			{
				string fullPath = Path.GetFullPath(files[i]);
				if (fullPath.StartsWith(Path.GetFullPath(HistoryDir), StringComparison.OrdinalIgnoreCase))
				{
					File.Delete(fullPath);
				}
			}
		}
		catch (Exception ex)
		{
			ErrorLogger.Log(LogLevel.Error, "Failed to delete snapshot '" + id + "': " + ex.Message, ex);
		}
		_snapshots.RemoveAll((AnalysisSnapshot s) => s.Id == id);
	}
}
