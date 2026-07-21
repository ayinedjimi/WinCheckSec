using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Core.Services.Analysis;

public class ReportGenerator
{
	[CompilerGenerated]
	private sealed class _003CWrapText_003Ed__18 : IEnumerable<string>, IEnumerable, IEnumerator<string>, IEnumerator, IDisposable
	{
		private int _003C_003E1__state;

		private string _003C_003E2__current;

		private int _003C_003El__initialThreadId;

		private string text;

		public string _003C_003E3__text;

		private string prefix;

		public string _003C_003E3__prefix;

		private string continuationIndent;

		public string _003C_003E3__continuationIndent;

		private int maxWidth;

		public int _003C_003E3__maxWidth;

		private bool _003CisFirst_003E5__2;

		private string[] _003C_003E7__wrap2;

		private int _003C_003E7__wrap3;

		private StringBuilder _003Cline_003E5__5;

		private string[] _003C_003E7__wrap5;

		private int _003C_003E7__wrap6;

		private string _003Cword_003E5__8;

		string IEnumerator<string>.Current
		{
			[DebuggerHidden]
			get
			{
				return _003C_003E2__current;
			}
		}

		object IEnumerator.Current
		{
			[DebuggerHidden]
			get
			{
				return _003C_003E2__current;
			}
		}

		[DebuggerHidden]
		public _003CWrapText_003Ed__18(int _003C_003E1__state)
		{
			this._003C_003E1__state = _003C_003E1__state;
			_003C_003El__initialThreadId = Environment.CurrentManagedThreadId;
		}

		[DebuggerHidden]
		void IDisposable.Dispose()
		{
			_003C_003E7__wrap2 = null;
			_003Cline_003E5__5 = null;
			_003C_003E7__wrap5 = null;
			_003Cword_003E5__8 = null;
			_003C_003E1__state = -2;
		}

		private bool MoveNext()
		{
			string text;
			int num;
			switch (_003C_003E1__state)
			{
			default:
				return false;
			case 0:
			{
				_003C_003E1__state = -1;
				if (string.IsNullOrWhiteSpace(this.text))
				{
					return false;
				}
				string[] array = this.text.Split('\n');
				_003CisFirst_003E5__2 = true;
				_003C_003E7__wrap2 = array;
				_003C_003E7__wrap3 = 0;
				goto IL_023c;
			}
			case 1:
				_003C_003E1__state = -1;
				goto IL_022e;
			case 2:
				_003C_003E1__state = -1;
				_003Cline_003E5__5.Clear();
				text = continuationIndent;
				num = maxWidth - continuationIndent.Length;
				goto IL_0195;
			case 3:
				{
					_003C_003E1__state = -1;
					goto IL_0227;
				}
				IL_0195:
				if (_003Cline_003E5__5.Length > 0)
				{
					_003Cline_003E5__5.Append(' ');
				}
				_003Cline_003E5__5.Append(_003Cword_003E5__8);
				_003Cword_003E5__8 = null;
				_003C_003E7__wrap6++;
				goto IL_01d8;
				IL_01d8:
				if (_003C_003E7__wrap6 < _003C_003E7__wrap5.Length)
				{
					_003Cword_003E5__8 = _003C_003E7__wrap5[_003C_003E7__wrap6];
					if (_003Cline_003E5__5.Length + _003Cword_003E5__8.Length + ((_003Cline_003E5__5.Length > 0) ? 1 : 0) > num)
					{
						_003C_003E2__current = text + _003Cline_003E5__5.ToString();
						_003C_003E1__state = 2;
						return true;
					}
					goto IL_0195;
				}
				_003C_003E7__wrap5 = null;
				if (_003Cline_003E5__5.Length > 0)
				{
					_003C_003E2__current = text + _003Cline_003E5__5.ToString();
					_003C_003E1__state = 3;
					return true;
				}
				goto IL_0227;
				IL_023c:
				if (_003C_003E7__wrap3 < _003C_003E7__wrap2.Length)
				{
					string text2 = _003C_003E7__wrap2[_003C_003E7__wrap3].TrimEnd('\r');
					if (!string.IsNullOrWhiteSpace(text2))
					{
						text = (_003CisFirst_003E5__2 ? prefix : continuationIndent);
						_003CisFirst_003E5__2 = false;
						num = maxWidth - text.Length;
						if (num <= 0)
						{
							num = 40;
						}
						if (text2.Length <= num)
						{
							_003C_003E2__current = text + text2;
							_003C_003E1__state = 1;
							return true;
						}
						string[] array2 = text2.Split(' ');
						_003Cline_003E5__5 = new StringBuilder();
						_003C_003E7__wrap5 = array2;
						_003C_003E7__wrap6 = 0;
						goto IL_01d8;
					}
					goto IL_022e;
				}
				_003C_003E7__wrap2 = null;
				return false;
				IL_0227:
				_003Cline_003E5__5 = null;
				goto IL_022e;
				IL_022e:
				_003C_003E7__wrap3++;
				goto IL_023c;
			}
		}

		bool IEnumerator.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			return this.MoveNext();
		}

		[DebuggerHidden]
		void IEnumerator.Reset()
		{
			throw new NotSupportedException();
		}

		[DebuggerHidden]
		IEnumerator<string> IEnumerable<string>.GetEnumerator()
		{
			_003CWrapText_003Ed__18 _003CWrapText_003Ed__;
			if (_003C_003E1__state == -2 && _003C_003El__initialThreadId == Environment.CurrentManagedThreadId)
			{
				_003C_003E1__state = 0;
				_003CWrapText_003Ed__ = this;
			}
			else
			{
				_003CWrapText_003Ed__ = new _003CWrapText_003Ed__18(0);
			}
			_003CWrapText_003Ed__.text = _003C_003E3__text;
			_003CWrapText_003Ed__.maxWidth = _003C_003E3__maxWidth;
			_003CWrapText_003Ed__.continuationIndent = _003C_003E3__continuationIndent;
			_003CWrapText_003Ed__.prefix = _003C_003E3__prefix;
			return _003CWrapText_003Ed__;
		}

		[DebuggerHidden]
		IEnumerator IEnumerable.GetEnumerator()
		{
			return ((IEnumerable<string>)this).GetEnumerator();
		}
	}

	private static readonly CultureInfo FrFr = CultureInfo.GetCultureInfo("fr-FR");

	private const string IconOK = "✅";

	private const string IconWarning = "⚠\ufe0f ";

	private const string IconCritical = "❌";

	private const string IconError = "\ud83d\udd34";

	private const string IconInfo = "ℹ\ufe0f ";

	private const string IconNotApplicable = "➖";

	private const string ToolVersion = "1.0.0";

	public async Task GenerateAsync(string outputPath, List<CollectorReport> reports, List<ComplianceGap> gaps, CancellationToken ct = default(CancellationToken))
	{
		string directoryName = Path.GetDirectoryName(outputPath);
		if (!string.IsNullOrEmpty(directoryName) && !Directory.Exists(directoryName))
		{
			Directory.CreateDirectory(directoryName);
		}
		UTF8Encoding encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);
		await using StreamWriter writer = new StreamWriter(outputPath, append: false, encoding);
		await WriteHeaderAsync(writer, ct);
		await WriteExecutiveSummaryAsync(writer, reports, gaps, ct);
		await WriteCollectorSectionsAsync(writer, reports, ct);
		await WriteMsctGapSectionAsync(writer, gaps, ct);
		await WriteFooterAsync(writer, ct);
		await writer.FlushAsync(ct);
	}

	private static async Task WriteHeaderAsync(StreamWriter w, CancellationToken ct)
	{
		string now = DateTime.Now.ToString("dddd dd MMMM yyyy à HH:mm:ss", FrFr);
		if (now.Length > 0)
		{
			ReadOnlySpan<char> readOnlySpan = new ReadOnlySpan<char>(char.ToUpperInvariant(now[0]));
			string original = now;
			now = string.Concat(readOnlySpan, original.Substring(1, original.Length - 1));
		}
		await w.WriteLineAsync("".AsMemory(), ct);
		await w.WriteLineAsync("════════════════════════════════════════════════════════════════════".AsMemory(), ct);
		await w.WriteLineAsync("  CHECKSEC - RAPPORT D'AUDIT DE SÉCURITÉ WINDOWS 11".AsMemory(), ct);
		await w.WriteLineAsync(("  Généré le        : " + now).AsMemory(), ct);
		await w.WriteLineAsync(("  Machine          : " + Environment.MachineName).AsMemory(), ct);
		await w.WriteLineAsync(("  Utilisateur      : " + Environment.UserDomainName + "\\" + Environment.UserName).AsMemory(), ct);
		await w.WriteLineAsync($"  Système          : {Environment.OSVersion}".AsMemory(), ct);
		await w.WriteLineAsync("  Version outil    : CHECKSEC v1.0.0".AsMemory(), ct);
		await w.WriteLineAsync("  Baseline         : Windows 11 Security Baseline (MSCT)".AsMemory(), ct);
		await w.WriteLineAsync("════════════════════════════════════════════════════════════════════".AsMemory(), ct);
		await w.WriteLineAsync("".AsMemory(), ct);
	}

	private static async Task WriteExecutiveSummaryAsync(StreamWriter w, List<CollectorReport> reports, List<ComplianceGap> gaps, CancellationToken ct)
	{
		List<SecurityResult> allResults = reports.SelectMany((CollectorReport r) => r.Results).ToList();
		int totalOK = 0;
		int totalWarning = 0;
		int totalCritical = 0;
		int totalError = 0;
		int totalInfo = 0;
		using (List<SecurityResult>.Enumerator enumerator = allResults.GetEnumerator())
		{
			while (enumerator.MoveNext())
			{
				switch (enumerator.Current.Status)
				{
				case SecurityStatus.OK:
					totalOK++;
					break;
				case SecurityStatus.Warning:
					totalWarning++;
					break;
				case SecurityStatus.Critical:
					totalCritical++;
					break;
				case SecurityStatus.Error:
					totalError++;
					break;
				case SecurityStatus.Info:
					totalInfo++;
					break;
				}
			}
		}
		totalError += reports.Count((CollectorReport r) => !r.Success);
		int total = allResults.Count;
		string percentDisplay = ((total > 0) ? $"{(double)totalOK / (double)total * 100.0:F1}%" : "N/A");
		int gapsCompliant = 0;
		int gapsNonCompliant = 0;
		int gapsCritical = 0;
		int gapsHigh = 0;
		int gapsMedium = 0;
		int gapsLow = 0;
		foreach (ComplianceGap gap in gaps)
		{
			if (gap.IsCompliant)
			{
				gapsCompliant++;
				continue;
			}
			gapsNonCompliant++;
			switch (gap.Severity)
			{
			case GapSeverity.Critical:
				gapsCritical++;
				break;
			case GapSeverity.High:
				gapsHigh++;
				break;
			case GapSeverity.Medium:
				gapsMedium++;
				break;
			case GapSeverity.Low:
				gapsLow++;
				break;
			}
		}
		List<CollectorReport> failedCollectors = reports.Where((CollectorReport r) => !r.Success).ToList();
		await w.WriteLineAsync("RÉSUMÉ EXÉCUTIF".AsMemory(), ct);
		await w.WriteLineAsync("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".AsMemory(), ct);
		await w.WriteLineAsync($"  {"✅"} Contrôles conformes    : {totalOK,6}".AsMemory(), ct);
		await w.WriteLineAsync($"  {"⚠\ufe0f "} Avertissements         : {totalWarning,6}".AsMemory(), ct);
		await w.WriteLineAsync($"  {"❌"} Contrôles critiques    : {totalCritical,6}".AsMemory(), ct);
		await w.WriteLineAsync($"  {"\ud83d\udd34"} Erreurs de collecte    : {totalError,6}".AsMemory(), ct);
		await w.WriteLineAsync($"  {"ℹ\ufe0f "} Informatif            : {totalInfo,6}".AsMemory(), ct);
		await w.WriteLineAsync($"  \ud83d\udcca Total vérifications    : {total,6}".AsMemory(), ct);
		await w.WriteLineAsync("".AsMemory(), ct);
		await w.WriteLineAsync(("  Taux de conformité        : " + percentDisplay).AsMemory(), ct);
		await w.WriteLineAsync("".AsMemory(), ct);
		string riskLevel;
		string riskIcon;
		if (totalCritical > 10 || gapsCritical > 20)
		{
			riskLevel = "CRITIQUE - ACTION IMMÉDIATE REQUISE";
			riskIcon = "\ud83d\udea8";
		}
		else if (totalCritical > 0 || gapsCritical > 0)
		{
			riskLevel = "ÉLEVÉ - Correctifs prioritaires requis";
			riskIcon = "\ud83d\udd34";
		}
		else if (totalWarning > 20 || gapsHigh > 10)
		{
			riskLevel = "MOYEN - Améliorations recommandées";
			riskIcon = "\ud83d\udfe0";
		}
		else
		{
			riskLevel = "FAIBLE - Configuration globalement sécurisée";
			riskIcon = "\ud83d\udfe2";
		}
		await w.WriteLineAsync(("  " + riskIcon + " Niveau de risque global  : " + riskLevel).AsMemory(), ct);
		await w.WriteLineAsync("".AsMemory(), ct);
		if (gaps.Count > 0)
		{
			await w.WriteLineAsync("  ÉCARTS MSCT BASELINE (Windows 11 v25H2):".AsMemory(), ct);
			await w.WriteLineAsync($"    Conformes     : {gapsCompliant}".AsMemory(), ct);
			await w.WriteLineAsync($"    Non-conformes : {gapsNonCompliant}".AsMemory(), ct);
			await w.WriteLineAsync($"      - Critiques : {gapsCritical}".AsMemory(), ct);
			await w.WriteLineAsync($"      - Élevés    : {gapsHigh}".AsMemory(), ct);
			await w.WriteLineAsync($"      - Moyens    : {gapsMedium}".AsMemory(), ct);
			await w.WriteLineAsync($"      - Faibles   : {gapsLow}".AsMemory(), ct);
			await w.WriteLineAsync("".AsMemory(), ct);
		}
		if (failedCollectors.Count > 0)
		{
			await w.WriteLineAsync("  COLLECTEURS EN ERREUR:".AsMemory(), ct);
			foreach (CollectorReport failedCollector in failedCollectors)
			{
				await w.WriteLineAsync($"    {"\ud83d\udd34"} {failedCollector.CollectorName}: {failedCollector.ErrorMessage}".AsMemory(), ct);
			}
			await w.WriteLineAsync("".AsMemory(), ct);
		}
		await w.WriteLineAsync("  DURÉE DE COLLECTE PAR MODULE:".AsMemory(), ct);
		foreach (CollectorReport report in reports.OrderByDescending((CollectorReport r) => r.Duration))
		{
			string statusIcon = (report.Success ? "✅" : "\ud83d\udd34");
			await w.WriteLineAsync($"    {statusIcon} {report.CollectorName,-40} {report.Duration.TotalSeconds:F1}s  ({report.Results.Count} vérifications)".AsMemory(), ct);
		}
		await w.WriteLineAsync("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".AsMemory(), ct);
		await w.WriteLineAsync("".AsMemory(), ct);
	}

	private static async Task WriteCollectorSectionsAsync(StreamWriter w, List<CollectorReport> reports, CancellationToken ct)
	{
		await w.WriteLineAsync("═══════════════════════════════════════════════════════════════════".AsMemory(), ct);
		await w.WriteLineAsync("  DÉTAIL DES CONTRÔLES DE SÉCURITÉ".AsMemory(), ct);
		await w.WriteLineAsync("═══════════════════════════════════════════════════════════════════".AsMemory(), ct);
		await w.WriteLineAsync("".AsMemory(), ct);
		foreach (CollectorReport report in reports)
		{
			ct.ThrowIfCancellationRequested();
			await WriteSectionHeaderAsync(w, report.CollectorName, report.CollectorName, ct);
			if (!report.Success)
			{
				await w.WriteLineAsync(("  \ud83d\udd34 ERREUR DE COLLECTE: " + report.ErrorMessage).AsMemory(), ct);
				await w.WriteLineAsync("".AsMemory(), ct);
				continue;
			}
			if (report.Results.Count == 0)
			{
				await w.WriteLineAsync("  Aucun résultat disponible pour ce collecteur.".AsMemory(), ct);
				await w.WriteLineAsync("".AsMemory(), ct);
				continue;
			}
			List<IGrouping<string, SecurityResult>> categoryGroups = (from r in report.Results
				group r by r.Category into g
				orderby g.Key
				select g).ToList();
			bool multipleCategories = categoryGroups.Count > 1;
			foreach (IGrouping<string, SecurityResult> group in categoryGroups)
			{
				if (multipleCategories)
				{
					await w.WriteLineAsync(("  ── " + group.Key + " ──").AsMemory(), ct);
					await w.WriteLineAsync("".AsMemory(), ct);
				}
				foreach (SecurityResult result in group)
				{
					ct.ThrowIfCancellationRequested();
					await WriteSecurityResultAsync(w, result, ct);
				}
			}
			await w.WriteLineAsync("".AsMemory(), ct);
		}
	}

	private static async Task WriteSectionHeaderAsync(StreamWriter w, string collectorName, string category, CancellationToken ct)
	{
		await w.WriteLineAsync("───────────────────────────────────────────────────────────────────".AsMemory(), ct);
		await w.WriteLineAsync(("  MODULE : " + collectorName).AsMemory(), ct);
		await w.WriteLineAsync(("  Catégorie : " + category).AsMemory(), ct);
		await w.WriteLineAsync("───────────────────────────────────────────────────────────────────".AsMemory(), ct);
		await w.WriteLineAsync("".AsMemory(), ct);
	}

	private static async Task WriteSecurityResultAsync(StreamWriter w, SecurityResult result, CancellationToken ct)
	{
		string statusIcon = result.Status switch
		{
			SecurityStatus.OK => "✅", 
			SecurityStatus.Warning => "⚠\ufe0f ", 
			SecurityStatus.Critical => "❌", 
			SecurityStatus.Error => "\ud83d\udd34", 
			SecurityStatus.Info => "ℹ\ufe0f ", 
			SecurityStatus.NotApplicable => "➖", 
			_ => "ℹ\ufe0f ", 
		};
		string statusLabel = result.Status switch
		{
			SecurityStatus.OK => "OK", 
			SecurityStatus.Warning => "ATTENTION", 
			SecurityStatus.Critical => "CRITIQUE", 
			SecurityStatus.Error => "ERREUR", 
			SecurityStatus.Info => "INFO", 
			SecurityStatus.NotApplicable => "N/A", 
			_ => result.Status.ToString().ToUpperInvariant(), 
		};
		await w.WriteLineAsync($"  {statusIcon} [{statusLabel}] {result.CheckName}".AsMemory(), ct);
		await w.WriteLineAsync($"     Collecté le      : {result.CollectedAt:yyyy-MM-dd HH:mm:ss}".AsMemory(), ct);
		if (!string.IsNullOrWhiteSpace(result.CurrentValue))
		{
			await w.WriteLineAsync(("     Valeur actuelle  : " + TruncateLine(result.CurrentValue, 200)).AsMemory(), ct);
		}
		if (!string.IsNullOrWhiteSpace(result.ExpectedValue))
		{
			await w.WriteLineAsync(("     Valeur attendue  : " + TruncateLine(result.ExpectedValue, 200)).AsMemory(), ct);
		}
		if (!string.IsNullOrWhiteSpace(result.Description))
		{
			foreach (string line in WrapText(result.Description, 120, "                        "))
			{
				await w.WriteLineAsync(line.AsMemory(), ct);
			}
		}
		if (!string.IsNullOrWhiteSpace(result.Recommendation))
		{
			foreach (string line in WrapText(result.Recommendation, 120, "                        ", "     Recommandation   : "))
			{
				await w.WriteLineAsync(line.AsMemory(), ct);
			}
		}
		if (!string.IsNullOrWhiteSpace(result.Reference))
		{
			await w.WriteLineAsync(("     Référence        : " + result.Reference).AsMemory(), ct);
		}
		await w.WriteLineAsync("".AsMemory(), ct);
	}

	private static async Task WriteMsctGapSectionAsync(StreamWriter w, List<ComplianceGap> gaps, CancellationToken ct)
	{
		if (gaps.Count == 0)
		{
			await w.WriteLineAsync("═══════════════════════════════════════════════════════════════════".AsMemory(), ct);
			await w.WriteLineAsync("  ANALYSE D'ÉCARTS MSCT BASELINE - Aucune politique à comparer".AsMemory(), ct);
			await w.WriteLineAsync("  (Vérifier que le toolkit MSCT est présent dans C:\\MSCTOOLKIT)".AsMemory(), ct);
			await w.WriteLineAsync("═══════════════════════════════════════════════════════════════════".AsMemory(), ct);
			await w.WriteLineAsync("".AsMemory(), ct);
			return;
		}
		await w.WriteLineAsync("═══════════════════════════════════════════════════════════════════".AsMemory(), ct);
		await w.WriteLineAsync("  ANALYSE D'ÉCARTS - MSCT BASELINE (Windows 11 v25H2)".AsMemory(), ct);
		await w.WriteLineAsync("═══════════════════════════════════════════════════════════════════".AsMemory(), ct);
		await w.WriteLineAsync("".AsMemory(), ct);
		List<ComplianceGap> nonCompliant = gaps.Where((ComplianceGap g) => !g.IsCompliant).ToList();
		if (nonCompliant.Count == 0)
		{
			await w.WriteLineAsync("  ✅ Toutes les politiques analysées sont conformes à la baseline MSCT.".AsMemory(), ct);
			await w.WriteLineAsync("".AsMemory(), ct);
			return;
		}
		(GapSeverity, string, string)[] severityLevels = new(GapSeverity, string, string)[4]
		{
			(GapSeverity.Critical, "CRITIQUES", "\ud83d\udea8"),
			(GapSeverity.High, "ÉLEVÉS", "\ud83d\udd34"),
			(GapSeverity.Medium, "MOYENS", "\ud83d\udfe0"),
			(GapSeverity.Low, "FAIBLES", "\ud83d\udfe1")
		};
		(GapSeverity, string, string)[] severityLevelsCopy = severityLevels;
		for (int i = 0; i < severityLevelsCopy.Length; i++)
		{
			var (severity, label, icon) = severityLevelsCopy[i];
			ct.ThrowIfCancellationRequested();
			List<ComplianceGap> severityGaps = (from g in nonCompliant
				where g.Severity == severity
				orderby g.GpoName, g.PolicyName
				select g).ToList();
			if (severityGaps.Count == 0)
			{
				continue;
			}
			await w.WriteLineAsync($"  {icon} ÉCARTS {label} ({severityGaps.Count}):".AsMemory(), ct);
			await w.WriteLineAsync(("  " + new string('─', 65)).AsMemory(), ct);
			await w.WriteLineAsync("".AsMemory(), ct);
			IOrderedEnumerable<IGrouping<string, ComplianceGap>> gpoGroups = from g in severityGaps
				group g by g.GpoName into g
				orderby g.Key
				select g;
			foreach (IGrouping<string, ComplianceGap> gpoGroup in gpoGroups)
			{
				ct.ThrowIfCancellationRequested();
				await w.WriteLineAsync(("  GPO: " + gpoGroup.Key).AsMemory(), ct);
				foreach (ComplianceGap gap in gpoGroup)
				{
					ct.ThrowIfCancellationRequested();
					await WriteComplianceGapAsync(w, gap, ct);
				}
				await w.WriteLineAsync("".AsMemory(), ct);
			}
		}
		List<ComplianceGap> compliant = gaps.Where((ComplianceGap g) => g.IsCompliant).ToList();
		if (compliant.Count > 0)
		{
			await w.WriteLineAsync($"  {"✅"} POLITIQUES CONFORMES: {compliant.Count} politique(s) conforme(s) à la baseline.".AsMemory(), ct);
			await w.WriteLineAsync("".AsMemory(), ct);
		}
	}

	private static async Task WriteComplianceGapAsync(StreamWriter w, ComplianceGap gap, CancellationToken ct)
	{
		await w.WriteLineAsync(("    " + gap.Severity switch
		{
			GapSeverity.Critical => "\ud83d\udea8", 
			GapSeverity.High => "\ud83d\udd34", 
			GapSeverity.Medium => "\ud83d\udfe0", 
			GapSeverity.Low => "\ud83d\udfe1", 
			_ => "  ", 
		} + " " + gap.PolicyName).AsMemory(), ct);
		if (!string.IsNullOrWhiteSpace(gap.RegistryPath))
		{
			await w.WriteLineAsync(("       Chemin           : " + gap.RegistryPath).AsMemory(), ct);
		}
		if (!string.IsNullOrWhiteSpace(gap.ValueName))
		{
			await w.WriteLineAsync(("       Valeur           : " + gap.ValueName).AsMemory(), ct);
		}
		await w.WriteLineAsync(("       Baseline MSCT    : " + gap.BaselineValue).AsMemory(), ct);
		await w.WriteLineAsync(("       Valeur actuelle  : " + gap.CurrentValue).AsMemory(), ct);
		if (!string.IsNullOrWhiteSpace(gap.Description))
		{
			await w.WriteLineAsync(("       Description      : " + TruncateLine(gap.Description, 150)).AsMemory(), ct);
		}
		await w.WriteLineAsync("".AsMemory(), ct);
	}

	private static async Task WriteFooterAsync(StreamWriter w, CancellationToken ct)
	{
		string generated = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", FrFr);
		await w.WriteLineAsync("════════════════════════════════════════════════════════════════════".AsMemory(), ct);
		await w.WriteLineAsync("  FIN DU RAPPORT D'AUDIT".AsMemory(), ct);
		await w.WriteLineAsync(("  Généré par CHECKSEC v1.0.0 - " + generated).AsMemory(), ct);
		await w.WriteLineAsync($"  Machine: {Environment.MachineName} | OS: {Environment.OSVersion}".AsMemory(), ct);
		await w.WriteLineAsync("".AsMemory(), ct);
		await w.WriteLineAsync("  Références:".AsMemory(), ct);
		await w.WriteLineAsync("    - Microsoft Security Compliance Toolkit (MSCT)".AsMemory(), ct);
		await w.WriteLineAsync("    - CIS Benchmark for Windows 11".AsMemory(), ct);
		await w.WriteLineAsync("    - ANSSI - Recommandations de sécurité pour Windows".AsMemory(), ct);
		await w.WriteLineAsync("    - NIST SP 800-171 / CMMC".AsMemory(), ct);
		await w.WriteLineAsync("".AsMemory(), ct);
		await w.WriteLineAsync("  AVERTISSEMENT: Ce rapport est confidentiel et destiné uniquement".AsMemory(), ct);
		await w.WriteLineAsync("  aux équipes de sécurité autorisées.".AsMemory(), ct);
		await w.WriteLineAsync("════════════════════════════════════════════════════════════════════".AsMemory(), ct);
	}

	private static string TruncateLine(string text, int maxLength)
	{
		if (string.IsNullOrEmpty(text) || text.Length <= maxLength)
		{
			return text;
		}
		return text.Substring(0, maxLength) + "…";
	}

	[IteratorStateMachine(typeof(_003CWrapText_003Ed__18))]
	private static IEnumerable<string> WrapText(string text, int maxWidth, string continuationIndent, string prefix = "     Description     : ")
	{
		//yield-return decompiler failed: Unexpected instruction in Iterator.Dispose()
		return new _003CWrapText_003Ed__18(-2)
		{
			_003C_003E3__text = text,
			_003C_003E3__maxWidth = maxWidth,
			_003C_003E3__continuationIndent = continuationIndent,
			_003C_003E3__prefix = prefix
		};
	}
}
