using System.Diagnostics;

namespace Checksec.Mac.Core;

/// <summary>
/// Base commune : mesure la duree, capture les exceptions, et court-circuite
/// proprement si on n'est pas sur macOS (renvoie un constat NotApplicable).
/// </summary>
public abstract class MacCollectorBase : IMacCollector
{
    public abstract string Name { get; }
    public abstract string Category { get; }

    /// <summary>Logique reelle du collecteur, implementee par chaque sous-classe.</summary>
    protected abstract Task CollectCoreAsync(CollectorReport report, CancellationToken ct);

    public async Task<CollectorReport> CollectAsync(CancellationToken ct)
    {
        var report = new CollectorReport { Collector = Name, Category = Category };
        var sw = Stopwatch.StartNew();
        try
        {
            if (!ProcessRunner.IsMacOs)
            {
                report.Findings.Add(new Finding
                {
                    Id = $"{Name}.NotMac",
                    Title = $"{Name} : execution hors macOS",
                    Severity = Severity.NotApplicable,
                    Detail = "Collecteur compile mais non evalue : la machine hote n'est pas macOS."
                });
            }
            else
            {
                await CollectCoreAsync(report, ct);
            }
        }
        catch (OperationCanceledException)
        {
            report.Error = "annule";
        }
        catch (Exception ex)
        {
            report.Error = ex.Message;
            report.Findings.Add(new Finding
            {
                Id = $"{Name}.Error",
                Title = $"{Name} : erreur de collecte",
                Severity = Severity.Error,
                Detail = ex.Message
            });
        }
        finally
        {
            sw.Stop();
            report.DurationMs = sw.Elapsed.TotalMilliseconds;
        }
        return report;
    }

    /// <summary>Raccourci d'execution d'un outil systeme.</summary>
    protected static Task<ProcResult> Run(string file, CancellationToken ct, params string[] args)
        => ProcessRunner.RunAsync(file, args, ct);
}
