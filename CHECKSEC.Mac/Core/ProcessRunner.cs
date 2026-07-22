using System.Diagnostics;
using System.Text;

namespace Checksec.Mac.Core;

/// <summary>Resultat d'execution d'une commande.</summary>
public readonly record struct ProcResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Success => ExitCode == 0;
    public string Combined => string.IsNullOrEmpty(StdErr) ? StdOut : $"{StdOut}\n{StdErr}";
}

/// <summary>
/// Execute des outils systeme macOS et capture leur sortie.
/// Toutes les commandes sont invoquees sans shell (pas d'injection) avec un timeout.
/// </summary>
public static class ProcessRunner
{
    public static async Task<ProcResult> RunAsync(
        string fileName,
        IReadOnlyList<string> args,
        CancellationToken ct,
        int timeoutMs = 15000)
    {
        using var proc = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            }
        };
        foreach (var a in args)
            proc.StartInfo.ArgumentList.Add(a);

        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
        proc.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };

        try
        {
            if (!proc.Start())
                return new ProcResult(-1, "", $"impossible de demarrer {fileName}");
        }
        catch (Exception ex)
        {
            // Outil absent sur cette plateforme (ex. execute hors macOS).
            return new ProcResult(-2, "", ex.Message);
        }

        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeoutMs);
        try
        {
            await proc.WaitForExitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { /* deja termine */ }
            return new ProcResult(-3, stdout.ToString(), "timeout ou annulation");
        }

        return new ProcResult(proc.ExitCode, stdout.ToString().Trim(), stderr.ToString().Trim());
    }

    /// <summary>Vrai si on tourne bien sur macOS (sinon les collecteurs renvoient NotApplicable).</summary>
    public static bool IsMacOs => OperatingSystem.IsMacOS();
}
