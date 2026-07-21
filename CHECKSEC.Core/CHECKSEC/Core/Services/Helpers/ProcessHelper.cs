using System;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Threading;

namespace CHECKSEC.Core.Services.Helpers;

public static class ProcessHelper
{
	public static (int exitCode, string output) Run(string fileName, string arguments, int timeoutMs = 15000, CancellationToken ct = default(CancellationToken))
	{
		try
		{
			using Process process = Process.Start(new ProcessStartInfo
			{
				FileName = fileName,
				Arguments = arguments,
				UseShellExecute = false,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				CreateNoWindow = true,
				StandardOutputEncoding = Encoding.GetEncoding(CultureInfo.InstalledUICulture.TextInfo.OEMCodePage)
			});
			if (process == null)
			{
				return (exitCode: -1, output: "Failed to start process");
			}
			StringBuilder stderrBuilder = new StringBuilder();
			process.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e)
			{
				if (e.Data != null)
				{
					stderrBuilder.AppendLine(e.Data);
				}
			};
			process.BeginErrorReadLine();
			string output = process.StandardOutput.ReadToEnd();
			// Correctif L5: attente qui respecte le CancellationToken via un CTS lié (token + timeout),
			// au lieu du WaitForExit(timeoutMs) bloquant qui ignorait l'annulation.
			using CancellationTokenSource timeoutCts = new CancellationTokenSource(timeoutMs);
			using CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
			try
			{
				process.WaitForExitAsync(linkedCts.Token).GetAwaiter().GetResult();
			}
			catch (OperationCanceledException)
			{
				try
				{
					process.Kill();
				}
				catch
				{
				}
				// Annulation externe demandée par l'appelant → propage; sinon c'est un timeout.
				if (ct.IsCancellationRequested)
				{
					throw new OperationCanceledException(ct);
				}
				return (exitCode: -1, output: "Process timed out");
			}
			// Correctif L4: en cas d'échec, intègre stderr au résultat pour le diagnostic.
			string stderr = stderrBuilder.ToString().Trim();
			if (process.ExitCode != 0 && stderr.Length > 0)
			{
				return (exitCode: process.ExitCode, output: output + Environment.NewLine + "[stderr] " + stderr);
			}
			return (exitCode: process.ExitCode, output: output);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			return (exitCode: -1, output: "Error: " + ex.Message);
		}
	}
}
