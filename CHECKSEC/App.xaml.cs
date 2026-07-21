using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services;
using CHECKSEC.Services;
using CHECKSEC.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using EventLogEntry = CHECKSEC.Core.Models.EventLogEntry;

namespace CHECKSEC;

public partial class App : Application
{
	private static ServiceProvider? _serviceProvider;

	public static IServiceProvider Services => _serviceProvider;

	public static Window? MainAppWindow { get; private set; }

	public App()
	{
		InitializeComponent();
		ErrorLogger.Initialize();
		base.UnhandledException += OnUnhandledException;
		ServiceCollection services = new ServiceCollection();
		ConfigureServices(services);
		_serviceProvider = services.BuildServiceProvider();
	}

	private static void ConfigureServices(ServiceCollection services)
	{
		services.AddSingleton<AnalysisService>();
		services.AddSingleton<HistoryService>();
		services.AddSingleton<DashboardViewModel>();
		services.AddSingleton<ResultsViewModel>();
		services.AddSingleton<GapsViewModel>();
		services.AddSingleton<CisViewModel>();
		services.AddSingleton<EventLogViewModel>();
		services.AddSingleton<SecureCoreViewModel>();
		services.AddSingleton<SystemInfoViewModel>();
		services.AddSingleton<AboutViewModel>();
		services.AddSingleton<RemediationService>();
		services.AddSingleton<RemediationViewModel>();
		services.AddSingleton<HistoryViewModel>();
		services.AddSingleton<SettingsService>();
		services.AddSingleton<SettingsViewModel>();
		services.AddSingleton<HtmlReportService>();
		services.AddSingleton<UnifiedReportService>();
		services.AddSingleton<ConsolidatedExcelService>();
		services.AddSingleton<CefExportService>();
	}

	protected override void OnLaunched(LaunchActivatedEventArgs args)
	{
		string[] array = Environment.GetCommandLineArgs().Skip(1).ToArray();
		if (array.Contains("--headless"))
		{
			RunHeadlessAsync(array).ContinueWith(delegate(Task t)
			{
				if (t.IsFaulted && t.Exception != null)
				{
					ErrorLogger.Log(LogLevel.Fatal, "[Headless] " + (t.Exception.InnerException?.Message ?? t.Exception.Message), t.Exception.InnerException ?? t.Exception);
					Environment.Exit(99);
				}
			}, TaskScheduler.Default);
		}
		else if (!IsRunningAsAdmin())
		{
			RestartAsAdmin();
		}
		else
		{
			MainAppWindow = new MainWindow();
			MainAppWindow.Activate();
		}
	}

	private async Task RunHeadlessAsync(string[] args)
	{
		AnalysisService analysis = Services.GetRequiredService<AnalysisService>();
		string outputPath = "";
		string format = "json";
		for (int j = 0; j < args.Length; j++)
		{
			if (args[j] == "--output" && j + 1 < args.Length)
			{
				outputPath = args[j + 1];
			}
			if (args[j] == "--format" && j + 1 < args.Length)
			{
				format = args[j + 1].ToLower();
			}
		}
		Console.WriteLine("CHECKSEC v6.0 — Mode headless");
		Console.WriteLine("Analyse de " + Environment.MachineName + "...");
		await analysis.RunAsync();
		Console.WriteLine($"Score: {analysis.GlobalScore}% (Grade: {analysis.GlobalGrade})");
		Console.WriteLine($"OK: {analysis.TotalOK} | Warning: {analysis.TotalWarning} | Critical: {analysis.TotalCritical} | Error: {analysis.TotalError}");
		if (!string.IsNullOrEmpty(outputPath))
		{
			if (format == "cef")
			{
				string contents = Services.GetRequiredService<CefExportService>().GenerateCef(analysis);
				File.WriteAllText(outputPath, contents);
				Console.WriteLine("CEF report saved to " + outputPath);
			}
			else
			{
				// JSON headless == JSON interactif : source de vérité unique (fin de la divergence de schéma).
				string contents2 = ReportJsonBuilder.Build(analysis, Services.GetRequiredService<RemediationService>());
				File.WriteAllText(outputPath, contents2);
				Console.WriteLine("Report saved to " + outputPath);
			}
		}
		Environment.Exit((analysis.TotalCritical > 0) ? 3 : ((analysis.TotalWarning > 0) ? 2 : ((analysis.TotalError > 0) ? 1 : 0)));
	}

	private static bool IsRunningAsAdmin()
	{
		try
		{
			using WindowsIdentity ntIdentity = WindowsIdentity.GetCurrent();
			return new WindowsPrincipal(ntIdentity).IsInRole(WindowsBuiltInRole.Administrator);
		}
		catch
		{
			return false;
		}
	}

	private void RestartAsAdmin()
	{
		try
		{
			string processPath = Environment.ProcessPath;
			if (processPath == null)
			{
				Exit();
				return;
			}
			Process.Start(new ProcessStartInfo
			{
				FileName = processPath,
				UseShellExecute = true,
				Verb = "runas"
			});
		}
		catch (Win32Exception)
		{
		}
		catch (Exception ex2)
		{
			ErrorLogger.Log(LogLevel.Error, "[RestartAsAdmin] " + ex2.Message, ex2);
		}
		finally
		{
			Exit();
		}
	}

	private void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
	{
		e.Handled = true;
		ErrorLogger.Log(LogLevel.Fatal, "Unhandled: " + e.Exception?.Message, e.Exception);
	}
}
