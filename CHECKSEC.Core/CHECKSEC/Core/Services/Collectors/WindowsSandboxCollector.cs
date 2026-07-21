using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class WindowsSandboxCollector : ISecurityCollector
{
	public string Name => "Windows Sandbox";

	public string Category => "Isolation";

	public Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport collectorReport = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch stopwatch = Stopwatch.StartNew();
		try
		{
			ct.ThrowIfCancellationRequested();
			CollectSandboxStatus(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectHyperVStatus(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "WindowsSandboxCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectSandboxStatus(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			bool isSandboxInstalled = false;
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\PackageIndex");
			if (registryKey != null)
			{
				string[] subKeyNames = registryKey.GetSubKeyNames();
				foreach (string subKeyName in subKeyNames)
				{
					ct.ThrowIfCancellationRequested();
					if (subKeyName.Contains("Containers-DisposableClientVM", StringComparison.OrdinalIgnoreCase))
					{
						isSandboxInstalled = true;
						break;
					}
				}
			}
			if (!isSandboxInstalled)
			{
				try
				{
					ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_OptionalFeature WHERE Name='Containers-DisposableClientVM'");
					try
					{
						using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
						foreach (ManagementObject item in managementObjectCollection)
						{
							ct.ThrowIfCancellationRequested();
							object installState = item["InstallState"];
							if (installState != null && Convert.ToInt32(installState) == 1)
							{
								isSandboxInstalled = true;
							}
						}
					}
					finally
					{
						((IDisposable)managementObjectSearcher)?.Dispose();
					}
				}
				catch
				{
				}
			}
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Windows Sandbox",
				CurrentValue = (isSandboxInstalled ? "Installé" : "Non installé"),
				ExpectedValue = "Installé (recommandé)",
				Status = ((!isSandboxInstalled) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = (isSandboxInstalled ? "Windows Sandbox est installé. Vous pouvez exécuter des applications suspectes dans un environnement isolé jetable." : "Windows Sandbox n'est pas installé. Cette fonctionnalité permet d'exécuter des applications dans un environnement isolé."),
				Recommendation = (isSandboxInstalled ? "Utilisez Windows Sandbox pour tester les fichiers ou applications suspectes." : "Installez Windows Sandbox: Enable-WindowsOptionalFeature -FeatureName 'Containers-DisposableClientVM' -Online"),
				Reference = "https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview"
			});
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Windows Sandbox — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier Windows Sandbox: " + ex.Message,
				Recommendation = "Vérifiez les permissions et la disponibilité de WMI.",
				Reference = ""
			});
		}
	}

	private void CollectHyperVStatus(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			bool isHyperVInstalled = false;
			try
			{
				ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_OptionalFeature WHERE Name='Microsoft-Hyper-V'");
				try
				{
					using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
					foreach (ManagementObject item in managementObjectCollection)
					{
						ManagementObject managementObject2 = item;
						try
						{
							object installState = item["InstallState"];
							if (installState != null && Convert.ToInt32(installState) == 1)
							{
								isHyperVInstalled = true;
							}
						}
						finally
						{
							((IDisposable)managementObject2)?.Dispose();
						}
					}
				}
				finally
				{
					((IDisposable)managementObjectSearcher)?.Dispose();
				}
			}
			catch
			{
				using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization");
				isHyperVInstalled = registryKey != null;
			}
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Hyper-V (prérequis Sandbox)",
				CurrentValue = (isHyperVInstalled ? "Installé" : "Non détecté"),
				ExpectedValue = "Installé",
				Status = ((!isHyperVInstalled) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = (isHyperVInstalled ? "Hyper-V est installé, permettant l'utilisation de Windows Sandbox et d'autres fonctionnalités d'isolation." : "Hyper-V n'est pas détecté. Requis pour Windows Sandbox."),
				Recommendation = (isHyperVInstalled ? "Configuration correcte." : "Hyper-V est nécessaire pour Windows Sandbox et les fonctionnalités VBS."),
				Reference = ""
			});
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Hyper-V — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Erreur: " + ex.Message,
				Recommendation = "Vérifiez les permissions.",
				Reference = ""
			});
		}
	}
}
