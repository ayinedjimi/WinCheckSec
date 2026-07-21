using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class SmbHardeningCollector : ISecurityCollector
{
	private const string SmbServerKey = "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters";

	private const string SmbClientKey = "SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters";

	private const string Smb1FeatureKey = "SYSTEM\\CurrentControlSet\\Services\\mrxsmb10";

	public string Name => "Durcissement SMB";

	public string Category => "Réseau";

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
			CollectSmb1Status(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectSmbSigning(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectSmbEncryption(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			collectorReport.ErrorMessage = "SmbHardeningCollector fatal error: " + ex.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectSmb1Status(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey serverParamsKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters");
			object smb1Value = serverParamsKey?.GetValue("SMB1");
			bool smb1DisabledOnServer = smb1Value != null && Convert.ToInt32(smb1Value) == 0;
			using RegistryKey smb1DriverKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\mrxsmb10");
			object smb1DriverStartValue = smb1DriverKey?.GetValue("Start");
			bool smb1DriverDisabled = smb1DriverStartValue != null && Convert.ToInt32(smb1DriverStartValue) == 4;
			bool smb1Disabled = smb1DisabledOnServer || smb1DriverDisabled;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "SMBv1",
				CurrentValue = (smb1Disabled ? "Désactivé" : ((smb1Value == null) ? "Non configuré (actif par défaut)" : "Activé")),
				ExpectedValue = "Désactivé",
				Status = ((!smb1Disabled) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = (smb1Disabled ? "SMBv1 est désactivé. Ce protocole obsolète est vulnérable (EternalBlue, WannaCry)." : "SMBv1 est potentiellement activé. Ce protocole est vulnérable à de nombreuses attaques."),
				Recommendation = (smb1Disabled ? "Configuration correcte." : "Désactivez SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false"),
				Reference = "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
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
				CheckName = "SMBv1 — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier SMBv1: " + ex.Message,
				Recommendation = "Vérifiez les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}

	private void CollectSmbSigning(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey serverParamsKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters");
			object serverSigningValue = serverParamsKey?.GetValue("RequireSecuritySignature");
			bool serverSigningRequired = serverSigningValue != null && Convert.ToInt32(serverSigningValue) == 1;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "SMB Signing — Serveur",
				CurrentValue = (serverSigningRequired ? "Requis" : "Non requis"),
				ExpectedValue = "Requis",
				Status = ((!serverSigningRequired) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = (serverSigningRequired ? "La signature SMB est requise côté serveur, protégeant contre les attaques man-in-the-middle." : "La signature SMB n'est pas requise côté serveur."),
				Recommendation = (serverSigningRequired ? "Configuration correcte." : "Activez RequireSecuritySignature = 1 dans LanmanServer\\Parameters."),
				Reference = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing"
			});
			using RegistryKey clientParamsKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters");
			object clientSigningValue = clientParamsKey?.GetValue("RequireSecuritySignature");
			bool clientSigningRequired = clientSigningValue != null && Convert.ToInt32(clientSigningValue) == 1;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "SMB Signing — Client",
				CurrentValue = (clientSigningRequired ? "Requis" : "Non requis"),
				ExpectedValue = "Requis",
				Status = ((!clientSigningRequired) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = (clientSigningRequired ? "La signature SMB est requise côté client." : "La signature SMB n'est pas requise côté client."),
				Recommendation = (clientSigningRequired ? "Configuration correcte." : "Activez RequireSecuritySignature = 1 dans LanmanWorkstation\\Parameters."),
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
				CheckName = "SMB Signing — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier le SMB signing: " + ex.Message,
				Recommendation = "Vérifiez les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}

	private void CollectSmbEncryption(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey serverParamsKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters");
			object encryptDataValue = serverParamsKey?.GetValue("EncryptData");
			bool encryptionEnabled = encryptDataValue != null && Convert.ToInt32(encryptDataValue) == 1;
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "SMB Encryption",
				CurrentValue = (encryptionEnabled ? "Activé" : "Non activé"),
				ExpectedValue = "Activé",
				Status = ((!encryptionEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = (encryptionEnabled ? "Le chiffrement SMB est activé, protégeant les données en transit." : "Le chiffrement SMB n'est pas activé."),
				Recommendation = (encryptionEnabled ? "Configuration correcte." : "Activez EncryptData = 1 dans LanmanServer\\Parameters pour chiffrer le trafic SMB."),
				Reference = "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security"
			});
			object rejectUnencryptedValue = serverParamsKey?.GetValue("RejectUnencryptedAccess");
			if (rejectUnencryptedValue != null)
			{
				bool rejectUnencrypted = Convert.ToInt32(rejectUnencryptedValue) == 1;
				results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "SMB — Rejeter connexions non chiffrées",
					CurrentValue = (rejectUnencrypted ? "Activé" : "Désactivé"),
					ExpectedValue = "Activé",
					Status = ((!rejectUnencrypted) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = (rejectUnencrypted ? "Les connexions SMB non chiffrées sont rejetées." : "Les connexions SMB non chiffrées sont acceptées."),
					Recommendation = (rejectUnencrypted ? "Configuration correcte." : "Activez RejectUnencryptedAccess pour forcer le chiffrement."),
					Reference = ""
				});
			}
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
				CheckName = "SMB Encryption — Erreur",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Impossible de vérifier le chiffrement SMB: " + ex.Message,
				Recommendation = "Vérifiez les permissions d'accès au registre.",
				Reference = ""
			});
		}
	}
}
