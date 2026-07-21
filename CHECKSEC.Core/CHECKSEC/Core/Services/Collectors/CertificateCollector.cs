using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class CertificateCollector : ISecurityCollector
{
	public string Name => "Certificats & PKI";

	public string Category => "Cryptographie";

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
			CollectPersonalCerts(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectRootCAs(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectIntermediateCAs(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectDisallowedStore(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectAutoEnrollmentPolicy(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectCrlCheckPolicy(collectorReport.Results, ct);
			ct.ThrowIfCancellationRequested();
			CollectSummary(collectorReport.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			collectorReport.ErrorMessage = "CertificateCollector fatal error: " + ex2.Message;
		}
		finally
		{
			stopwatch.Stop();
			collectorReport.Duration = stopwatch.Elapsed;
		}
		return Task.FromResult(collectorReport);
	}

	private void CollectPersonalCerts(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			using X509Store x509Store = new X509Store("My", StoreLocation.LocalMachine);
			x509Store.Open(OpenFlags.OpenExistingOnly);
			foreach (X509Certificate2 certificate in x509Store.Certificates)
			{
				ct.ThrowIfCancellationRequested();
				string subject = certificate.Subject;
				string issuer = certificate.Issuer;
				string thumbprint = certificate.Thumbprint;
				_ = certificate.NotBefore;
				DateTime notAfter = certificate.NotAfter;
				bool isSelfSigned = subject == issuer;
				bool isExpired = notAfter < DateTime.Now;
				bool expiresSoon30 = !isExpired && notAfter < DateTime.Now.AddDays(30.0);
				bool expiresSoon90 = !isExpired && !expiresSoon30 && notAfter < DateTime.Now.AddDays(90.0);
				int keySize = 0;
				string keyAlgo = "Unknown";
				bool weakKey = false;
				try
				{
					using RSA rsa = certificate.PublicKey.GetRSAPublicKey();
					if (rsa != null)
					{
						keyAlgo = "RSA";
						keySize = rsa.KeySize;
						weakKey = keySize < 2048;
					}
					else
					{
						using ECDsa ecdsa = certificate.PublicKey.GetECDsaPublicKey();
						if (ecdsa != null)
						{
							keyAlgo = "EC";
							keySize = ecdsa.KeySize;
							weakKey = keySize < 256;
						}
					}
				}
				catch
				{
				}
				string sigAlgo = certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value ?? "Unknown";
				bool isMd5Sig = sigAlgo.IndexOf("md5", StringComparison.OrdinalIgnoreCase) >= 0;
				bool isSha1Sig = sigAlgo.IndexOf("sha1", StringComparison.OrdinalIgnoreCase) >= 0 && sigAlgo.IndexOf("sha1", StringComparison.OrdinalIgnoreCase) == sigAlgo.ToLowerInvariant().LastIndexOf("sha1");
				bool hasPrivateKey = certificate.HasPrivateKey;
				string privKeyInfo = "No private key";
				if (hasPrivateKey)
				{
					try
					{
						using RSA rsaPrivate = certificate.GetRSAPrivateKey();
						privKeyInfo = ((rsaPrivate != null) ? "RSA private key present" : "Private key present");
					}
					catch
					{
						privKeyInfo = "Private key present (access restricted)";
					}
				}
				SecurityStatus certStatus;
				string statusReason;
				if (isExpired)
				{
					certStatus = SecurityStatus.Critical;
					statusReason = "Certificate expired";
				}
				else if (expiresSoon30)
				{
					certStatus = SecurityStatus.Critical;
					statusReason = "Expires within 30 days";
				}
				else if (isMd5Sig)
				{
					certStatus = SecurityStatus.Critical;
					statusReason = "MD5 signature algorithm (broken)";
				}
				else if (keyAlgo == "RSA" && keySize > 0 && keySize < 2048)
				{
					certStatus = SecurityStatus.Critical;
					statusReason = $"RSA key too small ({keySize} bits < 2048)";
				}
				else if (keyAlgo == "EC" && keySize > 0 && keySize < 256)
				{
					certStatus = SecurityStatus.Critical;
					statusReason = $"EC key too small ({keySize} bits < 256)";
				}
				else if (expiresSoon90)
				{
					certStatus = SecurityStatus.Warning;
					statusReason = "Expires within 90 days";
				}
				else if (isSha1Sig)
				{
					certStatus = SecurityStatus.Warning;
					statusReason = "SHA-1 signature algorithm (deprecated)";
				}
				else if (keyAlgo == "RSA" && keySize > 0 && keySize < 4096)
				{
					certStatus = SecurityStatus.Warning;
					statusReason = $"RSA key below 4096 bits ({keySize} bits)";
				}
				else if (isSelfSigned)
				{
					certStatus = SecurityStatus.Info;
					statusReason = "Self-signed certificate";
				}
				else
				{
					certStatus = SecurityStatus.OK;
					statusReason = "Certificate OK";
				}
				string thumbCapture = thumbprint;
				TryAdd(results, () => new SecurityResult
				{
					Category = Category,
					CheckName = "Personal Cert: " + ((subject.Length > 60) ? (subject.Substring(0, 60) + "…") : subject),
					CurrentValue = $"Thumbprint={thumbCapture} | Key={keyAlgo} {keySize}b | Sig={sigAlgo} | Expires={notAfter:yyyy-MM-dd} | {privKeyInfo}",
					ExpectedValue = "Valid, RSA>=2048/EC>=256, SHA-256+, not expired",
					Status = certStatus,
					Description = $"Subject: {subject} | Issuer: {issuer}{(isSelfSigned ? " | SELF-SIGNED" : "")} | {statusReason}",
					Recommendation = (isExpired ? "Remove or renew expired certificate immediately." : (expiresSoon30 ? "Renew certificate within 30 days urgently." : (expiresSoon90 ? "Plan certificate renewal within 90 days." : (isMd5Sig ? "Replace certificate — MD5 signature is cryptographically broken." : (isSha1Sig ? "Replace certificate — SHA-1 is deprecated and weakening." : (weakKey ? "Replace certificate with stronger key (RSA>=2048, EC>=256)." : "Certificate is in good standing.")))))),
					Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/certificate-management"
				});
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Personal Certificates (LocalMachine)",
				CurrentValue = "Error: " + ex2.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to open X509Store 'My' on LocalMachine.",
				Recommendation = "Run as Administrator and verify the certificate store is accessible.",
				Reference = ""
			});
		}
	}

	private void CollectRootCAs(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			using X509Store x509Store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
			x509Store.Open(OpenFlags.OpenExistingOnly);
			int total = 0;
			int expired = 0;
			int weakSig = 0;
			int nonMs = 0;
			int notYetValid = 0;
			foreach (X509Certificate2 certificate in x509Store.Certificates)
			{
				ct.ThrowIfCancellationRequested();
				int prev = total;
				total = prev + 1;
				string subject = certificate.Subject;
				string issuer = certificate.Issuer;
				DateTime notBefore = certificate.NotBefore;
				DateTime notAfter = certificate.NotAfter;
				bool certExpired = notAfter < DateTime.Now;
				bool notYetValidFlag = notBefore > DateTime.Now;
				string sigAlgo = certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value ?? "Unknown";
				bool isSha1Sig = sigAlgo.IndexOf("sha1", StringComparison.OrdinalIgnoreCase) >= 0 && sigAlgo.IndexOf("sha2", StringComparison.OrdinalIgnoreCase) < 0;
				int keySize = 0;
				bool weakKeySize = false;
				try
				{
					using RSA rsa = certificate.PublicKey.GetRSAPublicKey();
					if (rsa != null)
					{
						keySize = rsa.KeySize;
						weakKeySize = keySize < 2048;
					}
				}
				catch
				{
				}
				bool isMicrosoft = subject.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0 || issuer.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
				bool isDigiNotar = subject.IndexOf("DigiNotar", StringComparison.OrdinalIgnoreCase) >= 0;
				bool isCnnic = subject.IndexOf("CNNIC", StringComparison.OrdinalIgnoreCase) >= 0;
				if (certExpired)
				{
					prev = expired;
					expired = prev + 1;
				}
				if (isSha1Sig)
				{
					prev = weakSig;
					weakSig = prev + 1;
				}
				if (notYetValidFlag)
				{
					prev = notYetValid;
					notYetValid = prev + 1;
				}
				if (!isMicrosoft)
				{
					prev = nonMs;
					nonMs = prev + 1;
				}
				SecurityStatus securityStatus;
				string statusReason;
				if (isDigiNotar)
				{
					securityStatus = SecurityStatus.Critical;
					statusReason = "DigiNotar — compromised/revoked CA";
				}
				else if (certExpired)
				{
					securityStatus = SecurityStatus.Critical;
					statusReason = "Root CA expired — may break chain validation";
				}
				else if (isCnnic)
				{
					securityStatus = SecurityStatus.Warning;
					statusReason = "CNNIC — controversial CA";
				}
				else if (weakKeySize)
				{
					securityStatus = SecurityStatus.Warning;
					statusReason = $"Weak key size ({keySize} bits < 2048)";
				}
				else if (isSha1Sig)
				{
					securityStatus = SecurityStatus.Warning;
					statusReason = "SHA-1 signature deprecated for root CAs";
				}
				else if (notYetValidFlag)
				{
					securityStatus = SecurityStatus.Warning;
					statusReason = "Not yet valid (NotBefore > now)";
				}
				else if (!isMicrosoft)
				{
					securityStatus = SecurityStatus.Info;
					statusReason = "Non-Microsoft root CA — review if expected";
				}
				else
				{
					securityStatus = SecurityStatus.OK;
					statusReason = "Microsoft root CA — OK";
				}
				if (securityStatus != 0)
				{
					string subjectCapture = subject;
					string reasonCapture = statusReason;
					string sigCapture = sigAlgo;
					int ksCapture = keySize;
					DateTime naCapture = notAfter;
					SecurityStatus sCapture = securityStatus;
					TryAdd(results, () => new SecurityResult
					{
						Category = Category,
						CheckName = "Root CA: " + ((subjectCapture.Length > 60) ? (subjectCapture.Substring(0, 60) + "…") : subjectCapture),
						CurrentValue = $"Sig={sigCapture} | Key={ksCapture}b | Expires={naCapture:yyyy-MM-dd}",
						ExpectedValue = "Valid, RSA>=2048, SHA-256+, trusted CA",
						Status = sCapture,
						Description = "Root CA: " + subjectCapture + " — " + reasonCapture,
						Recommendation = (isDigiNotar ? "Remove DigiNotar from Trusted Root — it is a known compromised CA." : (certExpired ? "Remove expired root CA to prevent chain validation issues." : (isSha1Sig ? "Replace or remove SHA-1 root CA; SHA-1 is deprecated." : (weakKeySize ? "Remove or replace weak-key root CA." : "Review this root CA and remove if not required.")))),
						Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/certificate-management"
					});
				}
			}
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Root CAs: Summary",
				CurrentValue = $"Total={total} | Expired={expired} | WeakSig(SHA1)={weakSig} | NotYetValid={notYetValid} | Non-Microsoft={nonMs}",
				ExpectedValue = "0 expired, 0 weak-signature, all known-good CAs",
				Status = ((expired > 0) ? SecurityStatus.Critical : ((weakSig > 0) ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = $"Summary of Trusted Root Certificate Authorities in LocalMachine store. Non-Microsoft count: {nonMs}.",
				Recommendation = ((expired > 0) ? "Remove expired root CAs from the trusted store." : ((weakSig > 0) ? "Replace SHA-1 root CAs with SHA-256 equivalents." : "Root CA store appears healthy.")),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration"
			});
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Trusted Root CAs",
				CurrentValue = "Error: " + ex2.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to open X509Store Root on LocalMachine.",
				Recommendation = "Run as Administrator.",
				Reference = ""
			});
		}
	}

	private void CollectIntermediateCAs(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			using X509Store x509Store = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine);
			x509Store.Open(OpenFlags.OpenExistingOnly);
			int total = 0;
			int expired = 0;
			int weakSig = 0;
			foreach (X509Certificate2 certificate in x509Store.Certificates)
			{
				ct.ThrowIfCancellationRequested();
				total++;
				string subject = certificate.Subject;
				DateTime notAfter = certificate.NotAfter;
				bool isExpired = notAfter < DateTime.Now;
				string sigAlgo = certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value ?? "Unknown";
				bool isSha1Sig = sigAlgo.IndexOf("sha1", StringComparison.OrdinalIgnoreCase) >= 0 && sigAlgo.IndexOf("sha2", StringComparison.OrdinalIgnoreCase) < 0;
				int keySize = 0;
				bool weakKeySize = false;
				try
				{
					using RSA rsa = certificate.PublicKey.GetRSAPublicKey();
					if (rsa != null)
					{
						keySize = rsa.KeySize;
						weakKeySize = keySize < 2048;
					}
				}
				catch
				{
				}
				if (isExpired)
				{
					expired++;
				}
				if (isSha1Sig)
				{
					weakSig++;
				}
				if (isExpired || weakKeySize)
				{
					string subjectCapture = subject;
					string sigCapture = sigAlgo;
					int ksCapture = keySize;
					DateTime naCapture = notAfter;
					bool expCapture = isExpired;
					TryAdd(results, () => new SecurityResult
					{
						Category = Category,
						CheckName = "Intermediate CA: " + ((subjectCapture.Length > 60) ? (subjectCapture.Substring(0, 60) + "…") : subjectCapture),
						CurrentValue = $"Sig={sigCapture} | Key={ksCapture}b | Expires={naCapture:yyyy-MM-dd}",
						ExpectedValue = "Valid, RSA>=2048, SHA-256+",
						Status = ((!expCapture) ? SecurityStatus.Warning : SecurityStatus.Critical),
						Description = "Intermediate CA: " + subjectCapture + " — " + (expCapture ? "EXPIRED — breaks certificate chain validation" : $"Weak key ({ksCapture} bits)"),
						Recommendation = (expCapture ? "Remove expired intermediate CA — it breaks chain validation for all certificates it signed." : "Replace intermediate CA with stronger key (RSA>=2048)."),
						Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/certificate-management"
					});
				}
			}
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Intermediate CAs: Summary",
				CurrentValue = $"Total={total} | Expired={expired} | WeakSig(SHA1)={weakSig}",
				ExpectedValue = "0 expired, 0 weak-signature",
				Status = ((expired > 0) ? SecurityStatus.Critical : ((weakSig > 0) ? SecurityStatus.Warning : SecurityStatus.OK)),
				Description = "Summary of Intermediate Certificate Authorities in LocalMachine store.",
				Recommendation = ((expired > 0) ? "Remove expired intermediate CAs to ensure certificate chain validation works." : ((weakSig > 0) ? "Replace SHA-1 intermediate CAs." : "Intermediate CA store appears healthy.")),
				Reference = ""
			});
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Intermediate CAs",
				CurrentValue = "Error: " + ex2.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to open X509Store CertificateAuthority on LocalMachine.",
				Recommendation = "Run as Administrator.",
				Reference = ""
			});
		}
	}

	private void CollectDisallowedStore(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		try
		{
			using X509Store x509Store = new X509Store(StoreName.Disallowed, StoreLocation.LocalMachine);
			x509Store.Open(OpenFlags.OpenExistingOnly);
			int count = x509Store.Certificates.Count;
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Disallowed/Revoked Certificates Store",
				CurrentValue = $"{count} revoked certificate(s) in Disallowed store",
				ExpectedValue = "> 0 entries (revocation enforced)",
				Status = ((count == 0) ? SecurityStatus.Warning : SecurityStatus.Info),
				Description = ((count == 0) ? "Disallowed store is empty — revocation enforcement may not be configured. Known-bad certificates would not be explicitly blocked." : $"Disallowed store contains {count} entries. Revocation is being enforced via explicit block list."),
				Recommendation = ((count == 0) ? "Configure certificate revocation policies and ensure Windows auto-update for root certificates is enabled." : "Having entries is normal and expected — revocation is enforced."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/certificate-management"
			});
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Disallowed Certificates Store",
				CurrentValue = "Error: " + ex2.Message,
				Status = SecurityStatus.Error,
				Description = "Failed to open Disallowed certificate store.",
				Recommendation = "Run as Administrator.",
				Reference = ""
			});
		}
	}

	private void CollectAutoEnrollmentPolicy(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey autoEnrollKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Cryptography\\AutoEnrollment");
			object policyValueRaw = autoEnrollKey?.GetValue("AEPolicy");
			int aePolicy = ((policyValueRaw != null) ? Convert.ToInt32(policyValueRaw) : (-1));
			string policyLabel = ((aePolicy == 0) ? "0 — Disabled" : ((aePolicy != 7) ? ((aePolicy == -1) ? "Not configured (default)" : $"{aePolicy} — Custom value") : "7 — Enabled with auto-renew (recommended)"));
			string currentValue = policyLabel;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Auto-Enrollment Policy (HKLM)",
				CurrentValue = currentValue,
				ExpectedValue = "7 (Enabled with auto-renew) in enterprise environment",
				Status = ((aePolicy == 0) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Certificate auto-enrollment and auto-renewal policy (machine scope). Disabling auto-enrollment may cause certificates to expire unnoticed.",
				Recommendation = ((aePolicy == 0) ? "Enable auto-enrollment (AEPolicy=7) to ensure certificates are renewed automatically before expiry." : "Auto-enrollment is enabled or not restricted."),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
			using RegistryKey autoEnrollKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography\\AutoEnrollment");
			object policyValueRaw = autoEnrollKey?.GetValue("AEPolicy");
			int aePolicy = ((policyValueRaw != null) ? Convert.ToInt32(policyValueRaw) : (-1));
			string policyLabel = ((aePolicy == 0) ? "0 — Disabled" : ((aePolicy != 7) ? ((aePolicy == -1) ? "Not configured (default)" : $"{aePolicy} — Custom value") : "7 — Enabled with auto-renew (recommended)"));
			string currentValue = policyLabel;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Auto-Enrollment Policy (HKCU)",
				CurrentValue = currentValue,
				ExpectedValue = "7 (Enabled with auto-renew)",
				Status = ((aePolicy == 0) ? SecurityStatus.Warning : SecurityStatus.Info),
				Description = "Certificate auto-enrollment policy for the current user. Disabled auto-enrollment means user certificates may expire unnoticed.",
				Recommendation = ((aePolicy == 0) ? "Enable user auto-enrollment (AEPolicy=7) to prevent user certificates from expiring silently." : "User auto-enrollment is not restricted."),
				Reference = ""
			};
		});
	}

	private void CollectCrlCheckPolicy(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
			using RegistryKey publishingKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WinTrust\\Trust Providers\\Software Publishing");
			object stateValueRaw = publishingKey?.GetValue("State");
			long state = ((stateValueRaw != null) ? Convert.ToInt64(stateValueRaw) : 0);
			string currentValue = state switch
			{
				146944L => "0x23E00 — Do NOT check revocation (WARNING)", 
				146432L => "0x23C00 — Check revocation (GOOD)", 
				_ => $"0x{state:X} — Custom/unknown", 
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "WinTrust: Software Publishing Revocation Check",
				CurrentValue = currentValue,
				ExpectedValue = "0x23C00 (revocation checked)",
				Status = state switch
				{
					146432L => SecurityStatus.OK, 
					146944L => SecurityStatus.Warning, 
					_ => SecurityStatus.Info, 
				},
				Description = "WinTrust Software Publishing state controls whether revocation is checked when verifying Authenticode signatures.",
				Recommendation = ((state == 146944) ? "Enable revocation checking: set WinTrust\\Trust Providers\\Software Publishing\\State = 0x23C00." : "Revocation check is configured correctly."),
				Reference = "https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/certificate-management"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey authRootKey = baseKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot");
			object autoUpdateValueRaw = authRootKey?.GetValue("DisableRootAutoUpdate");
			int disableAutoUpdate = ((autoUpdateValueRaw != null) ? Convert.ToInt32(autoUpdateValueRaw) : 0);
			bool autoUpdateEnabled = disableAutoUpdate == 0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Root Certificate Auto-Update",
				CurrentValue = disableAutoUpdate switch
				{
					1 => "1 — Auto-update DISABLED (WARNING)", 
					0 => "0 — Auto-update ON (recommended)", 
					_ => $"{disableAutoUpdate} — Custom", 
				},
				ExpectedValue = "0 (auto-update enabled)",
				Status = ((!autoUpdateEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = "Controls whether Windows automatically downloads updated root certificates from Windows Update. Disabling may cause trust failures for new CAs.",
				Recommendation = ((!autoUpdateEnabled) ? "Enable root certificate auto-update: set DisableRootAutoUpdate = 0 or remove the policy." : "Root certificate auto-update is enabled."),
				Reference = "https://docs.microsoft.com/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration"
			};
		});
	}

	private void CollectSummary(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		int personalTotal = 0;
		int expiredCount = 0;
		int weakKeyCount = 0;
		int rootTotal = 0;
		try
		{
			using X509Store x509Store = new X509Store("My", StoreLocation.LocalMachine);
			x509Store.Open(OpenFlags.OpenExistingOnly);
			personalTotal = x509Store.Certificates.Count;
			foreach (X509Certificate2 certificate in x509Store.Certificates)
			{
				ct.ThrowIfCancellationRequested();
				if (certificate.NotAfter < DateTime.Now)
				{
					expiredCount++;
				}
				try
				{
					using RSA rsa = certificate.PublicKey.GetRSAPublicKey();
					if (rsa != null && rsa.KeySize < 2048)
					{
						weakKeyCount++;
					}
				}
				catch
				{
				}
			}
		}
		catch
		{
		}
		try
		{
			using X509Store rootStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
			rootStore.Open(OpenFlags.OpenExistingOnly);
			rootTotal = rootStore.Certificates.Count;
		}
		catch
		{
		}
		int pt = personalTotal;
		int pe = expiredCount;
		int pw = weakKeyCount;
		int rt = rootTotal;
		TryAdd(results, () => new SecurityResult
		{
			Category = Category,
			CheckName = "PKI Summary",
			CurrentValue = $"Personal certs={pt} (expired={pe}, weak-key={pw}) | Root CAs={rt}",
			ExpectedValue = "0 expired, 0 weak-key certificates",
			Status = ((pe > 0 || pw > 0) ? SecurityStatus.Warning : SecurityStatus.Info),
			Description = "High-level certificate inventory summary across personal and root CA stores.",
			Recommendation = ((pe > 0) ? "Renew or remove expired personal certificates." : ((pw > 0) ? "Replace certificates with weak keys." : "Certificate stores appear healthy.")),
			Reference = ""
		});
	}

	private static void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			results.Add(factory());
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = "Cryptographie",
				CheckName = "Check Error",
				CurrentValue = "Error",
				Status = SecurityStatus.Error,
				Description = "Check failed: " + ex.Message,
				Recommendation = "Review certificate store access and run as Administrator.",
				Reference = ""
			});
		}
	}
}
