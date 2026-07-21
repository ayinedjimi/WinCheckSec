using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class KerberosCollector : ISecurityCollector
{
	public string Name => "Kerberos & Authentification";

	public string Category => "Authentification";

	public async Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch sw = Stopwatch.StartNew();
		try
		{
			await Task.Run(delegate
			{
				ct.ThrowIfCancellationRequested();
				CheckKerberosEncryptionTypes(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckKerberosTicketLifetime(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckDomainMembership(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckNtlmRestrictions(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckProtectedUsers(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckCredentialCache(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckPassTheHashMitigations(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckLocalAdministratorAccount(report.Results, ct);
			}, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			report.ErrorMessage = "KerberosCollector — erreur fatale : " + ex.Message;
		}
		finally
		{
			sw.Stop();
			report.Duration = sw.Elapsed;
		}
		return report;
	}

	private void CheckKerberosEncryptionTypes(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			int? policyEncTypes = null;
			using (RegistryKey kerberosParamsKey = localMachineKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters"))
			{
				if (kerberosParamsKey?.GetValue("SupportedEncryptionTypes") is int encTypesValue)
				{
					policyEncTypes = encTypesValue;
				}
			}
			int? lsaEncTypes = null;
			using (RegistryKey lsaKerberosParamsKey = localMachineKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters"))
			{
				if (lsaKerberosParamsKey?.GetValue("SupportedEncryptionTypes") is int lsaEncTypesValue)
				{
					lsaEncTypes = lsaEncTypesValue;
				}
			}
			int encTypesBitmask = policyEncTypes ?? lsaEncTypes ?? (-1);
			bool notConfigured = encTypesBitmask == -1;
			List<string> supportedTypes = new List<string>();
			List<string> weakTypes = new List<string>();
			SecurityStatus status;
			if (notConfigured)
			{
				supportedTypes.Add("Valeur par défaut Windows : RC4-HMAC + AES128 + AES256 (bitmask non configuré)");
				status = SecurityStatus.Info;
			}
			else
			{
				if ((encTypesBitmask & 1) != 0)
				{
					supportedTypes.Add("DES-CBC-CRC (FAIBLE)");
					weakTypes.Add("DES-CBC-CRC");
				}
				if ((encTypesBitmask & 2) != 0)
				{
					supportedTypes.Add("DES-CBC-MD5 (FAIBLE)");
					weakTypes.Add("DES-CBC-MD5");
				}
				if ((encTypesBitmask & 4) != 0)
				{
					supportedTypes.Add("RC4-HMAC (faible — CVE-2022-37966)");
					weakTypes.Add("RC4-HMAC");
				}
				if ((encTypesBitmask & 8) != 0)
				{
					supportedTypes.Add("AES128-CTS-HMAC-SHA1-96 (correct)");
				}
				if ((encTypesBitmask & 0x10) != 0)
				{
					supportedTypes.Add("AES256-CTS-HMAC-SHA1-96 (idéal)");
				}
				if (supportedTypes.Count == 0)
				{
					supportedTypes.Add($"Aucun type connu (bitmask={encTypesBitmask})");
				}
				bool hasDes = weakTypes.Contains("DES-CBC-CRC") || weakTypes.Contains("DES-CBC-MD5");
				bool hasAes256 = (encTypesBitmask & 0x10) != 0;
				bool onlyRc4 = (encTypesBitmask & -5) == 0 && (encTypesBitmask & 4) != 0;
				status = (hasDes ? SecurityStatus.Critical : ((onlyRc4 || !hasAes256 || weakTypes.Count > 0) ? SecurityStatus.Warning : SecurityStatus.OK));
			}
			string sourceLabel = (policyEncTypes.HasValue ? "Stratégie de groupe (Policy)" : (lsaEncTypes.HasValue ? "LSA Parameters" : "Clé absente (valeurs par défaut Windows)"));
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Kerberos : Types de chiffrement pris en charge",
				CurrentValue = $"[{sourceLabel}] Bitmask={encTypesBitmask} → {string.Join(", ", supportedTypes)}",
				ExpectedValue = "AES256 activé, DES et idéalement RC4 désactivés (bitmask = 0x18 ou 0x10)",
				Status = status,
				Description = "Le bitmask SupportedEncryptionTypes contrôle les algorithmes de chiffrement acceptés par Kerberos. DES est cryptographiquement cassé depuis 2008. RC4-HMAC est vulnérable à CVE-2022-37966 (AS-REP Roasting, Kerberoasting). AES256 est le seul algorithme recommandé pour les déploiements modernes. Source de la valeur : " + sourceLabel + ".",
				Recommendation = (notConfigured ? "La clé SupportedEncryptionTypes n'est pas configurée explicitement. Configurer via GPO 'Network security: Configure encryption types allowed for Kerberos' avec uniquement AES128 + AES256 (bitmask 0x18). Tester la compatibilité avec les services et comptes existants avant de désactiver RC4." : ((weakTypes.Count == 0) ? "Configuration Kerberos correcte. AES256 est actif et les algorithmes faibles sont désactivés." : ("Désactiver les algorithmes faibles : " + string.Join(", ", weakTypes) + ". Configurer GPO 'Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Network security: Configure encryption types allowed for Kerberos' → cocher uniquement AES128-CTS-HMAC-SHA1-96 et AES256-CTS-HMAC-SHA1-96."))),
				Reference = "https://learn.microsoft.com/windows-server/security/kerberos/kerberos-authentication-overview | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-37966"
			};
		});
	}

	private void CheckKerberosTicketLifetime(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		using RegistryKey localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
		RegistryKey kerberosParamsKey = localMachineKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters");
		try
		{
			TryAdd(results, delegate
			{
				int maxServiceAge = ((kerberosParamsKey?.GetValue("MaxServiceAge") is int rawMaxServiceAge) ? rawMaxServiceAge : (-1));
				bool notConfigured = maxServiceAge == -1;
				int effectiveMaxServiceAge = (notConfigured ? 600 : maxServiceAge);
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Kerberos : MaxServiceAge (durée max ticket de service)",
					CurrentValue = (notConfigured ? "Non configuré (défaut : 600 minutes)" : $"{maxServiceAge} minutes"),
					ExpectedValue = "<= 600 minutes (10 heures)",
					Status = ((effectiveMaxServiceAge > 1440) ? SecurityStatus.Warning : SecurityStatus.Info),
					Description = "Durée de vie maximale d'un ticket de service Kerberos (TGS). La valeur par défaut est 600 minutes (10h). Des tickets de service à longue durée de vie augmentent la fenêtre d'exploitation en cas de vol de ticket (Pass-the-Ticket).",
					Recommendation = (notConfigured ? "Valeur par défaut (600 min). Configurer explicitement via GPO si une durée plus courte est souhaitée." : ((effectiveMaxServiceAge > 600) ? $"MaxServiceAge ({maxServiceAge} min) est supérieur à la valeur par défaut recommandée (600 min). Réduire via GPO 'Maximum lifetime for service ticket'." : "Valeur configurée acceptable.")),
					Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/maximum-lifetime-for-service-ticket"
				};
			});
			ct.ThrowIfCancellationRequested();
			TryAdd(results, delegate
			{
				int maxTicketAge = ((kerberosParamsKey?.GetValue("MaxTicketAge") is int rawMaxTicketAge) ? rawMaxTicketAge : (-1));
				bool notConfigured = maxTicketAge == -1;
				bool exceedsMax = (notConfigured ? 10 : maxTicketAge) > 24;
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Kerberos : MaxTicketAge (durée max TGT)",
					CurrentValue = (notConfigured ? "Non configuré (défaut : 10 heures)" : $"{maxTicketAge} heures"),
					ExpectedValue = "<= 10 heures (maximum : 24 heures)",
					Status = (exceedsMax ? SecurityStatus.Warning : SecurityStatus.Info),
					Description = "Durée de vie maximale d'un Ticket Granting Ticket (TGT). La valeur par défaut est 10 heures. Un TGT volé peut être utilisé jusqu'à son expiration pour accéder à des services (Pass-the-Ticket). Des TGT de plus de 24 heures créent un risque significatif.",
					Recommendation = (exceedsMax ? $"MaxTicketAge ({maxTicketAge}h) dépasse 24 heures. Réduire via GPO 'Maximum lifetime for user ticket' à 10 heures (recommandé) ou au maximum 24 heures." : (notConfigured ? "Valeur par défaut (10h). Configurer explicitement pour documenter l'intention de sécurité." : "Valeur configurée acceptable.")),
					Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/maximum-lifetime-for-user-ticket"
				};
			});
			ct.ThrowIfCancellationRequested();
			TryAdd(results, delegate
			{
				int maxRenewAge = ((kerberosParamsKey?.GetValue("MaxRenewAge") is int rawMaxRenewAge) ? rawMaxRenewAge : (-1));
				bool notConfigured = maxRenewAge == -1;
				int effectiveMaxRenewAge = (notConfigured ? 7 : maxRenewAge);
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Kerberos : MaxRenewAge (durée max de renouvellement TGT)",
					CurrentValue = (notConfigured ? "Non configuré (défaut : 7 jours)" : $"{maxRenewAge} jours"),
					ExpectedValue = "<= 7 jours",
					Status = ((effectiveMaxRenewAge > 14) ? SecurityStatus.Warning : SecurityStatus.Info),
					Description = "Durée maximale pendant laquelle un TGT peut être renouvelé. La valeur par défaut est 7 jours. Un ticket Golden Ticket (attaque Mimikatz) peut être généré avec une durée de renouvellement arbitraire.",
					Recommendation = ((effectiveMaxRenewAge > 7) ? $"MaxRenewAge ({effectiveMaxRenewAge}j) dépasse la valeur par défaut de 7 jours. Configurer via GPO 'Maximum lifetime for user ticket renewal'." : "Valeur acceptable."),
					Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/maximum-lifetime-for-user-ticket-renewal"
				};
			});
			ct.ThrowIfCancellationRequested();
			TryAdd(results, delegate
			{
				int maxClockSkew = ((kerberosParamsKey?.GetValue("MaxClockSkew") is int rawMaxClockSkew) ? rawMaxClockSkew : (-1));
				bool notConfigured = maxClockSkew == -1;
				int effectiveMaxClockSkew = (notConfigured ? 5 : maxClockSkew);
				bool exceedsRecommended = effectiveMaxClockSkew > 10;
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Kerberos : MaxClockSkew (tolérance de décalage horaire)",
					CurrentValue = (notConfigured ? "Non configuré (défaut : 5 minutes)" : $"{maxClockSkew} minutes"),
					ExpectedValue = "<= 5 minutes",
					Status = (exceedsRecommended ? SecurityStatus.Warning : SecurityStatus.Info),
					Description = "Tolérance maximale de décalage d'horloge entre le client et le KDC. La valeur par défaut est 5 minutes. Kerberos requiert une synchronisation horaire stricte pour prévenir les attaques par rejeu. Un décalage élevé affaiblit la protection anti-rejeu et peut indiquer une désynchronisation NTP.",
					Recommendation = (exceedsRecommended ? ($"MaxClockSkew ({effectiveMaxClockSkew} min) est supérieur à la valeur recommandée (5 min). " + "Vérifier la synchronisation NTP de tous les postes avec le contrôleur de domaine. Réduire MaxClockSkew via GPO 'Maximum tolerance for computer clock synchronization'.") : "Valeur acceptable. S'assurer que NTP est correctement configuré (sync avec le DC)."),
					Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/maximum-tolerance-for-computer-clock-synchronization"
				};
			});
		}
		finally
		{
			if (kerberosParamsKey != null)
			{
				((IDisposable)kerberosParamsKey).Dispose();
			}
		}
	}

	private void CheckDomainMembership(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			string domainName = string.Empty;
			bool isPartOfDomain = false;
			int domainRole = 0;
			try
			{
				ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT PartOfDomain, Domain, DomainRole FROM Win32_ComputerSystem");
				try
				{
					using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
					using ManagementObjectCollection.ManagementObjectEnumerator managementObjectEnumerator = managementObjectCollection.GetEnumerator();
					if (managementObjectEnumerator.MoveNext())
					{
						ManagementObject managementObject = (ManagementObject)managementObjectEnumerator.Current;
						ManagementObject managementObjectToDispose = managementObject;
						try
						{
							isPartOfDomain = Convert.ToBoolean(managementObject["PartOfDomain"] ?? ((object)false));
							domainName = managementObject["Domain"]?.ToString() ?? string.Empty;
							domainRole = Convert.ToInt32(managementObject["DomainRole"] ?? ((object)0));
						}
						finally
						{
							((IDisposable)managementObjectToDispose)?.Dispose();
						}
					}
				}
				finally
				{
					((IDisposable)managementObjectSearcher)?.Dispose();
				}
			}
			catch (ManagementException)
			{
			}
			catch (Exception)
			{
			}
			string roleLabel = domainRole switch
			{
				0 => "Poste de travail autonome (Standalone Workstation)",
				1 => "Poste de travail membre du domaine (Member Workstation)",
				2 => "Serveur autonome (Standalone Server)",
				3 => "Serveur membre du domaine (Member Server)",
				4 => "Contrôleur de domaine secondaire (Backup DC)",
				5 => "Contrôleur de domaine principal (Primary DC)",
				_ => $"Rôle inconnu ({domainRole})",
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Domaine : Appartenance et rôle",
				CurrentValue = (isPartOfDomain ? ("Membre du domaine '" + domainName + "' — Rôle : " + roleLabel) : ("Hors domaine — Rôle : " + roleLabel)),
				ExpectedValue = "Membre d'un domaine Active Directory (pour les systèmes d'entreprise)",
				Status = ((!isPartOfDomain) ? SecurityStatus.Warning : SecurityStatus.Info),
				Description = $"Ce système {(isPartOfDomain ? "est membre" : "n'est PAS membre")} d'un domaine Active Directory. Rôle WMI DomainRole={domainRole} : {roleLabel}. " + "Les systèmes hors domaine ne bénéficient pas des politiques de groupe (GPO), de la gestion centralisée des comptes et du durcissement centralisé.",
				Recommendation = (isPartOfDomain ? "Vérifier que les GPO de sécurité sont correctement appliquées (gpresult /h)." : "Ce système est hors domaine. S'assurer qu'il dispose d'un durcissement local équivalent aux GPO de domaine. Si ce système devrait être dans le domaine, investiguer."),
				Reference = "https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview"
			};
		});
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			using RegistryKey localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey gpoHistoryKey = localMachineKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History");
			string currentValue = "Non disponible";
			SecurityStatus status = SecurityStatus.Info;
			if (gpoHistoryKey != null)
			{
				gpoHistoryKey.GetValue("DSPollingIntervalMinutes");
				using RegistryKey gpoHistoryMachineKey = localMachineKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\Machine");
				if (gpoHistoryMachineKey != null)
				{
					gpoHistoryMachineKey.GetValue("Extensions");
					currentValue = "Clé GPO History présente (date détaillée non disponible via registre)";
					status = SecurityStatus.Info;
				}
				else
				{
					currentValue = "Sous-clé Machine absente (système peut-être hors domaine)";
				}
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Stratégie de groupe : Dernière mise à jour",
				CurrentValue = currentValue,
				ExpectedValue = "GPO appliquées (système membre de domaine)",
				Status = status,
				Description = "Indicateur de présence de l'historique des stratégies de groupe dans le registre. Pour vérifier l'heure exacte de la dernière application des GPO, exécuter : 'gpresult /r'.",
				Recommendation = "Exécuter 'gpresult /h rapport_gpo.html' pour un rapport complet des GPO appliquées. Vérifier que les GPO de sécurité sont bien appliquées (AppLocker, LAPS, etc.).",
				Reference = "https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview"
			};
		});
	}

	private void CheckNtlmRestrictions(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		RegistryKey localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
		try
		{
			RegistryKey netlogonParamsKey = localMachineKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters");
			try
			{
				TryAdd(results, delegate
				{
					int requireSignOrSeal = ((netlogonParamsKey?.GetValue("RequireSignOrSeal") is int rawRequireSignOrSeal) ? rawRequireSignOrSeal : (-1));
					bool notConfigured = requireSignOrSeal == -1;
					bool isEnabled = requireSignOrSeal == 1;
					return new SecurityResult
					{
						Category = Category,
						CheckName = "Netlogon : RequireSignOrSeal",
						CurrentValue = (notConfigured ? "Non configuré (défaut OS : 1)" : $"{requireSignOrSeal}"),
						ExpectedValue = "1 (Signature ou chiffrement requis)",
						Status = ((!notConfigured && !isEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
						Description = "RequireSignOrSeal = 1 force la signature ou le chiffrement du canal sécurisé Netlogon entre le client et le contrôleur de domaine. Si désactivé, les communications Netlogon peuvent être interceptées et modifiées (attaque Zerologon CVE-2020-1472).",
						Recommendation = ((!notConfigured && !isEnabled) ? "Activer RequireSignOrSeal = 1 via GPO 'Domain member: Digitally encrypt or sign secure channel data (always)'." : "Configuration correcte ou valeur par défaut (1). Configurer explicitement via GPO pour documenter l'intention."),
						Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/domain-member-digitally-encrypt-or-sign-secure-channel-data-always | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472"
					};
				});
				ct.ThrowIfCancellationRequested();
				TryAdd(results, delegate
				{
					int requireStrongKey = ((netlogonParamsKey?.GetValue("RequireStrongKey") is int rawRequireStrongKey) ? rawRequireStrongKey : (-1));
					bool notConfigured = requireStrongKey == -1;
					bool isEnabled = requireStrongKey == 1;
					return new SecurityResult
					{
						Category = Category,
						CheckName = "Netlogon : RequireStrongKey",
						CurrentValue = (notConfigured ? "Non configuré (défaut OS : 1)" : $"{requireStrongKey}"),
						ExpectedValue = "1 (Clé forte requise pour le canal sécurisé)",
						Status = ((!notConfigured && !isEnabled) ? SecurityStatus.Warning : SecurityStatus.OK),
						Description = "RequireStrongKey = 1 exige l'utilisation d'une clé de session forte (128 bits) pour le canal sécurisé Netlogon. Des clés faibles permettent une attaque par force brute sur les communications Netlogon.",
						Recommendation = ((!notConfigured && !isEnabled) ? "Activer RequireStrongKey = 1 via GPO 'Domain member: Require strong (Windows 2000 or later) session key'." : "Configuration correcte ou valeur par défaut."),
						Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/domain-member-require-strong-windows-2000-or-later-session-key"
					};
				});
				ct.ThrowIfCancellationRequested();
				TryAdd(results, delegate
				{
					int sealSecureChannel = ((netlogonParamsKey?.GetValue("SealSecureChannel") is int rawSealSecureChannel) ? rawSealSecureChannel : (-1));
					bool notConfigured = sealSecureChannel == -1;
					bool isEnabledOrDefault = notConfigured || sealSecureChannel == 1;
					return new SecurityResult
					{
						Category = Category,
						CheckName = "Netlogon : SealSecureChannel",
						CurrentValue = (notConfigured ? "Non configuré (comportement par défaut)" : $"{sealSecureChannel}"),
						ExpectedValue = "1 (Chiffrement du canal sécurisé)",
						Status = ((!isEnabledOrDefault) ? SecurityStatus.Warning : SecurityStatus.OK),
						Description = "SealSecureChannel = 1 chiffre (et ne signe pas seulement) toutes les communications du canal sécurisé Netlogon. Le chiffrement offre une protection supérieure à la simple signature contre l'écoute passive.",
						Recommendation = (isEnabledOrDefault ? "Configuration correcte." : "Activer SealSecureChannel = 1 via GPO 'Domain member: Digitally encrypt secure channel data (when possible)'."),
						Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/domain-member-digitally-encrypt-secure-channel-data-when-possible"
					};
				});
				ct.ThrowIfCancellationRequested();
				TryAdd(results, delegate
				{
					int signSecureChannel = ((netlogonParamsKey?.GetValue("SignSecureChannel") is int rawSignSecureChannel) ? rawSignSecureChannel : (-1));
					bool notConfigured = signSecureChannel == -1;
					bool isEnabledOrDefault = notConfigured || signSecureChannel == 1;
					return new SecurityResult
					{
						Category = Category,
						CheckName = "Netlogon : SignSecureChannel",
						CurrentValue = (notConfigured ? "Non configuré (comportement par défaut)" : $"{signSecureChannel}"),
						ExpectedValue = "1 (Signature du canal sécurisé)",
						Status = ((!isEnabledOrDefault) ? SecurityStatus.Warning : SecurityStatus.OK),
						Description = "SignSecureChannel = 1 active la signature cryptographique de toutes les communications du canal sécurisé Netlogon, garantissant l'intégrité des données échangées entre le client et le DC.",
						Recommendation = (isEnabledOrDefault ? "Configuration correcte." : "Activer SignSecureChannel = 1 via GPO 'Domain member: Digitally sign secure channel data (when possible)'."),
						Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/domain-member-digitally-sign-secure-channel-data-when-possible"
					};
				});
				ct.ThrowIfCancellationRequested();
				TryAdd(results, delegate
				{
					using RegistryKey systemPolicyKey = localMachineKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\System");
					int msaOptional = ((systemPolicyKey?.GetValue("MSAOptional") is int rawMsaOptional) ? rawMsaOptional : (-1));
					return new SecurityResult
					{
						Category = Category,
						CheckName = "Politique : Comptes Microsoft optionnels (MSAOptional)",
						CurrentValue = msaOptional switch
						{
							1 => "1 — Comptes Microsoft optionnels",
							-1 => "Non configuré",
							_ => $"{msaOptional}",
						},
						ExpectedValue = "1 ou non configuré (comptes Microsoft non obligatoires)",
						Status = SecurityStatus.Info,
						Description = "MSAOptional contrôle si les comptes Microsoft (Live/Outlook) sont optionnels lors de la configuration Windows. Sur les systèmes d'entreprise, les comptes Microsoft personnels ne devraient pas être utilisés.",
						Recommendation = "Sur les systèmes d'entreprise, configurer 'Accounts: Block Microsoft accounts' via GPO pour empêcher l'utilisation de comptes Microsoft personnels.",
						Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/accounts-block-microsoft-accounts"
					};
				});
			}
			finally
			{
				if (netlogonParamsKey != null)
				{
					((IDisposable)netlogonParamsKey).Dispose();
				}
			}
		}
		finally
		{
			if (localMachineKey != null)
			{
				((IDisposable)localMachineKey).Dispose();
			}
		}
	}

	private void CheckProtectedUsers(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			List<string> membres = new List<string>();
			string errorMessage = string.Empty;
			try
			{
				using Process process = Process.Start(new ProcessStartInfo("net.exe", "localgroup \"Protected Users\"")
				{
					RedirectStandardOutput = true,
					RedirectStandardError = true,
					UseShellExecute = false,
					CreateNoWindow = true,
					StandardOutputEncoding = Encoding.GetEncoding(850)
				});
				if (process != null)
				{
					string stderrPu = "";
					process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs errorArgs)
					{
						if (errorArgs.Data != null)
						{
							stderrPu += errorArgs.Data;
						}
					};
					process.BeginErrorReadLine();
					string stdoutContent = process.StandardOutput.ReadToEnd();
					if (!process.WaitForExit(8000))
					{
						try
						{
							process.Kill();
						}
						catch
						{
						}
					}
					ct.ThrowIfCancellationRequested();
					if (process.ExitCode != 0)
					{
						errorMessage = $"net localgroup exited with code {process.ExitCode}";
					}
					else
					{
						bool inMemberSection = false;
						string[] lines = stdoutContent.Split('\n');
						for (int i = 0; i < lines.Length; i++)
						{
							string trimmedLine = lines[i].Trim();
							if (trimmedLine.StartsWith("---"))
							{
								inMemberSection = true;
							}
							else if (inMemberSection && !string.IsNullOrEmpty(trimmedLine) && !trimmedLine.StartsWith("The command") && !trimmedLine.StartsWith("La commande"))
							{
								membres.Add(trimmedLine);
							}
						}
					}
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				errorMessage = ex.Message;
			}
			using RegistryKey localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey systemPolicyKey = localMachineKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\System");
			int allowProtectedCreds = ((systemPolicyKey?.GetValue("AllowProtectedCreds") is int rawAllowProtectedCreds) ? rawAllowProtectedCreds : (-1));
			string membresAffichage = ((membres.Count > 0) ? string.Join(", ", membres) : "(groupe vide ou inaccessible)");
			if (!string.IsNullOrEmpty(errorMessage))
			{
				membresAffichage = "Erreur : " + errorMessage;
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Protected Users : Membres du groupe local",
				CurrentValue = "Membres : " + membresAffichage + " | AllowProtectedCreds = " + ((allowProtectedCreds == -1) ? "non configuré" : allowProtectedCreds.ToString()),
				ExpectedValue = "Comptes privilégiés dans le groupe Protected Users (sur DC uniquement)",
				Status = SecurityStatus.Info,
				Description = "Le groupe 'Protected Users' (Windows 8.1/2012 R2+) offre des protections supplémentaires aux membres : désactivation de la délégation Kerberos, interdiction de NTLM, RC4 et DES, pas de mise en cache des credentials, tickets Kerberos non renouvelables. NOTE : Sur un poste de travail, ce groupe local est distinct du groupe Protected Users de domaine. La protection réelle est fournie par le groupe Protected Users dans Active Directory.",
				Recommendation = "Sur un contrôleur de domaine, ajouter tous les comptes d'administrateurs de domaine (DA, EA, Schema Admins) au groupe Protected Users AD. Sur un poste de travail, cette vérification est indicative. Référence : KB2871997 et Windows Server 2012 R2+ Protected Users Security Group.",
				Reference = "https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group"
			};
		});
	}

	private void CheckCredentialCache(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			using RegistryKey localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey winlogonKey = localMachineKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
			object? cachedLogonsRaw = winlogonKey?.GetValue("CachedLogonsCount");
			string cachedLogonsText = cachedLogonsRaw?.ToString() ?? string.Empty;
			int parsedCount;
			int cachedLogonsCount = (int.TryParse(cachedLogonsText, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsedCount) ? parsedCount : 10);
			bool notConfigured = cachedLogonsRaw == null;
			SecurityStatus status;
			string expectedValue;
			string recommendationText;
			if (cachedLogonsCount == 0)
			{
				status = SecurityStatus.OK;
				expectedValue = "0 (aucun cache) ou 1 (secours)";
				recommendationText = "Excellent. Aucun credential de domaine n'est mis en cache localement. Attention : en cas d'indisponibilité du DC, les utilisateurs ne pourront pas se connecter hors ligne.";
			}
			else if (cachedLogonsCount == 1)
			{
				status = SecurityStatus.OK;
				expectedValue = "0-1";
				recommendationText = "Acceptable. Un seul credential est mis en cache (accès secours). Envisager de le réduire à 0 si l'accès hors ligne n'est pas requis.";
			}
			else if (cachedLogonsCount <= 5)
			{
				status = SecurityStatus.Warning;
				expectedValue = "0 ou 1";
				recommendationText = $"CachedLogonsCount = {cachedLogonsCount}. Réduire à 1 ou 0 via GPO 'Interactive logon: Number of previous logons to cache'. " + "Les credentials mis en cache sont stockés sous forme de hash NL$Cache et peuvent être craqués hors ligne si un attaquant obtient un accès physique au disque.";
			}
			else
			{
				status = SecurityStatus.Critical;
				expectedValue = "0 ou 1";
				recommendationText = $"CachedLogonsCount = {cachedLogonsCount} est élevé. Réduire immédiatement à 1 via GPO 'Interactive logon: Number of previous logons to cache'. " + "Les {count} credentials mis en cache constituent une cible prioritaire pour les attaques de vol de credentials hors ligne (extraction via reg save HKLM\\SECURITY).";
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Cache credentials : CachedLogonsCount (Winlogon)",
				CurrentValue = (notConfigured ? "Non configuré (défaut Windows : 10)" : (cachedLogonsText ?? "")),
				ExpectedValue = expectedValue,
				Status = (notConfigured ? SecurityStatus.Warning : status),
				Description = "CachedLogonsCount définit le nombre de credentials de domaine (hash NL$Cache) stockés localement pour permettre la connexion hors ligne. Ces hashes, bien que plus résistants que les LM/NTLM hashes, peuvent être attaqués hors ligne. Ils sont stockés dans HKLM\\SECURITY\\Cache et accessibles uniquement avec les droits SYSTEM. Valeur actuelle : " + (notConfigured ? "défaut (10)" : cachedLogonsText) + ".",
				Recommendation = (notConfigured ? "La valeur par défaut (10) est trop élevée. Configurer CachedLogonsCount = 1 via GPO 'Interactive logon: Number of previous logons to cache'. Sur les postes non itinérants, utiliser 0." : recommendationText),
				Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/interactive-logon-number-of-previous-logons-to-cache"
			};
		});
	}

	private void CheckPassTheHashMitigations(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		RegistryKey localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
		try
		{
			TryAdd(results, delegate
			{
				ct.ThrowIfCancellationRequested();
				using RegistryKey lsaKey = localMachineKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
				int disableRestrictedAdmin = ((lsaKey?.GetValue("DisableRestrictedAdmin") is int rawDisableRestrictedAdmin) ? rawDisableRestrictedAdmin : (-1));
				bool notConfigured = disableRestrictedAdmin == -1;
				bool isSecure = notConfigured || disableRestrictedAdmin == 0;
				return new SecurityResult
				{
					Category = Category,
					CheckName = "PtH : DisableRestrictedAdmin (mode Admin Restreint RDP)",
					CurrentValue = (notConfigured ? "Non configuré (Restricted Admin activé par défaut)" : ((disableRestrictedAdmin == 0) ? "0 — Restricted Admin activé (correct)" : $"{disableRestrictedAdmin} — Restricted Admin DÉSACTIVÉ")),
					ExpectedValue = "0 ou absent (Restricted Admin activé)",
					Status = ((!isSecure) ? SecurityStatus.Critical : SecurityStatus.OK),
					Description = "DisableRestrictedAdmin contrôle le mode 'Restricted Admin' pour les connexions RDP. En mode Restricted Admin (valeur 0 ou absente), les credentials de l'utilisateur ne sont PAS transmis au serveur RDP distant lors de la connexion. Cela empêche l'extraction des credentials depuis la mémoire LSASS du serveur distant (Pass-the-Hash via RDP). Si DisableRestrictedAdmin = 1, les credentials sont exposés sur le serveur distant.",
					Recommendation = (isSecure ? "Mode Restricted Admin RDP actif. Les credentials ne sont pas transmis au serveur distant lors des sessions RDP." : "CRITIQUE : Désactiver DisableRestrictedAdmin en le supprimant ou en le mettant à 0. Commande : 'reg delete HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin /f' ou via GPO. Référence : Microsoft KB2871997."),
					Reference = "https://support.microsoft.com/kb/2871997 | https://attack.mitre.org/techniques/T1550/002/"
				};
			});
			ct.ThrowIfCancellationRequested();
			TryAdd(results, delegate
			{
				using RegistryKey lsaKey = localMachineKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa");
				int disableOutboundCreds = ((lsaKey?.GetValue("DisableRestrictedAdminOutboundCreds") is int rawOutboundCreds) ? rawOutboundCreds : (-1));
				bool notConfigured = disableOutboundCreds == -1;
				bool isSecure = notConfigured || disableOutboundCreds == 0;
				return new SecurityResult
				{
					Category = Category,
					CheckName = "PtH : DisableRestrictedAdminOutboundCreds",
					CurrentValue = (notConfigured ? "Non configuré (défaut : credentials sortants restreints)" : $"{disableOutboundCreds}"),
					ExpectedValue = "0 ou absent (credentials sortants restreints)",
					Status = ((!isSecure) ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = "DisableRestrictedAdminOutboundCreds = 0 (ou absent) empêche l'utilisation des credentials de l'utilisateur pour les connexions sortantes initiées depuis une session RDP en mode Restricted Admin. Réduit le risque de mouvement latéral depuis une session RDP compromise.",
					Recommendation = (isSecure ? "Configuration correcte." : "Mettre DisableRestrictedAdminOutboundCreds = 0 pour restreindre les credentials sortants depuis les sessions RDP Restricted Admin."),
					Reference = "https://support.microsoft.com/kb/2871997"
				};
			});
			ct.ThrowIfCancellationRequested();
			TryAdd(results, delegate
			{
				using RegistryKey credDelegationKey = localMachineKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation");
				int allowDefaultCredentials = ((credDelegationKey?.GetValue("AllowDefaultCredentials") is int rawAllowDefaultCredentials) ? rawAllowDefaultCredentials : (-1));
				bool notConfigured = allowDefaultCredentials == -1;
				bool isVulnerable = !notConfigured && allowDefaultCredentials != 0;
				return new SecurityResult
				{
					Category = Category,
					CheckName = "PtH : AllowDefaultCredentials (délégation CredSSP)",
					CurrentValue = (notConfigured ? "Non configuré (délégation désactivée par défaut)" : $"{allowDefaultCredentials}"),
					ExpectedValue = "Absent ou 0 (délégation désactivée)",
					Status = (isVulnerable ? SecurityStatus.Critical : SecurityStatus.OK),
					Description = "AllowDefaultCredentials = 1 autorise la délégation automatique des credentials CredSSP vers des serveurs distants. Cela permet à un serveur malveillant ou compromis de capturer les credentials de l'utilisateur (attaque CredSSP MitM). La délégation CredSSP ne doit être autorisée que vers des serveurs spécifiques et de confiance.",
					Recommendation = (isVulnerable ? "CRITIQUE : AllowDefaultCredentials est activé. Désactiver via GPO 'Computer Configuration → Administrative Templates → System → Credentials Delegation → Allow delegating default credentials'. Utiliser AllowFreshCredentialsList pour restreindre à des serveurs spécifiques si nécessaire." : "AllowDefaultCredentials n'est pas configuré (sécurisé par défaut)."),
					Reference = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers"
				};
			});
			ct.ThrowIfCancellationRequested();
			TryAdd(results, delegate
			{
				using RegistryKey credDelegationKey = localMachineKey.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation");
				int allowSavedCredentials = ((credDelegationKey?.GetValue("AllowSavedCredentials") is int rawAllowSavedCredentials) ? rawAllowSavedCredentials : (-1));
				bool notConfigured = allowSavedCredentials == -1;
				bool isVulnerable = !notConfigured && allowSavedCredentials != 0;
				return new SecurityResult
				{
					Category = Category,
					CheckName = "PtH : AllowSavedCredentials (credentials sauvegardés CredSSP)",
					CurrentValue = (notConfigured ? "Non configuré (désactivé par défaut)" : $"{allowSavedCredentials}"),
					ExpectedValue = "Absent ou 0",
					Status = (isVulnerable ? SecurityStatus.Warning : SecurityStatus.OK),
					Description = "AllowSavedCredentials autorise la délégation de credentials sauvegardés via CredSSP. Cela expose les credentials stockés (Credential Manager) aux serveurs distants lors des sessions RDP/WinRM.",
					Recommendation = (isVulnerable ? "Désactiver AllowSavedCredentials via GPO 'Allow delegating saved credentials'. Les credentials sauvegardés ne doivent pas être délégués automatiquement à des serveurs distants." : "Configuration correcte."),
					Reference = "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-credentproviders"
				};
			});
		}
		finally
		{
			if (localMachineKey != null)
			{
				((IDisposable)localMachineKey).Dispose();
			}
		}
	}

	private void CheckLocalAdministratorAccount(List<SecurityResult> results, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		TryAdd(results, delegate
		{
			ct.ThrowIfCancellationRequested();
			bool isEnabled = false;
			bool foundSid500 = false;
			int passwordAgeDays = 0;
			bool passwordAgeKnown = false;
			string accountName = "Administrator";
			string accountSid = string.Empty;
			try
			{
				// Correctif H2 : PasswordAge n'existe pas sur Win32_UserAccount (provoquait WBEM_E_INVALID_QUERY).
				// On ne sélectionne que Name, Disabled, SID. L'âge du mot de passe est récupéré best-effort plus bas.
				ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT Name, Disabled, SID FROM Win32_UserAccount WHERE LocalAccount=True");
				try
				{
					using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
					foreach (ManagementObject userAccount in managementObjectCollection)
					{
						ManagementObject managementObjectToDispose = userAccount;
						try
						{
							ct.ThrowIfCancellationRequested();
							string sid = userAccount["SID"]?.ToString() ?? string.Empty;
							if (sid.EndsWith("-500"))
							{
								foundSid500 = true;
								accountName = userAccount["Name"]?.ToString() ?? "Administrator";
								accountSid = sid;
								isEnabled = !Convert.ToBoolean(userAccount["Disabled"] ?? ((object)true));
								break;
							}
						}
						finally
						{
							((IDisposable)managementObjectToDispose)?.Dispose();
						}
					}
				}
				finally
				{
					((IDisposable)managementObjectSearcher)?.Dispose();
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Compte Administrateur local",
					CurrentValue = "Erreur WMI : " + ex.Message,
					Status = SecurityStatus.Error,
					Description = "Impossible de récupérer les informations du compte Administrateur local via WMI.",
					Recommendation = "Exécuter CHECKSEC en tant qu'administrateur et vérifier le service WMI.",
					Reference = ""
				};
			}
			if (!foundSid500)
			{
				return new SecurityResult
				{
					Category = Category,
					CheckName = "Compte Administrateur local (SID-500)",
					CurrentValue = "Compte SID-500 introuvable",
					ExpectedValue = "Désactivé",
					Status = SecurityStatus.Info,
					Description = "Le compte Administrateur intégré (SID-500) n'a pas été trouvé via WMI. Cela peut indiquer un environnement restreint.",
					Recommendation = "Vérifier manuellement avec : 'net user administrator' ou 'Get-LocalUser -SID S-1-5-21-*-500'.",
					Reference = ""
				};
			}
			// Correctif H2 : récupération best-effort de l'âge du mot de passe via une requête SÉPARÉE
			// sur Win32_NetworkLoginProfile (jointe par Name). Isolée dans son propre try/catch : un échec
			// n'impacte jamais le verdict principal (compte activé/désactivé).
			try
			{
				ManagementObjectSearcher profileSearcher = new ManagementObjectSearcher("SELECT Name, PasswordAge FROM Win32_NetworkLoginProfile");
				try
				{
					using ManagementObjectCollection profiles = profileSearcher.Get();
					foreach (ManagementObject profile in profiles)
					{
						ManagementObject profileToDispose = profile;
						try
						{
							string profileName = profile["Name"]?.ToString() ?? string.Empty;
							int backslashIndex = profileName.LastIndexOf('\\');
							if (backslashIndex >= 0)
							{
								profileName = profileName.Substring(backslashIndex + 1);
							}
							if (profileName.Equals(accountName, StringComparison.OrdinalIgnoreCase))
							{
								object passwordAgeRaw = profile["PasswordAge"];
								if (passwordAgeRaw != null)
								{
									passwordAgeDays = (int)(Convert.ToInt64(passwordAgeRaw) / 86400);
									passwordAgeKnown = true;
								}
								break;
							}
						}
						finally
						{
							((IDisposable)profileToDispose)?.Dispose();
						}
					}
				}
				finally
				{
					((IDisposable)profileSearcher)?.Dispose();
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception)
			{
				passwordAgeKnown = false;
			}
			string passwordAgeText = (passwordAgeKnown ? $"{passwordAgeDays} jours" : "N/A");
			SecurityStatus status;
			string recommendation;
			if (!isEnabled)
			{
				status = SecurityStatus.OK;
				recommendation = "Le compte Administrateur intégré est désactivé. Configuration recommandée.";
			}
			else if (passwordAgeKnown && passwordAgeDays > 90)
			{
				status = SecurityStatus.Warning;
				recommendation = $"Le compte Administrateur intégré '{accountName}' est actif et son mot de passe n'a pas été changé depuis {passwordAgeDays} jours (> 90 jours). " + "Changer le mot de passe immédiatement et envisager d'utiliser LAPS (Local Administrator Password Solution) pour gérer les mots de passe locaux.";
			}
			else
			{
				status = SecurityStatus.Warning;
				recommendation = "Le compte Administrateur intégré '" + accountName + "' est actif. Désactiver le compte ou déployer LAPS pour garantir des mots de passe uniques par machine.";
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Compte Administrateur local (SID-500)",
				CurrentValue = (isEnabled ? $"Actif — Nom : '{accountName}' — Âge du mot de passe : {passwordAgeText}" : ("Désactivé — Nom : '" + accountName + "'")),
				ExpectedValue = "Désactivé ou géré par LAPS avec mot de passe < 90 jours",
				Status = status,
				Description = $"Le compte Administrateur intégré Windows (SID-500 : {accountSid}) est {(isEnabled ? "ACTIF" : "désactivé")}. " + "Le compte SID-500 est la cible privilégiée des attaques de type Pass-the-Hash et brute-force car son SID est connu et identique sur tous les systèmes Windows. " + (isEnabled ? (passwordAgeKnown ? $"Le mot de passe a été changé il y a {passwordAgeDays} jours." : "L'âge du mot de passe n'a pas pu être déterminé (N/A).") : ""),
				Recommendation = recommendation,
				Reference = "https://learn.microsoft.com/windows-server/identity/laps/laps-overview | https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/accounts-administrator-account-status"
			};
		});
	}

	private void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			results.Add(factory());
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
				CheckName = "Erreur de vérification",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Vérification échouée : " + ex.Message,
				Recommendation = "Vérifier les droits d'accès au registre et relancer en tant qu'administrateur.",
				Reference = ""
			});
		}
	}
}
