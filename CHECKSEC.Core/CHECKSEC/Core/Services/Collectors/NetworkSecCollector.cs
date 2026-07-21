using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class NetworkSecCollector : ISecurityCollector
{
	public string Name => "NetworkSecCollector";

	public string Category => "Sécurité Réseau";

	public async Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		Stopwatch stopwatch = Stopwatch.StartNew();
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		try
		{
			await Task.Run(delegate
			{
				ct.ThrowIfCancellationRequested();
				CheckLLMNR(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckNbtNs(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckMdns(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckDnssecAndDoH(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckWpad(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckSmbSecurity(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckNtlm(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckIpv6(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckWinRm(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckRdpSecurity(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckPsRemoting(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckPrintSpooler(report.Results);
			}, ct);
		}
		catch (OperationCanceledException)
		{
			report.ErrorMessage = "Collecte annulée.";
			throw;
		}
		catch (Exception exception)
		{
			report.ErrorMessage = "Erreur générale NetworkSecCollector: " + exception.Message;
		}
		finally
		{
			stopwatch.Stop();
			report.Duration = stopwatch.Elapsed;
		}
		return report;
	}

	private static (object? value, bool success, string? error) ReadReg(string hive, string subKey, string valueName)
	{
		try
		{
			RegistryHive hKey;
			switch (hive.ToUpperInvariant())
			{
			case "HKLM":
			case "HKEY_LOCAL_MACHINE":
				hKey = RegistryHive.LocalMachine;
				break;
			case "HKCU":
			case "HKEY_CURRENT_USER":
				hKey = RegistryHive.CurrentUser;
				break;
			case "HKCC":
			case "HKEY_CURRENT_CONFIG":
				hKey = RegistryHive.CurrentConfig;
				break;
			case "HKU":
			case "HKEY_USERS":
				hKey = RegistryHive.Users;
				break;
			default:
				hKey = RegistryHive.LocalMachine;
				break;
			}
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey subKeyHandle = baseKey.OpenSubKey(subKey, writable: false);
			if (subKeyHandle == null)
			{
				return (value: null, success: false, error: "Key not found: " + hive + "\\" + subKey);
			}
			return (value: subKeyHandle.GetValue(valueName), success: true, error: null);
		}
		catch (UnauthorizedAccessException unauthorizedException)
		{
			return (value: null, success: false, error: "Access denied: " + unauthorizedException.Message);
		}
		catch (SecurityException securityException)
		{
			return (value: null, success: false, error: "Security error: " + securityException.Message);
		}
		catch (Exception exception)
		{
			return (value: null, success: false, error: "Error: " + exception.Message);
		}
	}

	private static object? ReadRegHklm(string subKey, string valueName)
	{
		var (regValue, success, errorMessage) = ReadReg("HKLM", subKey, valueName);
		if (!success && errorMessage != null)
		{
			ErrorLogger.AddError("[NetworkSec] Reg Error: " + errorMessage);
		}
		return regValue;
	}

	private static IEnumerable<string> EnumerateSubKeys(string hive, string subKey)
	{
		try
		{
			string hiveName = hive.ToUpperInvariant();
			RegistryHive hKey = ((hiveName == "HKLM") ? RegistryHive.LocalMachine : ((!(hiveName == "HKCU")) ? RegistryHive.LocalMachine : RegistryHive.CurrentUser));
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hKey, RegistryView.Registry64);
			using RegistryKey subKeyHandle = baseKey.OpenSubKey(subKey, writable: false);
			return subKeyHandle?.GetSubKeyNames() ?? Array.Empty<string>();
		}
		catch
		{
			return Array.Empty<string>();
		}
	}

	private static string GetServiceState(string serviceName)
	{
		try
		{
			string escapedServiceName = serviceName.Replace("'", "''");
			ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT State FROM Win32_Service WHERE Name='" + escapedServiceName + "'");
			try
			{
				using (ManagementObjectCollection.ManagementObjectEnumerator enumerator = searcher.Get().GetEnumerator())
				{
					if (enumerator.MoveNext())
					{
						ManagementObject serviceObject = (ManagementObject)enumerator.Current;
						ManagementObject disposableService = serviceObject;
						try
						{
							return serviceObject["State"]?.ToString() ?? "NotFound";
						}
						finally
						{
							((IDisposable)disposableService)?.Dispose();
						}
					}
				}
				return "NotFound";
			}
			finally
			{
				((IDisposable)searcher)?.Dispose();
			}
		}
		catch
		{
			return "NotFound";
		}
	}

	private static bool ServiceIsRunning(string serviceName)
	{
		return GetServiceState(serviceName).Equals("Running", StringComparison.OrdinalIgnoreCase);
	}

	private static SecurityResult MakeResult(string checkName, string currentValue, string expectedValue, SecurityStatus status, string description, string recommendation, string reference = "")
	{
		return new SecurityResult
		{
			Category = "Sécurité Réseau",
			CheckName = checkName,
			CurrentValue = currentValue,
			ExpectedValue = expectedValue,
			Status = status,
			Description = description,
			Recommendation = recommendation,
			Reference = reference,
			CollectedAt = DateTime.Now
		};
	}

	private static void CheckLLMNR(List<SecurityResult> results)
	{
		object enableMulticastValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "EnableMulticast");
		object queryNetAdapterNameValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "QueryNetAdapterName");
		int effectiveMulticast = ((!(enableMulticastValue is int multicastInt)) ? 1 : multicastInt);
		bool isLlmnrEnabled = effectiveMulticast != 0;
		results.Add(MakeResult("LLMNR - Link-Local Multicast Name Resolution", (enableMulticastValue == null) ? "Non configuré (activé par défaut)" : $"EnableMulticast = {effectiveMulticast}", "EnableMulticast = 0 (désactivé)", isLlmnrEnabled ? SecurityStatus.Critical : SecurityStatus.OK, isLlmnrEnabled ? "LLMNR est activé. Il peut être exploité pour des attaques de type MITM (Responder, PCredz) permettant le vol d'identifiants NTLM." : "LLMNR est désactivé. Le risque d'empoisonnement de résolution de noms est mitigé.", "Désactiver via GPO: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off Multicast Name Resolution = Enabled", "CIS Benchmark - 18.5.4.2 | ANSSI - Durcissement Windows"));
		if (queryNetAdapterNameValue != null)
		{
			results.Add(MakeResult("LLMNR - QueryNetAdapterName", $"QueryNetAdapterName = {queryNetAdapterNameValue}", "0 (désactivé)", (queryNetAdapterNameValue is int && (int)queryNetAdapterNameValue != 0) ? SecurityStatus.Warning : SecurityStatus.OK, "Contrôle si LLMNR interroge les noms d'adaptateurs réseau.", "Définir QueryNetAdapterName = 0 pour limiter la surface d'attaque LLMNR.", "Microsoft Security Baseline"));
		}
	}

	private static void CheckNbtNs(List<SecurityResult> results)
	{
		// Correctif M3b : détecter un échec de lecture de la clé Interfaces (droits) pour ne pas conclure « désactivé » à tort
		bool interfacesKeyReadable = false;
		try
		{
			using RegistryKey nbtBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey nbtInterfacesKey = nbtBaseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces", writable: false);
			interfacesKeyReadable = nbtInterfacesKey != null;
		}
		catch
		{
			interfacesKeyReadable = false;
		}
		string netbtServiceState = GetServiceState("NetBT");
		bool netbtServiceExists = !netbtServiceState.Equals("NotFound", StringComparison.OrdinalIgnoreCase);
		List<string> interfaceKeys = EnumerateSubKeys("HKLM", "SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces").ToList();
		List<string> enabledInterfaces = new List<string>();
		List<string> disabledInterfaces = new List<string>();
		List<string> defaultInterfaces = new List<string>();
		foreach (string interfaceKey in interfaceKeys)
		{
			switch ((ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\" + interfaceKey, "NetbiosOptions") is int netbiosOption) ? netbiosOption : 0)
			{
			case 2:
				disabledInterfaces.Add(interfaceKey);
				break;
			case 1:
				enabledInterfaces.Add(interfaceKey);
				break;
			default:
				defaultInterfaces.Add(interfaceKey);
				break;
			}
		}
		bool isNetbiosActive = enabledInterfaces.Count > 0 || defaultInterfaces.Count > 0;
		// Correctif M3b : état indéterminé si la clé Interfaces est illisible/absente ou si aucune interface lue alors que le service NetBT existe
		bool isNbtNsIndeterminate = interfaceKeys.Count == 0 && (!interfacesKeyReadable || netbtServiceExists);
		if (isNbtNsIndeterminate)
		{
			results.Add(MakeResult("NBT-NS - NetBIOS over TCP/IP (par adaptateur)", "État NBT-NS indéterminé (lecture impossible)", "NetbiosOptions = 2 (désactivé) sur tous les adaptateurs", SecurityStatus.Warning, "Impossible de déterminer l'état de NBT-NS : la clé de registre des interfaces NetBT est illisible/absente ou aucune interface n'a pu être lue alors que le service NetBT est présent. Ne pas conclure à une désactivation. Les attaques NBT-NS via Responder permettent le vol d'identifiants NTLM sur le réseau local.", "Vérifier les droits d'accès à HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces et confirmer manuellement NetbiosOptions = 2 sur toutes les cartes réseau.", "CIS Benchmark - 18.4.14 | ANSSI R69"));
		}
		else
		{
			string currentValue = ((interfaceKeys.Count == 0) ? "Aucune interface NetBT trouvée" : $"Activé/Défaut: {enabledInterfaces.Count + defaultInterfaces.Count} adaptateur(s), Désactivé: {disabledInterfaces.Count} adaptateur(s)");
			results.Add(MakeResult("NBT-NS - NetBIOS over TCP/IP (par adaptateur)", currentValue, "NetbiosOptions = 2 (désactivé) sur tous les adaptateurs", isNetbiosActive ? SecurityStatus.Critical : SecurityStatus.OK, isNetbiosActive ? ($"NetBIOS est actif sur {enabledInterfaces.Count + defaultInterfaces.Count} adaptateur(s). " + "Les attaques NBT-NS via Responder permettent le vol d'identifiants NTLM sur le réseau local.") : "NetBIOS est désactivé sur tous les adaptateurs réseau.", "Désactiver NetBIOS sur toutes les cartes réseau: Paramètres adaptateur > TCP/IP > Avancé > WINS > Désactiver NetBIOS. Ou via script PowerShell: Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.TcpipNetbiosOptions -ne 2} | ForEach-Object {$_.SetTcpipNetbios(2)}", "CIS Benchmark - 18.4.14 | ANSSI R69"));
		}
		object globalNetbiosValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters", "NetbiosOptions");
		if (globalNetbiosValue != null)
		{
			int globalNetbiosOption = ((globalNetbiosValue is int parsedGlobalNetbios) ? parsedGlobalNetbios : (-1));
			results.Add(MakeResult("NBT-NS - Paramètre global NetBT", $"NetbiosOptions global = {globalNetbiosOption}", "2 (désactivé)", (globalNetbiosOption != 2) ? SecurityStatus.Warning : SecurityStatus.OK, "Paramètre global de configuration NetBIOS sur TCP/IP.", "Définir la valeur globale NetbiosOptions = 2.", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters"));
		}
	}

	private static void CheckMdns(List<SecurityResult> results)
	{
		object enableMdnsValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", "EnableMDNS");
		// Correctif mDNS : suppression de la lecture morte de EnableMulticast/DNSClient (résultat jeté)
		bool isMdnsEnabled;
		string mdnsDisplay;
		if (enableMdnsValue is int mdnsValue)
		{
			isMdnsEnabled = mdnsValue != 0;
			mdnsDisplay = $"EnableMDNS = {mdnsValue}";
		}
		else
		{
			isMdnsEnabled = true;
			mdnsDisplay = "Non configuré (activé par défaut)";
		}
		string serviceState = GetServiceState("Dnscache");
		// Correctif mDNS : mDNS activé est exploitable par Responder (comme LLMNR/NBT-NS) -> sévérité relevée à Critical
		results.Add(MakeResult("mDNS - Multicast DNS", mdnsDisplay + " | Service Dnscache: " + serviceState, "EnableMDNS = 0 (désactivé)", isMdnsEnabled ? SecurityStatus.Critical : SecurityStatus.OK, isMdnsEnabled ? "mDNS est actif. Il peut être exploité sur des réseaux locaux non sécurisés pour de l'empoisonnement de résolution de noms (attaques de type Responder)." : "mDNS est désactivé, réduisant la surface d'attaque liée à la résolution de noms multicast.", "Désactiver mDNS via le registre: HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\EnableMDNS = 0. Ou via GPO DNS Client.", "CIS Benchmark - mDNS | RFC 6762"));
	}

	private static void CheckDnssecAndDoH(List<SecurityResult> results)
	{
		object enableAutoDohValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", "EnableAutoDoh");
		object dohFlagsValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", "DohFlags");
		object dohPolicyValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "DOHPolicy");
		object enableDnssecValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "EnableDnssec");
		int autoDohLevel = ((enableAutoDohValue is int autoDohInt) ? autoDohInt : 0);
		string dohDescription = autoDohLevel switch
		{
			2 => "DNS over HTTPS forcé (optimal)",
			1 => "DNS over HTTPS automatique",
			_ => "DNS over HTTPS désactivé",
		};
		results.Add(MakeResult("DNS over HTTPS (DoH) - EnableAutoDoh", $"EnableAutoDoh = {autoDohLevel} ({dohDescription})", "EnableAutoDoh = 2 (DNS over HTTPS forcé)", autoDohLevel switch
		{
			1 => SecurityStatus.Warning,
			2 => SecurityStatus.OK,
			_ => SecurityStatus.Warning,
		}, "DNS over HTTPS chiffre les requêtes DNS, empêchant l'interception et la manipulation des résolutions de noms. Distinct du DNSSEC qui garantit l'intégrité des réponses DNS.", "Forcer DoH via: HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\EnableAutoDoh = 2. Ou via GPO: Computer Configuration > Windows Settings > Name Resolution Policy.", "RFC 8484 | Microsoft DoH Documentation"));
		if (dohPolicyValue != null)
		{
			results.Add(MakeResult("DNS over HTTPS - Politique GPO (DOHPolicy)", $"DOHPolicy = {dohPolicyValue}", "2 (forcer DoH) ou 3 (DoH avec fallback)", (!(dohPolicyValue is int dohPolicyInt) || (dohPolicyInt != 2 && dohPolicyInt != 3)) ? SecurityStatus.Warning : SecurityStatus.OK, "Politique GPO contrôlant le comportement DNS over HTTPS.", "Configurer DOHPolicy = 2 pour forcer DoH sur tous les clients.", "Microsoft Security Baseline - DNS"));
		}
		bool isDnssecEnabled = enableDnssecValue is int dnssecInt && dnssecInt == 1;
		results.Add(MakeResult("DNSSEC - Validation des signatures DNS", (enableDnssecValue == null) ? "Non configuré" : $"EnableDnssec = {enableDnssecValue}", "EnableDnssec = 1 (activé)", (!isDnssecEnabled) ? SecurityStatus.Warning : SecurityStatus.OK, "DNSSEC garantit l'authenticité et l'intégrité des réponses DNS via des signatures cryptographiques. Différent du DoH: DNSSEC protège le contenu, DoH protège la confidentialité de la transmission.", "Activer DNSSEC via GPO ou configurer un résolveur DNS validant DNSSEC (ex: 1.1.1.1, 8.8.8.8).", "RFC 4033-4035 | CIS Benchmark DNS"));
		if (dohFlagsValue != null)
		{
			results.Add(MakeResult("DNS over HTTPS - DohFlags", $"DohFlags = {dohFlagsValue}", "Valeur non nulle (DoH configuré)", SecurityStatus.Info, "Drapeaux de configuration avancée pour DNS over HTTPS.", "Vérifier la configuration DoH complète.", "Microsoft DoH Registry Settings"));
		}
	}

	private static void CheckWpad(List<SecurityResult> results)
	{
		object wpadOverrideValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "WpadOverride");
		ReadRegHklm("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "AutoDetect");
		var (autoDetectValue, success, errorMessage) = ReadReg("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "AutoDetect");
		if (!success && errorMessage != null)
		{
			ErrorLogger.AddError("[NetworkSec] Reg HKCU Error: " + errorMessage);
		}
		string serviceState = GetServiceState("WinHttpAutoProxySvc");
		bool isWpadDisabledByPolicy = wpadOverrideValue is int wpadOverrideInt && wpadOverrideInt == 1;
		bool isAutoDetectEnabled = autoDetectValue is int autoDetectInt && autoDetectInt == 1;
		bool isProxyServiceRunning = serviceState.Equals("Running", StringComparison.OrdinalIgnoreCase);
		// Correctif M3 : ancienne expression (A&&B)||A se réduisait à A, ignorant AutoDetect et le service
		SecurityStatus status = (!isWpadDisabledByPolicy && (isAutoDetectEnabled || isProxyServiceRunning)) ? SecurityStatus.Warning : (!isWpadDisabledByPolicy ? SecurityStatus.Info : SecurityStatus.OK);
		results.Add(MakeResult("WPAD - Politique HKLM (WpadOverride)", (wpadOverrideValue == null) ? "Non défini (WPAD non désactivé par politique)" : $"WpadOverride = {wpadOverrideValue}", "WpadOverride = 1 (désactivé via politique machine)", (!isWpadDisabledByPolicy) ? SecurityStatus.Warning : SecurityStatus.OK, "Paramètre de politique HKLM contrôlant WPAD. Ce paramètre est défini par l'administrateur via GPO et s'applique à tous les utilisateurs. C'est le contrôle le plus robuste contre les attaques WPAD.", "Définir HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WpadOverride = 1 via GPO.", "CVE-2016-3234 | CIS Benchmark - 18.4.6"));
		results.Add(MakeResult("WPAD - Web Proxy Auto-Discovery (état global)", $"WpadOverride (HKLM) = {((wpadOverrideValue == null) ? "Non défini" : wpadOverrideValue.ToString())} | AutoDetect (HKCU) = {((autoDetectValue == null) ? "Non défini" : autoDetectValue.ToString())} | Service WinHttpAutoProxySvc: {serviceState}", "WpadOverride = 1 (désactivé) | AutoDetect = 0 | Service désactivé", status, "WPAD permet la découverte automatique de proxy. Un attaquant contrôlant le réseau peut répondre aux requêtes WPAD et rediriger tout le trafic HTTP/HTTPS à travers un proxy malveillant (attaque WPAD). HKCU AutoDetect reflète le paramètre de l'utilisateur courant (moins fiable que la politique HKLM).", "Désactiver WPAD via: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WpadOverride = 1. Désactiver également la détection automatique de proxy dans les paramètres Internet Explorer/Edge.", "CVE-2016-3234 | CIS Benchmark - 18.4.6"));
	}

	private static void CheckSmbSecurity(List<SecurityResult> results)
	{
		object smb1Value = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "SMB1");
		if (smb1Value == null)
		{
			_ = 1;
		}
		else if (smb1Value is int smb1Int)
		{
			_ = smb1Int != 0;
		}
		else
			_ = 0;
		results.Add(MakeResult("SMB1 - Protocole SMBv1 (EternalBlue / WannaCry)", (smb1Value == null) ? "Non défini (désactivé par défaut sur Win11)" : $"SMB1 = {smb1Value}", "SMB1 = 0 (explicitement désactivé)", (smb1Value is int && (int)smb1Value != 0) ? SecurityStatus.Critical : ((smb1Value == null) ? SecurityStatus.OK : SecurityStatus.OK), "SMBv1 est un protocole obsolète et vulnérable exploité par EternalBlue (MS17-010) / WannaCry / NotPetya. Il ne supporte pas le chiffrement ni la signature de session moderne.", "Désactiver explicitement via: Set-SmbServerConfiguration -EnableSMB1Protocol $false. Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 = 0.", "MS17-010 | CVE-2017-0144 | CIS Benchmark - 18.3.3"));
		object smb2Value = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "SMB2");
		results.Add(MakeResult("SMB2/3 - Protocole SMBv2/v3", (smb2Value == null) ? "Non défini (activé par défaut)" : $"SMB2 = {smb2Value}", "SMB2 = 1 (activé) ou non défini", (smb2Value is int && (int)smb2Value == 0) ? SecurityStatus.Warning : SecurityStatus.OK, "SMBv2/v3 est le protocole de partage de fichiers moderne avec chiffrement et signature renforcés.", "S'assurer que SMBv2 est activé. Ne pas désactiver SMBv2 sans raison valable.", "Microsoft SMB Documentation"));
		object serverSigningValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "RequireSecuritySignature");
		bool isServerSigningRequired = serverSigningValue is int serverSigningInt && serverSigningInt == 1;
		results.Add(MakeResult("SMB Signing - Serveur (RequireSecuritySignature)", (serverSigningValue == null) ? "Non défini (non requis)" : $"RequireSecuritySignature = {serverSigningValue}", "RequireSecuritySignature = 1 (requis)", (!isServerSigningRequired) ? SecurityStatus.Critical : SecurityStatus.OK, "La signature SMB côté serveur empêche les attaques de relais SMB (SMB Relay). Sans signature obligatoire, un attaquant peut relayer les authentifications NTLM.", "Activer la signature SMB obligatoire: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature = 1. Via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network server: Digitally sign communications (always).", "CIS Benchmark - 2.3.9.2 | ANSSI - Durcissement SMB"));
		object clientSigningValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters", "RequireSecuritySignature");
		bool isClientSigningRequired = clientSigningValue is int clientSigningInt && clientSigningInt == 1;
		results.Add(MakeResult("SMB Signing - Client (RequireSecuritySignature)", (clientSigningValue == null) ? "Non défini (non requis)" : $"RequireSecuritySignature = {clientSigningValue}", "RequireSecuritySignature = 1 (requis)", (!isClientSigningRequired) ? SecurityStatus.Critical : SecurityStatus.OK, "La signature SMB côté client empêche les attaques de type SMB Relay depuis le poste de travail. Essentiel pour prévenir les attaques PetitPotam et NTLM Relay.", "Activer via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network client: Digitally sign communications (always).", "CIS Benchmark - 2.3.8.1 | ANSSI R45"));
		object encryptDataValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "EncryptData");
		bool isEncryptionEnabled = encryptDataValue is int encryptDataInt && encryptDataInt == 1;
		results.Add(MakeResult("SMB Encryption - Chiffrement des données", (encryptDataValue == null) ? "Non défini (désactivé)" : $"EncryptData = {encryptDataValue}", "EncryptData = 1 (activé)", (!isEncryptionEnabled) ? SecurityStatus.Warning : SecurityStatus.OK, "Le chiffrement SMB (SMB 3.x) protège les données en transit contre l'interception réseau. Applicable uniquement aux clients SMB 3.0+.", "Activer via PowerShell: Set-SmbServerConfiguration -EncryptData $true. Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\EncryptData = 1.", "Microsoft SMB 3.0 Encryption"));
		object nameHardeningValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "SMBServerNameHardeningLevel");
		results.Add(MakeResult("SMB Server Name Hardening", (nameHardeningValue == null) ? "Non défini (0 = aucun durcissement)" : $"SMBServerNameHardeningLevel = {nameHardeningValue}", "1 ou 2 (audit ou rejet des connexions incorrectes)", (!(nameHardeningValue is int nameHardeningInt) || nameHardeningInt < 1) ? SecurityStatus.Warning : SecurityStatus.OK, "Contrôle si le serveur SMB valide le nom du serveur cible dans les connexions entrantes. Niveau 1 = audit, Niveau 2 = rejet des connexions avec mauvais nom.", "Définir SMBServerNameHardeningLevel = 1 ou 2 pour renforcer l'authentification SMB.", "Microsoft KB2745867"));
		object nullSessionValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "RestrictNullSessAccess");
		bool isNullSessionRestricted = nullSessionValue == null || (nullSessionValue is int nullSessionInt && nullSessionInt == 1);
		results.Add(MakeResult("SMB - Accès anonyme aux partages (RestrictNullSessAccess)", (nullSessionValue == null) ? "Non défini (restreint par défaut)" : $"RestrictNullSessAccess = {nullSessionValue}", "RestrictNullSessAccess = 1 (accès anonyme restreint)", (!isNullSessionRestricted) ? SecurityStatus.Critical : SecurityStatus.OK, "Contrôle si les sessions null (anonymes) peuvent accéder aux partages réseau. L'accès anonyme peut permettre l'énumération de partages et d'informations sensibles.", "Activer la restriction: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RestrictNullSessAccess = 1.", "CIS Benchmark - 2.3.10.8"));
	}

	private static void CheckNtlm(List<SecurityResult> results)
	{
		object lmCompatValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LmCompatibilityLevel");
		int lmCompatLevel = ((lmCompatValue is int lmCompatInt) ? lmCompatInt : 0);
		string lmCompatDescription = lmCompatLevel switch
		{
			0 => "LM + NTLM (très faible)",
			1 => "LM + NTLM (faible)",
			2 => "NTLM uniquement (faible)",
			3 => "NTLMv2 uniquement (acceptable)",
			4 => "NTLMv2 + refus LM (bon)",
			5 => "NTLMv2 + refus LM + NTLM (optimal)",
			_ => $"Valeur inconnue: {lmCompatLevel}",
		};
		results.Add(MakeResult("NTLM - LmCompatibilityLevel (Niveau d'authentification)", (lmCompatValue == null) ? "Non défini (niveau 0 par défaut)" : $"LmCompatibilityLevel = {lmCompatLevel} ({lmCompatDescription})", "LmCompatibilityLevel = 5 (NTLMv2 uniquement, refus LM + NTLM)", (lmCompatLevel < 5) ? ((lmCompatLevel >= 3) ? SecurityStatus.Warning : SecurityStatus.Critical) : SecurityStatus.OK, "Détermine le protocole d'authentification réseau utilisé. LM et NTLMv1 sont vulnérables au craquage de hachage et aux attaques de relais. NTLMv2 avec niveau 5 est la configuration la plus sécurisée.", "Configurer LmCompatibilityLevel = 5 via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM.", "CIS Benchmark - 2.3.11.7 | ANSSI R67"));
		object minClientSecValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NTLMMinClientSec");
		int minClientSec = ((minClientSecValue is int minClientSecInt) ? minClientSecInt : 0);
		bool isClientSecStrong = minClientSec >= 536870912;
		results.Add(MakeResult("NTLM - NTLMMinClientSec (Sécurité minimale client)", (minClientSecValue == null) ? "Non défini (0)" : $"NTLMMinClientSec = {minClientSec} (0x{minClientSec:X8})", "536870912 (0x20080000) = NTLMv2 + chiffrement 128 bits", (!isClientSecStrong) ? SecurityStatus.Critical : SecurityStatus.OK, "Définit les exigences de sécurité minimales pour les sessions NTLM client. La valeur 0x20080000 impose NTLMv2 et le chiffrement 128 bits.", "Configurer via GPO: Network security: Minimum session security for NTLM SSP based (including secure RPC) clients = Require NTLMv2 session security + Require 128-bit encryption.", "CIS Benchmark - 2.3.11.9"));
		object minServerSecValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NTLMMinServerSec");
		int minServerSec = ((minServerSecValue is int minServerSecInt) ? minServerSecInt : 0);
		bool isServerSecStrong = minServerSec >= 536870912;
		results.Add(MakeResult("NTLM - NTLMMinServerSec (Sécurité minimale serveur)", (minServerSecValue == null) ? "Non défini (0)" : $"NTLMMinServerSec = {minServerSec} (0x{minServerSec:X8})", "536870912 (0x20080000) = NTLMv2 + chiffrement 128 bits", (!isServerSecStrong) ? SecurityStatus.Critical : SecurityStatus.OK, "Définit les exigences de sécurité minimales pour les sessions NTLM serveur. Protège contre les clients NTLM faibles qui tenteraient de négocier des protocoles vulnérables.", "Configurer via GPO: Network security: Minimum session security for NTLM SSP based (including secure RPC) servers = Require NTLMv2 session security + Require 128-bit encryption.", "CIS Benchmark - 2.3.11.10"));
		object restrictNtlmValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic");
		int restrictNtlmLevel = ((restrictNtlmValue is int restrictNtlmInt) ? restrictNtlmInt : 0);
		string restrictNtlmDescription = restrictNtlmLevel switch
		{
			0 => "Tout autorisé (aucune restriction)",
			1 => "Audit uniquement",
			2 => "Refus de trafic NTLM sortant (optimal)",
			_ => $"Valeur: {restrictNtlmLevel}",
		};
		results.Add(MakeResult("NTLM - RestrictSendingNTLMTraffic (Restriction trafic NTLM sortant)", (restrictNtlmValue == null) ? "Non défini (0 - aucune restriction)" : $"RestrictSendingNTLMTraffic = {restrictNtlmLevel} ({restrictNtlmDescription})", "RestrictSendingNTLMTraffic = 2 (refus du trafic NTLM sortant)", restrictNtlmLevel switch
		{
			1 => SecurityStatus.Warning,
			2 => SecurityStatus.OK,
			_ => SecurityStatus.Critical,
		}, "Contrôle si le client Windows envoie du trafic NTLM à des serveurs distants. La valeur 2 bloque tout trafic NTLM sortant, forçant l'utilisation de Kerberos.", "Configurer RestrictSendingNTLMTraffic = 2 via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers.", "CIS Benchmark - 2.3.11.4 | ANSSI R68"));
	}

	private static void CheckIpv6(List<SecurityResult> results)
	{
		object disabledComponentsValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", "DisabledComponents");
		int disabledComponents = ((disabledComponentsValue is int disabledComponentsInt) ? disabledComponentsInt : 0);
		string ipv6Description = disabledComponents switch
		{
			255 => "IPv6 complètement désactivé (255)",
			32 => "Tunnels Teredo/6to4 désactivés uniquement",
			0 => "IPv6 entièrement activé (par défaut)",
			_ => $"Configuration partielle (0x{disabledComponents:X2})",
		};
		results.Add(MakeResult("IPv6 - Composants désactivés (DisabledComponents)", (disabledComponentsValue == null) ? "Non défini (IPv6 activé par défaut)" : $"DisabledComponents = {disabledComponents} (0x{disabledComponents:X2}) - {ipv6Description}", "0xFF (255) si désactivation complète souhaitée, ou 0x20 pour désactiver tunnels uniquement", disabledComponents switch
		{
			0 => SecurityStatus.Info,
			255 => SecurityStatus.Info,
			_ => SecurityStatus.Info,
		}, "IPv6 est activé par défaut sur Windows 11. La désactivation complète peut perturber certains services Windows (HomeGroup, DirectAccess). La désactivation des tunnels Teredo/6to4 (0x20) est recommandée si IPv6 natif n'est pas utilisé. Microsoft déconseille la désactivation totale d'IPv6.", "Si IPv6 non utilisé en natif: DisabledComponents = 0x20 (désactiver tunnels) via HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters. Ne pas désactiver complètement IPv6 sans évaluation de l'impact.", "Microsoft KB929852 | CIS Benchmark - IPv6"));
	}

	private static void CheckWinRm(List<SecurityResult> results)
	{
		string serviceState = GetServiceState("WinRM");
		bool isWinRmRunning = ServiceIsRunning("WinRM");
		object clientUnencryptedValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client", "AllowUnencryptedTraffic");
		object serviceUnencryptedValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service", "AllowUnencryptedTraffic");
		bool isClientUnencryptedAllowed = clientUnencryptedValue is int clientUnencryptedInt && clientUnencryptedInt == 1;
		bool isServiceUnencryptedAllowed = serviceUnencryptedValue is int serviceUnencryptedInt && serviceUnencryptedInt == 1;
		results.Add(MakeResult("WinRM - Service Windows Remote Management", "Service: " + serviceState, "Désactivé si non requis, ou configuré avec HTTPS uniquement", isWinRmRunning ? SecurityStatus.Warning : SecurityStatus.OK, "WinRM (Windows Remote Management) permet la gestion et l'exécution de commandes à distance. S'il n'est pas nécessaire, il représente une surface d'attaque pour l'exécution de code à distance.", "Désactiver WinRM si non utilisé: Stop-Service WinRM; Set-Service WinRM -StartupType Disabled. Si requis, restreindre l'accès par IP et utiliser uniquement HTTPS.", "CIS Benchmark - WinRM | ANSSI Durcissement PowerShell"));
		results.Add(MakeResult("WinRM Client - Trafic non chiffré (AllowUnencryptedTraffic)", (clientUnencryptedValue == null) ? "Non défini (politique par défaut)" : $"AllowUnencryptedTraffic = {clientUnencryptedValue}", "AllowUnencryptedTraffic = 0 (trafic chiffré uniquement)", isClientUnencryptedAllowed ? SecurityStatus.Critical : SecurityStatus.OK, "Contrôle si le client WinRM peut envoyer des données en clair. Le trafic WinRM non chiffré expose les identifiants et commandes à l'interception réseau.", "Interdire le trafic non chiffré: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\AllowUnencryptedTraffic = 0.", "CIS Benchmark - 18.9.86.1.1"));
		results.Add(MakeResult("WinRM Service - Trafic non chiffré (AllowUnencryptedTraffic)", (serviceUnencryptedValue == null) ? "Non défini (politique par défaut)" : $"AllowUnencryptedTraffic = {serviceUnencryptedValue}", "AllowUnencryptedTraffic = 0 (trafic chiffré uniquement)", isServiceUnencryptedAllowed ? SecurityStatus.Critical : SecurityStatus.OK, "Contrôle si le service WinRM accepte les connexions non chiffrées. Identifiants et données exposés en clair si activé.", "Interdire le trafic non chiffré côté service: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\AllowUnencryptedTraffic = 0.", "CIS Benchmark - 18.9.86.2.1"));
	}

	private static void CheckRdpSecurity(List<SecurityResult> results)
	{
		object denyConnectionsValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "fDenyTSConnections");
		object securityLayerValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "SecurityLayer");
		object userAuthValue = ReadRegHklm("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "UserAuthentication");
		object minEncryptionValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", "MinEncryptionLevel");
		bool isRdpEnabled = denyConnectionsValue is int denyConnectionsInt && denyConnectionsInt == 0;
		results.Add(MakeResult("RDP - Bureau à distance activé (fDenyTSConnections)", (denyConnectionsValue == null) ? "Non défini" : $"fDenyTSConnections = {denyConnectionsValue}", "fDenyTSConnections = 1 (RDP désactivé) si non requis", isRdpEnabled ? SecurityStatus.Warning : SecurityStatus.OK, isRdpEnabled ? "Le Bureau à distance (RDP) est activé. Si non requis, il expose le port 3389 aux attaques par force brute et aux exploits RDP." : "Le Bureau à distance (RDP) est désactivé, réduisant la surface d'attaque réseau.", "Si RDP non requis: Désactiver via GPO. Si requis: restreindre l'accès par firewall, activer NLA et TLS.", "CVE-2019-0708 (BlueKeep) | CIS Benchmark - RDP"));
		if (isRdpEnabled)
		{
			int securityLayer = ((!(securityLayerValue is int securityLayerInt)) ? 1 : securityLayerInt);
			string securityLayerDescription = securityLayer switch
			{
				0 => "Couche RDP native (faible)",
				1 => "Négociation automatique",
				2 => "TLS/SSL (optimal)",
				_ => $"Valeur {securityLayer}",
			};
			results.Add(MakeResult("RDP - Couche de sécurité (SecurityLayer)", $"SecurityLayer = {securityLayer} ({securityLayerDescription})", "SecurityLayer = 2 (TLS/SSL)", securityLayer switch
			{
				1 => SecurityStatus.Warning,
				2 => SecurityStatus.OK,
				_ => SecurityStatus.Critical,
			}, "La couche de sécurité RDP détermine le protocole d'authentification et de chiffrement utilisé. TLS (valeur 2) est requis pour une sécurité optimale.", "Configurer SecurityLayer = 2 (TLS) via GPO: Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Security Layer.", "CIS Benchmark - 18.9.65.3.9.5"));
			int userAuthentication = ((userAuthValue is int userAuthInt) ? userAuthInt : 0);
			results.Add(MakeResult("RDP - Authentification au niveau réseau - NLA (UserAuthentication)", $"UserAuthentication = {userAuthentication} ({((userAuthentication == 1) ? "NLA activé (GOOD)" : "NLA désactivé")})", "UserAuthentication = 1 (NLA requis)", (userAuthentication != 1) ? SecurityStatus.Critical : SecurityStatus.OK, "NLA (Network Level Authentication) exige l'authentification de l'utilisateur avant l'établissement de la session RDP complète. Sans NLA, les attaques BlueKeep et similaires sont facilitées.", "Activer NLA via GPO: Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Require use of specific security layer = NLA.", "CIS Benchmark - 18.9.65.3.9.6 | CVE-2019-0708"));
			int minEncryptionLevel = ((minEncryptionValue is int minEncryptionInt) ? minEncryptionInt : 0);
			string encryptionLevelDescription = minEncryptionLevel switch
			{
				1 => "Faible",
				2 => "Compatible client",
				3 => "Élevé (128 bits)",
				4 => "FIPS-140",
				_ => $"Non défini ou valeur {minEncryptionLevel}",
			};
			results.Add(MakeResult("RDP - Niveau de chiffrement minimum (MinEncryptionLevel)", (minEncryptionValue == null) ? "Non défini" : $"MinEncryptionLevel = {minEncryptionLevel} ({encryptionLevelDescription})", "MinEncryptionLevel = 3 (Élevé, 128 bits) ou 4 (FIPS)", (minEncryptionLevel < 3) ? ((minEncryptionLevel > 0) ? SecurityStatus.Warning : SecurityStatus.Warning) : SecurityStatus.OK, "Définit le niveau de chiffrement minimum pour les connexions RDP. Le niveau élevé (3) impose un chiffrement 128 bits entre client et serveur.", "Configurer MinEncryptionLevel = 3 via GPO: Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Set client connection encryption level = High.", "CIS Benchmark - 18.9.65.3.9.3"));
		}
	}

	private static void CheckPsRemoting(List<SecurityResult> results)
	{
		object allowAutoConfigValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service", "AllowAutoConfig");
		string serviceState = GetServiceState("WinRM");
		results.Add(MakeResult("PowerShell Remoting - AllowAutoConfig (WinRM Service)", (allowAutoConfigValue == null) ? "Non défini" : $"AllowAutoConfig = {allowAutoConfigValue} | Service WinRM: {serviceState}", "AllowAutoConfig = 0 (désactivé) si PSRemoting non requis", (allowAutoConfigValue is int allowAutoConfigInt && allowAutoConfigInt == 1) ? SecurityStatus.Warning : SecurityStatus.OK, "PowerShell Remoting utilise WinRM pour l'exécution de commandes à distance. Si activé, il peut être utilisé pour du mouvement latéral dans un réseau compromis.", "Désactiver PSRemoting si non requis: Disable-PSRemoting -Force. Si requis, restreindre les endpoints et activer la journalisation PowerShell complète.", "ANSSI - Durcissement PowerShell | CIS Benchmark WinRM"));
	}

	private static void CheckPrintSpooler(List<SecurityResult> results)
	{
		object remoteRpcValue = ReadRegHklm("SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers", "RegisterSpoolerRemoteRpcEndPoint");
		string serviceState = GetServiceState("Spooler");
		bool isSpoolerRunning = ServiceIsRunning("Spooler");
		results.Add(MakeResult("Print Spooler - Service (PrintNightmare CVE-2021-34527)", "Service Spooler: " + serviceState, "Désactivé sur les systèmes sans imprimante réseau", isSpoolerRunning ? SecurityStatus.Warning : SecurityStatus.OK, "Le service Print Spooler est vulnérable à PrintNightmare (CVE-2021-34527) permettant l'exécution de code à distance et l'élévation de privilèges. Il devrait être désactivé sur les serveurs et postes n'utilisant pas d'impression réseau.", "Désactiver le service Spooler si impression non requise: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled. Sinon, appliquer les correctifs KB5004945 et ultérieurs.", "CVE-2021-34527 | CVE-2021-1675 | PrintNightmare"));
		int remoteRpcEndpoint = ((remoteRpcValue is int remoteRpcInt) ? remoteRpcInt : (-1));
		results.Add(MakeResult("Print Spooler - RegisterSpoolerRemoteRpcEndPoint", (remoteRpcValue == null) ? "Non défini" : $"RegisterSpoolerRemoteRpcEndPoint = {remoteRpcEndpoint}", "2 (point de terminaison RPC distant désactivé)", remoteRpcEndpoint switch
		{
			1 => SecurityStatus.Warning, 
			2 => SecurityStatus.OK, 
			_ => SecurityStatus.Warning, 
		}, "Contrôle si le service Spooler enregistre un point de terminaison RPC accessible à distance. La valeur 2 désactive le point de terminaison distant, mitigation clé de PrintNightmare.", "Configurer RegisterSpoolerRemoteRpcEndPoint = 2 via GPO: Computer Configuration > Administrative Templates > Printers > Configure RPC connection settings.", "Microsoft PrintNightmare Mitigation | KB5005652"));
	}
}
