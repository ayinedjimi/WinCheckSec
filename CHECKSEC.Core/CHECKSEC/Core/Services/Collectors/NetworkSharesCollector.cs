using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using Microsoft.Win32;

namespace CHECKSEC.Core.Services.Collectors;

public class NetworkSharesCollector : ISecurityCollector
{
	public string Name => "Partages Réseau";

	public string Category => "Réseau";

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
				CollectSharedFolders(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckAnonymousAccess(report.Results);
				ct.ThrowIfCancellationRequested();
				CheckSharePermissions(report.Results, ct);
				ct.ThrowIfCancellationRequested();
				CheckAdministrativeShares(report.Results);
				ct.ThrowIfCancellationRequested();
				CollectOpenSessions(report.Results);
			}, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception generalException)
		{
			report.ErrorMessage = "Erreur générale NetworkSharesCollector : " + generalException.Message;
		}
		finally
		{
			stopwatch.Stop();
			report.Duration = stopwatch.Elapsed;
		}
		return report;
	}

	private void CollectSharedFolders(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ManagementObjectSearcher shareSearcher = new ManagementObjectSearcher("SELECT Name, Path, Description, Type, AllowMaximum, MaximumAllowed FROM Win32_Share");
			try
			{
				using ManagementObjectCollection shareCollection = shareSearcher.Get();
				bool allowMaximumValue = default(bool);
				foreach (ManagementObject shareObject in shareCollection)
				{
					ManagementObject shareObjectDisposable = shareObject;
					try
					{
						ct.ThrowIfCancellationRequested();
						try
						{
							string shareName = shareObject["Name"]?.ToString() ?? "(sans nom)";
							string sharePath = shareObject["Path"]?.ToString() ?? string.Empty;
							string shareDesc = shareObject["Description"]?.ToString() ?? string.Empty;
							uint shareType = WmiUInt(shareObject, "Type");
							object allowMaximumRaw = shareObject["AllowMaximum"];
							int allowMaximumIsBoolFlag;
							if (allowMaximumRaw is bool)
							{
								allowMaximumValue = (bool)allowMaximumRaw;
								allowMaximumIsBoolFlag = 1;
							}
							else
							{
								allowMaximumIsBoolFlag = 0;
							}
							bool allowMaximum = (byte)((uint)allowMaximumIsBoolFlag & (allowMaximumValue ? 1u : 0u)) != 0;
							long maxConnections = (allowMaximum ? (-1) : WmiLong(shareObject, "MaximumAllowed", -1L));
							bool isSpecialType = (shareType & 0x80000000u) != 0;
							string typeLabel = (shareType & 0x7FFFFFFF) switch
							{
								0u => isSpecialType ? "Spécial/Admin" : "Disque",
								1u => "Imprimante",
								2u => "Périphérique",
								3u => "IPC",
								_ => isSpecialType ? "Spécial/Admin" : $"Inconnu ({shareType})",
							};
							string maxConnStr = (allowMaximum ? "Maximum autorisé" : ((maxConnections >= 0) ? maxConnections.ToString() : "N/D"));
							string currentVal = $"Nom={shareName} | Chemin={sharePath} | Type={typeLabel} | MaxConn={maxConnStr}";
							if (shareName.Equals("IPC$", StringComparison.OrdinalIgnoreCase) || shareName.Equals("ADMIN$", StringComparison.OrdinalIgnoreCase) || (shareName.Length == 2 && shareName[1] == '$' && char.IsLetter(shareName[0])))
							{
								TryAdd(results, () => new SecurityResult
								{
									Category = Category,
									CheckName = "Partage Admin : " + shareName,
									CurrentValue = currentVal,
									ExpectedValue = "Partage administratif natif Windows",
									Status = SecurityStatus.Info,
									Description = $"Le partage '{shareName}' est un partage administratif par défaut créé automatiquement par Windows. Chemin : '{sharePath}'. Ces partages permettent la gestion distante mais constituent une surface d'attaque.",
									Recommendation = "Évaluer si ces partages administratifs sont nécessaires. Sur les postes de travail, envisager de désactiver AutoShareWks dans la stratégie de groupe. IPC$ ne peut pas être désactivé sans impacter les fonctionnalités Windows.",
									Reference = "CIS Benchmark Windows - Section 2.3.10",
									CollectedAt = DateTime.Now
								});
								continue;
							}
							bool emptyPath = string.IsNullOrWhiteSpace(sharePath);
							bool isUserPath = !emptyPath && (sharePath.StartsWith("C:\\Users", StringComparison.OrdinalIgnoreCase) || sharePath.StartsWith("C:\\Documents and Settings", StringComparison.OrdinalIgnoreCase));
							if (emptyPath || isUserPath)
							{
								TryAdd(results, () => new SecurityResult
								{
									Category = Category,
									CheckName = "Partage Critique : " + shareName,
									CurrentValue = currentVal,
									ExpectedValue = "Chemin dans un répertoire sécurisé hors Users",
									Status = SecurityStatus.Critical,
									Description = (emptyPath ? ("Le partage '" + shareName + "' a un chemin vide — comportement anormal pouvant indiquer un partage fantôme ou mal configuré.") : $"Le partage '{shareName}' expose un répertoire utilisateur ('{sharePath}') qui peut contenir des données sensibles."),
									Recommendation = "Supprimer ou reconfigurer ce partage. Vérifier qu'aucune donnée sensible n'est exposée. Auditer les permissions ACL via icacls ou Get-SmbShareAccess.",
									Reference = "ANSSI - Recommandations de sécurité relatives aux systèmes Windows",
									CollectedAt = DateTime.Now
								});
								continue;
							}
							bool isSystemPath = sharePath.StartsWith("C:\\Program Files", StringComparison.OrdinalIgnoreCase) || sharePath.StartsWith("C:\\Windows", StringComparison.OrdinalIgnoreCase) || sharePath.StartsWith("C:\\ProgramData", StringComparison.OrdinalIgnoreCase);
							SecurityStatus status = ((!isSystemPath) ? SecurityStatus.Warning : SecurityStatus.OK);
							string reco = (isSystemPath ? "Partage dans un chemin système standard — vérifier néanmoins les permissions ACL." : ("Le chemin '" + sharePath + "' est hors des répertoires système standards. Vérifier si ce partage est légitime et restreindre les permissions."));
							TryAdd(results, () => new SecurityResult
							{
								Category = Category,
								CheckName = "Partage Réseau : " + shareName,
								CurrentValue = currentVal,
								ExpectedValue = "Chemin dans Program Files ou Windows, permissions restreintes",
								Status = status,
								Description = $"Partage réseau '{shareName}' pointant sur '{sharePath}'. Description : '{shareDesc}'. Type : {typeLabel}. Connexions max : {maxConnStr}.",
								Recommendation = reco,
								Reference = "CIS Benchmark Windows - Section Réseau",
								CollectedAt = DateTime.Now
							});
						}
						catch (OperationCanceledException)
						{
							throw;
						}
						catch (Exception shareReadException)
						{
							Exception shareReadExceptionCopy = shareReadException;
							Exception shareReadExceptionRef = shareReadExceptionCopy;
							string failedName = "(inconnu)";
							try
							{
								failedName = shareObject["Name"]?.ToString() ?? failedName;
							}
							catch
							{
							}
							TryAdd(results, () => new SecurityResult
							{
								Category = Category,
								CheckName = "Partage : " + failedName,
								CurrentValue = "Erreur de lecture",
								ExpectedValue = "Données du partage",
								Status = SecurityStatus.Error,
								Description = "Erreur lors de la lecture du partage '" + failedName + "' : " + shareReadExceptionRef.Message,
								Recommendation = "Vérifier manuellement ce partage avec 'net share' ou Get-SmbShare.",
								CollectedAt = DateTime.Now
							});
						}
					}
					finally
					{
						((IDisposable)shareObjectDisposable)?.Dispose();
					}
				}
			}
			finally
			{
				((IDisposable)shareSearcher)?.Dispose();
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception wmiException)
		{
			Exception wmiExceptionCopy = wmiException;
			Exception wmiExceptionRef = wmiExceptionCopy;
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Énumération des partages réseau",
				CurrentValue = "Erreur WMI",
				ExpectedValue = "Liste des partages Win32_Share",
				Status = SecurityStatus.Error,
				Description = "Impossible d'énumérer les partages via WMI Win32_Share : " + wmiExceptionRef.Message,
				Recommendation = "Vérifier les droits d'accès WMI et que le service Winmgmt est démarré.",
				CollectedAt = DateTime.Now
			});
		}
	}

	private void CheckAnonymousAccess(List<SecurityResult> results)
	{
		TryAdd(results, delegate
		{
			object restrictNullSessRaw = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "RestrictNullSessAccess");
			int restrictNullSess = ((!(restrictNullSessRaw is int restrictNullSessValue)) ? 1 : restrictNullSessValue);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Session Nulle - RestrictNullSessAccess",
				CurrentValue = ((restrictNullSessRaw == null) ? "Absent (défaut = 1)" : restrictNullSess.ToString()),
				ExpectedValue = "1",
				Status = ((restrictNullSess == 0) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = ((restrictNullSess == 0) ? "RestrictNullSessAccess=0 : les sessions null sont autorisées. Un attaquant peut énumérer les comptes, partages et politiques sans authentification." : "RestrictNullSessAccess est correctement configuré — les sessions null sont restreintes."),
				Recommendation = ((restrictNullSess == 0) ? "Définir HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RestrictNullSessAccess = 1 via GPO ou regedit." : "Aucune action requise."),
				Reference = "CIS Benchmark Windows - 2.3.10.5 | MS-KB Article Q246261",
				CollectedAt = DateTime.Now
			};
		});
		TryAdd(results, delegate
		{
			string[] nullSessionShares = ((ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "NullSessionShares") is string[] nullSessionSharesValue) ? nullSessionSharesValue : Array.Empty<string>());
			bool hasNullSessionShares = nullSessionShares.Length != 0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Session Nulle - NullSessionShares",
				CurrentValue = (hasNullSessionShares ? string.Join(", ", nullSessionShares) : "(vide)"),
				ExpectedValue = "(vide)",
				Status = (hasNullSessionShares ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = (hasNullSessionShares ? ("Des partages accessibles sans authentification sont configurés : " + string.Join(", ", nullSessionShares) + ". Cela permet l'accès anonyme à ces ressources réseau.") : "Aucun partage accessible en session nulle — configuration correcte."),
				Recommendation = (hasNullSessionShares ? "Supprimer toutes les entrées de NullSessionShares sauf si absolument requis (ex : certains environnements Active Directory legacy)." : "Aucune action requise."),
				Reference = "CIS Benchmark Windows - 2.3.10.6",
				CollectedAt = DateTime.Now
			};
		});
		TryAdd(results, delegate
		{
			string[] nullSessionPipes = ((ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "NullSessionPipes") is string[] nullSessionPipesValue) ? nullSessionPipesValue : Array.Empty<string>());
			bool hasNullSessionPipes = nullSessionPipes.Length != 0;
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Session Nulle - NullSessionPipes",
				CurrentValue = (hasNullSessionPipes ? string.Join(", ", nullSessionPipes) : "(vide)"),
				ExpectedValue = "(vide)",
				Status = (hasNullSessionPipes ? SecurityStatus.Warning : SecurityStatus.OK),
				Description = (hasNullSessionPipes ? ("Des pipes nommés accessibles sans authentification sont configurés : " + string.Join(", ", nullSessionPipes) + ". Certains peuvent être requis pour des services legacy.") : "Aucun pipe nommé accessible en session nulle."),
				Recommendation = (hasNullSessionPipes ? "Examiner la liste et supprimer les pipes non indispensables. Les pipes BROWSER, COMNAP, COMNODE sont des reliques legacy." : "Aucune action requise."),
				Reference = "CIS Benchmark Windows - 2.3.10.7",
				CollectedAt = DateTime.Now
			};
		});
		TryAdd(results, delegate
		{
			object restrictAnonymousRaw = ReadRegHklm("SYSTEM\\CurrentControlSet\\Control\\Lsa", "RestrictAnonymous");
			int restrictAnonymous = ((restrictAnonymousRaw is int restrictAnonymousValue) ? restrictAnonymousValue : 0);
			SecurityStatus status = ((restrictAnonymous < 1) ? SecurityStatus.Warning : SecurityStatus.OK);
			string restrictAnonymousLabel = restrictAnonymous switch
			{
				0 => "0 - Aucune restriction",
				1 => "1 - Pas d'énumération SAM",
				2 => "2 - Pas d'accès sans auth",
				_ => restrictAnonymous.ToString(),
			};
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA - RestrictAnonymous",
				CurrentValue = ((restrictAnonymousRaw == null) ? "Absent (défaut = 0)" : restrictAnonymousLabel),
				ExpectedValue = "1 ou 2",
				Status = status,
				Description = "RestrictAnonymous contrôle ce qu'un utilisateur non authentifié peut faire sur ce système. Valeur actuelle : " + restrictAnonymousLabel + ".",
				Recommendation = ((restrictAnonymous < 1) ? "Définir RestrictAnonymous = 1 (minimum) ou 2 (recommandé) dans HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa." : "Configuration correcte. La valeur 2 est recommandée pour les postes isolés."),
				Reference = "CIS Benchmark Windows - 2.3.10.2",
				CollectedAt = DateTime.Now
			};
		});
		TryAdd(results, delegate
		{
			object restrictAnonymousSamRaw = ReadRegHklm("SYSTEM\\CurrentControlSet\\Control\\Lsa", "RestrictAnonymousSAM");
			int restrictAnonymousSam = ((!(restrictAnonymousSamRaw is int restrictAnonymousSamValue)) ? 1 : restrictAnonymousSamValue);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "LSA - RestrictAnonymousSAM",
				CurrentValue = ((restrictAnonymousSamRaw == null) ? "Absent (défaut = 1)" : restrictAnonymousSam.ToString()),
				ExpectedValue = "1",
				Status = ((restrictAnonymousSam != 1) ? SecurityStatus.Critical : SecurityStatus.OK),
				Description = ((restrictAnonymousSam == 1) ? "RestrictAnonymousSAM=1 : l'énumération anonyme de la base SAM (comptes locaux) est interdite." : "RestrictAnonymousSAM=0 : un utilisateur anonyme peut énumérer les comptes de la base SAM locale — risque d'attaque par force brute ciblée."),
				Recommendation = ((restrictAnonymousSam != 1) ? "Définir HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM = 1." : "Aucune action requise."),
				Reference = "CIS Benchmark Windows - 2.3.10.1",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CheckSharePermissions(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			ManagementObjectSearcher shareSearcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Share WHERE Type = 0");
			try
			{
				using ManagementObjectCollection shareCollection = shareSearcher.Get();
				foreach (ManagementObject shareObject in shareCollection)
				{
					ManagementObject shareObjectDisposable = shareObject;
					try
					{
						ct.ThrowIfCancellationRequested();
						string shareName = shareObject["Name"]?.ToString() ?? "(sans nom)";
						if (shareName.EndsWith("$", StringComparison.Ordinal))
						{
							continue;
						}
						TryAdd(results, delegate
						{
							try
							{
								string escapedShareName = shareName.Replace("'", "''");
								ManagementObjectSearcher securitySettingSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalShareSecuritySetting WHERE Name='" + escapedShareName + "'");
								try
								{
									using ManagementObjectCollection securitySettingCollection = securitySettingSearcher.Get();
									using (ManagementObjectCollection.ManagementObjectEnumerator securitySettingEnumerator = securitySettingCollection.GetEnumerator())
									{
										if (securitySettingEnumerator.MoveNext())
										{
											ManagementObject securitySettingObject = (ManagementObject)securitySettingEnumerator.Current;
											ManagementObject securitySettingObjectDisposable = securitySettingObject;
											try
											{
												ManagementBaseObject securityDescriptorResult = null;
												ManagementBaseObject securityDescriptor = null;
												try
												{
													securityDescriptorResult = securitySettingObject.InvokeMethod("GetSecurityDescriptor", null, null);
													if (securityDescriptorResult != null && WmiUInt(securityDescriptorResult, "ReturnValue", 99u) == 0)
													{
														securityDescriptor = securityDescriptorResult["Descriptor"] as ManagementBaseObject;
														if (securityDescriptor?["DACL"] is ManagementBaseObject[] dacl)
														{
															List<string> fullControlEntries = new List<string>();
															ManagementBaseObject[] daclEntries = dacl;
															foreach (ManagementBaseObject aceObject in daclEntries)
															{
																try
																{
																	ManagementBaseObject trustee = aceObject["Trustee"] as ManagementBaseObject;
																	string trusteeName = trustee?["Name"]?.ToString() ?? string.Empty;
																	string trusteeDomain = trustee?["Domain"]?.ToString() ?? string.Empty;
																	uint aceType = WmiUInt(aceObject, "AceType");
																	uint accessMask = WmiUInt(aceObject, "AccessMask");
																	bool isEveryone = trusteeName.Equals("Everyone", StringComparison.OrdinalIgnoreCase) || trusteeName.Equals("Tout le monde", StringComparison.OrdinalIgnoreCase);
																	bool isAuthenticatedUsers = trusteeName.Equals("Authenticated Users", StringComparison.OrdinalIgnoreCase) || trusteeName.Equals("Utilisateurs authentifiés", StringComparison.OrdinalIgnoreCase);
																	bool hasFullControl = (accessMask & 0x1F01FF) == 2032127;
																	if (aceType == 0 && hasFullControl && (isEveryone || isAuthenticatedUsers))
																	{
																		fullControlEntries.Add((string.IsNullOrEmpty(trusteeDomain) ? "" : (trusteeDomain + "\\")) + trusteeName + " (Contrôle total)");
																	}
																}
																catch (Exception)
																{
																}
															}
															bool hasBroadFullControl = fullControlEntries.Count > 0;
															return new SecurityResult
															{
																Category = Category,
																CheckName = "Permissions partage : " + shareName,
																CurrentValue = (hasBroadFullControl ? string.Join("; ", fullControlEntries) : "Pas de Contrôle total anonyme détecté"),
																ExpectedValue = "Aucun Contrôle total pour Everyone / Authenticated Users",
																Status = (hasBroadFullControl ? SecurityStatus.Critical : SecurityStatus.OK),
																Description = (hasBroadFullControl ? ($"Le partage '{shareName}' accorde le Contrôle total à des groupes larges ({string.Join(", ", fullControlEntries)}). " + "Cela permet à tout utilisateur du réseau de lire, écrire et supprimer des fichiers.") : ("Les permissions du partage '" + shareName + "' ne semblent pas accorder de Contrôle total à Everyone ou Authenticated Users.")),
																Recommendation = (hasBroadFullControl ? ("Restreindre immédiatement les permissions du partage '" + shareName + "'. Utiliser Get-SmbShareAccess et Set-SmbPathAcl pour configurer les permissions adéquates.") : "Vérifier manuellement les permissions NTFS sous-jacentes via icacls ou l'explorateur Windows."),
																Reference = "CIS Benchmark - Partages réseau | ANSSI - Sécurisation SMB",
																CollectedAt = DateTime.Now
															};
														}
													}
												}
												finally
												{
													securityDescriptor?.Dispose();
													securityDescriptorResult?.Dispose();
												}
											}
											finally
											{
												((IDisposable)securitySettingObjectDisposable)?.Dispose();
											}
										}
									}
									return new SecurityResult
									{
										Category = Category,
										CheckName = "Permissions partage : " + shareName,
										CurrentValue = "Non lisible via WMI",
										ExpectedValue = "DACL vérifiable",
										Status = SecurityStatus.Info,
										Description = "Impossible de lire le descripteur de sécurité du partage '" + shareName + "' via Win32_LogicalShareSecuritySetting.",
										Recommendation = "Vérifier manuellement avec Get-SmbShareAccess ou l'onglet Partage des propriétés du dossier.",
										Reference = "Get-SmbShareAccess -Name '" + shareName + "'",
										CollectedAt = DateTime.Now
									};
								}
								finally
								{
									((IDisposable)securitySettingSearcher)?.Dispose();
								}
							}
							catch (Exception permissionException)
							{
								return new SecurityResult
								{
									Category = Category,
									CheckName = "Permissions partage : " + shareName,
									CurrentValue = "Erreur",
									ExpectedValue = "DACL sans Contrôle total pour Everyone",
									Status = SecurityStatus.Info,
									Description = $"Erreur lors de la lecture des permissions du partage '{shareName}' : {permissionException.Message}. Vérification manuelle requise.",
									Recommendation = "Exécuter : Get-SmbShareAccess -Name '" + shareName + "'",
									CollectedAt = DateTime.Now
								};
							}
						});
					}
					finally
					{
						((IDisposable)shareObjectDisposable)?.Dispose();
					}
				}
			}
			finally
			{
				((IDisposable)shareSearcher)?.Dispose();
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception wmiException)
		{
			Exception wmiExceptionCopy = wmiException;
			Exception wmiExceptionRef = wmiExceptionCopy;
			TryAdd(results, () => new SecurityResult
			{
				Category = Category,
				CheckName = "Vérification des permissions de partages",
				CurrentValue = "Erreur WMI",
				ExpectedValue = "Analyse DACL des partages disque",
				Status = SecurityStatus.Error,
				Description = "Impossible d'analyser les permissions des partages : " + wmiExceptionRef.Message,
				Recommendation = "Vérifier manuellement avec Get-SmbShareAccess ou l'Explorateur Windows.",
				CollectedAt = DateTime.Now
			});
		}
	}

	private void CheckAdministrativeShares(List<SecurityResult> results)
	{
		TryAdd(results, delegate
		{
			object autoShareWksRaw = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "AutoShareWks");
			object autoShareServerRaw = ReadRegHklm("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "AutoShareServer");
			int autoShareWks = ((!(autoShareWksRaw is int autoShareWksValue)) ? 1 : autoShareWksValue);
			int autoShareServer = ((!(autoShareServerRaw is int autoShareServerValue)) ? 1 : autoShareServerValue);
			bool autoShareWksEnabled = autoShareWks != 0;
			bool autoShareServerEnabled = autoShareServer != 0;
			string currentValue = $"AutoShareWks={((autoShareWksRaw == null) ? "Absent(défaut=1)" : autoShareWks.ToString())} | AutoShareServer={((autoShareServerRaw == null) ? "Absent(défaut=1)" : autoShareServer.ToString())}";
			SecurityStatus status = ((autoShareWksEnabled || autoShareServerEnabled) ? SecurityStatus.Warning : SecurityStatus.OK);
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Partages Admin - AutoShareWks / AutoShareServer",
				CurrentValue = currentValue,
				ExpectedValue = "AutoShareWks=0 (postes de travail) | AutoShareServer=0 si non requis",
				Status = status,
				Description = $"AutoShareWks={(autoShareWksEnabled ? "Activé" : "Désactivé")}, AutoShareServer={(autoShareServerEnabled ? "Activé" : "Désactivé")}. " + "Ces valeurs contrôlent la création automatique des partages C$, D$, ADMIN$ au démarrage du service LanmanServer. Activés par défaut, ils permettent la gestion distante mais constituent une surface d'attaque si non nécessaires.",
				Recommendation = (autoShareWksEnabled ? "Sur les postes de travail, définir AutoShareWks=0 dans HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters via GPO (Computer Configuration > Windows Settings > Security Settings > Registry) pour désactiver les partages admin automatiques." : "Configuration correcte pour un poste de travail. Surveiller via 'net share' pour détecter toute réactivation."),
				Reference = "CIS Benchmark Windows - 2.3.10.3 | MS-KB Q288164",
				CollectedAt = DateTime.Now
			};
		});
	}

	private void CollectOpenSessions(List<SecurityResult> results)
	{
		TryAdd(results, delegate
		{
			int connectionCount = 0;
			HashSet<string> uniqueUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			try
			{
				ManagementObjectSearcher connectionSearcher = new ManagementObjectSearcher("SELECT UserName, ShareName, NumberOfFiles FROM Win32_ServerConnection");
				try
				{
					using ManagementObjectCollection connectionCollection = connectionSearcher.Get();
					foreach (ManagementObject connectionObject in connectionCollection)
					{
						ManagementObject connectionObjectDisposable = connectionObject;
						try
						{
							connectionCount++;
							string userName = connectionObject["UserName"]?.ToString() ?? string.Empty;
							if (!string.IsNullOrWhiteSpace(userName))
							{
								uniqueUsers.Add(userName);
							}
						}
						finally
						{
							((IDisposable)connectionObjectDisposable)?.Dispose();
						}
					}
				}
				finally
				{
					((IDisposable)connectionSearcher)?.Dispose();
				}
			}
			catch (ManagementException)
			{
			}
			catch (UnauthorizedAccessException)
			{
			}
			catch (Exception)
			{
			}
			return new SecurityResult
			{
				Category = Category,
				CheckName = "Sessions SMB actives",
				CurrentValue = $"{connectionCount} connexion(s) | {uniqueUsers.Count} utilisateur(s) unique(s) : {((uniqueUsers.Count > 0) ? string.Join(", ", uniqueUsers) : "(aucun)")}",
				ExpectedValue = "Connexions légitimes uniquement",
				Status = ((connectionCount > 0) ? SecurityStatus.Info : SecurityStatus.OK),
				Description = ((connectionCount > 0) ? ($"{connectionCount} connexion(s) SMB active(s) vers des partages locaux par {uniqueUsers.Count} utilisateur(s). " + "Vérifier que ces connexions sont toutes légitimes et attendues.") : "Aucune connexion SMB active vers les partages locaux de ce système."),
				Recommendation = ((connectionCount > 0) ? "Examiner les connexions via 'net session' ou 'Get-SmbSession' pour identifier les accès non autorisés. Fermer les sessions suspectes avec 'net session /delete'." : "Aucune action requise."),
				Reference = "Get-SmbSession | Get-SmbOpenFile",
				CollectedAt = DateTime.Now
			};
		});
	}

	private static object? ReadRegHklm(string subKey, string valueName)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey openedSubKey = baseKey.OpenSubKey(subKey, writable: false);
			return openedSubKey?.GetValue(valueName);
		}
		catch (Exception)
		{
			return null;
		}
	}

	private static int WmiInt(ManagementBaseObject obj, string prop, int def = -1)
	{
		try
		{
			object rawValue = obj[prop];
			return (rawValue != null && !(rawValue is DBNull)) ? Convert.ToInt32(rawValue) : def;
		}
		catch (OverflowException)
		{
			return def;
		}
	}

	private static long WmiLong(ManagementBaseObject obj, string prop, long def = -1L)
	{
		try
		{
			object rawValue = obj[prop];
			return (rawValue != null && !(rawValue is DBNull)) ? Convert.ToInt64(rawValue) : def;
		}
		catch (Exception)
		{
			return def;
		}
	}

	private static uint WmiUInt(ManagementBaseObject obj, string prop, uint def = 0u)
	{
		try
		{
			object rawValue = obj[prop];
			return (rawValue != null && !(rawValue is DBNull)) ? Convert.ToUInt32(rawValue) : def;
		}
		catch (Exception)
		{
			return def;
		}
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
				Category = "Réseau",
				CheckName = "Erreur de vérification",
				CurrentValue = "Erreur",
				Status = SecurityStatus.Error,
				Description = "Échec d'une vérification partages réseau : " + ex.Message,
				CollectedAt = DateTime.Now
			});
		}
	}
}
