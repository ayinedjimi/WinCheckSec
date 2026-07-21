using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;
using CHECKSEC.Core.Services.Helpers;

namespace CHECKSEC.Core.Services.Collectors;

/// <summary>
/// Collecteur ÉDITEUR-AGNOSTIQUE qui audite l'antivirus / anti-logiciels espions / pare-feu
/// tels qu'ils sont ENREGISTRÉS auprès du Centre de sécurité Windows (Windows Security Center, WSC).
///
/// Contrairement au <c>DefenderCollector</c> qui ne cible que Microsoft Defender, ce collecteur
/// interroge le namespace WMI <c>root\SecurityCenter2</c>, qui recense TOUS les produits de sécurité
/// enregistrés par leur éditeur : CrowdStrike, SentinelOne, Kaspersky, ESET, Bitdefender, Sophos,
/// Trend Micro… ainsi que Microsoft Defender.
///
/// Objectif principal : remonter le NOM du produit de sécurité tiers réellement installé et actif,
/// et déterminer s'il assure la protection à la place de Defender (qui devient alors légitimement passif).
///
/// ⚠️ Le namespace <c>root\SecurityCenter2</c> N'EXISTE QUE sur les éditions CLIENT de Windows
/// (Windows 10/11). Il est ABSENT sur Windows Server → on émet un résultat NotApplicable, pas une erreur.
///
/// Référence : https://learn.microsoft.com/windows/win32/api/iwscapi/
/// </summary>
public class SecurityCenterCollector : ISecurityCollector
{
	// Namespace WMI du Centre de sécurité Windows (WSC) — clients uniquement.
	private const string SecurityCenterNamespace = "\\\\.\\root\\SecurityCenter2";

	private const string WscReference = "https://learn.microsoft.com/windows/win32/api/iwscapi/";

	public string Name => "Centre de sécurité (AV/Pare-feu)";

	public string Category => "Antivirus";

	public Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken))
	{
		CollectorReport report = new CollectorReport
		{
			CollectorName = Name
		};
		Stopwatch stopwatch = Stopwatch.StartNew();
		try
		{
			ct.ThrowIfCancellationRequested();

			// Étape 1 : vérifier la disponibilité du namespace root\SecurityCenter2.
			// Sur Windows Server, il est absent → on émet un unique résultat NotApplicable et on s'arrête.
			if (!IsSecurityCenterAvailable(out string availabilityError))
			{
				report.Results.Add(new SecurityResult
				{
					Category = Category,
					CheckName = "Centre de sécurité Windows",
					CurrentValue = "Indisponible",
					ExpectedValue = "Disponible (édition cliente de Windows)",
					Status = SecurityStatus.NotApplicable,
					Description = "Le namespace WMI root\\SecurityCenter2 est introuvable sur cette machine. " +
						"Ce namespace n'existe que sur les éditions CLIENT de Windows (10/11) ; il est absent sur Windows Server. " +
						(string.IsNullOrEmpty(availabilityError) ? string.Empty : "Détail : " + availabilityError),
					Recommendation = "Sur Windows Server, auditez directement le produit de sécurité (ex. via le collecteur Defender ou l'agent EDR tiers).",
					Reference = WscReference
				});
				return FinalizeReport(report, stopwatch);
			}

			// Étape 2 : chaque classe est interrogée dans son propre bloc → une classe absente
			// ou en erreur ne casse pas l'analyse des autres.
			ct.ThrowIfCancellationRequested();
			CollectAntiVirusProducts(report.Results, ct);

			ct.ThrowIfCancellationRequested();
			CollectAntiSpywareProducts(report.Results, ct);

			ct.ThrowIfCancellationRequested();
			CollectFirewallProducts(report.Results, ct);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			// Échec global inattendu.
			report.ErrorMessage = "SecurityCenterCollector fatal error: " + ex.Message;
		}
		return FinalizeReport(report, stopwatch);
	}

	// ---------------------------------------------------------------------------------------------
	// Disponibilité du namespace
	// ---------------------------------------------------------------------------------------------

	/// <summary>
	/// Tente de se connecter au namespace root\SecurityCenter2.
	/// Retourne false si le namespace est « non valide » (typiquement Windows Server).
	/// </summary>
	private static bool IsSecurityCenterAvailable(out string error)
	{
		error = string.Empty;
		try
		{
			ManagementScope scope = new ManagementScope(SecurityCenterNamespace)
			{
				Options =
				{
					Timeout = TimeSpan.FromSeconds(15L)
				}
			};
			scope.Connect();
			return scope.IsConnected;
		}
		catch (ManagementException mex)
		{
			// Code « InvalidNamespace » = namespace absent (Windows Server).
			error = mex.Message;
			return false;
		}
		catch (Exception ex)
		{
			error = ex.Message;
			return false;
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Décodage du champ productState (heuristique standard, non documentée officiellement par Microsoft)
	// ---------------------------------------------------------------------------------------------

	/// <summary>
	/// Décode le champ WMI <c>productState</c> (uint) exposé par les classes du Centre de sécurité.
	///
	/// Il s'agit d'une valeur sur 3 octets de la forme 0xWWSSUU :
	///  - octet SS (scanner)   : 0x10 ou 0x11 ⇒ activé (protection temps réel ON) ; 0x00 ⇒ désactivé.
	///  - octet UU (signatures): 0x00 ⇒ à jour ; 0x10 ⇒ périmées / obsolètes.
	///
	/// ⚠️ Ce format N'EST PAS officiellement documenté par Microsoft : il s'agit de l'heuristique
	/// standard largement utilisée par la communauté et fiable en pratique sur les produits courants.
	/// </summary>
	private static (bool enabled, bool upToDate) DecodeProductState(uint productState)
	{
		int scanner = (int)((productState >> 8) & 0xFF);
		int signature = (int)(productState & 0xFF);
		bool enabled = scanner == 0x10 || scanner == 0x11;
		bool upToDate = signature == 0x00;
		return (enabled, upToDate);
	}

	// ---------------------------------------------------------------------------------------------
	// AntiVirusProduct
	// ---------------------------------------------------------------------------------------------

	private void CollectAntiVirusProducts(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			List<ManagementObject> products = WmiHelper.Query("SELECT * FROM AntiVirusProduct", SecurityCenterNamespace);
			try
			{
				// Résultat 2 : AUCUN AV enregistré → machine non protégée.
				if (products.Count == 0)
				{
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "Antivirus enregistré",
						CurrentValue = "Aucun",
						ExpectedValue = ">= 1 antivirus actif et à jour",
						Status = SecurityStatus.Critical,
						Description = "Aucun antivirus n'est enregistré dans le Centre de sécurité Windows. La machine est potentiellement NON protégée contre les logiciels malveillants.",
						Recommendation = "Installer / activer un antivirus (Microsoft Defender ou une solution tierce EDR/AV).",
						Reference = WscReference
					});
					return;
				}

				// Agrégats pour la synthèse (Résultat 3).
				int activeCount = 0;
				List<string> activeUpToDateThirdParty = new List<string>();

				// Résultat 1 : un résultat par AV enregistré.
				foreach (ManagementObject av in products)
				{
					ct.ThrowIfCancellationRequested();
					ManagementObject current = av;
					TryAdd(results, delegate
					{
						string displayName = WmiHelper.GetString(current, "displayName") ?? "Inconnu";
						uint productState = ReadProductState(current);
						(bool enabled, bool upToDate) = DecodeProductState(productState);

						bool isDefender = displayName.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) >= 0;
						bool isThirdParty = !isDefender;

						// Comptabilisation pour la synthèse.
						if (enabled)
						{
							activeCount++;
							if (isThirdParty && upToDate)
							{
								activeUpToDateThirdParty.Add(displayName);
							}
						}

						string enabledText = enabled ? "Activé" : "Désactivé";
						string signatureText = upToDate ? "à jour" : "périmées";

						// Statut : activé + à jour → OK ; activé + périmé → Warning ; désactivé → Critical.
						SecurityStatus status;
						if (!enabled)
						{
							status = SecurityStatus.Critical;
						}
						else if (!upToDate)
						{
							status = SecurityStatus.Warning;
						}
						else
						{
							status = SecurityStatus.OK;
						}

						string editeurText = isDefender
							? "Il s'agit de Microsoft Defender (antivirus intégré à Windows)."
							: "Il s'agit d'un ANTIVIRUS TIERS enregistré dans le Centre de sécurité — le nom de l'éditeur est ainsi remonté.";

						return new SecurityResult
						{
							Category = Category,
							CheckName = "Antivirus enregistré : " + displayName,
							CurrentValue = $"{displayName} — {enabledText} — Signatures {signatureText}",
							ExpectedValue = "Activé et signatures à jour",
							Status = status,
							Description = $"Produit antivirus enregistré dans le Centre de sécurité Windows (productState=0x{productState:X6}). {editeurText}",
							Recommendation = status switch
							{
								SecurityStatus.Critical => "Antivirus désactivé : réactiver la protection en temps réel ou installer une solution de remplacement.",
								SecurityStatus.Warning => "Signatures périmées : forcer la mise à jour des définitions de l'antivirus.",
								_ => "Antivirus actif et à jour."
							},
							Reference = WscReference
						};
					});
				}

				// Résultat 3 : synthèse AV.
				TryAdd(results, () =>
				{
					bool hasThirdPartyProtection = activeUpToDateThirdParty.Count > 0;
					return new SecurityResult
					{
						Category = Category,
						CheckName = "Synthèse antivirus enregistrés",
						CurrentValue = $"{products.Count} enregistré(s), {activeCount} actif(s)" +
							(hasThirdPartyProtection ? " — protection tierce : " + string.Join(", ", activeUpToDateThirdParty) : string.Empty),
						ExpectedValue = "Au moins un AV actif et à jour",
						Status = (activeCount > 0) ? SecurityStatus.OK : SecurityStatus.Critical,
						Description = hasThirdPartyProtection
							? "Protection tierce active et à jour : " + string.Join(", ", activeUpToDateThirdParty) +
							  ". Dans ce cas, Microsoft Defender est légitimement passif (mode désactivé automatique)."
							: "Synthèse du nombre d'antivirus enregistrés et actifs dans le Centre de sécurité.",
						Recommendation = (activeCount > 0)
							? "Au moins un antivirus assure la protection."
							: "Aucun antivirus actif : activer immédiatement une protection en temps réel.",
						Reference = WscReference
					};
				});
			}
			finally
			{
				DisposeAll(products);
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
				CheckName = "AntiVirusProduct (WMI)",
				CurrentValue = "Erreur : " + ex.Message,
				ExpectedValue = "Requête WMI réussie",
				Status = SecurityStatus.Warning,
				Description = "Impossible d'interroger la classe AntiVirusProduct du Centre de sécurité.",
				Recommendation = "Vérifier que le service WMI et le Centre de sécurité Windows fonctionnent.",
				Reference = WscReference
			});
		}
	}

	// ---------------------------------------------------------------------------------------------
	// AntiSpywareProduct (souvent identique à l'AV → un seul résultat synthétique)
	// ---------------------------------------------------------------------------------------------

	private void CollectAntiSpywareProducts(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			List<ManagementObject> products = WmiHelper.Query("SELECT * FROM AntiSpywareProduct", SecurityCenterNamespace);
			try
			{
				TryAdd(results, () =>
				{
					if (products.Count == 0)
					{
						return new SecurityResult
						{
							Category = Category,
							CheckName = "Anti-logiciel espion enregistré",
							CurrentValue = "Aucun",
							ExpectedValue = "Au moins un produit anti-spyware (souvent l'AV)",
							Status = SecurityStatus.Info,
							Description = "Aucun produit anti-logiciel espion distinct n'est enregistré dans le Centre de sécurité. Il est souvent fusionné avec l'antivirus.",
							Recommendation = "Vérifier que l'antivirus assure aussi la protection anti-spyware.",
							Reference = WscReference
						};
					}

					// Résumé compact : noms + états, sans dupliquer un résultat par produit.
					List<string> summaries = new List<string>();
					int activeCount = 0;
					foreach (ManagementObject sp in products)
					{
						string displayName = WmiHelper.GetString(sp, "displayName") ?? "Inconnu";
						(bool enabled, bool upToDate) = DecodeProductState(ReadProductState(sp));
						if (enabled)
						{
							activeCount++;
						}
						summaries.Add($"{displayName} ({(enabled ? "Activé" : "Désactivé")}, signatures {(upToDate ? "à jour" : "périmées")})");
					}

					return new SecurityResult
					{
						Category = Category,
						CheckName = "Anti-logiciels espions enregistrés",
						CurrentValue = string.Join(" ; ", summaries),
						ExpectedValue = "Au moins un produit anti-spyware actif",
						Status = (activeCount > 0) ? SecurityStatus.OK : SecurityStatus.Warning,
						Description = "Produits anti-logiciels espions enregistrés dans le Centre de sécurité (généralement identiques à l'antivirus).",
						Recommendation = (activeCount > 0)
							? "Protection anti-spyware active."
							: "Aucun produit anti-spyware actif : vérifier la configuration de l'antivirus.",
						Reference = WscReference
					};
				});
			}
			finally
			{
				DisposeAll(products);
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
				CheckName = "AntiSpywareProduct (WMI)",
				CurrentValue = "Erreur : " + ex.Message,
				ExpectedValue = "Requête WMI réussie",
				Status = SecurityStatus.Info,
				Description = "Impossible d'interroger la classe AntiSpywareProduct du Centre de sécurité.",
				Recommendation = "Vérifier le service WMI et le Centre de sécurité Windows.",
				Reference = WscReference
			});
		}
	}

	// ---------------------------------------------------------------------------------------------
	// FirewallProduct
	// ---------------------------------------------------------------------------------------------

	private void CollectFirewallProducts(List<SecurityResult> results, CancellationToken ct)
	{
		try
		{
			List<ManagementObject> products = WmiHelper.Query("SELECT * FROM FirewallProduct", SecurityCenterNamespace);
			try
			{
				// Aucun pare-feu enregistré : le pare-feu Windows peut malgré tout être actif
				// sans être remonté ici → on reste en Info.
				if (products.Count == 0)
				{
					results.Add(new SecurityResult
					{
						Category = Category,
						CheckName = "Pare-feu enregistré",
						CurrentValue = "Aucun",
						ExpectedValue = "Au moins un pare-feu enregistré",
						Status = SecurityStatus.Info,
						Description = "Aucun pare-feu tiers n'est enregistré dans le Centre de sécurité. Le Pare-feu Windows Defender peut néanmoins être actif (à vérifier via son collecteur dédié).",
						Recommendation = "Vérifier l'état du Pare-feu Windows Defender.",
						Reference = WscReference
					});
					return;
				}

				foreach (ManagementObject fw in products)
				{
					ct.ThrowIfCancellationRequested();
					ManagementObject current = fw;
					TryAdd(results, delegate
					{
						string displayName = WmiHelper.GetString(current, "displayName") ?? "Inconnu";
						uint productState = ReadProductState(current);
						// Pour un pare-feu, l'octet scanner indique l'état activé/désactivé.
						(bool enabled, _) = DecodeProductState(productState);

						return new SecurityResult
						{
							Category = Category,
							CheckName = "Pare-feu enregistré : " + displayName,
							CurrentValue = $"{displayName} — {(enabled ? "Activé" : "Désactivé")}",
							ExpectedValue = "Activé",
							Status = enabled ? SecurityStatus.OK : SecurityStatus.Warning,
							Description = $"Pare-feu enregistré dans le Centre de sécurité Windows (productState=0x{productState:X6}).",
							Recommendation = enabled
								? "Pare-feu actif."
								: "Pare-feu désactivé : réactiver la protection réseau.",
							Reference = WscReference
						};
					});
				}
			}
			finally
			{
				DisposeAll(products);
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
				CheckName = "FirewallProduct (WMI)",
				CurrentValue = "Erreur : " + ex.Message,
				ExpectedValue = "Requête WMI réussie",
				Status = SecurityStatus.Info,
				Description = "Impossible d'interroger la classe FirewallProduct du Centre de sécurité.",
				Recommendation = "Vérifier le service WMI et le Centre de sécurité Windows.",
				Reference = WscReference
			});
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------------------------------

	/// <summary>
	/// Lit le champ WMI <c>productState</c> de façon robuste (uint sur les produits courants).
	/// </summary>
	private static uint ReadProductState(ManagementObject obj)
	{
		try
		{
			object raw = obj["productState"];
			if (raw == null || raw is DBNull)
			{
				return 0u;
			}
			return Convert.ToUInt32(raw);
		}
		catch
		{
			return 0u;
		}
	}

	private static void DisposeAll(List<ManagementObject> objects)
	{
		if (objects == null)
		{
			return;
		}
		foreach (ManagementObject o in objects)
		{
			try
			{
				((IDisposable)o)?.Dispose();
			}
			catch
			{
			}
		}
	}

	private static Task<CollectorReport> FinalizeReport(CollectorReport report, Stopwatch stopwatch)
	{
		stopwatch.Stop();
		report.Duration = stopwatch.Elapsed;
		return Task.FromResult(report);
	}

	private void TryAdd(List<SecurityResult> results, Func<SecurityResult> factory)
	{
		try
		{
			results.Add(factory());
		}
		catch (Exception ex)
		{
			results.Add(new SecurityResult
			{
				Category = Category,
				CheckName = "Check Error",
				CurrentValue = "Error",
				ExpectedValue = string.Empty,
				Status = SecurityStatus.Error,
				Description = "La vérification a échoué : " + ex.Message,
				Recommendation = "Vérifier l'accès WMI au Centre de sécurité Windows.",
				Reference = WscReference
			});
		}
	}
}
