namespace Checksec.Mac.Core;

/// <summary>
/// Contrat d'un collecteur macOS. Miroir de <c>ISecurityCollector</c> cote Windows :
/// un collecteur interroge le systeme (via <see cref="ProcessRunner"/> ou lecture de plist)
/// et renvoie un <see cref="CollectorReport"/>.
/// </summary>
public interface IMacCollector
{
    /// <summary>Nom lisible du collecteur (ex. "FileVault").</summary>
    string Name { get; }

    /// <summary>Categorie de regroupement (ex. "Chiffrement", "Reseau").</summary>
    string Category { get; }

    Task<CollectorReport> CollectAsync(CancellationToken ct);
}
