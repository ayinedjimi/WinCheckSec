# CHECKSEC for macOS

Portage de [CHECKSEC](../README.md) (auditeur de posture de sécurité) vers **macOS Sonoma 14 / Tahoe 26**.

> État : **PoC v0.1** — CLI fonctionnelle, 7 collecteurs réels, export JSON forensique signé SHA-256.
> Le moteur est du C# multiplateforme ; les collecteurs appellent les outils système macOS.

## Architecture

Même patron que la version Windows, mais découplé de Windows :

| Élément | Rôle | Équivalent Windows |
|---|---|---|
| `Core/IMacCollector` | Contrat d'un collecteur | `ISecurityCollector` |
| `Core/MacCollectorBase` | Timing, erreurs, court-circuit hors-macOS | — |
| `Core/ProcessRunner` | Exécution sûre d'outils (`spctl`, `fdesetup`…) sans shell | WMI / P-Invoke |
| `Core/ScanEngine` | Exécution parallèle + scoring (Info/NA/Error exclus) | `AnalysisService` |
| `Core/JsonReportBuilder` | Rapport JSON + empreinte SHA-256 | `ReportJsonBuilder` |
| `Collectors/*` | Contrôles réels | `Collectors/*` |

## Collecteurs (PoC)

| Collecteur | Domaine | Source |
|---|---|---|
| FileVault | Chiffrement disque | `fdesetup status` |
| Gatekeeper | Contrôle applicatif | `spctl --status` |
| SIP | Intégrité système | `csrutil status` |
| Pare-feu applicatif | Réseau | `socketfilterfw` |
| XProtect | Antimalware | plist XProtect |
| Services de partage | Surface d'attaque | `systemsetup`, `launchctl` |
| Mises à jour | Maintenance | `defaults read com.apple.SoftwareUpdate` |

## Build

```bash
# Compilation (multiplateforme — fonctionne aussi depuis Windows/Linux)
dotnet build -c Release

# Binaire natif macOS Apple Silicon (auto-contenu, sans .NET préinstallé)
dotnet publish -c Release -r osx-arm64 --self-contained true -p:PublishSingleFile=true
# Intel : -r osx-x64
```

## Exécution (sur un Mac)

```bash
chmod +x checksec
./checksec                 # audit + tableau + rapport JSON sur le Bureau
sudo ./checksec            # recommandé : certains contrôles exigent root (SSH, SIP complet)
./checksec --json /tmp/rapport.json --quiet
```

Code retour : `0` si score ≥ 40, `2` sinon (exploitable en CI).

## Feuille de route

1. **Intégration mSCP** — charger les YAML du [NIST macOS Security Compliance Project](https://github.com/usnistgov/macos_security) (CIS/NIST/DISA) pour élargir automatiquement la couverture.
2. Collecteurs supplémentaires : TCC (permissions vie privée), extensions système/kext, profils de configuration MDM, Lockdown Mode, Secure Boot (Apple Silicon, `bputil`), Time Machine chiffré, comptes/mots de passe (`pwpolicy`).
3. Exports PDF/HTML/SARIF (QuestPDF & ClosedXML sont déjà multiplateformes).
4. UI **Avalonia** partageant 100 % du moteur (rendu proche de l'app Windows).
5. Packaging `.app` **signé + notarisé**, binaire universel (arm64 + x64).

Voir le plan complet : [`../docs/MACOS_PORT.md`](../docs/MACOS_PORT.md).
