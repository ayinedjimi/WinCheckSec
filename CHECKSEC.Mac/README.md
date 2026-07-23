# MacSecCheck

Portage macOS de [WinCheckSec](../README.md) (auditeur de posture de sécurité) vers **macOS Sonoma 14 / Tahoe 26**. Binaire : `macseccheck`.

> État : **PoC v0.2** — CLI fonctionnelle, 7 collecteurs natifs + **intégration des baselines mSCP (NIST)**, export JSON forensique signé SHA-256.
> Le moteur est du C# multiplateforme ; les collecteurs appellent les outils système macOS.

## Baselines mSCP (NIST macOS Security Compliance Project)

Les règles et baselines YAML du projet [usnistgov/macos_security](https://github.com/usnistgov/macos_security)
(domaine public) sont **embarquées dans le binaire**. Chaque règle fournit une commande de vérification,
la valeur attendue, la remédiation et le mapping CIS / NIST 800-53 / DISA.

- **478 règles** indexées, **17 baselines** macOS 26 : `cis_lvl1`, `cis_lvl2`, `disa_stig`, `800-53r5_high/moderate/low`, `cmmc_lvl1/2`, `cnssi-1253_*`, `cisv8`, `800-171`, `hicp_lp`, `nlmapgov_*`, `all_rules`.
- Exemple : `cis_lvl1` → 98 règles réparties en 5 sections (Auditing, Operating System, Password Policy, System Settings, Supplemental).
- Un **collecteur par section** exécute le `check` de chaque règle et compare la sortie à la valeur attendue → conforme / écart (gravité issue de la sévérité DISA STIG).

```bash
./macseccheck --list-baselines                 # liste les baselines disponibles
./macseccheck --baseline cis_lvl2              # évalue une autre baseline
./macseccheck --baseline disa_stig             # STIG DISA
./macseccheck --dump-rule os_sip_enable        # diagnostic : check/attendu/fix résolus
./macseccheck --mscp /chemin/vers/macos_security   # utilise un checkout externe (données à jour)
```

Les données embarquées peuvent être régénérées depuis un checkout mSCP ; voir la note en bas de fichier.

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
chmod +x macseccheck
./macseccheck                 # audit + tableau + rapport JSON sur le Bureau
sudo ./macseccheck            # recommandé : certains contrôles exigent root (SSH, SIP complet)
./macseccheck --json /tmp/rapport.json --quiet
```

Code retour : `0` si score ≥ 40, `2` sinon (exploitable en CI).

## Feuille de route

1. ~~**Intégration mSCP**~~ — ✅ fait : 478 règles + 17 baselines embarquées, collecteur par section.
2. Collecteurs natifs supplémentaires : TCC (permissions vie privée), extensions système/kext, profils de configuration MDM, Lockdown Mode, Secure Boot (Apple Silicon, `bputil`), Time Machine chiffré.
3. Exports PDF/HTML/SARIF (QuestPDF & ClosedXML sont déjà multiplateformes).
4. UI **Avalonia** partageant 100 % du moteur (rendu proche de l'app Windows).
5. Packaging `.app` **signé + notarisé**, binaire universel (arm64 + x64).

Voir le plan complet : [`../docs/MACOS_PORT.md`](../docs/MACOS_PORT.md).

---

### Mettre à jour les données mSCP embarquées

Les YAML sont dans `mscp/rules/` et `mscp/baselines/` (embarqués via `<EmbeddedResource>`).
Pour les régénérer depuis la dernière version du projet NIST :

```bash
git clone https://github.com/usnistgov/macos_security
cp -R macos_security/src/mscp/data/rules/*       CHECKSEC.Mac/mscp/rules/
cp    macos_security/src/mscp/data/baselines/macos/*.yaml CHECKSEC.Mac/mscp/baselines/
```

Données mSCP sous licence NIST (domaine public / œuvre du gouvernement américain) — voir `mscp/LICENSE_mscp.md`.
