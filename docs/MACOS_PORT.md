# Portage macOS de CHECKSEC — plan & état

Cible : **macOS Tahoe 26** (prioritaire) et **Sonoma 14** (socle minimal). Apple Silicon + Intel.

## Principe

CHECKSEC (Windows) = **moteur C#** + **collecteurs** + **UI**. Seul le moteur est réutilisable ;
les collecteurs et l'UI sont spécifiques à l'OS. Le portage garde le moteur, réécrit le reste.

```
┌────────────────────────────────────────────────────────┐
│  Moteur (C# multiplateforme)                            │  ← réutilisé
│  IMacCollector · ScanEngine · scoring · JsonReport      │
├────────────────────────────────────────────────────────┤
│  Collecteurs macOS (spctl, fdesetup, csrutil, defaults) │  ← réécrits
├────────────────────────────────────────────────────────┤
│  Sortie : CLI (v0.1) → Avalonia (v0.3) → .app notarisé  │  ← remplacée
└────────────────────────────────────────────────────────┘
```

## Correspondance des contrôles Windows → macOS

| Domaine CHECKSEC | Équivalent macOS | Outil |
|---|---|---|
| BitLocker | FileVault | `fdesetup status` |
| Defender / SecurityCenter2 | XProtect / XProtect Remediator | plist XProtect |
| Secure Boot / VBS | Secure Boot policy + SIP | `bputil`, `csrutil status` |
| Pare-feu Windows | Application Firewall + pf | `socketfilterfw` |
| SmartScreen | Gatekeeper / notarisation | `spctl --status` |
| UAC / droits | sudoers, comptes admin, auto-login | `dscl`, `pwpolicy`, `defaults` |
| Autoruns / persistance | LaunchAgents/Daemons, login items, profils | `launchctl`, `profiles list` |
| Politique mot de passe | pwpolicy, verrouillage écran | `pwpolicy`, `defaults` |
| Journaux Windows | Unified log | `log show` |
| WiFi (WEP/TKIP/802.1X) | Profils WiFi + réseaux connus | `networksetup`, `security` |
| *(spécifique macOS)* | TCC, kext/system extensions, partages, Time Machine chiffré, Lockdown Mode, Rapid Security Response | `sqlite3 TCC.db`, `systemextensionsctl`, `systemsetup`, `tmutil` |

## Levier clé : le projet mSCP (NIST)

[usnistgov/macos_security](https://github.com/usnistgov/macos_security) fournit, en YAML, pour chaque
contrôle : commande de vérification, valeur attendue, remédiation, et mapping **CIS / NIST 800-53 / DISA / CMMC**.
Une **CIS Apple macOS 26 Tahoe v1.0.0** existe déjà. → piloter les collecteurs depuis ce YAML
(comme les baselines MSCT côté Windows) démultiplie la couverture sans écrire chaque contrôle à la main.

## Contraintes spécifiques

- **Privilèges** : nombre de contrôles exigent `sudo` **et** surtout **Full Disk Access** (lecture de `TCC.db`, certains plists MDM) → l'app doit le détecter et guider l'utilisateur (équivalent UAC).
- **Signature & notarisation** : pour une distribution sans alerte Gatekeeper, il faut un compte Apple Developer (signer + notariser le `.app`).
- **Apple Silicon vs Intel** : cibler `osx-arm64` **et** `osx-x64` ; certains contrôles (`bputil`) n'existent que sur Apple Silicon → conditionnels.

## Phases

| Phase | Contenu | État |
|---|---|---|
| 0 | PoC CLI + moteur + 7 collecteurs + JSON signé | ✅ **fait** (`CHECKSEC.Mac/`) |
| 1 | Extraire un `CHECKSEC.Core` réellement cross-platform (bénéficie aussi à Windows) | à faire |
| 2 | Intégration mSCP (chargement YAML CIS Tahoe) | à faire |
| 3 | Collecteurs TCC / extensions / MDM / Secure Boot / pwpolicy | à faire |
| 4 | Exports PDF/HTML/SARIF | à faire |
| 5 | UI Avalonia partagée | à faire |
| 6 | Packaging `.app` signé + notarisé, binaire universel | à faire |

## État actuel (v0.1)

- CLI `checksec` compilée et cross-compilée en **Mach-O arm64** depuis Windows (73 Mo, auto-contenu).
- 7 collecteurs réels : FileVault, Gatekeeper, SIP, pare-feu, XProtect, partages, mises à jour.
- Export JSON forensique identique à Windows (contexte hôte, scores par catégorie, modules horodatés, empreinte SHA-256).
- Reste à faire avant un vrai test : **exécuter sur un Mac** (Sonoma/Tahoe) et ajuster le parsing selon les sorties réelles.
