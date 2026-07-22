# 🗺️ CHECKSEC — Feuille de route

Légende : ✅ **livré** · 🚧 **en cours (vague 1)** · 📋 **planifié (vague 2+)** · ✔️ *déjà couvert par un collecteur existant*

---

## A. Nouveaux collecteurs

### A1. AMSI 🚧
- État global, providers AMSI enregistrés (CLSID → DLL), provider Defender présent
- Clés de désactivation (`AmsiEnable`), providers dans chemin suspect (hijack)
- 📋 Détection de patch mémoire runtime (`AmsiScanBuffer` hooks) — *non faisable en lecture statique, documenté*

### A2. User Rights Assignment 🚧
- `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege`, `SeCreateTokenPrivilege`, `SeLoadDriverPrivilege`, `SeBackup/Restore/TakeOwnership`
- Logon rights (Deny RDP/local, service/batch), comparaison à la baseline (titulaires anormaux) — via `secedit /export USER_RIGHTS`

### A3. PowerShell — durcissement avancé 📋
- Constrained Language Mode (`__PSLockdownPolicy`)
- 📋 PSRemoting endpoints (`Get-PSSessionConfiguration`)
- ✔️ ExecutionPolicy, ScriptBlock/Module/Transcription logging, PSv2 *(déjà dans « Sécurité Additionnelle » ; désinstallation feature PSv2 à renforcer)*

### A4. Boot integrity / anti-tampering firmware 🚧
- Test Signing, No Integrity Checks, Kernel Debug (`bcdedit`)
- **Microsoft Vulnerable Driver Blocklist** (BYOVD), Driver Signature Enforcement
- 📋 Contenu db/dbx/KEK/PK, mode Standard vs Custom Keys, version dbx *(nécessite API UEFI avancée)*

### A5. Signature & réputation des binaires en persistance 📋
- Authenticode + éditeur de confiance + chemin standard vs suspect pour chaque entrée de persistance
- « Ghost services » (binaire de service absent du disque)
- *Reporté vague 2 : vérification de signature en masse (coût/perf) — à faire par lots*

### A6. Proxy & résolution réseau 🚧
- Proxy système (`ProxyEnable`/`ProxyServer`/`AutoConfigURL`), WinHTTP proxy, service Auto-Proxy, NRPT, DNS cache

### A7. Persistance avancée 🚧
- **COM Hijacking** (CLSID HKCU → AppData/Temp), AppCertDlls, AppInit_DLLs, LSA SSP injection
- **Accessibility backdoors** (IFEO Debugger sur sethc/utilman/osk…), Print Monitors, KnownDLLs
- 📋 Shim Database (sdbinst), Office COM Add-ins *(voir section B)*

### A8. Fonctionnalités Windows 11 récentes 🚧
- **Recall** (Copilot+), **Quick Assist**, **Sudo for Windows** (24H2), **Developer Mode** (sideloading), Copilot

### A9. WSL / conteneurs / virtualisation 📋
- WSL (version, distros, intégration), Windows Sandbox (isolation réseau), Nested Virtualization, Docker/Podman *(collecteur optionnel poste dev)*

### A10. Attaques réseau (relay / spoofing) 📋
- EPA (Extended Protection for Authentication) LDAP/RDP/web
- Tunnels IPv6 (Teredo/6to4/ISATAP), NetBIOS global, RPC (`RestrictRemoteClients`), RA/DHCPv6 Guard

### A11. Crypto / Schannel 🚧
- **FIPS mode**, ordre des cipher suites, cache Schannel, ciphers/hashes/keyexchange faibles (RC4/DES/3DES/MD5/SHA1/DH<2048)
- Certificats faibles (SHA1, RSA<2048, expirés) dans les magasins machine

---

## B. Ajouts à des collecteurs existants

| Domaine | Ajout | Statut |
|---|---|---|
| Application Control | ASR détail par règle (GUID, Audit/Warn/Block) | ✔️ déjà par règle (19 GUID) |
| Application Control | WDAC base vs supplemental, Audit/Enforce, signature policy | 📋 |
| Application Control | Exploit Protection mitigations par processus (XML) | 📋 |
| **Defender** | **Exclusions** (fichiers/dossiers/ext/process), planification, dernière analyse, Network Protection mode, SmartScreen précis | 🚧 |
| LAPS | **Windows LAPS natif** (post-22H2) | 🚧 |
| Kerberos | Types de chiffrement **forcés** (AES only), rejet NTLMv1 explicite, complexité PIN Hello | 📋 |
| Services | Chemin non standard, signature du binaire, Failure Actions, Delayed Start | 📋 (partiel dans ProcessDriver) |
| Scheduled Tasks | Permissions XML (`\System32\Tasks` inscriptible = EoP), tâches cachées/non signées | 📋 |
| Office | **COM Add-ins** (distinct macros VBA), OWA add-ins | 📋 |
| Print Spooler | Drivers d'impression tiers non signés WHQL | 📋 |
| Firewall | Règles récentes/désactivées/Any-Any/Allow Inbound à risque ; filtrage localhost | 📋 |
| **FS/Registre** | **ACL System32/Program Files/clés Run inscriptibles par utilisateur standard** (EoP) | 🚧 |

---

## C. Fonctionnalités transverses de l'outil

| Fonctionnalité | Statut |
|---|---|
| Scoring pondéré | ✔️ Déjà pondéré (`OK×1 + Warning×0.5 + Critical×0`) |
| **Mapping MITRE ATT&CK** par contrôle (ex. WDigest → T1003.001) | ✅ livré (JSON : `MitreTechniques` par résultat + `MitreSummary`) |
| Mapping référentiels (CIS ID, ANSSI BP28, NIST 800-53) | ✔️ CIS mappé · 📋 ANSSI/NIST |
| Mode Diff / régression entre 2 scans | ✔️ Historique présent — 📋 **Vague 3** : diff détaillé check-à-check |
| Corrélation de chaînes d'attaque | 📋 **Vague 3** |
| Export **SARIF** (CI/CD) | ✅ livré (`--format sarif` + UI) |
| Export **CEF** enrichi (Error + modules en échec) | ✔️ CEF présent — 📋 **Vague 3** : Error / timeouts collecteurs |
| Profil machine (Workstation/Serveur/PAW) | 📋 **Vague 3** |

---

## D. Vague 4 — livré ✅

| Item | Collecteur / fix |
|---|---|
| Signatures Authenticode + ghost binaries (A5) | `PersistenceSignatureCollector` |
| WDAC base/supplemental Audit·Enforce (B) | `WdacDetailCollector` (CiTool + fallback) |
| ACL Tasks + chemins utilisateur (B) | `ScheduledTaskAclCollector` |
| Fiabilisation bug-review | N5 DoHPolicy=1, N3-bis skip, H2-bis ZIP/dossier, timeouts 120/180, ACL composites, CiTool deadlock, etc. |

## E. Vague 3 — backlog restant

| Item | Notes |
|---|---|
| Historique check-à-check / hash JSON (M7) | Vrai diff entre deux scans |
| CEF + Error / échecs modules (L2) | Export SIEM complet |
| WSL / conteneurs / nested virt (A9) | Collecteur optionnel poste dev |
| EPA / tunnels IPv6 détaillés / RPC RestrictRemoteClients (A10) | Relay / spoofing (IPv6 partiel déjà dans NetworkSec) |
| PSRemoting endpoints, Office COM Add-ins | Compléments A3 / B |
| Approfondir Tasks (profondeur > 1) + timeout Signatures/WDAC | Fiabilisation post Vague 4 |

> **CisFallback (M6)** : clé registre absente = `Warning` — **choix de conception** (policy non déployée = écart).

> Détail bugs ouverts : voir [`BUG_REVIEW.md`](../BUG_REVIEW.md) — notamment **H-AUDIT** (lookup GUID vs nom auditpol).

---

> Roadmap issue d'une revue croisée multi-IA de la [liste des 664 contrôles](CHECKS.md). Contributions bienvenues via [Issues](https://github.com/ayinedjimi/WinCheckSec/issues) / [Discussions](https://github.com/ayinedjimi/WinCheckSec/discussions).
