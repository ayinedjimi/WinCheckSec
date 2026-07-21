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
| Mode Diff / régression entre 2 scans | ✔️ Historique présent — 📋 diff détaillé check-à-check |
| Corrélation de chaînes d'attaque | 📋 vague 3 |
| Export **SARIF** (CI/CD) | ✅ livré (`--format sarif` + UI) |
| Profil machine (Workstation/Serveur/PAW) | 📋 |

> **Correctifs bug-review (v6.2.1+)** : H1 timeout, H3 LAPS, H4 User Rights, H5 score N/A/Error, M5 PS longueur — corrigés. M1 DoH consolidé, M2 PowerShellCollector mort supprimé, M4 Secure Boot harmonisé, M8 CSV RFC 4180, M9 enum DoH — corrigés.

---

> Roadmap issue d'une revue croisée multi-IA de la [liste des 664 contrôles](CHECKS.md). Contributions bienvenues via [Issues](https://github.com/ayinedjimi/CHECKSEC/issues) / [Discussions](https://github.com/ayinedjimi/CHECKSEC/discussions).
