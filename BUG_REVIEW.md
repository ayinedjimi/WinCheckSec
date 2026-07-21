# CHECKSEC — Bug Review approfondi

**Date :** 2026-07-21  
**Périmètre :** `c:\CHECKSEC\src` (CHECKSEC UI + CHECKSEC.Core)  
**Méthode :** revue statique du code source, inventaire des 60 collecteurs, chemins d’export, scoring, MSCT/CIS, croisement avec `AUDIT_CHECKSEC.md` et `docs/ROADMAP.md`.

> **Note :** plusieurs bugs listés dans `AUDIT_CHECKSEC.md` (H1–H5, M1–M8, M10, L1–L8, CisFallback, Secure Core) ont déjà été corrigés. Ce document se concentre sur l’**état actuel** du code.

---

## Résumé exécutif

| Domaine | Verdict |
|---|---|
| Collecteurs | ~59 enregistrés, 1 fichier mort (`PowerShellCollector`), implémentations réelles (pas de stubs vides) |
| Fiabilité détection | Problèmes **hauts** : timeout 30s, MSCT embarqué qui ignore le toolkit, LAPS chemin faux, DoH triple verdict, score pollué par Error/N/A |
| Code factice | `CisFallbackCollector` (partiel), `MsctBaselineData` hardcodé, MSCT User Rights / Security Options non vérifiés → faux écarts |
| Exports | JSON unifié **fiable** ; CSV dashboard fragile ; Historique incomplet ; CEF partiel ; PDF/Excel page-scoped OK |
| Collecteurs manquants | Voir section F (WSL, SARIF, signature persistance, EPA/IPv6, etc.) |

---

## A. Bugs confirmés (code actuel)

### Sévérité HAUTE

| ID | Localisation | Problème | Impact |
|---|---|---|---|
| **H1** | `AnalysisService.cs` ~L145 | Timeout **dur** de **30 s** par collecteur (`CancelAfter(30s)`), indépendant du timeout global | Collecteurs lourds (`EventLogExtended`, `SoftwareInventory`, `WifiSecurity`+netsh, `AutoRuns`+schtasks) peuvent être **coupés** → rapport incomplet présenté comme « terminé » |
| **H2** | `MsctToolkitParser.cs` L34–41 | `ParseAsync` retourne **toujours** les baselines **embarquées** si `Count > 0` (~330 policies) | Le chemin `MsctToolkitPath` / ZIP externe est **mort** en pratique → baseline figée, non alignée sur le toolkit réel de l’orga |
| **H3** | `LapsCollector.cs` L142 | Lit `...\LAPS\Config` | La config GPO/MDM réelle est sous `SOFTWARE\Microsoft\Policies\LAPS` (+ State) — déjà correctement lue par `WindowsLapsCollector`. **Faux Warning** « Windows LAPS non configuré » alors que LAPS natif est OK |
| **H4** | `GapAnalyzer.AnalyzeUserRights` + `AnalyzeSecurityOption` | User Rights MSCT : **toujours** `IsCompliant=false` ; options non-registre (`System Access`) : non évaluées → non conformes | Contamine la liste **Écarts MSCT** / score conformité alors que `UserRightsCollector` évalue vraiment via secedit |
| **H5** | `AnalysisService.ComputeCategoryScores` / `GlobalScore` | `NotApplicable` compté comme **Error** (catégories) ; Error + N/A entrent dans le dénominateur du score **sans** être OK/Warn/Crit | Machine sans WiFi (N/A) ou collecteur en Error **baisse artificiellement** le score global / catégorie |

### Sévérité MOYENNE

| ID | Localisation | Problème | Impact |
|---|---|---|---|
| **M1** | `NetworkSecCollector` + `DnsOverHttpsCollector` + `AdditionalSecurityCollector` | **Triple contrôle DoH** avec sévérités contradictoires pour `EnableAutoDoh=1` : Warning / Info / OK | Confusion UI, score incohérent, bruit dans les exports |
| **M2** | `PowerShellCollector.cs` | Collecteur **complet** (ExecutionPolicy, ScriptBlock, Transcription, Module logging, CLM) **non enregistré** dans `BuildCollectors()` | Fonctionnalité morte ; CLM / durcissement PS avancé absents du scan (sauf checks partiels ailleurs) |
| **M3** | `PowerShellCollector.CollectConstrainedLanguage` | CLM via `Environment.GetEnvironmentVariable("__PSLockdownPolicy")` dans le process WinUI | Même enregistré : **faux négatif systématique** (la var n’est typiquement pas injectée hors host PowerShell) — il faudrait WDAC/AppLocker/registre |
| **M4** | `SecureBootPolicyCollector` vs `VbsSecurityCollector` | Secure Boot absent/Legacy = **Warning** vs **Critical** selon le collecteur ; tuile Secure Core via `Contains("Secure Boot")` | Tuile dashboard / export SecureCore **non déterministe** selon l’ordre des résultats |
| **M5** | `EventLogExtendedCollector` ~L228 | Heuristique « suspect » = `Message.Length > 350` (après troncature 400) | Faux positifs massifs sur scripts légitimes longs ; faux négatifs si mots-clés hors des 400 premiers caractères |
| **M6** | `CisFallbackCollector` | Clé absente → `evaluated=true`, `Warning` (« Non défini ») | Faux écarts CIS scoré pour policies jamais déployées (intentionnel ? mais pollue le score) |
| **M7** | `HistoryService.SaveSnapshot` | Ne persiste que score + totaux + catégories + SecureCore | **Pas de diff réel** check-à-check ; régression silencieuse impossible à auditer |
| **M8** | `DashboardViewModel.BuildCsvReport` | CSV 3 colonnes, échappement naïf (`;` → `,`), pas de quotes RFC 4180 | Champs avec `;`/guillemets/newlines **cassent** le CSV ; pas de Statut / Attendu / Reco |
| **M9** | `DnsOverHttpsCollector` L107 | `dohStatus != 0` compare un **enum** à un int | Fragile si l’ordre des enum change ; logique de recommandation opaque |
| **M10** | `GapAnalyzer` vs `UserRightsCollector` | Deux pipelines User Rights non reliés | MSCT Gaps ≠ résultats collecteur → double vérité |

### Sévérité FAIBLE

| ID | Localisation | Problème |
|---|---|---|
| **L1** | `HexToBrushConverter` / `DateTimeConverter` | `ConvertBack` → `NotImplementedException` (converters one-way — OK sauf binding TwoWay) |
| **L2** | `CefExportService` | N’exporte que Critical + Warning + Gaps non conformes — pas Error / Info / modules en échec |
| **L3** | `ReportJsonBuilder` Integrity | Hash SHA-256 du corps sans `Integrity` — re-vérifiable seulement avec **mêmes** `JsonSerializerOptions` / ordre Dictionary ; peu documenté pour les consommateurs |
| **L4** | `AzureAdCollector.RunDsregCmd` | `catch (Exception) { }` vide → map vide = fallback registre silencieux (acceptable mais opaque) |
| **L5** | `AdditionalSecurityCollector` LAPS | Check LAPS simplifié en plus de `LapsCollector` + `WindowsLapsCollector` → 3ᵉ source de vérité |
| **L6** | Exports Excel/PDF Results/Gaps/CIS | Exportent `FilteredResults` (filtre UI) — OK si voulu, mais **pas** un dump exhaustif ; risque de confusion |
| **L7** | `WifiSecurityCollector` | Export `key=clear` bien nettoyé en `finally` — OK ; mais timeout netsh 20s + timeout collecteur 30s = marge faible |
| **L8** | `App` headless exit code | Exit 1 si Error, 2 Warning, 3 Critical — Error « technique » (timeout) peut masquer un scan partiel en CI |

---

## B. Stubs, fake code, placeholders

| Élément | Nature | Commentaire |
|---|---|---|
| `CisFallbackCollector` | Semi-fake | Contrôles sans `Set HKLM\` → `SecurityStatus.Info` (« Vérification manuelle ») — **correct** (n’affecte plus le score). Contrôles HKLM absents → Warning réel. Libellé `[Automated fallback attempt]` encore présent |
| `MsctBaselineData` / `ParseFromEmbeddedData` | Baseline **hardcodée** (~330 policies) | Pas un stub, mais **données figées** qui court-circuitent le toolkit externe |
| `GapAnalyzer.AnalyzeUserRights` | Placeholder explicite | `CurrentValue = "(vérification via secedit requise)"`, toujours non conforme — alors que secedit est déjà fait ailleurs |
| `GapAnalyzer.AnalyzeSecurityOption` (hors HKLM/HKCU) | Semi-placeholder | `"(vérification manuelle requise)"` + non conforme |
| `PowerShellCollector` | Code **mort** (non branché) | Fichier réel, jamais invoqué |
| Converters `ConvertBack` | Stub technique | Standard XAML |
| Placeholders XAML (`PlaceholderText=`) | UI uniquement | Pas des stubs fonctionnels |

**Pas trouvé :** `throw new NotImplementedException` dans la logique métier des collecteurs, ni collecteur retournant uniquement des listes vides hardcodées « OK ».

---

## C. Fiabilité des collecteurs (synthèse)

### Inventaire enregistrés (`BuildCollectors`)

59 collecteurs via `TryAdd<>` : SystemInfo, VbsSecurity, Defender, SecurityCenter, Firewall, BitLocker, AppControl, NetworkSec, EventLog, AuditPolicy, UserAccounts, Tls, AdditionalSecurity, AutoRuns, ProcessDriver, NetworkShares, ScreenLock, OfficeMacro, SoftwareInventory, Kerberos, EventLogExtended, Mde, WindowsUpdateDetail, Certificate, AzureAd, Hardening, AsrRules, **Laps**, **DnsOverHttps**, SmbHardening, PrintSpooler, WDigest, LsaProtection, ExploitProtection, RdpHardening, CisFallback, UacDetail, CredentialDelegation, WindowsSandbox, Bluetooth, WifiSecurity, SecureBootPolicy, BrowserHardening, SystemHardeningExtra, RemoteAccessExtra, LocalGroup, LogConfig, NetworkServicesHardening, DomainAuthHardening, Amsi, ProxyNetwork, UserRights, **WindowsLaps**, ModernWindowsFeatures, AdvancedPersistence, DefenderExclusions, FileSystemAcl, BootIntegrity, SchannelCrypto.

### Points de non-fiabilité transverses

1. **Timeout 30 s** (H1) — principal risque de faux « Success=false » / résultats partiels.
2. **Doublons / contradictions** : DoH ×3, LAPS ×2–3, Secure Boot ×2, Print Spooler (dédié + Additional), HVCI/CredGuard (Vbs + Additional).
3. **Élévation admin** : `UserRights` (secedit), certains EventLogs, WiFi export — échec → Error (bien), mais score pénalisé (H5).
4. **Locale** : schtasks corrigé (OEM + plus de filtre Ready/Running) ; WiFi basé XML (bon) ; auditpol/libellés encore potentiellement sensibles à la langue selon chemins.
5. **Heuristiques bruitées** : EventLog PS longueur > 350 ; SoftwareInventory matching sous-chaîne (amélioré mais fragile) ; AdvancedPersistence KnownDLLs « Info » (FP documentés).

### Collecteurs récents (vague 1) — qualité

| Collecteur | Fiabilité | Notes |
|---|---|---|
| `AmsiCollector` | Bonne | Providers + disable keys ; note explicite « pas de hook mémoire » |
| `UserRightsCollector` | Bonne | secedit Unicode, SID invariants ; Error explicite si échec |
| `WindowsLapsCollector` | Bonne | Policy + State ; détection legacy |
| `LapsCollector` | **Faible** sur LAPS natif | Mauvais chemin Config (H3) |
| `WifiSecurityCollector` | Bonne | XML + nettoyage PSK ; N/A si pas de WiFi |
| `BootIntegrityCollector` | Bonne | Blocklist BYOVD + bcdedit |
| `SchannelCryptoCollector` | Bonne | FIPS neutre (Info), ciphers faibles, certs |
| `FileSystemAclCollector` | Bonne | SID invariants Users/Everyone/Authenticated |
| `AdvancedPersistenceCollector` | Moyenne | Couverture utile ; FP possibles sur Print Monitors / KnownDLLs |
| `DefenderExclusionsCollector` | Bonne | Complète Defender |
| `ProxyNetworkCollector` | Moyenne | Best-effort WMI |
| `ModernWindowsFeaturesCollector` | Bonne | Recall, Quick Assist, Sudo, Dev Mode |
| `CisFallbackCollector` | Moyenne | Info pour non-évalués ; Warning pour clés absentes |

---

## D. Collecteurs / contrôles manquants (pertinents)

D’après `ROADMAP.md` + absences réelles dans `BuildCollectors` :

| Priorité | Manque | Pourquoi |
|---|---|---|
| **P0** | Brancher `PowerShellCollector` (+ corriger détection CLM) | Déjà codé, non livré |
| **P0** | Relier MSCT User Rights → `UserRightsCollector` | Éliminer faux Gaps (H4) |
| **P1** | WSL / Docker / nested virt | Surface attaque poste dev (roadmap A9) |
| **P1** | Signature Authenticode des persistance | Autoruns sans réputation binaire (A5) |
| **P1** | WDAC base vs supplemental / Enforce | AppControl partiel (B) |
| **P1** | EPA (LDAP/RDP), tunnels IPv6, NetBIOS global, RPC RestrictRemoteClients | Relay/spoofing (A10) |
| **P2** | Office COM Add-ins | Distinct des macros (B) |
| **P2** | Scheduled Tasks ACL (`\System32\Tasks` writable) | EoP classique (B) |
| **P2** | Exploit Protection mitigations **par processus** (XML) | Collecteur global existant insuffisant |
| **P2** | Export **SARIF** | CI/CD (roadmap C) |
| **P2** | Scoring pondéré Critique/Élevé + MITRE ATT&CK | Roadmap C |
| **P2** | Profil machine Workstation/Serveur/PAW | Pondération sévérité |

---

## E. Fiabilité des exports de résultats

| Format / chemin | Fiabilité | Détail |
|---|---|---|
| **JSON** (`ReportJsonBuilder`) | **Bonne** | Schéma unifié UI + headless ; `SchemaVersion`, Host, Execution, SecureCore, CIS, Gaps, Modules+CollectedAt, Diagnostics, AnalysisLog, **SHA-256** |
| **CSV Dashboard** | **Faible** | 3 colonnes, pas de statut, échappement insuffisant (M8) |
| **CSV Results/Gaps/CIS pages** | **Correcte** | Quotes + doublement `""`, BOM UTF-8, séparateur configurable |
| **Excel / PDF** (pages) | **Correcte** | Contenu = vue filtrée ; fallback Bureau si picker échoue |
| **HTML** (`HtmlReportService`) | Correcte | En-tête Description MSCT corrigé |
| **CEF** | Partielle | Pas d’Error, pas de contexte d’échec collecteur, pas de score détaillé par module |
| **Historique** | **Faible** pour forensique | Snapshot agrégé seulement (M7) |
| **UnifiedReportService** (PDF global) | Présent | Dépend de QuestPDF ; à valider en runtime (non exécuté ici) |

### Incohérences export ↔ UI

- Score global JSON = `GlobalScore` (pénalisé par Error/N/A) vs badges Results (Info exclus du TotalCount après correctif M9).
- CEF / remédiation n’incluent pas les modules en timeout (ErrorMessage collecteur).
- Historique ne permet pas de reconstituer un rapport JSON complet d’un run passé.

---

## F. Bugs de l’ancien audit — statut

| Ancien ID | Statut actuel |
|---|---|
| H1 schtasks locale/encoding | **Corrigé** |
| H2 WQL PasswordAge | **Corrigé** (`Win32_NetworkLoginProfile`) |
| H3 ActiveX ternaire | **Corrigé** |
| H4 NormalizeVersion boucle infinie | **Corrigé** |
| H5 SecurityOption always compliant | **Corrigé** (désormais non conforme si non vérifiable — crée H4 actuel côté Gaps) |
| M1–M8, M10, L1–L8, CisFallback D, Secure Core B4 | **Corrigés** (vérifiés dans le code) |
| Wifi absent | **Corrigé** (`WifiSecurityCollector` enregistré) |
| Export JSON divergent headless | **Corrigé** (`ReportJsonBuilder`) |

---

## G. Plan d’action recommandé

1. **H1** — Timeout collecteur configurable (ex. 90–120 s pour EventLog/Software/Wifi) ou par collecteur.  
2. **H2** — Prioriser toolkit externe si path valide ; embarqué = fallback uniquement.  
3. **H3** — Aligner `LapsCollector` sur Policy/State ou supprimer la branche Windows LAPS du legacy collector.  
4. **H4** — Brancher `AnalyzeUserRights` sur les résultats secedit / ne plus émettre de Gap non vérifié comme non conforme scoré.  
5. **H5** — Exclure `NotApplicable` (et idéalement `Error` technique) du dénominateur de score ; ne pas mapper N/A → Error.  
6. **M1** — Un seul collecteur DoH (ou une seule sévérité canonique).  
7. **M2/M3** — `TryAdd<PowerShellCollector>()` + détection CLM via WDAC/registre.  
8. **M7/M8** — Historique : sauver hash JSON complet ou delta ; CSV dashboard = même Esc que ResultsPage.  
9. Roadmap P1 : WSL, signatures persistance, EPA/IPv6.

---

## H. Fichiers clés à relire en priorité

- `CHECKSEC/Services/AnalysisService.cs` — orchestration, timeout, scoring, Secure Core  
- `CHECKSEC.Core/.../Analysis/MsctToolkitParser.cs` + `MsctBaselineData.cs` + `GapAnalyzer.cs`  
- `CHECKSEC.Core/.../Collectors/LapsCollector.cs` vs `WindowsLapsCollector.cs`  
- `CHECKSEC.Core/.../Collectors/PowerShellCollector.cs` (non branché)  
- `CHECKSEC/Services/ReportJsonBuilder.cs`, `HistoryService.cs`, `CefExportService.cs`  
- `CHECKSEC/ViewModels/DashboardViewModel.cs` — export CSV  

---

*Rapport généré par revue de code statique — non exécuté contre une machine cible. Les sévérités reflètent l’impact sur la fiabilité d’un audit de sécurité automatisé.*
