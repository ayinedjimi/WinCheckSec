# CHECKSEC — Bug Review ultra-complet

**Date :** 2026-07-22  
**Base :** `9a50b0d` (Vague 4) + historique `d7b10e1` → `ab35b4b`  
**Périmètre :** tout le code source sous `c:\CHECKSEC\src` (UI + Core)  
**Méthode :** revue statique exhaustive — orchestration, 62 collecteurs, GapAnalyzer/MSCT/CIS, scoring, Mitre/SARIF/CEF/JSON, nouveaux modules Vague 4.

---

## Résumé exécutif

| Domaine | Verdict |
|---|---|
| Correctifs antérieurs (H1–H5, R1–R8, N1–N5, ACL composites, CiTool deadlock…) | **Globalement solides** |
| Vague 4 (+3 collecteurs) | **ROI élevé**, qualité correcte ; quelques limites de couverture |
| **Bug HAUTE** ouvert | Lookup audit MSCT par **GUID** → écarts audit **toujours « non configuré »** (régression Vague 4) |
| **Bug MOYENNE** | `ScheduledTaskAclCollector` profondeur 1 → rate la majorité des tâches `Microsoft\Windows\…` |
| **Bug MOYENNE** | Timeouts différenciés **n’incluent pas** Signatures / WDAC / Tasks ACL (risque timeout 120 s) |
| Stubs / fake | CisFallback semi-manuel (M6 accepté) ; pas de collecteur vide |
| Exports | JSON/SARIF **fiables** ; CEF encore sans Error ; Historique agrégé (Vague 3) |
| Collecteurs manquants | WSL, EPA/IPv6 détaillé, COM Add-ins, etc. (Vague 3) |

**Score de maturité estimé :** outil prêt pour audit terrain, avec **1 correctif urgent** (audit MSCT) avant confiance totale sur les écarts de conformité.

---

## A. Inventaire

### A.1 Orchestration
- `AnalysisService.BuildCollectors()` : **62** collecteurs via `TryAdd<>`
- Timeout : **120 s** défaut / **180 s** si nom contient Journ|Forensi|Inventaire|WiFi|Autoruns|Certificat
- Score global : exclut Info, NotApplicable, Error
- Score catégorie (`SecurityScore`) : `Total - Info - Error` (aligné)
- Secure Core : préférence lignes WMI/Running ; Secure Boot canonique

### A.2 Collecteurs enregistrés (62)

SystemInfo, VbsSecurity, Defender, SecurityCenter, Firewall, BitLocker, AppControl, NetworkSec, EventLog, AuditPolicy, UserAccounts, Tls, AdditionalSecurity, AutoRuns, ProcessDriver, NetworkShares, ScreenLock, OfficeMacro, SoftwareInventory, Kerberos, EventLogExtended, Mde, WindowsUpdateDetail, Certificate, AzureAd, Hardening, AsrRules, Laps, DnsOverHttps, SmbHardening, PrintSpooler, WDigest, LsaProtection, ExploitProtection, RdpHardening, CisFallback, UacDetail, CredentialDelegation, WindowsSandbox, Bluetooth, WifiSecurity, SecureBootPolicy, BrowserHardening, SystemHardeningExtra, RemoteAccessExtra, LocalGroup, LogConfig, NetworkServicesHardening, DomainAuthHardening, Amsi, ProxyNetwork, UserRights, WindowsLaps, ModernWindowsFeatures, AdvancedPersistence, DefenderExclusions, FileSystemAcl, BootIntegrity, SchannelCrypto, **PersistenceSignature**, **WdacDetail**, **ScheduledTaskAcl**.

### A.3 Exports
| Canal | Fiabilité |
|---|---|
| JSON (`ReportJsonBuilder`) | Haute — schéma unifié, Integrity SHA-256, Mitre, Diagnostics |
| SARIF 2.1.0 | Haute — findings + Gaps MSCT + partialFingerprints |
| CSV dashboard | Haute — RFC 4180 |
| Excel/PDF pages | Correcte — vue filtrée |
| CEF | Partielle — Critical/Warning/Gaps ; **pas Error ni modules timeout** |
| Historique | Faible forensique — agrégats uniquement (Vague 3) |

---

## B. Bugs ouverts (code actuel)

### Sévérité HAUTE

| ID | Localisation | Problème | Impact |
|---|---|---|---|
| **H-AUDIT** | `GapAnalyzer.AnalyzeAuditPolicy` | Lookup `auditPolicies[policy.ValueName]` alors que la baseline embarquée met des **GUID** (`{0cce923f-…}`) dans `ValueName`, et `auditpol /r` indexe par **nom de sous-catégorie** (`Credential Validation`). | **Tous** les contrôles Audit MSCT embarqués → `(non configuré)` / non conformes → **pollution massive des Gaps** + taux MSCT faux. Régression Vague 4 (« clé audit réelle » a empiré le cas embarqué). |

**Correctif recommandé :**  
`key = StripPrefix(policy.Section, "Audit ")` (ex. `"Audit Credential Validation"` → `"Credential Validation"`), avec fallback Section/ValueName ; ou table GUID→nom.

---

### Sévérité MOYENNE

| ID | Localisation | Problème | Impact |
|---|---|---|---|
| **M-TASKS-DEPTH** | `ScheduledTaskAclCollector` `MaxDepth = 1` | N’énumère que `Tasks\` + un niveau (`Tasks\Microsoft\…` fichiers directs). La majorité des tâches sont sous `Tasks\Microsoft\Windows\…` (profondeur ≥ 2). | Faux sentiment de propreté : synthèse « 0 à risque » alors que des tâches utilisateur/suspectes plus profondes ne sont **pas** vues. |
| **M-TIMEOUT-V4** | `AnalysisService.TimeoutFor` | Noms « Signatures de persistance », « WDAC… », « Tâches planifiées… » **hors** liste 180 s. | Jusqu’à 150× WinVerifyTrust / parcours Tasks → risque **Timeout 120 s** → module Error, scan partiel. |
| **M-DOUBLE-WDAC** | `AppControlCollector` + `WdacDetailCollector` | Deux modules scorent WDAC (présence vs détail). | Bruit / double pénalité ou double Info ; score Application Control dilué. Consolider ou marquer AppControl WDAC en Info quand WdacDetail OK. |
| **M-MITRE-LSA** | `MitreMapper` | Mot-clé `"LSA"` seul → T1547.005 en plus de T1003.001 sur « LSA Protection ». | Faux mapping ATT&CK bénin. |
| **M-SCORE-EMPTY** | `SecurityScore.ComputeScore` | `applicable == 0` → **100 %**. | Catégorie 100 % Error → grade A trompeur (rare). |

---

### Sévérité FAIBLE

| ID | Localisation | Problème |
|---|---|---|
| **L-PERSIST-SCOPE** | `PersistenceSignatureCollector` | Couvre Run/RunOnce, services non-MS, Winlogon — **pas** tâches planifiées / IFEO / COM (partiellement ailleurs). Cap 150. |
| **L-REVOKE** | WinVerifyTrust `WTD_REVOKE_NONE` | Pas de check révocation réseau — perf OK, certs révoqués récents peuvent passer Trusted. |
| **L-TASKS-ACL-FOLDER** | Tasks ACL | Dossier : seuls Delete/ChangePerm/TakeOwnership (volontaire vs défaut Write AuthUsers). CreateFiles sur **fichier** de tâche toujours dangereuse — OK. Documenter le trade-off. |
| **L-WDAC-FALLBACK-HVCI** | `WdacDetailCollector` fallback | Lit `HypervisorEnforcedCodeIntegrity\Enabled` comme signal voisin — ce n’est **pas** UMCI ; risque de confusion dans le raisonnement fallback (CiTool absent). |
| **L-CEF** | `CefExportService` | Pas d’événements `Error` ni `CollectorFailed`. |
| **L-HISTORY** | `HistoryService` | Pas de snapshot check-à-check. |
| **L-CONVERTERS** | Hex/DateTime `ConvertBack` | `NotImplementedException` (one-way OK). |

---

## C. Statut des bugs des reviews précédents

| ID | Statut |
|---|---|
| H1 timeout 30s → 120/180 | ✅ |
| H2 / H2-bis toolkit externe ZIP + dossier dézippé | ✅ |
| H3 LAPS mauvais chemin | ✅ |
| H4 / R3 User Rights Gaps | ✅ skip |
| H5 score N/A/Error | ✅ |
| N5 DoHPolicy=1 Prohibit | ✅ Warning |
| N3-bis SecurityOption non-registre | ✅ skip |
| N1 Mitre WiFi resserré | ✅ |
| ACL Modify/FullControl faux Critical | ✅ (FS + Tasks + Reg) |
| CiTool deadlock stdout/stderr | ✅ |
| WinVerifyTrust Win32→Error, rundll32, DestroyStructure | ✅ |
| MsctToolkitParser `=`/`,` DWORD | ✅ |
| M6 CisFallback clé absente = Warning | ✅ **choix produit** |
| M7 / L2 CEF Error / Vague 3 collectors | 📋 backlog |

---

## D. Revue des 3 collecteurs Vague 4

### D.1 `PersistenceSignatureCollector` — **Bonne**
- WinVerifyTrust + catalogue, ghost rooted vs relatif, rundll32 DLL, cap 150, synthèse claire.
- Limites : scope (pas Tasks/IFEO), timeout non heavy, révocation off.
- Pas de stub.

### D.2 `WdacDetailCollector` — **Bonne**
- CiTool JSON prioritaire ; Error explicite si échec ; fallback .cip + Error si dossier illisible.
- Base vs supplemental via PolicyID==BasePolicyID ; Audit→Warning, Enforce→Info/OK.
- Limites : double emploi avec AppControl ; fallback mode moins fiable.

### D.3 `ScheduledTaskAclCollector` — **Moyenne (couverture)**
- XML + ACL SID-invariants ; pas de schtasks localisé — excellent design.
- **Faiblesse majeure :** `MaxDepth=1` sous-échantillonne fortement.
- Recommandation : `MaxDepth=3` ou 4 + garder cap 200–500 ; ou BFS priorisant hors `Microsoft\Windows` puis échantillon.

---

## E. Fiabilité transverse des collecteurs

| Thème | État |
|---|---|
| Timeout / annulation | Bon (sauf liste heavy incomplète) |
| Error vs posture | Globalement respecté (WDAC, LAPS, ACL illisible→Info) |
| Doublons contradictoires | DoH/LAPS/SecureBoot OK ; WDAC encore double |
| Locale | WiFi XML, Tasks XML, secedit SID — bons ; auditpol noms encore sensibles à la langue |
| Running vs config | Secure Core OK ; à étendre (Tamper, NP…) |
| Admin required | UserRights, CiTool, certaines ACL — Error explicite |

---

## F. Code factice / placeholders

| Élément | Nature |
|---|---|
| `CisFallbackCollector` | Semi-automatique ; non-HKLM → Info ; clé absente → Warning (**M6**) |
| MSCT User Rights / SecurityOption non-registre | **Skip** (pas de faux conforme) |
| Baseline embarquée | Fallback légitime si toolkit externe vide |
| PowerShellCollector | **Supprimé** ; CLM via AdditionalSecurity (registre) |

---

## G. Collecteurs / features manquants (pertinents)

| Priorité | Item | Notes |
|---|---|---|
| P0 | **Fix H-AUDIT** | Avant tout nouveau module |
| P0 | Approfondir Tasks (`MaxDepth`) + timeout Signatures | Fiabilisation Vague 4 |
| P1 | WSL / Docker / nested virt | Roadmap A9 |
| P1 | EPA / LDAP signing+channel binding, IPv6 tunnels détaillés, RPC RestrictRemoteClients | A10 (IPv6 partiel existe) |
| P1 | Office COM Add-ins | ≠ macros |
| P2 | CEF Error + modules ; Historique diff ; profil Workstation/Server/PAW | Transverse |
| P2 | PSRemoting endpoints ; Firewall Any-Any listées ; Print drivers WHQL | B |
| P2 | Signatures aussi sur Tasks/IFEO (étendre PersistenceSignature) | Complément A5 |

---

## H. Plan d’action priorisé

1. **H-AUDIT** — mapper Section/GUID → nom subcategory auditpol (critique conformité MSCT).  
2. **M-TASKS-DEPTH** — augmenter profondeur + éventuellement prioriser hors Microsoft.  
3. **M-TIMEOUT-V4** — ajouter Signatures / WDAC / Tâches planifiées / EventLogExtended à la liste 180 s (ou timeout par type).  
4. **M-DOUBLE-WDAC** — réduire bruit AppControl vs WdacDetail.  
5. Mitre `"LSA"` → retirer ou RequireAlso.  
6. Vague 3 : WSL, EPA, historique, CEF Error.

---

## I. Ce qui est solide (ne pas casser)

- Score sans Error/N/A ; timeouts 120/180  
- Toolkit MSCT externe (ZIP fichier + dossier)  
- DoH unique + Prohibit=Warning  
- ACL sans composites Modify/FullControl  
- PersistenceSignature WinVerifyTrust + anti-faux-ghost  
- WdacDetail CiTool parallèle + Error droits  
- JSON Integrity + SARIF fingerprints + Mitre resserré WiFi  
- 62 collecteurs, couverture poste Windows très large  

---

*Revue 100 % statique. H-AUDIT vérifié contre `MsctBaselineData` (ValueName=GUID) et `GetAuditPolicies` (clé=nom subcategory auditpol).*
