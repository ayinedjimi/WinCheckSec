# CHECKSEC — Bug Review (re-audit post-correctifs)

**Date :** 2026-07-21 (2ᵉ passe)  
**Base :** commits `44cd02f` (H1–H5 + M5) et `8df6b77` (Vague 2 : MITRE/SARIF + M1/M2/M4/M8/M9)  
**Périmètre :** `c:\CHECKSEC\src`  
**Objectif :** vérifier les correctifs, détecter **régressions** et **nouveaux bugs**.

---

## Résumé exécutif

| Domaine | Verdict |
|---|---|
| Correctifs H1–H5 / M1 / M4 / M5 / M8 / M9 | **Globalement OK**, avec quelques **oublis / régressions** listés ci-dessous |
| Nouveautés Vague 2 (MITRE, SARIF) | Utiles, mais MITRE trop large → **faux mappings** ; SARIF OK avec limites |
| Problèmes encore ouverts | H2 (MSCT embarqué), LAPS fantôme dans AdditionalSecurity, DOHPolicy perdu, score catégorie vs global |
| Stubs / fake | `AnalyzeUserRights` = toujours conforme (choix volontaire) ; code mort `CollectWindowsLaps` |

---

## 1. Statut des bugs du review précédent

| ID | Statut | Preuve / nuance |
|---|---|---|
| **H1** timeout 30s | **Corrigé** (120s) | **Régression mineure :** message d’erreur encore `"Timeout 30s"` (`AnalysisService.cs` ~L159) |
| **H2** MSCT embarqué prioritaire | **Toujours ouvert** | `MsctToolkitParser.ParseAsync` retourne encore l’embarqué si `Count > 0` — toolkit externe mort |
| **H3** LapsCollector mauvais chemin | **Corrigé** (appel retiré) | **Régression / dette :** méthode `CollectWindowsLaps` + constante `WindowsLapsKey` **toujours présentes** (code mort). **H3-bis :** même mauvais chemin encore dans `AdditionalSecurityCollector` (~L654) |
| **H4** faux écarts User Rights MSCT | **Corrigé** (plus de faux Gaps) | **Régression produit :** `IsCompliant = true` **toujours** → page Écarts MSCT **masque** les User Rights non conformes trouvés par `UserRightsCollector` (double vérité inversée) |
| **H5** N/A / Error dans le score | **Corrigé** pour le **score global** | **Incomplet :** `SecurityScore.ScorePercent` = `TotalChecks - InfoChecks` → les **Error** restent dans le dénominateur des scores **par catégorie** |
| **M1** DoH ×3 | **Corrigé** (une source) | **Régression couverture :** check **DOHPolicy** (GPO) retiré de NetworkSec et **non repris** dans `DnsOverHttpsCollector` |
| **M2** PowerShellCollector mort | **« Corrigé » par suppression** | **Régression couverture :** plus de Constrained Language Mode / checks PS dédiés ; seulement `AdditionalSecurity` (ExecutionPolicy, ScriptBlock, Module, Transcription, PSv2) |
| **M3** CLM via env var | **N/A** (fichier supprimé) | Problème disparu avec le collecteur — CLM **non couvert** |
| **M4** Secure Boot dual | **Corrigé** | Vbs → `Info` ; source canonique SecureBootPolicyCollector |
| **M5** heuristique longueur PS | **Corrigé** | **Oubli :** texte UI encore `"longueur > 350 ou mots-clés"` (`EventLogExtendedCollector` ~L248) |
| **M6** CisFallback clé absente = Warning | **Toujours ouvert** | Non traité dans les commits |
| **M7** Historique incomplet | **Toujours ouvert** | Non traité |
| **M8** CSV dashboard | **Corrigé** | `CsvField` RFC 4180 + colonne Statut |
| **M9** DoH enum | **Corrigé** | `dohStatus != SecurityStatus.OK` |
| **M10** pipelines User Rights | **Partiel** | Gaps ne polluent plus, mais **ne reflètent plus** non plus l’état réel |

---

## 2. Régressions introduites par les correctifs

### R1 — Message timeout trompeur (faible)
- **Fichier :** `AnalysisService.cs` ~L148–159  
- Timeout réel = **120 s**, message = `"Temps d'exécution dépassé (Timeout 30s)."`  
- Impact : diagnostic / support trompeur.

### R2 — LAPS toujours faux Warning via AdditionalSecurity (haute)
- **Fichier :** `AdditionalSecurityCollector.cs` ~L654–665  
- Lit encore `SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config`  
- H3 corrigé dans `LapsCollector`, **reproduit** ici → machine avec LAPS GPO/MDM (`Policies\LAPS`) peut afficher `Windows LAPS (v2)=False` + Warning alors que `WindowsLapsCollector` est OK.

### R3 — User Rights MSCT toujours « conformes » (moyenne–haute)
- **Fichier :** `GapAnalyzer.AnalyzeUserRights`  
- `IsCompliant = true` systématique pour éviter les faux écarts.  
- Impact : taux de conformité MSCT **gonflé** ; un admin qui ne regarde que la page Gaps **ne voit pas** SeDebugPrivilege etc. en échec (visibles seulement dans Résultats / collecteur).  
- Correctif souhaitable : mapper les Gaps vers les `SecurityResult` de `UserRightsCollector`, ou marquer `Info` / « reporté ailleurs » sans compter comme conforme.

### R4 — Perte du contrôle DOHPolicy GPO (moyenne)
- Consolidation M1 a retiré EnableAutoDoh **et** DOHPolicy de NetworkSec.  
- `DnsOverHttpsCollector` ne lit que `EnableAutoDoh` + `DohFlags`.  
- Impact : politique machine `DOHPolicy` (souvent le vrai levier GPO) **plus évaluée**.

### R5 — Score catégorie ≠ score global (moyenne)
- Global : exclut Info, N/A, **Error**.  
- Catégorie (`SecurityScore.ScorePercent`) : exclut Info (+ N/A via InfoChecks), **garde Error** dans `applicable`.  
- Impact : tuiles catégorie plus basses que le score global pour la même machine.

### R6 — Texte EventLog obsolète (faible)
- Filtre longueur retiré, libellé encore « longueur > 350 ou mots-clés ».

### R7 — Suppression PowerShellCollector (moyenne, couverture)
- Plus de CLM / checks PS avancés du fichier dédié.  
- Couverture restante = AdditionalSecurity uniquement (acceptable mais en retrait vs roadmap A3).

### R8 — Code mort LapsCollector (faible)
- `CollectWindowsLaps` + `WindowsLapsKey` jamais appelés → risque de réactivation accidentelle du bug H3.

---

## 3. Nouveaux bugs / risques (Vague 2)

### N1 — MitreMapper : faux positifs de mapping (moyenne)
Mots-clés trop génériques dans `MitreMapper.cs` :

| Mot-clé | Problème |
|---|---|
| `"Service"` | Matche presque tout check contenant « Service » → T1543.003 à tort |
| `"Office"` | Tout contrôle Office (pas seulement macros) → T1204.002 / T1059.005 |
| `"Print"` | Trop large vs PrintNightmare seul → T1068 |
| `"open"` | Sous-chaîne dangereuse (ex. « Open », chemins, etc.) → T1557 |
| `"RC4"` | Cipher Schannel → T1558 (Kerberos) incorrect |
| `"SSP"` | Peut matcher hors LSA SSP |
| `"NBT"` | Court, risque de collision |

Principe affiché (« en cas de doute, ne rien mapper ») **non respecté** pour ces règles larges. Contamine `MitreTechniques` JSON + `MitreSummary`.

### N2 — SARIF : limites (faible–moyenne)
- `SarifExportService` : OK minimal 2.1.0, `$schema` via rename string (fragile mais fonctionnel).  
- `SecurityStatus.Error` → niveau SARIF `"note"` (sous-sévérité pour échecs techniques / timeouts).  
- Pas d’écarts MSCT (`ComplianceGap`) dans le SARIF.  
- Pas de `partialFingerprints` / id stable par machine → bruit en CI entre runs.

### N3 — AnalyzeSecurityOption hors registre (inchangé, moyenne)
- Options `System Access` non-HKLM/HKCU : toujours `IsCompliant=false` + « vérification manuelle ».  
- Non traité par H4 (seulement User Rights). Contamine encore les Gaps MSCT.

### N4 — H2 MSCT toolkit (haute, inchangé)
- Baseline embarquée ~330 policies toujours prioritaire → path Settings ignoré.

---

## 4. Toujours ouverts (non régressions)

| ID | Sujet |
|---|---|
| M6 | CisFallback : clé absente → Warning scoré |
| M7 | HistoryService : pas de snapshot check-à-check / hash JSON |
| L2 | CEF sans Error / modules en échec |
| Manques roadmap | WSL, signatures persistance, EPA/IPv6, WDAC détail, scoring pondéré… |

---

## 5. Ce qui est solide après correctifs

- Timeout collecteur **120 s** (collecteurs lourds).  
- DoH **une seule** source (`DnsOverHttpsCollector`) + enum OK.  
- Secure Core Secure Boot **déterministe**.  
- CSV dashboard **RFC 4180**.  
- Score global **sans N/A ni Error technique**.  
- JSON unifié + Integrity + **MitreSummary** + export **SARIF** headless/UI.  
- Plus de faux écarts User Rights massifs dans Gaps.

---

## 6. Plan d’action priorisé (post re-audit)

1. **R2** — Corriger / retirer le check LAPS de `AdditionalSecurityCollector` (aligner sur `Policies\LAPS` ou déléguer à WindowsLapsCollector uniquement).  
2. **H2** — Toolkit externe prioritaire ; embarqué = fallback.  
3. **R3 / M10** — Bridger Gaps User Rights ↔ résultats secedit (pas `IsCompliant=true` aveugle).  
4. **R4** — Réintégrer `DOHPolicy` dans `DnsOverHttpsCollector`.  
5. **R5** — Aligner `SecurityScore.ScorePercent` sur la même règle que le score global (exclure Error).  
6. **N1** — Resserrer MitreMapper (supprimer Service/Office/Print/open génériques ; exiger phrases plus spécifiques).  
7. **R1 / R6 / R8** — Message 120s, texte M5, supprimer code mort LAPS.  
8. **N3 / M6 / M7** — SecurityOption manuelles en Info ; CisFallback ; historique enrichi.

---

## 7. Fichiers à relire en priorité

- `AdditionalSecurityCollector.cs` (LAPS)  
- `MsctToolkitParser.cs`  
- `GapAnalyzer.cs` (UserRights + SecurityOption)  
- `SecurityScore.cs` + `AnalysisService.ComputeCategoryScores`  
- `DnsOverHttpsCollector.cs` (DOHPolicy manquant)  
- `MitreMapper.cs`  
- `SarifExportService.cs`  
- `AnalysisService.cs` (message timeout)  
- `EventLogExtendedCollector.cs` (libellé M5)  
- `LapsCollector.cs` (code mort)

---

*Re-audit statique uniquement. Les commits indiquent une vérif machine réelle pour H1–H5 ; les items R2/R4/N1 n’étaient pas dans cette vérif.*
