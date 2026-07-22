# CHECKSEC — Bug Review (3ᵉ passe — post `d7b10e1`)

**Date :** 2026-07-22  
**Base :** commit `d7b10e1` (*Fix re-audit : regressions R1-R8 + N1-N3 + H2*)  
**Périmètre :** `c:\CHECKSEC\src`  
**Objectif :** vérifier absences de régressions, nouveaux bugs, fiabilité / collecteurs manquants.

**Choix produit acceptés (hors scope correctif) :**
- **M6** CisFallback : clé absente = Warning — *policy non déployée = écart* (conception volontaire).
- **M7** historique check-à-check, **L2** CEF+Error, collecteurs roadmap (WSL, signatures persistance, EPA/IPv6, WDAC détaillé) → **Vague 3** (`docs/ROADMAP.md`).

---

## Résumé exécutif

| Domaine | Verdict |
|---|---|
| Correctifs R1–R8 / N1–N3 / H2 | **Validés** — pas de régression majeure sur le périmètre annoncé |
| Nouveau bug | **DoHPolicy = 1 (Prohibit)** mal étiqueté « Non configuré » / Info |
| Résidus mineurs | N3 gonfle encore légèrement le % MSCT ; Mitre `WiFi` trop large ; toolkit = fichier ZIP ou baseline dézippée non gérés |
| Collecteurs manquants | Reportés Vague 3 (OK) ; couverture actuelle = **59** collecteurs enregistrés |

---

## 1. Vérification des correctifs `d7b10e1`

| ID | Attendu | Statut | Notes |
|---|---|---|---|
| **R1** message timeout | « Timeout 120s » | ✅ | `AnalysisService.cs` |
| **R2** LAPS fantôme Additional | retiré | ✅ | Délégué WindowsLaps + Laps legacy |
| **R3/M10** User Rights Gaps | skip (pas de gap fantôme) | ✅ | `continue` si `UserRightsAssignment` — vérité = `UserRightsCollector` |
| **R4** DoHPolicy | réintégré | ✅ *avec bug N5* | Voir §2 |
| **R5** ScorePercent | exclut Error | ✅ | `Total - Info - Error` |
| **R6** libellé EventLog | mots-clés seuls | ✅ | |
| **R7/M3** CLM | registre Session Manager | ✅ | `Info` si non forcé (ne pollue pas le score) |
| **R8** code mort LAPS | supprimé | ✅ | |
| **N1** Mitre | mots génériques retirés | ✅ | `RequireAlso` OK pour Kerberos+chiffrement |
| **N2** SARIF | Gaps MSCT + fingerprints | ✅ | |
| **N3** SecurityOption hors registre | non-écart | ✅ *nuance* | `IsCompliant=true` plutôt que skip → léger gonflement % (voir §3) |
| **H2** toolkit externe prioritaire | oui | ✅ *limites* | Voir §3 |

---

## 2. Nouveau bug

### N5 — DoHPolicy = 1 (Prohibit DoH) mal classé — **moyenne**

**Fichier :** `DnsOverHttpsCollector.cs` ~L135–148  

Valeurs Microsoft officielles :
| Valeur | Sens |
|---|---|
| **1** | **Prohibit DoH** (interdit le chiffrement DNS) |
| 2 | Allow DoH |
| 3 | Require DoH |

Code actuel : `1` tombe dans `_ => "Non configuré"` + `SecurityStatus.Info`.

**Impact :** une GPO (ou VPN) qui **interdit** DoH est rapportée comme absente / neutre — **faux négatif** de posture.  
**Correctif :** `1 => Warning` (ou Critical) + libellé « DoH interdit (Prohibit) ».

---

## 3. Résidus / risques résiduels (pas des régressions bloquantes)

### N3-bis — SecurityOption manuelles comptées « conformes »
- User Rights : **skip** (n’entrent pas dans le dénominateur MSCT).  
- SecurityOption hors HKLM/HKCU : **`IsCompliant = true`** → entrent dans `CountCompliant` et **gonflent** le taux.  
- Amélioration cohérente : `continue` comme pour User Rights, ou statut dédié « non évalué » exclu du %.

### H2-bis — Toolkit externe : cas non couverts
- `FindBaselineZip()` exige un **répertoire** ; si Settings pointe vers un **fichier `.zip`**, `File.Exists` ouvre le chemin externe puis échoue → fallback embarqué.  
- Baseline **déjà extraite** (pas de ZIP, dossiers GPO) : non détectée → fallback embarqué.  
Impact : H2 fonctionne pour le cas nominal (dossier MSCT contenant un ZIP Baseline).

### Mitre — `WiFi` encore large (faible)
- Règle `WiFi | réseau ouvert | …` : le mot **`WiFi` seul** mappe **tous** les contrôles WiFi vers T1557, pas seulement les réseaux ouverts.  
- Idem `"LSA"` peut ajouter T1547.005 à côté de T1003.001 sur « LSA Protection » (double mapping bénin).

### SecurityScore edge case (faible)
- Catégorie **uniquement** Error (+Info) → `applicable == 0` → **ScorePercent = 100**. Rare.

---

## 4. Pas de régression constatée sur

- Timeout 120 s + message aligné  
- DoH unique (`DnsOverHttpsCollector`) + EnableAutoDoh  
- LAPS (plus de faux Warning Additional)  
- Secure Boot canonique  
- Score global / catégorie alignés (Error exclus)  
- CSV RFC 4180, SARIF Gaps+fingerprints, Integrity JSON  
- Suppression code mort LAPS / PowerShellCollector mort  

---

## 5. Fiabilisation — état

| Amélioration | État |
|---|---|
| Timeout collecteurs lourds | ✅ |
| Score sans N/A / Error | ✅ |
| MSCT externe prioritaire | ✅ (limites H2-bis) |
| DoH consolidé + GPO | ✅ (fix N5) |
| CLM via registre | ✅ |
| Mitre resserré | ✅ (WiFi à affiner) |
| SARIF CI-friendly | ✅ |
| CisFallback clé absente = Warning | ✅ **choix M6 accepté** |

---

## 6. Collecteurs / features manquants

**Hors scope immédiat** — Vague 3 (confirmé avec toi / à refléter dans ROADMAP) :

| Item | Priorité Vague 3 |
|---|---|
| Historique diff check-à-check (M7) | P1 |
| CEF : Error + modules en échec (L2) | P2 |
| WSL / conteneurs (A9) | P1 |
| Signatures Authenticode persistance (A5) | P1 |
| EPA / IPv6 tunnels / RPC (A10) | P1 |
| WDAC base vs supplemental / Enforce (B) | P1 |
| PSRemoting endpoints (A3) | P2 |
| Office COM Add-ins, Tasks ACL, etc. | P2 |

**Couverture actuelle :** 59 collecteurs dans `BuildCollectors()` — pas de fichier collecteur orphelin majeur (PowerShellCollector retiré volontairement ; CLM compensé).

---

## 7. Plan d’action court

1. **Corriger N5** — `DoHPolicy == 1` → Prohibit / Warning.  
2. **Optionnel N3-bis** — skip SecurityOption non-registre (comme User Rights).  
3. **Optionnel H2-bis** — accepter un path ZIP fichier ; parser dossier déjà extrait.  
4. **Optionnel Mitre** — exiger « ouvert/open network » pour WiFi → T1557 ; retirer `"LSA"` seul.  
5. **Vague 3** — M7, L2 CEF, WSL, signatures, EPA/IPv6, WDAC.

---

*Revue statique. N5 confirmé contre la doc Microsoft DoHPolicy (1=Prohibit, 2=Allow, 3=Require).*
