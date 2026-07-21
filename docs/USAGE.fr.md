# Guide d'utilisation — CHECKSEC 🇫🇷

## Démarrage
1. Lancez `CHECKSEC.exe` (double‑clic) et acceptez l'invite **UAC** — l'analyse a besoin des droits administrateur pour lire la configuration système.
2. Le badge en haut à droite affiche la version et **`Admin`** (vert) confirmant l'élévation. S'il affiche **`NON‑ADMIN`** (rouge), l'analyse sera incomplète.

## Les onglets
| Onglet | Contenu |
|---|---|
| **Tableau de bord** | Score global (0‑100) + grade, boutons *Lancer l'analyse* / *Annuler* / *Exporter*. |
| **Secure Core** | Tuiles des protections matérielles : VBS, Credential Guard, HVCI, DMA Protection, Secure Boot, TPM — **état réel (running)**. |
| **Résultats Sécurité** | Tous les contrôles, avec filtres (OK/Warning/Critical) et recherche. |
| **Écarts MSCT** | Différences vs baseline Microsoft (attendu / actuel / sévérité). |
| **Benchmark CIS** | Conformité aux contrôles CIS. |
| **Remédiation** | Plan d'actions priorisé, avec commandes de correction. |
| **Journaux** | Événements de sécurité et erreurs système. |
| **Historique** | Comparaison d'analyses successives. |
| **Système** | Informations machine (OS, TPM, BIOS, réseau…). |

## Exports
Bouton **Exporter** → choisissez le format :
- **JSON** (forensique complet, hash SHA‑256, `AnalysisLog`) — également sauvegardé automatiquement sur le **Bureau**.
- **CSV**, **TXT**, **PDF**, **Excel**, **HTML**, **CEF** (SIEM).

## Mode ligne de commande (headless)
```powershell
CHECKSEC.exe --headless --output rapport.json --format json
CHECKSEC.exe --headless --output events.cef --format cef
```
Code de sortie : `0` = aucun problème critique · `2` = warnings · `3` = critiques présents.

## Vérifier l'intégrité d'un rapport JSON
Le bloc `Integrity` contient un **SHA‑256** calculé sur tout le rapport *sans* ce bloc. Pour vérifier : retirez `Integrity`, re‑sérialisez à l'identique (indentation), et comparez le hash.

## Raccourcis clavier
`Ctrl+1..8` naviguent entre les onglets · `F5` rafraîchit · `Ctrl+E` exporte.
