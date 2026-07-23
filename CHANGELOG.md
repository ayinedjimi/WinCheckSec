# Changelog — WinCheckSec

🇫🇷 Toutes les évolutions notables du projet. · 🇬🇧 All notable changes to the project.

Le format s'inspire de [Keep a Changelog](https://keepachangelog.com/). / Format inspired by [Keep a Changelog](https://keepachangelog.com/).

---

## v6.5.0 — 2026-07-23

**🇫🇷 Rebranding + build autonome**
- Le projet **CHECKSEC** devient **WinCheckSec** ; le binaire portable est désormais `WinCheckSec.exe`.
- Nom mis à jour partout : fenêtre, badge, boîtes UAC, en-têtes PDF/HTML/Excel/CEF, nom d'outil JSON et SARIF, URL du dépôt.
- Lancement du **compagnon macOS** : [MacSecCheck](https://github.com/ayinedjimi/MacSecCheck).

**🇬🇧 Rebranding + self-contained build**
- **CHECKSEC** is now **WinCheckSec**; the portable binary is now `WinCheckSec.exe`.
- Name updated everywhere: window, badge, UAC dialogs, PDF/HTML/Excel/CEF headers, JSON & SARIF tool name, repo URL.
- Launched the **macOS companion**: [MacSecCheck](https://github.com/ayinedjimi/MacSecCheck).

## v6.4.1 — 2026-07-22

**🇫🇷** Build **100 % autonome** : runtime Visual C++ embarqué dans le single-file (`IncludeAllContentForSelfExtract`). Plus aucune dépendance externe. README FR/EN : décompte porté à 62 collecteurs.
**🇬🇧** **Fully self-contained** build: Visual C++ runtime embedded in the single-file. No external dependency left. FR/EN README: collector count bumped to 62.

## v6.4.0 — 2026-07-22

**🇫🇷** +3 collecteurs P0/P1 et fiabilisation générale (bug review).
**🇬🇧** +3 P0/P1 collectors and general reliability hardening (bug review).

## v6.3.0 — 2026-07-21

**🇫🇷** Mapping **MITRE ATT&CK** par contrôle + export **SARIF 2.1.0** (CI/CD).
**🇬🇧** Per-control **MITRE ATT&CK** mapping + **SARIF 2.1.0** export (CI/CD).

## v6.2.0 — 2026-07-21

**🇫🇷** 59 collecteurs, 756 contrôles, baselines MSCT & CIS, rapports signés SHA-256.
**🇬🇧** 59 collectors, 756 checks, MSCT & CIS baselines, SHA-256 signed reports.
