# Usage guide — CHECKSEC 🇬🇧

## Getting started
1. Launch `CHECKSEC.exe` (double‑click) and accept the **UAC** prompt — the analysis needs administrator rights to read the system configuration.
2. The top‑right badge shows the version and **`Admin`** (green), confirming elevation. If it shows **`NON‑ADMIN`** (red), the analysis will be incomplete.

## Tabs
| Tab | Content |
|---|---|
| **Dashboard** | Global score (0‑100) + grade, *Run analysis* / *Cancel* / *Export* buttons. |
| **Secure Core** | Hardware protection tiles: VBS, Credential Guard, HVCI, DMA Protection, Secure Boot, TPM — **real (running) state**. |
| **Security Results** | All checks, with filters (OK/Warning/Critical) and search. |
| **MSCT Gaps** | Differences vs Microsoft baseline (expected / actual / severity). |
| **CIS Benchmark** | Compliance with CIS controls. |
| **Remediation** | Prioritized action plan with fix commands. |
| **Logs** | Security events and system errors. |
| **History** | Comparison across successive analyses. |
| **System** | Machine info (OS, TPM, BIOS, network…). |

## Exports
**Export** button → choose a format:
- **JSON** (full forensic, SHA‑256 hash, `AnalysisLog`) — also auto‑saved to the **Desktop**.
- **CSV**, **TXT**, **PDF**, **Excel**, **HTML**, **CEF** (SIEM).

## Command line (headless)
```powershell
CHECKSEC.exe --headless --output report.json --format json
CHECKSEC.exe --headless --output events.cef --format cef
```
Exit codes: `0` = no critical issue · `2` = warnings · `3` = criticals present.

## Verifying a JSON report's integrity
The `Integrity` block holds a **SHA‑256** computed over the whole report *without* that block. To verify: remove `Integrity`, re‑serialize identically (indentation), and compare the hash.

## Keyboard shortcuts
`Ctrl+1..8` navigate tabs · `F5` refresh · `Ctrl+E` export.
