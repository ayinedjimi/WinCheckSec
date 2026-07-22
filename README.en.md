<div align="center">

# 🛡️ CHECKSEC

### Windows 11 security posture auditor — fast, comprehensive, offline

**756 checks · 62 collectors · MSCT & CIS baselines · SHA‑256 signed reports**

[![Windows 11](https://img.shields.io/badge/Windows-11-0078D4?logo=windows11&logoColor=white)](https://www.microsoft.com/windows/windows-11)
[![.NET 9](https://img.shields.io/badge/.NET-9.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![WinUI 3](https://img.shields.io/badge/WinUI-3-0067B8)](https://learn.microsoft.com/windows/apps/winui/)
[![Portable](https://img.shields.io/badge/Portable-single--file-107C10)](#-installation)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![By Ayi NEDJIMI Consultants](https://img.shields.io/badge/By-Ayi%20NEDJIMI%20Consultants-C50F1F)](https://ayinedjimi-consultants.fr)

[🇫🇷 Français](README.md) · 🇬🇧 **English**

</div>

---

## 📸 Preview

<div align="center">
<img src="docs/screenshots/dashboard.png" alt="CHECKSEC dashboard" width="850">
<br><em>Dashboard — global score, run analysis, export</em>
</div>

---

## 🎯 Overview

**CHECKSEC** performs a deep audit of a **Windows 11** machine's security configuration and compares it against the **Microsoft Security Compliance Toolkit (MSCT)** and **CIS Benchmark** baselines. It produces a score, a prioritized remediation plan, and reports designed for **post‑incident / compliance review**.

- 🔒 **100% local & offline** — no data ever leaves the machine.
- ⚡ **Fast** — 62 collectors run **in parallel**; a full scan takes seconds.
- 📦 **Portable** — a single self‑contained `.exe` (no .NET install required).
- 🧾 **Rich reports** — forensic JSON (SHA‑256 integrity hash), PDF, Excel, HTML, CEF (SIEM).

---

## ✨ Key features

| Area | What is audited |
|---|---|
| 🦠 **Antivirus / EDR** | Microsoft Defender (real‑time, tamper protection, cloud, ASR, CFA), **Defender for Endpoint (MDE)**, and **third‑party AV/firewall** via `SecurityCenter2` (name, enabled, signatures up‑to‑date) |
| 🔐 **Encryption & Boot** | BitLocker (method, protectors, TPM+PIN), **Secure Boot**, **VBS / Credential Guard / HVCI / Kernel DMA Protection** (real *running* state via WMI) |
| 🌐 **Network** | LLMNR / NBT‑NS / mDNS (Responder poisoning), SMB signing v1/v2/3, TLS/cipher suites, WPAD, NTLM, per‑profile firewall, DoH |
| 📶 **WiFi** | WLAN profiles: **open / WEP / TKIP** networks, 802.1X without server‑cert validation, hotspot auto‑connect, MAC randomization |
| 👤 **Accounts & Auth** | Password policy, **local Administrators** members, dormant accounts, Kerberos, LAPS, LSA, WDigest, UAC |
| 🧩 **Attack surface** | Autoruns & persistence, scheduled tasks, **AlwaysInstallElevated**, Office macros (VBA/DDE/ActiveX), PowerShell logging, WDAC/AppLocker, ASR, Exploit Protection |
| 🌍 **Browsers** | Edge / Chrome policies: SmartScreen, forced extensions, download restrictions, min TLS |
| 🗂️ **Logs & Forensics** | Real Critical/Error Windows event log entries, log size/retention, key security events |
| 💿 **Inventory** | Installed software (registry + **AppX/MSIX**), **risky / EOL** software, browser extensions, Sysmon |

➡️ **Full list of the 756 checks: [`docs/CHECKS.md`](docs/CHECKS.md)** · 🗺️ [Roadmap](docs/ROADMAP.md)

---

## 🚀 Installation

### Option 1 — Portable executable (recommended)
1. Download `CHECKSEC.exe` from the [**latest release**](https://github.com/ayinedjimi/WinCheckSec/releases/latest).
2. Double‑click it. Accept the **UAC** prompt (the analysis requires administrator privileges).
3. Click **Run analysis**.

> Requirements: **Windows 11 x64 only — nothing to install.** The exe is **100% self-contained**: .NET 9, WindowsAppSDK/WinUI **and the Visual C++ runtime** are all embedded in the single-file (auto-extracted at launch). Runs on a clean Windows.

### Option 2 — Headless mode (CLI / automation)
```powershell
CHECKSEC.exe --headless --output report.json --format json
# formats: json | cef
```

---

## 🧾 Reports & forensic export

The JSON report (saved to the Desktop) is built for **post‑incident review**:

- `SchemaVersion`, `Host` / `Execution` blocks (context, elevation, analysis time window);
- `CollectedAt` **per check**, **ISO‑8601 / UTC** timestamps;
- **`AnalysisLog`** — execution log (per‑collector status/duration/result count);
- **`Integrity`** — re‑verifiable **SHA‑256** hash of the report (non‑repudiation);
- **MITRE ATT&CK mapping** (`MitreTechniques` per control + `MitreSummary` for ATT&CK coverage);
- MSCT detail (baseline vs actual), per‑control CIS, real Windows event log errors.

Other formats: **PDF** (QuestPDF), **Excel** (ClosedXML), **HTML**, **CEF** (SIEM), **SARIF 2.1.0** (CI/CD).

---

## 🏗️ Build from source

```powershell
# Requirements: .NET 9 SDK, on Windows (the WinUI XAML compiler is Windows-only)
git clone https://github.com/ayinedjimi/WinCheckSec.git
cd WinCheckSec
dotnet build CHECKSEC.sln -c Release -p:Platform=x64

# Portable single-file exe
dotnet publish CHECKSEC/CHECKSEC.csproj -c Release -r win-x64 -p:Platform=x64 `
  --self-contained true -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true -p:WindowsAppSDKSelfContained=true
```

Code architecture (for contributors): [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
Adding a collector = create an `ISecurityCollector` class + one line in `BuildCollectors()`.

---

## 🔒 Privacy & ethics

CHECKSEC is a **defensive** audit tool. It **reads** system state (registry, WMI, services) and **changes nothing**. No data is sent over the network. Use it only on systems you are authorized to audit.

---

## 👤 Author & services

Built by **Ayi NEDJIMI** — [**Ayi NEDJIMI Consultants**](https://ayinedjimi-consultants.fr), offensive security & AI expert.

📚 **Related articles & resources**:
- [622 Microsoft CVEs in one month: can your IT keep up?](https://ayinedjimi-consultants.fr/articles)
- [SME IT Security Audit: Complete Guide](https://ayinedjimi-consultants.fr/articles)
- [ISO 27001 Internal Audit: Method & Checklist](https://ayinedjimi-consultants.fr/iso-27001)
- [Microsoft 365 Audit](https://ayinedjimi-consultants.fr/audit-microsoft-365) · [NIS 2 Compliance](https://ayinedjimi-consultants.fr/nis-2)

💼 Need a professional security audit? [**Request a quote →**](https://ayinedjimi-consultants.fr/contact)

---

## 📄 License

Released under the **MIT** license — see [`LICENSE`](LICENSE).

<div align="center">
<sub>⭐ If CHECKSEC helps you, drop a star and join the <a href="https://github.com/ayinedjimi/WinCheckSec/discussions">Discussions</a>!</sub>
</div>
