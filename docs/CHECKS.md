# CHECKSEC — Liste complète des tests/contrôles

Généré depuis un rapport réel. 49 collecteurs.

## Accès distant (extra)  (5 résultats, 5 types de contrôle)
- Assistance à distance — contrôle total / non sollicité
- Assistance à distance (fAllowToGetHelp)
- Service WinRM — état de démarrage (contexte)
- WinRM Client — Basic Auth (AllowBasic)
- WinRM Service — Basic Auth (AllowBasic)

## Application Control  (21 résultats, 21 types de contrôle)
- AppLocker: AppID Service (AppIDSvc)
- AppLocker: DLL Rules
- AppLocker: Exe Enforcement Mode
- AppLocker: Executable Rules
- AppLocker: MSI/Installer Rules
- AppLocker: Packaged App Rules
- AppLocker: Script Rules
- Smart App Control (SAC) State
- UAC: ConsentPromptBehaviorAdmin
- UAC: ConsentPromptBehaviorUser
- UAC: EnableInstallerDetection
- UAC: EnableLUA
- UAC: EnableVirtualization
- UAC: FilterAdministratorToken (Admin Approval Mode for Built-in Admin)
- UAC: PromptOnSecureDesktop
- UAC: ValidateAdminCodeSignatures
- WDAC: Active CI Policy Files
- WDAC: CI Config Registry Key
- WDAC: CI Policy VelocityId
- WDAC: CIPolicyActive Key
- WDAC: CodeIntegrityPoliciesActive

## Audit Policy  (37 résultats, 37 types de contrôle)
- Advanced Audit: Subcategory Override
- Audit Policy Collection
- Audit: Account Logon > Credential Validation
- Audit: Account Logon > Kerberos Authentication Service
- Audit: Account Logon > Kerberos Service Ticket Operations
- Audit: Account Management > Application Group Management
- Audit: Account Management > Computer Account Management
- Audit: Account Management > Distribution Group Management
- Audit: Account Management > Security Group Management
- Audit: Account Management > User Account Management
- Audit: Detailed Tracking > Process Creation
- Audit: Detailed Tracking > Process Termination
- Audit: Logon/Logoff > Account Lockout
- Audit: Logon/Logoff > Logoff
- Audit: Logon/Logoff > Logon
- Audit: Logon/Logoff > Other Logon/Logoff Events
- Audit: Logon/Logoff > Special Logon
- Audit: Object Access > Removable Storage
- Audit: Object Access > SAM
- Audit: Policy Change > Audit Policy Change
- Audit: Policy Change > Authentication Policy Change
- Audit: Policy Change > Authorization Policy Change
- Audit: Policy Change > MPSSVC Rule-Level Policy Change
- Audit: Privilege Use > Sensitive Privilege Use
- Audit: System > IPsec Driver
- Audit: System > Other System Events
- Audit: System > Security State Change
- Audit: System > Security System Extension
- Audit: System > System Integrity
- Event Log Retention: Application
- Event Log Retention: Security
- Event Log Retention: System
- Event Log Size: Application
- Event Log Size: Security
- Event Log Size: System
- LSA: AuditBaseObjects
- LSA: CrashOnAuditFail

## Autoruns & Persistance  (529 résultats, 38 types de contrôle)
- AppInit_DLLs
- BHO (HKLM BHO (WOWN)): {GUID}
- BHO (HKLM BHO (WOWN)): IEToEdge BHO
- BHO (HKLM BHO (WOWN)): Skype for Business Browser Helper
- BHO (HKLM BHO): IEToEdge BHO
- BHO (HKLM BHO): Java(tm) Plug-In 2 SSV Helper
- BHO (HKLM BHO): Java(tm) Plug-In SSV Helper
- BHO (HKLM BHO): Skype for Business Browser Helper
- IFEO Debugger: CompatTelRunner.exe
- IFEO Debugger: DeviceCensus.exe
- IFEO Debugger: LicenseManager.exe
- IFEO Debugger: software_reporter_tool.exe
- LSA: Authentication Packages
- LSA: Notification Packages
- LSA: Security Packages
- Run Key: HKCU Run → Advanced SystemCare
- Run Key: HKCU Run → GoogleDriveFS
- Run Key: HKCU Run → Microsoft.Lists
- Run Key: HKCU Run → MicrosoftCopilotAutoLaunch_NCADNF6B0CCND8ANCND8ENA8
- Run Key: HKCU Run → MicrosoftEdgeAutoLaunch_3BA6DEENFNFABNCNANENED8
- Run Key: HKCU Run → OneDrive
- Run Key: HKCU Run → pCloud
- Run Key: HKCU Run → Unified Remote V3
- Run Key: HKCU RunOnce
- Run Key: HKLM Run → RtkAudUService
- Run Key: HKLM Run → SecurityHealth
- Run Key: HKLM Run → WavesSvc
- Run Key: HKLM RunOnce
- Run Key: HKLM WOWN Run → SunJavaUpdateSched
- Scheduled Task:
- Scheduled Tasks: Summary
- Startup Folders
- Winlogon: AppSetup
- Winlogon: Shell
- Winlogon: Userinit
- WMI EventConsumer: SCM Event Log Consumer
- WMI EventFilter: SCM Event Log Filter
- WMI FilterToConsumerBinding Query

## Azure AD & Conformité Cloud  (6 résultats, 6 types de contrôle)
- Azure AD / Domain Join Status
- Conditional Access Compliance
- Intune MDM Enrollment
- Microsoft Account (MSA) Restriction
- OneDrive KFM (Known Folder Move)
- Windows Hello for Business

## BitLocker  (7 résultats, 7 types de contrôle)
- BitLocker WMI Access
- FVE Policy: EnableBDEWithNoTPM
- FVE Policy: EncryptionMethod (Fixed Drives)
- FVE Policy: EncryptionMethod (OS Drive)
- FVE Policy: UseAdvancedStartup
- FVE Policy: UseTPM
- FVE Policy: UseTPMPIN

## Centre de sécurité (AV/Pare-feu)  (4 résultats, 4 types de contrôle)
- Anti-logiciel espion enregistré
- Antivirus enregistré : Windows Defender
- Pare-feu enregistré
- Synthèse antivirus enregistrés

## Certificats & PKI  (68 résultats, 67 types de contrôle)
- Auto-Enrollment Policy (HKCU)
- Auto-Enrollment Policy (HKLM)
- Disallowed/Revoked Certificates Store
- Intermediate CA: CN=Microsoft Code Signing PCA N, O=Microsoft Corporation,…
- Intermediate CA: CN=Microsoft Windows Hardware Compatibility, OU=Microsoft Co…
- Intermediate CA: OU=www.verisign.com/CPS Incorp.by Ref. LIABILITY LTD.(c)N V…
- Intermediate CAs: Summary
- Personal Cert: CN=localhost
- PKI Summary
- Root CA: CN=AAA Certificate Services, O=Comodo CA Limited, L=Salford,…
- Root CA: CN=AddTrust External CA Root, OU=AddTrust External TTP Netwo…
- Root CA: CN=Certigna, O=Dhimyotis, C=FR
- Root CA: CN=Certum Trusted Network CA 2, OU=Certum Certification Auth…
- Root CA: CN=Certum Trusted Network CA, OU=Certum Certification Author…
- Root CA: CN=COMODO RSA Certification Authority, O=COMODO CA Limited, …
- Root CA: CN=DESKTOP-IMFK2O0
- Root CA: CN=DigiCert Assured ID Root CA, OU=www.digicert.com, O=DigiC…
- Root CA: CN=DigiCert CS RSAN Root G5, O="DigiCert, Inc.", C=US
- Root CA: CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert …
- Root CA: CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert …
- Root CA: CN=DigiCert Global Root G3, OU=www.digicert.com, O=DigiCert …
- Root CA: CN=DigiCert High Assurance EV Root CA, OU=www.digicert.com, …
- Root CA: CN=DigiCert Trusted Root G4, OU=www.digicert.com, O=DigiCert…
- Root CA: CN=DST Root CA X3, O=Digital Signature Trust Co.
- Root CA: CN=EC-ACC, OU=Jerarquia Entitats de Certificacio Catalanes, …
- Root CA: CN=Entrust Root Certification Authority - G2, OU="(c) N E…
- Root CA: CN=Entrust.net Certification Authority (N), OU=(c) N E…
- Root CA: CN=GlobalSign Code Signing Root RN, O=GlobalSign nv-sa, C=B…
- Root CA: CN=GlobalSign Root CA, OU=Root CA, O=GlobalSign nv-sa, C=BE
- Root CA: CN=GlobalSign, O=GlobalSign, OU=GlobalSign ECC Root CA - R4
- Root CA: CN=GlobalSign, O=GlobalSign, OU=GlobalSign Root CA - R3
- Root CA: CN=GlobalSign, O=GlobalSign, OU=GlobalSign Root CA - R6
- Root CA: CN=Go Daddy Root Certificate Authority - G2, O="GoDaddy.com,…
- Root CA: CN=HARICA TLS ECC Root CA N, O=Hellenic Academic and Rese…
- Root CA: CN=HARICA TLS RSA Root CA N, O=Hellenic Academic and Rese…
- Root CA: CN=Hellenic Academic and Research Institutions ECC RootCA N…
- Root CA: CN=Hellenic Academic and Research Institutions RootCA N, …
- Root CA: CN=ISRG Root X1, O=Internet Security Research Group, C=US
- Root CA: CN=Microsoft Authenticode(tm) Root Authority, O=MSFT, C=US
- Root CA: CN=Microsoft Root Authority, OU=Microsoft Corporation, OU=Co…
- Root CA: CN=Microsoft Root Certificate Authority, DC=microsoft, DC=co…
- Root CA: CN=QuoVadis Root Certification Authority, OU=Root Certificat…
- Root CA: CN=Sectigo Public Code Signing Root RN, O=Sectigo Limited, …
- Root CA: CN=Sectigo Public Server Authentication Root RN, O=Sectigo …
- Root CA: CN=SSL.com EV Root Certification Authority RSA R2, O=SSL Cor…
- Root CA: CN=SSL.com Root Certification Authority ECC, O=SSL Corporati…
- Root CA: CN=SSL.com Root Certification Authority RSA, O=SSL Corporati…
- Root CA: CN=starcolor.symplicity.fr
- Root CA: CN=Starfield Root Certificate Authority - G2, O="Starfield T…
- Root CA: CN=Starfield Services Root Certificate Authority - G2, O="St…
- Root CA: CN=SwissSign Gold CA - G2, O=SwissSign AG, C=CH
- Root CA: CN=thawte Primary Root CA, OU="(c) N thawte, Inc. - For a…
- Root CA: CN=Thawte Timestamping CA, OU=Thawte Certification, O=Thawte…
- Root CA: CN=USERTrust ECC Certification Authority, O=The USERTRUST Ne…
- Root CA: CN=USERTrust RSA Certification Authority, O=The USERTRUST Ne…
- Root CA: CN=UTN-USERFirst-Object, OU=http://www.usertrust.com, O=The …
- Root CA: CN=VeriSign Class 3 Public Primary Certification Authority -…
- Root CA: CN=VeriSign Universal Root Certification Authority, OU="(c) …
- Root CA: E=premium-server@thawte.com, CN=Thawte Premium Server CA, OU…
- Root CA: OU="NO LIABILITY ACCEPTED, (c)N VeriSign, Inc.", OU=VeriSig…
- Root CA: OU=Class 3 Public Primary Certification Authority, O="VeriSi…
- Root CA: OU=Copyright (c) N Microsoft Corp., OU=Microsoft Time Sta…
- Root CA: OU=Go Daddy Class 2 Certification Authority, O="The Go Daddy…
- Root CA: OU=Starfield Class 2 Certification Authority, O="Starfield T…
- Root CAs: Summary
- Root Certificate Auto-Update
- WinTrust: Software Publishing Revocation Check

## CisFallbackCollector  (30 résultats, 24 types de contrôle)
- CISFallback_5.6
- CISFallback_5.9
- CISFallback_5.N
- CISFallback_N.1.1.1
- CISFallback_N.1.1.2
- CISFallback_N.4.4
- CISFallback_N.4.5
- CISFallback_N.4.7
- CISFallback_N.4.9
- CISFallback_N.4.N
- CISFallback_N.5.8
- CISFallback_N.5.N.1
- CISFallback_N.5.N.2
- CISFallback_N.8.N.1.2
- CISFallback_N.9.N.1
- CISFallback_N.9.N.2
- CISFallback_N.N.7.1
- CISFallback_N.N.N.1
- CISFallback_N.N.N.2
- CISFallback_N.N.N.3
- CISFallback_N.N.N.3.1
- CISFallback_N.N.N.4
- CISFallback_N.N.N.5
- CISFallback_N.N.N.6

## Configuration des journaux  (7 résultats, 7 types de contrôle)
- Rétention du journal : Application
- Rétention du journal : Security
- Rétention du journal : System
- Taille du journal : Application
- Taille du journal : PowerShell/Operational
- Taille du journal : Security
- Taille du journal : System

## Délégation de Credentials  (3 résultats, 3 types de contrôle)
- CredSSP — AllowEncryptionOracle
- Délégation de credentials
- Remote Credential Guard

## DNS-over-HTTPS  (1 résultats, 1 types de contrôle)
- DNS-over-HTTPS (DoH)

## Durcissement authentification domaine  (3 résultats, 3 types de contrôle)
- Channel binding LDAP (ADVN — contexte)
- Contexte : appartenance au domaine
- Signature LDAP client (LDAPClientIntegrity)

## Durcissement Avancé  (6 résultats, 6 types de contrôle)
- Audit de la ligne de commande à la création de processus
- Audit et restriction du trafic NTLM
- Chemins de services non quotés (Unquoted Service Paths)
- Permissions des binaires de services
- Restrictions d'installation de périphériques USB
- Restrictions Point and Print (PrintNightmare)

## Durcissement navigateurs  (9 résultats, 9 types de contrôle)
- Chrome: Contrôle des extensions (blocklist/allowlist)
- Chrome: Gestionnaire de mots de passe intégré
- Chrome: Restrictions de téléchargement
- Chrome: Safe Browsing (SafeBrowsingProtectionLevel)
- Edge: Contrôle des extensions (blocklist/allowlist)
- Edge: Gestionnaire de mots de passe intégré
- Edge: Microsoft Defender SmartScreen
- Edge: Restrictions de téléchargement
- Edge: Version TLS minimale (SSLVersionMin)

## Durcissement RDP  (4 résultats, 4 types de contrôle)
- RDP — Couche de sécurité
- RDP — État
- RDP — Niveau de chiffrement
- RDP — NLA (Network Level Authentication)

## Durcissement SMB  (4 résultats, 4 types de contrôle)
- SMB Encryption
- SMB Signing — Client
- SMB Signing — Serveur
- SMBv1

## Durcissement système (extra)  (3 résultats, 3 types de contrôle)
- AlwaysInstallElevated (escalade via MSI)
- Stockage USB (USBSTOR / écriture amovible)
- Windows Defender Application Guard (WDAG)

## EventLogCollector  (7 résultats, 7 types de contrôle)
- Journal: Application
- Journal: Microsoft-Windows-AppLocker/EXE and DLL
- Journal: Microsoft-Windows-BitLocker/BitLocker Management
- Journal: Microsoft-Windows-PowerShell/Operational
- Journal: Microsoft-Windows-Windows Defender/Operational
- Journal: Security
- Journal: System

## Groupes & comptes locaux  (4 résultats, 4 types de contrôle)
- Compte Invité (Guest, RID N)
- Comptes locaux : mot de passe qui n'expire jamais
- Comptes locaux dormants
- Membres du groupe Administrateurs local

## Inventaire Logiciels  (14 résultats, 14 types de contrôle)
- .NET (Core) : Versions installées
- .NET Framework : Versions installées
- AppX / MSIX (Microsoft Store)
- Fonctionnalités Windows optionnelles dangereuses
- Google Chrome : Extensions installées
- Inventaire : N logiciels récents (par date d'installation)
- Inventaire : Nombre total de logiciels
- Inventaire : Top N éditeurs
- Logiciel risqué : Microsoft Silverlight
- Logiciel risqué : TeamViewer
- Logiciels de sécurité détectés
- Microsoft Edge : Extensions installées
- Mozilla Firefox : Extensions installées
- Sysmon : Service détecté

## Journaux Forensiques  (10 résultats, 10 types de contrôle)
- A. Événements Sécurité Critiques
- B. Événements Système Suspects
- C1. PowerShell — Exécution de Scripts (N)
- C2. PowerShell — Sessions et Module Logging
- D. Windows Defender — Menaces Détectées
- E1. AppLocker — Blocages EXE/DLL
- E2. WDAC Code Integrity — Politique de Blocage
- F1. RDP — Connexions Réussies/Échouées
- F2. RDP — Connexions Réseau Avant Auth (N)
- G. Résumé Forensique Global

## Kerberos & Authentification  (19 résultats, 19 types de contrôle)
- Cache credentials : CachedLogonsCount (Winlogon)
- Compte Administrateur local (SID-N)
- Domaine : Appartenance et rôle
- Kerberos : MaxClockSkew (tolérance de décalage horaire)
- Kerberos : MaxRenewAge (durée max de renouvellement TGT)
- Kerberos : MaxServiceAge (durée max ticket de service)
- Kerberos : MaxTicketAge (durée max TGT)
- Kerberos : Types de chiffrement pris en charge
- Netlogon : RequireSignOrSeal
- Netlogon : RequireStrongKey
- Netlogon : SealSecureChannel
- Netlogon : SignSecureChannel
- Politique : Comptes Microsoft optionnels (MSAOptional)
- Protected Users : Membres du groupe local
- PtH : AllowDefaultCredentials (délégation CredSSP)
- PtH : AllowSavedCredentials (credentials sauvegardés CredSSP)
- PtH : DisableRestrictedAdmin (mode Admin Restreint RDP)
- PtH : DisableRestrictedAdminOutboundCreds
- Stratégie de groupe : Dernière mise à jour

## LAPS  (1 résultats, 1 types de contrôle)
- LAPS Legacy (AdmPwd)

## Microsoft Defender for Endpoint  (8 résultats, 8 types de contrôle)
- A. MDE — Statut d'Enrôlement
- A2. MDE — Méthode d'Onboarding
- B1. Service Sense — Agent MDE
- B2. Service DiagTrack — Télémétrie Windows
- C. MDE — Capacités (AAD Join, Gestion)
- D. Services de Sécurité Associés
- E. Defender AV — Versions et Signatures
- F. ASR — Règles de Réduction de la Surface d'Attaque

## NetworkSecCollector  (26 résultats, 26 types de contrôle)
- DNS over HTTPS (DoH) - EnableAutoDoh
- DNSSEC - Validation des signatures DNS
- IPv6 - Composants désactivés (DisabledComponents)
- LLMNR - Link-Local Multicast Name Resolution
- mDNS - Multicast DNS
- NBT-NS - NetBIOS over TCP/IP (par adaptateur)
- NTLM - LmCompatibilityLevel (Niveau d'authentification)
- NTLM - NTLMMinClientSec (Sécurité minimale client)
- NTLM - NTLMMinServerSec (Sécurité minimale serveur)
- NTLM - RestrictSendingNTLMTraffic (Restriction trafic NTLM sortant)
- PowerShell Remoting - AllowAutoConfig (WinRM Service)
- Print Spooler - RegisterSpoolerRemoteRpcEndPoint
- Print Spooler - Service (PrintNightmare CVE-N-N)
- RDP - Bureau à distance activé (fDenyTSConnections)
- SMB - Accès anonyme aux partages (RestrictNullSessAccess)
- SMB Encryption - Chiffrement des données
- SMB Server Name Hardening
- SMB Signing - Client (RequireSecuritySignature)
- SMB Signing - Serveur (RequireSecuritySignature)
- SMB1 - Protocole SMBv1 (EternalBlue / WannaCry)
- SMB2/3 - Protocole SMBv2/v3
- WinRM - Service Windows Remote Management
- WinRM Client - Trafic non chiffré (AllowUnencryptedTraffic)
- WinRM Service - Trafic non chiffré (AllowUnencryptedTraffic)
- WPAD - Politique HKLM (WpadOverride)
- WPAD - Web Proxy Auto-Discovery (état global)

## Partages Réseau  (10 résultats, 10 types de contrôle)
- LSA - RestrictAnonymous
- LSA - RestrictAnonymousSAM
- Partage Admin : IPC$
- Partage Critique : Users
- Partages Admin - AutoShareWks / AutoShareServer
- Permissions partage : Users
- Session Nulle - NullSessionPipes
- Session Nulle - NullSessionShares
- Session Nulle - RestrictNullSessAccess
- Sessions SMB actives

## Print Spooler  (2 résultats, 2 types de contrôle)
- Service Print Spooler — Démarrage
- Spooler RPC Endpoint distant

## Processus & Drivers  (60 résultats, 20 types de contrôle)
- Driver (Suspicious Path): AscFileFilter
- Driver (Suspicious Path): AscRegistryFilter
- Driver (Suspicious Path): cpuzN
- Driver (Suspicious Path): googledrivefsN
- Driver (Suspicious Path): iobit_monitor_serverN
- Drivers: Summary
- Process: CHECKSEC.exe (PID N)
- Process: chrome-native-host.exe (PID N)
- Process: claude.exe (PID N)
- Process: Cursor.exe (PID N)
- Process: exfs.exe (PID N)
- Process: ExpanDrive.exe (PID N)
- Process: node.exe (PID N)
- Process: sppsvc.exe (PID N)
- Processes: Enumeration Coverage
- Service: MDCoreSvc
- Service: WdNisSvc
- Service: WinDefend
- Services: Summary
- System Integrity: Overall Summary

## Protection Exploit  (6 résultats, 6 types de contrôle)
- ASLR — MoveImages
- BootExecute
- Control Flow Guard (CFG)
- Kernel Mitigation Options
- Mitigation Audit Options
- SEHOP

## Protection LSA  (2 résultats, 2 types de contrôle)
- LSA Protection (RunAsPPL)
- Stockage hash LM

## Règles ASR  (1 résultats, 1 types de contrôle)
- Règles ASR

## Secure Boot & UEFI  (4 résultats, 4 types de contrôle)
- Firmware — Informations
- Firmware — Mode de démarrage
- Secure Boot — État
- Secure Boot — Mises à jour disponibles

## Sécurité Additionnelle  (24 résultats, 24 types de contrôle)
- Atténuations Spectre/Meltdown
- AutoPlay désactivé (NoAutoRun)
- AutoRun désactivé (NoDriveTypeAutoRun)
- Data Execution Prevention (DEP/NX)
- Defender Exploit Guard (CFA + Network Protection)
- DNS over HTTPS (DoH)
- Identifiants mis en cache (CachedLogonsCount)
- Intégrité de la mémoire (Core Isolation / HVCI)
- Intégrité du fichier hosts
- LAPS (Local Administrator Password Solution)
- Ports TCP en écoute inhabituels
- PowerShell v2 (risque de contournement)
- PowerShell: Execution Policy (GPO)
- PowerShell: Module Logging
- PowerShell: ScriptBlock Logging
- PowerShell: Transcription
- Print Spooler (PrintNightmare CVE-N-N)
- Service Remote Registry — désactivé
- WDigest: Stockage en clair des mots de passe
- Windows Script Host (WSH) — désactivé
- Windows SmartScreen
- Windows Update: Mise à jour automatique
- Windows Update: Mises à jour non suspendues
- WSUS / Serveur de mises à jour configuré

## Sécurité Bluetooth  (3 résultats, 3 types de contrôle)
- Bluetooth — Politique
- Bluetooth — Radio
- Bluetooth — Service (BTHPORT)

## Sécurité Microsoft Office  (23 résultats, 23 types de contrôle)
- ActiveX - Désactivation globale Office
- Affichage protégé - Excel (Office N/N/N)
- Affichage protégé - PowerPoint (Office N/N/N)
- Affichage protégé - Word (Office N/N/N)
- DDE - Mise à jour automatique désactivée - Excel (Office N/N/N)
- DDE - Mise à jour automatique désactivée - Word (Office N/N/N)
- Emplacements approuvés - Access (Office N/N/N)
- Emplacements approuvés - Excel (Office N/N/N)
- Emplacements approuvés - Outlook (Office N/N/N)
- Emplacements approuvés - PowerPoint (Office N/N/N)
- Emplacements approuvés - Publisher (Office N/N/N)
- Emplacements approuvés - Word (Office N/N/N)
- Macros VBA - Access (Office N/N/N)
- Macros VBA - Excel (Office N/N/N)
- Macros VBA - Outlook (Office N/N/N)
- Macros VBA - PowerPoint (Office N/N/N)
- Macros VBA - Publisher (Office N/N/N)
- Macros VBA - Word (Office N/N/N)
- Outlook - Garde Modèle Objet (Office N/N/N)
- Outlook - Hyperliens dans les emails (Office N/N/N)
- Outlook - Longueur minimale clé S/MIME (Office N/N/N)
- Outlook - Niveau de sécurité pièces jointes (Office N/N/N)
- SYNTHÈSE - Sécurité Microsoft Office

## Sécurité WiFi  (39 résultats, 11 types de contrôle)
- WiFi — Auto-connexion hotspots WiFi Sense
- WiFi — Auto-connexion OEM
- WiFi — Nombre total de profils
- WiFi — Profils TKIP
- WiFi — Profils WEP
- WiFi — Réseaux ouverts enregistrés
- WiFi — Service WLAN AutoConfig (Wlansvc)
- WiFi […] — Authentification
- WiFi […] — Chiffrement
- WiFi […] — Connexion automatique
- WiFi […] — Randomisation MAC

## Services de découverte réseau  (3 résultats, 3 types de contrôle)
- Service FDResPub (Function Discovery / WSD)
- Service SSDPSRV (SSDP Discovery / UPnP)
- Service upnphost (UPnP Device Host)

## System Information  (41 résultats, 41 types de contrôle)
- BIOS Manufacturer
- BIOS Release Date
- BIOS Version
- CPU[…] Cores
- CPU[…] Logical Processors (Threads)
- CPU[…] Max Speed
- CPU[…] Name
- CPU[…] Virtualization Firmware Enabled
- Domain / Workgroup Membership
- Domain Role
- Drive C: Space
- Drive G: Space
- Hyper-V Feature
- Hypervisor Present
- Last Boot Time
- Manufacturer
- Model
- NIC […] DHCP Enabled
- NIC […] DNS Servers
- NIC […] IP Address
- NIC […] MAC Address
- Number of Processors
- OS Architecture
- OS Build Number
- OS Caption
- OS Install Date
- OS Language Code
- OS Version
- Registered Organization
- Registered Owner
- Secure Boot Status
- System Directory
- System Type
- Total Physical Memory
- TPM Activated
- TPM Enabled
- TPM Manufacturer Version
- TPM Owned
- TPM Spec Version
- UEFI / BIOS Type
- Windows Directory

## TLS / Cryptography  (36 résultats, 32 types de contrôle)
- Cipher Suites: Policy Configuration
- Cipher: AES N/N
- Cipher: DES N/N
- Cipher: NULL
- Cipher: RC4 N/N
- Cipher: Triple DES N
- Hash Algorithm: MD5
- Hash Algorithm: SHA
- Hash Algorithm: SHAN
- IE/WinHTTP: SecureProtocols
- Key Exchange: DH Minimum Key Length
- Key Exchange: Diffie-Hellman
- Key Exchange: ECDH
- Key Exchange: PKCS
- Protocol SSL 2.0 - Client
- Protocol SSL 2.0 - Server
- Protocol SSL 3.0 - Client
- Protocol SSL 3.0 - Server
- Protocol TLS 1.0 - Client
- Protocol TLS 1.0 - Server
- Protocol TLS 1.1 - Client
- Protocol TLS 1.1 - Server
- Protocol TLS 1.2 - Client
- Protocol TLS 1.2 - Server
- Protocol TLS 1.3 - Client
- Protocol TLS 1.3 - Server
- SMB: Client Signing Required
- SMB: Reject Unencrypted Access
- SMB: Server Encryption (EncryptData)
- SMB: Server Name Hardening Level
- SMB: Server Signing Required
- SMB: SMBv1 Protocol

## UAC Détaillé  (8 résultats, 8 types de contrôle)
- UAC — Bureau sécurisé
- UAC — Chemins UIA sécurisés
- UAC — Comportement Admin
- UAC — Comportement Utilisateur
- UAC — Détection d'installateur
- UAC — EnableLUA
- UAC — Validation signatures admin
- UAC — Virtualisation

## User Accounts  (26 résultats, 26 types de contrôle)
- Built-in Administrator: Active
- Built-in Administrator: Renamed
- Guest Account Status
- Local Accounts: Total / Enabled
- Local User: a
- Local User: Administrateur
- Local User: Ayi
- Local User: DefaultAccount
- Local User: Invité
- Local User: WDAGUtilityAccount
- LSA: DisableDomainCreds
- LSA: EveryoneIncludesAnonymous
- LSA: ForceGuest (Sharing and Security Model)
- LSA: LimitBlankPasswordUse
- LSA: LmCompatibilityLevel
- LSA: NoLMHash (No LAN Manager Hash)
- LSA: RestrictAnonymous
- LSA: RestrictAnonymousSAM
- Password Policy: Account Lockout Threshold
- Password Policy: Lockout Duration
- Password Policy: Lockout Observation Window
- Password Policy: Maximum Password Age
- Password Policy: Minimum Length
- Password Policy: Minimum Password Age
- Password Policy: Password History Size
- Password Policy: Source

## VBS Security  (20 résultats, 20 types de contrôle)
- Credential Guard Running (WMI)
- Credential Guard: LsaCfgFlags
- DMA Protection in VBS Properties (WMI)
- DMA Protection Policy (FVE)
- HVCI Enabled (Registry)
- HVCI Enabled By
- HVCI Running (WMI)
- HVCI UEFI Lock
- Kernel DMA Protection Available
- LSA Protection (RunAsPPL)
- Secure Boot (VBS dependency)
- System Guard / Secure Launch
- VBS Available Security Properties
- VBS Registry: EnableVirtualizationBasedSecurity
- VBS Registry: HypervisorEnforcedCodeIntegrityLock
- VBS Registry: RequirePlatformSecurityFeatures
- VBS Required Security Properties
- VBS Security Services Configured
- VBS Security Services Running
- VBS Status (WMI)

## Verrouillage & Accès Physique  (13 résultats, 13 types de contrôle)
- Connexion par carte à puce (Smart Card)
- DeviceLock - Politiques PIN (PolicyManager)
- Économiseur d'écran - Délai d'activation
- Économiseur d'écran - Mot de passe à la reprise
- Hibernation - État
- Message légal à l'ouverture de session (Legal Banner)
- Mot de passe en clair - DefaultPassword (Winlogon)
- Ouverture de session automatique (AutoAdminLogon)
- Plan d'alimentation - Extinction d'écran (AC, GPO)
- Plan d'alimentation actif - Mise en veille écran
- Verrouillage par inactivité - InactivityTimeoutSecs
- Windows Hello - AllowDomainPINLogon
- Windows Hello for Business - État GPO

## WDigest  (2 résultats, 2 types de contrôle)
- WDigest — Negotiate
- WDigest — UseLogonCredential

## Windows Defender  (31 résultats, 31 types de contrôle)
- AM Engine Version
- AM Product Version
- AM Service Enabled
- AM Service Version
- Antispyware Enabled
- Antispyware Signature Age
- Antivirus Enabled
- Antivirus Signature Age
- ASR Rules Configured
- AV Signature Last Updated
- Behavior Monitoring Enabled
- Cloud Protection: SpynetReporting Level
- Cloud Protection: SubmitSamplesConsent
- Controlled Folder Access
- ELAM: Driver Load Policy
- Exploit Protection Registry Key
- GPO: DisableBehaviorMonitoring
- GPO: DisableBlockAtFirstSeen
- GPO: DisableIOAVProtection
- GPO: DisableRealtimeMonitoring
- GPO: Network Protection
- GPO: PUA Protection
- IOAV Protection (Download Scanning)
- Network Inspection System (NIS) Enabled
- Network Real-Time Inspection Enabled
- On-Access Protection Enabled
- Real-Time Protection Enabled
- Registry: DisableAntiSpyware
- Registry: DisableAntiVirus
- Tamper Protection
- Tamper Protection Source

## Windows Firewall  (35 résultats, 35 types de contrôle)
- COM: Domain (COM) Default Inbound Action
- COM: Domain (COM) Default Outbound Action
- COM: Domain (COM) Firewall Enabled
- COM: Private (COM) Default Inbound Action
- COM: Private (COM) Default Outbound Action
- COM: Private (COM) Firewall Enabled
- COM: Public (COM) Default Inbound Action
- COM: Public (COM) Default Outbound Action
- COM: Public (COM) Firewall Enabled
- Domain Profile: Default Inbound Action
- Domain Profile: Default Outbound Action
- Domain Profile: Firewall Enabled
- Domain Profile: Log Dropped Packets
- Domain Profile: Log File
- Domain Profile: Log Successful Connections
- Domain Profile: Notifications Disabled
- Firewall Rules Summary
- GPO Override: Domain Firewall
- GPO Override: Private (Standard) Firewall
- GPO Override: Public Firewall
- Private (Standard) Profile: Default Inbound Action
- Private (Standard) Profile: Default Outbound Action
- Private (Standard) Profile: Firewall Enabled
- Private (Standard) Profile: Log Dropped Packets
- Private (Standard) Profile: Log File
- Private (Standard) Profile: Log Successful Connections
- Private (Standard) Profile: Notifications Disabled
- Public Profile: Default Inbound Action
- Public Profile: Default Outbound Action
- Public Profile: Firewall Enabled
- Public Profile: Log Dropped Packets
- Public Profile: Log File
- Public Profile: Log Successful Connections
- Public Profile: Notifications Disabled
- Windows Firewall Service (MpsSvc)

## Windows Sandbox  (2 résultats, 2 types de contrôle)
- Hyper-V (prérequis Sandbox)
- Windows Sandbox

## Windows Update  (7 résultats, 7 types de contrôle)
- A. Services Windows Update
- B. Configuration Windows Update
- C. Dernière Activité de Mise à Jour
- D. Redémarrages en Attente
- E. Version Windows et EOL
- F. Historique des Mises à Jour (KBs)
- G. Pauses des Mises à Jour

---
**Total : 664 types de contrôle distincts** répartis sur 49 collecteurs (hors écarts MSCT : 330 politiques comparées, et contrôles CIS : 152).
