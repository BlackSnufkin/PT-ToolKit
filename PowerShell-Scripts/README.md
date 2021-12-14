# PowerShell-Scripts
PowerShell Scripts from various sources for Penetration-Testing and Red-Team engagements

---

## Enumeration

| Script| Description | Credit & Source |
| --------------- | --------------- | --------------- |
|**adPEAS**| Automate Active Directory enumeration| [61106960](https://github.com/61106960/adPEAS)
|**ADRecon**|ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.|[ADRecon](https://github.com/adrecon/ADRecon)
|**BlueKeepScan** | Scan if the target computer is vulnerable to the BlueKeep exploit (CVE-2019-0708)| [Source_WAS_vletoux](https://github.com/vletoux/pingcastle)
|**Dump-AzureDomainInfo**|PowerShell functions for enumerating information from AzureAD/MSOL domains.|[NetSPI](https://github.com/NetSPI/PowerShell)
|**Find-LOLBAS** | Enumerating living off the land binaries and scripts on a system |[NotoriousRebel](https://github.com/NotoriousRebel/Find-LOLBAS)
|**Get-LdapInfo**|Perform LDAP Queries of the current domain| [tobor88](https://github.com/tobor88/PowerShell-Red-Team)
|**Get-NetSessionEnum**|This script automates the enumeration of NetSessionEnum (network sessions of connected users in the domain)| [YossiSassi](https://github.com/YossiSassi/Get-NetSessionEnum)
|**Get-NetworkShareInfo**|This cmdlet is used to discover information associated with a network share such as the physical location of the network share, its creation date, and name| [tobor88](https://github.com/tobor88/PowerShell-Red-Team)
|**Get-UserLogon**|retrieve logged on users on remote machine | [Bravecold](https://github.com/Bravecold/FCampOps/tree/master/WindowsServer)
|**Inital_v0.1.ps1**|Automate some local and domain enumeration and generate html report| [BlackSnufkin](https://github.com/BlackSnufkin/PT-ToolKit/tree/main/PowerShell-Scripts)
|**Invoke-CheckForAzureAD**|check if given domain has AzureAD | [BlackSnufkin](https://github.com/BlackSnufkin/PT-ToolKit/tree/main/PowerShell-Scripts)
|**Invoke-HuntSMBShares**|This function can be used to inventory to SMB shares on the current Active Directory domain and identify potentially high risk exposures. It will automatically generate csv files and html summary report.|[NetSPI](https://github.com/NetSPI/PowerShell)
|**Invoke-Portscan**|Does a simple port scan using regular sockets, based (pretty) loosely on nmap| [webstersprodigy](https://github.com/webstersprodigy/PowerSploit/blob/Portscan/Recon/Invoke-Portscan.ps1)
|**MailSniper**|MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.). It can be used as a non-administrative user to search their own email, or by an administrator to search the mailboxes of every user in a domain.|[dafthack](https://github.com/dafthack/MailSniper)
|**MS17-010_Scanner**|Scan if the target computer is vulnerable to the EthernalBlue exploit (MS17-010) | [Source_WAS_vletoux](https://github.com/vletoux/pingcastle)
|**o365Recon**| retrieve information via O365 and AzureAD with a valid cred | [o365recon](https://github.com/nyxgeek/o365recon)
|**SharpHound**|Runs the BloodHound C# Ingestor using reflection. The assembly is stored in this file.|[BloodHoundAD](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1)
|**Test-AzureADUserExistence**|Check if an account exists in Azure AD for specified email addresses | [it-koehler](https://blog.it-koehler.com/en/Archive/3320)

---

## Initial_Access

| Script| Description | Credit & Source |
| --------------- | --------------- | --------------- |
|**DomainPasswordSpray-Kerb_Auth**|DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!|[dafthack](https://github.com/dafthack/DomainPasswordSpray)
|**DomainPasswordSpray**|DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. It will automatically generate a userlist from the domain which excludes accounts that are expired, disabled locked out, or within 1 lockout attempt.|[](https://github.com/mdavis332/DomainPasswordSpray)
|**Invoke-AzureAdPasswordSprayAttack**|Perform a password spray attack against Azure AD | [danielchronlund](https://danielchronlund.com/2020/03/17/azure-ad-password-spray-attacks-with-powershell-and-how-to-defend-your-tenant/)

---

## Privilege-Escalation

| Script| Description | Credit & Source |
| --------------- | --------------- | --------------- |
|**FilelessUACBypass**|The purpose of this script is to aggregate many popular UAC bypass methods into one file. All current tools do a mediocre job at bypassing uAC. This is because many UAC Bypass methods require hijacking DLLs and using common "elevator" dlls as their hijack method. The aim of this script is to aggregate all fileless bypass methods wrapped into one PowerShell script. |[RhinoSecurityLabs](https://github.com/RhinoSecurityLabs/Aggressor-Scripts/blob/master/UACBypass/modules/FilelessUACBypass.ps1) 
|**Find-PotentiallyCrackableAccounts** | Retreive information about user accounts associated with SPN | [cyberark](https://github.com/cyberark/RiskySPN)
|**Invoke-SysPSexec**|Open CMD as system with psexec| [BlackSnufkin](https://github.com/BlackSnufkin/PT-ToolKit/tree/main/PowerShell-Scripts)
|**Invoke-Zerologon**|Scan if the target computer is vulnerable to the ZeroLogon exploit (CVE-2020-1472) | [BC-SECURITYe](https://github.com/BC-SECURITY/Invoke-ZeroLogon)
|**LAPSToolkit**|Tool to audit and attack LAPS environments|[leoloobeek](https://github.com/leoloobeek/LAPSToolkit)
|**PrivescCheck**|Privilege Escalation Enumeration Script for Windows|[itm4n](https://github.com/itm4n/PrivescCheck)
|**SessionGopher**|SessionGopher is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally.|[Arvanaghi](https://github.com/Arvanaghi/SessionGopher)

---

## Lateral_Movement

| Script| Description | Credit & Source |
| --------------- | --------------- | --------------- |
|**Invoke-TheHash**|PowerShell Pass The Hash Utils|[Kevin-Robertson](https://github.com/Kevin-Robertson/Invoke-TheHash)
|**Invoke-PsExec**|A rough port of Metasploit's psexec functionality | [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/PowershellScripts)
|**Invoke-WmiCommand**|Executes a PowerShell ScriptBlock on a target computer using WMI as a pure C2 channel. | [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/PowershellScripts)

---

## Misc

| Script| Description | Credit & Source |
| --------------- | --------------- | --------------- |
|**Add-RemoteRegBackdoor**|Implements a new remote registry backdoor that allows for the remote retrieval ofa system's machine account hash | [HarmJ0y](https://github.com/HarmJ0y/DAMP)
|**ADModuleImport** |  Import Powershell Active directory Module on any machine  | [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/ADModuleImport.ps1)
|**Invoke-BuildAnonymousSMBServer**|Use to build an anonymous SMB file server.|[3gstudent](https://github.com/3gstudent/Invoke-BuildAnonymousSMBServer)
|**ProxyTunnel**|Creates a TCP Tunnel through the default system proxy. As such, it automatically handles proxy authentication if ever required. | [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/PowershellScripts) 
|**Start-Webserver**|Starts powershell webserver| [MScholtese](https://github.com/MScholtes/WebServer)

---

## Defense_Evasion

| Script| Description | Credit & Source |
| --------------- | --------------- | --------------- |
|**Invoke-SharpLoader**|Load encrypted and compressed C# Code from a remote Webserver or from a local file straight to memory and execute it there|[S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)
| **AMSIbypass** | AMSI Bypass to run malicious tools| [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)
|**Invoke-Phant0m**|This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads | [hlldze](https://github.com/hlldz/Phant0m)
|**MASK**|Download a script and encrypt it with given key and then write it to drive | Source Unkonw
|**Run-SecurePS**|Open PowerShell Console without AMSI| [S3cur3Th1sSh1te](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/PowershellScripts)

### Obfuscation

| Script| Description | Credit & Source |
| --------------- | --------------- | --------------- |
|**Invoke-Obfuscation**|Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.|[danielbohannon](https://github.com/danielbohannon/Invoke-Obfuscation)
| **BetterXencrypt**|A better version of Xencrypt.Xencrypt it self is a Powershell runtime crypter designed to evade AVs.|[GetRektBoy724](https://github.com/GetRektBoy724/BetterXencrypt)
|**Invoke-PSImage**|Encodes a PowerShell script in the pixels of a PNG file and generates a oneliner to execute|[peewpw](https://github.com/peewpw/Invoke-PSImage)
|**xencrypt**|A PowerShell script anti-virus evasion tool|[the-xentropy](https://github.com/the-xentropy/xencrypt)

---

## Payloads

### Payloads_Dev

| Script| Description | Credit & Source |
| --------------- | --------------- | --------------- |
|**QuickMacro**|Standalone Powershell script that will generate a malicious Microsoft Office document with a specified payload and persistence method | [enigma0x3](https://github.com/enigma0x3/Generate-Macro) 

### Reverse_Shells  

| Script| Description | Credit & Source |
| --------------- | --------------- | --------------- |
|**RevShell / RevShell-2**|Reverse Shell in powerhsell Cahnge IP and port | [BlackSnufkin](https://github.com/BlackSnufkin/PT-ToolKit/tree/main/PowerShell-Scripts) 

---

## Credential_Dumping 

| Script| Description | Credit & Source |
| --------------- | --------------- | --------------- |
| **Dump-Lsass_v1 / Dump-Lsass_v2** | Dump lsass process | [BlackSnufkin](https://github.com/BlackSnufkin/PT-ToolKit/tree/main/PowerShell-Scripts) 
| **Get-ClearTextPassword** |obtain clear text passwords from cached locations as well as the from the Windows Registry|[tobor88](https://github.com/tobor88/PowerShell-Red-Team)
|**Get-Wifi**|retrieve all wifi passwords in clear text| [BlackSnufkin](https://github.com/BlackSnufkin/PT-ToolKit/tree/main/PowerShell-Scripts) 
|**Impa-SecretDump**|impacket secretdump in binary format embeded into powershell script|[BlackSnufkin](https://github.com/BlackSnufkin/PT-ToolKit/tree/main/PowerShell-Scripts) 
|**Invoke-BooMiniDump**|Create a memory dump of a process using Boolang | [itm4n](https://github.com/itm4n/Pentest-Tools/tree/master/04_windows)
|**Invoke-InternalMonologue**|Retrieves NTLMv1 challenge-response for all available users | [eladshamir](https://github.com/eladshamir/Internal-Monologue)
|**Invoke-MassMimikatz-PsRemoting**|This script can be used to run mimikatz on multiple servers from both domain and non-domain systems using psremoting. It supports auto-targeting of domain systems, filtering systems by os/winrm, and limiting the number of systems to run mimikatz on.  It returns the list of credentials to the pipeline so they can be used by other cmdlets that includesdomain, username, password type, password, if user is a domain admin, and if user is an enterprise admin.| [NetSPI](https://github.com/NetSPI/PowerShell)
|**Invoke-Mimikatz**|Updated Version of Invoke-Mimikatz with the latest release of Mimikatz|[samratashok](https://github.com/samratashok/nishang/blob/master/Gather/Invoke-Mimikatz.ps1)
|**Invoke-PowerSAMHashes**| Dump hashes from SAM registry| [EmpireProject](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-PowerDump.ps1)
|**Invoke-SharpKatz**|Powershell Script that loads the binary of **SharpKatz** into memory | [BlackSnufkin](https://github.com/BlackSnufkin/PT-ToolKit/tree/main/PowerShell-Scripts)
|**NTLMExtract**|Extract all local NTLM user password hashes from the registry handling latest AES-128-CBC with IV obfuscation techniques | [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/PowershellScripts) 
|**PowerLsassSilentProcessExit**|PowerShell script to dump lsass.exe process memory to disk for credentials extraction via silent process exit mechanism | [CompassSecurity](https://github.com/CompassSecurity/PowerLsassSilentProcessExit) 
|**RemoteHashRetrieval**|Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine | [HarmJ0y](https://github.com/HarmJ0y/DAMP) 
|**ShadowDump**|PoC for CVE-2021-36934, Dumps the hives from the system's Volume Shadow Copies (This is a modified version) | [Based on WiredPulse](https://github.com/WiredPulse/Invoke-HiveNightmare)

---

## Offensive-Powershell

| Script| Description | Credit & Source |
| --------------- | --------------- | --------------- |
|**Inveigh**|Powershell IPv4/IPv6 machine-in-the-middle tool for penetration testers|[Kevin-Robertson](https://github.com/Kevin-Robertson/Inveigh)
|**PowerSharpPack**|Many usefull offensive CSharp Projects wraped into Powershell for easy usage.|[S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/PowerSharpPack)




