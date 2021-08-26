# PowerShell Scripts
PowerShell Scripts from various sources for Penetration-Testing and Red-Team engagements




| Script| Description | Source |
| --------------- | --------------- | --------------- |
| **ADModuleImport.ps1** |  Import Powershell Active directory Module on any machine  | [Source](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/ADModuleImport.ps1) | 
| **AMSIbypass.ps1** | AMSI Bypass to run malicious tools| [Source](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) |
|**Add-RemoteRegBackdoor.ps1**|Implements a new remote registry backdoor that allows for the remote retrieval ofa system's machine account hash | [Source](https://github.com/HarmJ0y/DAMP)
| **BlueKeepScan.ps1** | Scan if the target computer is vulnerable to the BlueKeep exploit (CVE-2019-0708)| [Source_WAS*](https://github.com/vletoux/pingcastle)
| **Dump_Lsass_v1-2.ps1** | Dump lsass process | Mine =) |
| **Find-LOLBAS.ps1** | Enumerating living off the land binaries and scripts on a system |[Source](https://github.com/NotoriousRebel/Find-LOLBAS)
| **Find-PotentiallyCrackableAccounts.ps1** | Retreive information about user accounts associated with SPN | [Source](https://github.com/cyberark/RiskySPN)
| **Get-AzureDomainInfo.ps1** | PowerShell functions for enumerating information from AzureAD domains | [Source](https://github.com/NetSPI/MicroBurst)
| **Get-ClearTextPassword.ps1** |obtain clear text passwords from cached locations as well as the from the Windows Registry|[Source](https://github.com/tobor88/PowerShell-Red-Team) 
|**Get-LdapInfo.ps1**|Perform LDAP Queries of the current domain| [Source](https://github.com/tobor88/PowerShell-Red-Team)
|**Get-NetSessionEnum.ps1**|This script automates the enumeration of NetSessionEnum (network sessions of connected users in the domain)| [Source](https://github.com/YossiSassi/Get-NetSessionEnum)
|**Get-NetworkShareInfo.ps1**|This cmdlet is used to discover information associated with a network share such as the physical location of the network share, its creation date, and name| [Source](https://github.com/tobor88/PowerShell-Red-Team)
|**Get-UserLogon.ps1**|retrieve logged on users on remote machine | [Source](https://github.com/Bravecold/FCampOps/tree/master/WindowsServer)
|**Get-Wifi.ps1**|retrieve all wifi passwords| Mine =)
|**impa-SecretDump.ps1**|impacket secretdump in binary format embeded into powershell script| Mine =)
|**Inital_v0.1.ps1**|Automate some local and domain enumeration and generate html report| Mine =)
|**Invoke-adPEAS.ps1**| Automate Active Directory enumeration| [Source](https://github.com/61106960/adPEAS)
|**Invoke-AzureAdPasswordSprayAttack.ps1**|Perform a password spray attack against Azure AD | [Source](https://danielchronlund.com/2020/03/17/azure-ad-password-spray-attacks-with-powershell-and-how-to-defend-your-tenant/)
|**Invoke-BloodHound.ps1**|Runs the BloodHound C# Ingestor using reflection. The assembly is stored in this file | [Source](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)
|**Invoke-BooMiniDump.ps1**|Create a memory dump of a process using Boolang | [Source](https://github.com/itm4n/Pentest-Tools/tree/master/04_windows)
|**Invoke-CheckForAzureAD.ps1**|check if given domain has AzureAD | Mine =)
|**Invoke-InternalMonologue.ps1**|Retrieves NTLMv1 challenge-response for all available users | [Source](https://github.com/eladshamir/Internal-Monologue)
|**Invoke-Phant0m.ps1**|This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads | [Source](https://github.com/hlldz/Phant0m)
|**Invoke-Portscan.ps1**|Does a simple port scan using regular sockets, based (pretty) loosely on nmap| [Source](https://github.com/webstersprodigy/PowerSploit/blob/Portscan/Recon/Invoke-Portscan.ps1)
|**Invoke-PowerSAMHashes.ps1**| | [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-PowerDump.ps1)
|**Invoke-PsExec.ps1**|A rough port of Metasploit's psexec functionality | [Source](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/PowershellScripts)
|**Invoke-SharpEncrypt.ps1**|AES Encrypt and GZip CSharp Files | [Source](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)
|**Invoke-SharpLoader.ps1**|Loads AES Encrypted compressed CSharp Files from a remote Webserver | [Source](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)
|**Invoke-SysPSexec.ps1**|Open CMD as system with psexec| [Source]()
|**Invoke-WmiCommand.ps1**|Executes a PowerShell ScriptBlock on a target computer using WMI as a pure C2 channel. | [Source](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/PowershellScripts)
|**Invoke-Zerologon.ps1**|Scan if the target computer is vulnerable to the ZeroLogon exploit (CVE-2020-1472) | [Source](https://github.com/BC-SECURITY/Invoke-ZeroLogon)
|**MASK.ps1**|Download a script and encrypt it with given key and then write it to drive | Source Unkonw 
|**MS17-010_Scanner.ps1**|Scan if the target computer is vulnerable to the EthernalBlue exploit (MS17-010) | [Source_WAS*](https://github.com/vletoux/pingcastle) 
|**NTLMExtract.ps1**|Extract all local NTLM user password hashes from the registry handling latest AES-128-CBC with IV obfuscation techniques | [Source](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/PowershellScripts) 
|**PowerLsassSilentProcessExit.ps1**|PowerShell script to dump lsass.exe process memory to disk for credentials extraction via silent process exit mechanism | [Source](https://github.com/CompassSecurity/PowerLsassSilentProcessExit) 
|**ProxyTunnel.ps1**|Creates a TCP Tunnel through the default system proxy. As such, it automatically handles proxy authentication if ever required. | [Source](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/PowershellScripts) 
|**QuickMacro.ps1**|Standalone Powershell script that will generate a malicious Microsoft Office document with a specified payload and persistence method | [Source](https://github.com/enigma0x3/Generate-Macro) 
|**RemoteHashRetrieval.ps1**|Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine | [Source](https://github.com/HarmJ0y/DAMP) 
|**RevShell.ps1 / RevShell-2.ps1**|Reverse Shell in powerhsell Cahnge IP and port | Mine =) 
|**Run-SecurePS.ps1**|Open PowerShell Console without AMSI| [Source](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/PowershellScripts) 
|**ShadowDump.ps1**|PoC for CVE-2021-36934, Dumps the hives from the system's Volume Shadow Copies (This is a modified version) | [Source](https://github.com/WiredPulse/Invoke-HiveNightmare) 
|**Start-Webserver.ps1**|Starts powershell webserver| [Source](https://github.com/MScholtes/WebServer) 

