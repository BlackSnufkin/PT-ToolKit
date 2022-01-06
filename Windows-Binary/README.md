# Windows-Binary 
Some tools i found on github and compiled them 

---

## Table of Contents
- [Enumeration](#Enumeration)
- [Privilege-Escalation](#Privilege-Escalation)
- [Offensive-Tools](#Offensive-Tools)
- [Defense_Evasion](#Defense_Evasion)
- [Payloads](#Payloads)
- [Credential_Dumping](#Credential_Dumping)

---

## Enumeration
|Tool Name|Description|Credit & Source|
|-----|-----------|----|
| **ADCollector** | ADCollector is a lightweight tool that enumerates the Active Directory environment to identify possible attack vectors. It will give you a basic understanding of the configuration/deployment of the environment as a starting point.|[dev-2null](https://github.com/dev-2null/ADCollector)
|**EDRHunt** | EDRHunt scans Windows services, drivers, processes, registry for installed EDRs (Endpoint Detection And Response). | [FourCoreLabs](https://github.com/FourCoreLabs/EDRHunt)
|**PingCastle** | Ping Castle is a tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework. It does not aim at a perfect evaluation but rather as an efficiency compromise.|[vletoux](https://github.com/vletoux/pingcastle)
|**SharpEDRChecker** | New and improved C# Implementation of Invoke-EDRChecker. Checks running processes, process metadata, Dlls loaded into your current process and each DLLs metadata, common install directories, installed services and each service binaries metadata, installed drivers and each drivers metadata, all for the presence of known defensive products such as AV's, EDR's and logging tools | [PwnDexter](https://github.com/PwnDexter/SharpEDRChecker)
|**SharpHound**| C# Data Collector for the BloodHound Project, Version 3|[BloodHoundAD](https://github.com/BloodHoundAD/SharpHound3)
|**SharpShares** | Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain | [mitchmoser](https://github.com/mitchmoser/SharpShares)
|**SharpShares2** | Enumerate all network shares in the current domain. Also, can resolve names to IP addresses.| [djhohnstein](https://github.com/djhohnstein/SharpShares)

---

## Network
|Tool Name|Description|Credit & Source|
|-----|-----------|----|
|**NetworkMiner** |NetworkMiner is an open source Network Forensic Analysis Tool (NFAT) for Windows (but also works in Linux / Mac OS X / FreeBSD). NetworkMiner can be used as a passive network sniffer/packet capturing tool in order to detect operating systems, sessions, hostnames, open ports etc. without putting any traffic on the network. NetworkMiner can also parse PCAP files for off-line analysis and to regenerate/reassemble transmitted files and certificates from PCAP files|[netresec](https://www.netresec.com/?page=networkminer)
|**BruteShark**|BruteShark is a Network Forensic Analysis Tool (NFAT) that performs deep processing and inspection of network traffic (mainly PCAP files, but it also capable of directly live capturing from a network interface). It includes: password extracting, building a network map, reconstruct TCP sessions, extract hashes of encrypted passwords and even convert them to a Hashcat format in order to perform an offline Brute Force attack.|[odedshimon](https://github.com/odedshimon/BruteShark)
|**Inveigh**|.NET IPv4/IPv6 machine-in-the-middle tool for penetration testers |[Kevin-Robertson](https://github.com/Kevin-Robertson/Inveigh)
|**TCPDUMP**|TCPDUMP for Windows is built with our own traffic capturectechnology Packet Sniffer SDK, which is used in EtherSensor as well. We stopped selling Packet Sniffer SDK in 2008, after the first release of EtherSensor. Currently we are increasingly receiving requests to make PSSDK open-source, but we haven't decided yet.If you want to comment on this issue, please email us.|[microolap](https://www.microolap.com/products/network/tcpdump/)

---

## Privilege-Escalation
|Tool Name|Description|Credit & Source|
|-----|-----------|----|
|**SweetPotato**|A collection of various native Windows privilege escalation techniques from service accounts to SYSTEM|[CCob](https://github.com/CCob/SweetPotato)
|**dazzleUP**|A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.|[hlldz](https://github.com/hlldz/dazzleUP)
|**Seatbelt**|Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.|[GhostPack](https://github.com/GhostPack/Seatbelt)
|**WinPEAS**|WinPEAS is a script that search for possible paths to escalate privileges on Windows hosts. The checks are explained on [book.hacktricks.xyz](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation)|[carlospolop](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe)

---

## Offensive-Tools

|Tool Name|Description|Credit & Source|
|-----|-----------|----|
|**Impacket-Windows** |Standalone binaries for Windows of Impacket's examples| [ropnop](https://github.com/ropnop/impacket_static_binaries)
|**SharpMapExec**| A sharpen version of [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec). This tool is made to simplify penetration testing of networks and to create a swiss army knife that is made for running on Windows which is often a requirement during insider threat simulation engagements.|[cube0x0](https://github.com/cube0x0/SharpMapExec)
|**Sysintenals_Selected**|advanced system utilities and technical information. Whether you’re an IT Pro or a developer, you’ll find Sysinternals utilities to help you manage, troubleshoot and diagnose your Windows systems and applications.|[microsoft](https://docs.microsoft.com/en-us/sysinternals/downloads/)
|**kerbrute** | A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication | [ropnop](https://github.com/ropnop/kerbrute)
|**SharpNoPSExec**| File less command execution for lateral movement. SharpNoPSExec will perform the lateralmovement without touching disk and without creating a new service to avoid detection |[juliourena](https://github.com/juliourena/SharpNoPSExec)
|**SharpRDPHijack** | Sharp RDP Hijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions|[bohops](https://github.com/bohops/SharpRDPHijack)
|**SharpSpray**|Active Directory password spraying tool. Auto fetches user list and avoids potential lockouts.|[iomoath](https://github.com/iomoath/SharpSpray)

---

## Defense_Evasion

|Tool Name|Description|Credit & Source|
|-----|-----------|----|
| **Ghost-In-The-Logs** |This tool allows you to evade sysmon and windows event logging, my blog post about it can be found [here](https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/)| [bats3c](https://github.com/bats3c/Ghost-In-The-Logs)
|**Phant0m**|Windows Event Log Killer|[hlldz](https://github.com/hlldz/Phant0m)
|**PowerShx** |Unmanaged PowerShell execution using DLLs or a standalone executable., PowerShx is a rewrite and expansion on the PowerShdll project. PowerShx provide functionalities for bypassing AMSI and running PS Cmdlets.|[iomoath](https://github.com/iomoath/PowerShx)
|**unDefender**|Killing your preferred antimalware by abusing native symbolic links and NT paths.|[APTortellini](https://github.com/APTortellini/unDefender)
|**nopowershell**|PowerShell rebuilt in C# for Red Teaming purposes|[bitsadmin](https://github.com/bitsadmin/nopowershell)
|**PowerShdll** | Run PowerShell with rundll32. Bypass software restrictions.|[p3nt4](https://github.com/p3nt4/PowerShdll)

---

## Payloads

### Payloads-Dev

|Tool Name|Description|Credit & Source|
|-----|-----------|----|
|**donut**|Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters|[TheWover](https://github.com/TheWover/donut)
|**MacroPhishing** |Word resources for phishing with macros. Includes "Click Enable Content" bait and decoy document deployment. The bait was created by me, but inspired by cerber ransomware document samples.|[TheKevinWang](https://github.com/TheKevinWang/MacroPhishing)
|**mortar** | red teaming evasion technique to defeat and divert detection and prevention of security products | [0xsp-SRD](https://github.com/0xsp-SRD/mortar)
|**ThreatCheck**|Identifies the bytes that Microsoft Defender / AMSI Consumer flags on.|[rasta-mouse](https://github.com/rasta-mouse/ThreatCheck)
|**DefenderCheck**|Identifies the bytes that Microsoft Defender flags on.|[matterpreter](https://github.com/matterpreter/DefenderCheck)
|**macro_pack** |macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.<br> This tool can be used for redteaming, pentests, demos, and social engineering assessments. macro_pack will simplify antimalware solutions bypass and automatize the process from vb source to final Office document or other payload type.|[sevagas](https://github.com/sevagas/macro_pack)
|**SigPirate**| Copy authenticode or Catalog signatures to unsigned binaries | [xorrior](https://github.com/xorrior/Random-CSharpTools)
|**Skrull**| Skrull is a malware DRM, that prevents Automatic Sample Submission by AV/EDR and Signature Scanning from Kernel | [aaaddress1](https://github.com/aaaddress1/Skrull)


### Executaion
|Tool Name|Description|Credit & Source|
|-----|-----------|----|
|**PR0CESS**|some gadgets about windows process and ready to use :)|[aaaddress1](https://github.com/aaaddress1/PR0CESS)
|**RunPE-In-Memory**|Run a Exe File (PE Module) in memory (like an Application Loader)|[aaaddress1](https://github.com/aaaddress1/RunPE-In-Memory)
|**wowInjector**|PoC: Exploit 32-bit Thread Snapshot of WOW64 to Take Over $RIP & Inject & Bypass Antivirus HIPS (HITB 2021)|[aaaddress1](https://github.com/aaaddress1/wowInjector)
|**RunPE**|C# Reflective loader for unmanaged binaries.|[nettitude](https://github.com/nettitude/RunPE)
|**ThreadStackSpoofing** | PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts| [mgeeky](https://github.com/mgeeky/ThreadStackSpoofer) 

---

## Credential_Dumping

|Tool Name|Description|Credit & Source|
|-----|-----------|----
|**NanoDump**|Dump LSASS like you mean it|[helpsystems](https://github.com/helpsystems/nanodump)
|**outflanknl-Dumpert**|LSASS memory dumper using direct system calls and API unhooking.|[outflanknl](https://github.com/outflanknl/Dumpert)
|**PPLdump**| This tool implements a __userland__ exploit that was initially discussed by James Forshaw (a.k.a. [@tiraniddo](https://twitter.com/tiraniddo)) - in this [blog post](https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html) - for __dumping the memory of any PPL__ as an administrator. I wrote two blog posts about this tool. The first part is about Protected Processes concepts while the second one dicusses the bypass technique itself.<br> - __Blog post part #1__: [Do You Really Know About LSA Protection (RunAsPPL)?](https://itm4n.github.io/lsass-runasppl/) <br>- __Blog post part #2__: [Bypassing LSA Protection in Userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) | [itm4n](https://github.com/itm4n/PPLdump)
|**ATPMiniDump**|Evading WinDefender ATP credential-theft|[b4rtik](https://github.com/b4rtik/ATPMiniDump)
|**CQDumpHashV2** | Dump SAM Hashes |[BlackDiverX](https://github.com/BlackDiverX/cqtools)
|**DumpNParse**|A Combination LSASS Dumper and LSASS Parser. All Credit goes to @slyd0g and @cube0x0.|[icyguider](https://github.com/icyguider/DumpNParse)
|**lsass-dumper**|Dump lsass.exe generating a file with the hostname and date in txt format using C++.|[ricardojoserf](https://github.com/ricardojoserf/lsass-dumper)
|**LsassSilentProcessExit** | New method of causing WerFault.exe to dump lsass.exe process memory to disk for credentials extraction via silent process exit mechanism without crasing lsass.|[deepinstinct](https://github.com/deepinstinct/LsassSilentProcessExit)
|**LsassUnhooker**|Little program written in C# to bypass EDR hooks and dump the content of the lsass process|[roberreigada](https://github.com/roberreigada/LsassUnhooker)
|**SharoSecDump**| .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py | [G0ldenGunSec](https://github.com/G0ldenGunSec/SharpSecDump)
|**SharpHandler**|The tool is now live, but still in beta, I would not recommend using this in opsec heavy engagements for now :P you'll look like a fool if this tool flunks and you burn your opsec ;)|[jfmaes](https://github.com/jfmaes/SharpHandler)

### Katz-Family
Mimikatz Style Tools

|Tool Name|Description|Credit & Source|
|-----|-----------|----|
|**mimikatz**|A little tool to play with Windows security + [Mimikatz log parser](https://github.com/chernodv/JSMimiLogParser), written in JS, hosted in a browser (Works Offline)|[gentilkiwi](https://github.com/gentilkiwi/mimikatz)
|**BetterSafetyKatz**|Fork of SafetyKatz that dynamically fetches the latest pre-compiled release of Mimikatz directly from gentilkiwi GitHub repo, runtime patches signatures and uses SharpSploit DInvoke to PE-Load into memory.|[Flangvik](https://github.com/Flangvik/BetterSafetyKatz)
|**MagnusKatz**| Research project for understanding how Mimikatz work and being better at C | [magnusstubman](https://github.com/magnusstubman/MagnusKatz)
|**SafetyKatz**|SafetyKatz is a combination of slightly modified version of @gentilkiwi's Mimikatz project and @subTee's .NET PE Loader|[GhostPack](https://github.com/GhostPack/SafetyKatz)
|**SharpKatz**| Porting of mimikatz sekurlsa::logonpasswords, sekurlsa::ekeys and lsadump::dcsync commands |[b4rtik](https://github.com/b4rtik/SharpKatz)
