# Windows Binary 
Some tools i found on gituhb and compiled them

| Tool Name| Description | Source |
| --------------- | --------------- | --------------- |
| ADCollector | ADCollector is a lightweight tool that enumerates the Active Directory environment to identify possible attack vectors. It will give you a basic understanding of the configuration/deployment of the environment as a starting point.|[dev-2null](https://github.com/dev-2null/ADCollector)
| Ghost-In-The-Logs |This tool allows you to evade sysmon and windows event logging, my blog post about it can be found [here](https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/)| [bats3c](https://github.com/bats3c/Ghost-In-The-Logs)
|Impacket-Windows |Standalone binaries for Windows of Impacket's examples| [ropnop](https://github.com/ropnop/impacket_static_binaries)
|PPLdump|This tool implements a __userland__ exploit that was initially discussed by James Forshaw (a.k.a. [@tiraniddo](https://twitter.com/tiraniddo)) - in this [blog post](https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html) - for __dumping the memory of any PPL__ as an administrator. I wrote two blog posts about this tool. The first part is about Protected Processes concepts while the second one dicusses the bypass technique itself.<br> - __Blog post part #1__: [Do You Really Know About LSA Protection (RunAsPPL)?](https://itm4n.github.io/lsass-runasppl/) <br>- __Blog post part #2__: [Bypassing LSA Protection in Userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) | [itm4n](https://github.com/itm4n/PPLdump)
|SharpMapExec|A sharpen version of [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec). This tool is made to simplify penetration testing of networks and to create a swiss army knife that is made for running on Windows which is often a requirement during insider threat simulation engagements.|[cube0x0](https://github.com/cube0x0/SharpMapExec)
|SysInternals_Selected | Some selected tools form Sysinternals Suite that i found used over and over agian| [microsoft](https://docs.microsoft.com/en-us/sysinternals/downloads/)
|CQDumpHashV2 |Dump SAM Hashes |[BlackDiverX](https://github.com/BlackDiverX/cqtools)
|PingCastle |Ping Castle is a tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework. It does not aim at a perfect evaluation but rather as an efficiency compromise.|[vletoux](https://github.com/vletoux/pingcastle)
|PowerShdll |Run PowerShell with rundll32. Bypass software restrictions.|[p3nt4](https://github.com/p3nt4/PowerShdll)
|SharpRDPHijack |Sharp RDP Hijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions|[bohops](https://github.com/bohops/SharpRDPHijack)
|SharpShares | Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain | [mitchmoser](https://github.com/mitchmoser/SharpShares)
