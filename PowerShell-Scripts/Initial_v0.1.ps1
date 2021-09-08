$ErrorActionPreference = "SilentlyContinue"
$Time = (Get-Date)
[string]$StartTime = $Time | Get-Date -UFormat "%d-%m-%Y_%H.%M"

# Create filename for HTMLReport

[string]$Hostname = $ENV:COMPUTERNAME
[string]$FileName = "InitalScript_" + $StartTime + '_' + $Hostname + '.html'
$HTMLReportFile = (Join-Path $PWD $FileName)

# Header for HTML table formatting

$HTMLReportHeader = @"
    <style>
        h1 {
            font-family: Arial, Helvetica, sans-serif;
            color: #e68a00;
            font-size: 28px;
        }
    
        h2 {
            font-family: Arial, Helvetica, sans-serif;
            color: #000099;
            font-size: 16px;
        }
    
    
       table {
		    font-size: 12px;
		    border: 0px; 
		    font-family: Arial, Helvetica, sans-serif;
	    } 
	
        td {
		    padding: 4px;
		    margin: 0px;
		    border: 0;
	    }
	
        th {
            background: #395870;
            background: linear-gradient(#49708f, #293f50);
            color: #fff;
            font-size: 11px;
            text-transform: uppercase;
            padding: 10px 15px;
            vertical-align: middle;
	    }
        tbody tr:nth-child(even) {
            background: #f0f0f2;
        }
    
        #CreationDate {
            font-family: Arial, Helvetica, sans-serif;
            color: #ff3300;
            font-size: 12px;
        }
        .StopStatus {
            color: #ff0000;
        }
    
  
        .RunningStatus {
            color: #008000;
        }
    </style>
"@


# Attempt to write out HTML report header and exit if there isn't sufficient permission
try {
	ConvertTo-Html -Title "System Report" -Head $HTMLReportHeader `
 		-Body "<H1>System Enumeration Report for $($Env:ComputerName) - $($Env:UserName)</H1>`n<div class='aLine'></div>" `
 		| Out-File $HTMLReportFile -ErrorAction Stop
}
catch { "`n[-] Error writing enumeration output to disk! Check your permissions on $PWD.`n$($Error[0])`n"; return }


# Print initial execution status
"[+] Inital Script"
"[+] STARTTIME:`t$StartTime"
"[+] PID:`t$PID`n"

function Get-EDRCheck {

	function Obj {
		param([Parameter(Mandatory = 1)] [hashtable]$Props)
		return New-Object PSCustomObject -Property $Props
	}
	# Driver Check
	$Result = switch ((Get-ChildItem $env:SystemDrive\Windows\System32\drivers | Where-Object Name -Match .sys$).Name) {
		##########################################################################
		#-------DRIVER---------####################-------------EDR-------------##
		atrsdfw.sys { Obj @{ Driver = $_; EDR = 'Altiris Symantec' } }
		avgtpx86.sys { Obj @{ Driver = $_; EDR = 'AVG Technologies' } }
		avgtpx64.sys { Obj @{ Driver = $_; EDR = 'AVG Technologies' } }
		naswSP.sys { Obj @{ Driver = $_; EDR = 'Avast' } }
		edrsensor.sys { Obj @{ Driver = $_; EDR = 'BitDefender SRL' } }
		CarbonBlackK.sys { Obj @{ Driver = $_; EDR = 'Carbon Black' } }
		parity.sys { Obj @{ Driver = $_; ERD = 'Carbon Black' } }
		csacentr.sys { Obj @{ Driver = $_; EDR = 'Cisco' } }
		csaenh.sys { Obj @{ Driver = $_; EDR = 'Cisco' } }
		csareg.sys { Obj @{ Driver = $_; EDR = 'Cisco' } }
		csascr.sys { Obj @{ Driver = $_; EDR = 'Cisco' } }
		csaav.sys { Obj @{ Driver = $_; EDR = 'Cisco' } }
		csaam.sys { Obj @{ Driver = $_; EDR = 'Cisco' } }
		rvsavd.sys { Obj @{ Driver = $_; EDR = 'CJSC Returnil Software' } }
		cfrmd.sys { Obj @{ Driver = $_; EDR = 'Comodo Security' } }
		cmdccav.sys { Obj @{ Driver = $_; EDR = 'Comodo Security' } }
		cmdguard.sys { Obj @{ Driver = $_; EDR = 'Comodo Security' } }
		CmdMnEfs.sys { Obj @{ Driver = $_; EDR = 'Comodo Security' } }
		MyDLPMF.sys { Obj @{ Driver = $_; EDR = 'Comodo Security' } }
		im.sys { Obj @{ Driver = $_; EDR = 'CrowdStrike' } }
		CSDeviceControl.sys { Obj @{ Driver = $_; EDR = 'CrowdStrike' } }
		csagent.sys { Obj @{ Driver = $_; EDR = 'CrowdStrike' } }
		CybKernelTracker.sys { Obj @{ Driver = $_; EDR = 'CyberArk Software' } }
		CRExecPrev.sys { Obj @{ Driver = $_; EDR = 'Cybereason' } }
		CyOptics.sys { Obj @{ Driver = $_; EDR = 'Cylance Inc.' } }
		CyProtectDrv32.sys { Obj @{ Driver = $_; EDR = 'Cylance Inc.' } }
		CyProtectDrv64.sys.sys { Obj @{ Driver = $_; EDR = 'Cylance Inc.' } }
		groundling32.sys { Obj @{ Driver = $_; EDR = 'Dell Secureworks' } }
		groundling64.sys { Obj @{ Driver = $_; EDR = 'Dell Secureworks' } }
		esensor.sys { Obj @{ Driver = $_; EDR = 'Endgame' } }
		edevmon.sys { Obj @{ Driver = $_; EDR = 'ESET' } }
		ehdrv.sys { Obj @{ Driver = $_; EDR = 'ESET' } }
		FeKern.sys { Obj @{ Driver = $_; EDR = 'FireEye' } }
		WFP_MRT.sys { Obj @{ Driver = $_; EDR = 'FireEye' } }
		xfsgk.sys { Obj @{ Driver = $_; EDR = 'F-Secure' } }
		fsatp.sys { Obj @{ Driver = $_; EDR = 'F-Secure' } }
		fshs.sys { Obj @{ Driver = $_; EDR = 'F-Secure' } }
		HexisFSMonitor.sys { Obj @{ Driver = $_; EDR = 'Hexis Cyber Solutions' } }
		klifks.sys { Obj @{ Driver = $_; EDR = 'Kaspersky' } }
		klifaa.sys { Obj @{ Driver = $_; EDR = 'Kaspersky' } }
		Klifsm.sys { Obj @{ Driver = $_; EDR = 'Kaspersky' } }
		mbamwatchdog.sys { Obj @{ Driver = $_; EDR = 'Malwarebytes' } }
		mfeaskm.sys { Obj @{ Driver = $_; EDR = 'McAfee' } }
		mfencfilter.sys { Obj @{ Driver = $_; EDR = 'McAfee' } }
		PSINPROC.SYS { Obj @{ Driver = $_; EDR = 'Panda Security' } }
		PSINFILE.SYS { Obj @{ Driver = $_; EDR = 'Panda Security' } }
		amfsm.sys { Obj @{ Driver = $_; EDR = 'Panda Security' } }
		amm8660.sys { Obj @{ Driver = $_; EDR = 'Panda Security' } }
		amm6460.sys { Obj @{ Driver = $_; EDR = 'Panda Security' } }
		eaw.sys { Obj @{ Driver = $_; EDR = 'Raytheon Cyber Solutions' } }
		SAFE-Agent.sys { Obj @{ Driver = $_; EDR = 'SAFE-Cyberdefense' } }
		SentinelMonitor.sys { Obj @{ Driver = $_; EDR = 'SentinelOne' } }
		SAVOnAccess.sys { Obj @{ Driver = $_; EDR = 'Sophos' } }
		savonaccess.sys { Obj @{ Driver = $_; EDR = 'Sophos' } }
		sld.sys { Obj @{ Driver = $_; EDR = 'Sophos' } }
		pgpwdefs.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		GEProtection.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		diflt.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		sysMon.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		ssrfsf.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		emxdrv2.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		reghook.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		spbbcdrv.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		bhdrvx86.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		bhdrvx64.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		SISIPSFileFilter { Obj @{ Driver = $_; EDR = 'Symantec' } }
		symevent.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		vxfsrep.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		VirtFile.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		SymAFR.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		symefasi.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		symefa.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		symefa64.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		SymHsm.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		evmf.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		GEFCMP.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		VFSEnc.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		pgpfs.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		fencry.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		symrg.sys { Obj @{ Driver = $_; EDR = 'Symantec' } }
		ndgdmk.sys { Obj @{ Driver = $_; EDR = 'Verdasys Inc' } }
		ssfmonm.sys { Obj @{ Driver = $_; EDR = 'Webroot Software' } }
	} #########################################################################
	#
	# Res
	if (-not $Result) { return 'No known EDR Driver found...' }
	else { return $Result }
}

function Get-SysInfo {
<#
    .SYNOPSIS
    Gets basic system information from the host
    #>
	$os_info = gwmi Win32_OperatingSystem
	$uptime = [datetime]::ParseExact($os_info.LastBootUpTime.SubString(0,14),"yyyyMMddHHmmss",$null)
	$uptime = (Get-Date).Subtract($uptime)
	$uptime = ("{0} Days, {1} Hours, {2} Minutes, {3} Seconds" -f ($uptime.Days,$uptime.Hours,$uptime.Minutes,$uptime.Seconds))
	$date = Get-Date
	$IsHighIntegrity = [bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

	$SysInfoHash = @{
		HOSTNAME = $ENV:COMPUTERNAME
		IPADDRESSES = (@([System.Net.Dns]::GetHostAddresses($ENV:HOSTNAME)) | ForEach-Object { $_.IPAddressToString }) -join ", "
		OS = $os_info.caption + ' ' + $os_info.CSDVersion
		ARCHITECTURE = $os_info.OSArchitecture
		"DATE(UTC)" = $date.ToUniversalTime() | Get-Date -UFormat "%Y%m%d%H%M%S"
		"DATE(LOCAL)" = $date | Get-Date -UFormat "%Y%m%d%H%M%S%Z"
		INSTALLDATE = $os_info.INSTALLDATE
		UPTIME = $uptime
		USERNAME = $ENV:USERNAME
		DOMAIN = (gwmi Win32_ComputerSystem).DOMAIN
		LOGONSERVER = $ENV:LOGONSERVER
		PSVERSION = $PSVersionTable.PSVERSION.ToString()
		PSCOMPATIBLEVERSIONS = ($PSVersionTable.PSCOMPATIBLEVERSIONS) -join ', '
		PSSCRIPTBLOCKLOGGING = if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -EA 0).EnableScriptBlockLogging -eq 1) { "Enabled" } else { "Disabled" }
		PSTRANSCRIPTION = if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -EA 0).EnableTranscripting -eq 1) { "Enabled" } else { "Disabled" }
		PSTRANSCRIPTIONDIR = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -EA 0).OutputDirectory
		PSMODULELOGGING = if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -EA 0).EnableModuleLogging -eq 1) { "Enabled" } else { "Disabled" }
		LSASSPROTECTION = if ((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -EA 0).RunAsPPL -eq 1) { "Enabled" } else { "Disabled" }
		LAPS = if ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -EA 0).AdmPwdEnabled -eq 1) { "Enabled" } else { "Disabled" }
		UAC = if ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).EnableLUA -eq 1) { "Enabled" } else { "Disabled (UAC is Disabled)" }
		# LocalAccountTokenFilterPolicy = 1 disables local account token filtering for all non-rid500 accounts
		UACLOCALACCOUNTTOKENFILTERPOLICY = if ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).LocalAccountTokenFilterPolicy -eq 1) { "Disabled (PTH likely w/ non-RID500 Local Admins)" } else { "Enabled (Remote Administration restricted for non-RID500 Local Admins)" }
		UACFILTERADMINISTRATORTOKEN = if ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).FilterAdministratorToken -eq 1) { "Enabled (RID500 protected)" } else { "Disabled (PTH likely with RID500 Account)" }
		HIGHINTEGRITY = $IsHighIntegrity
		DENYRDPCONNECTIONS = [bool](Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -EA 0).FDenyTSConnections
	}

	# PS feels the need to randomly re-order everything when converted to an object so let's presort
	New-Object -TypeName PSobject -Property $SysInfoHash | Select-Object Hostname,OS,Architecture,"Date(UTC)","Date(Local)",InstallDate,UpTime,IPAddresses,Domain,Username,LogonServer,PSVersion,PSCompatibleVersions,PSScriptBlockLogging,PSTranscription,PSTranscriptionDir,PSModuleLogging,LSASSProtection,LAPS,UAC,UACLocalAccountTokenFilterPolicy,UACFilterAdministratorToken,HighIntegrity
}


function Get-ProcessInfo () {
<#
    .SYNOPSIS
    Gets detailed process information via WMI
    #>
	# Extra work here to include process owner and commandline using WMI
	Write-Verbose "Enumerating running processes..."
	$owners = @{}
	$commandline = @{}

	gwmi win32_process | ForEach-Object { $owners[$_.handle] = $_.getowner().user }
	gwmi win32_process | ForEach-Object { $commandline[$_.handle] = $_.commandline }

	$procs = Get-Process | Sort-Object -Property ID
	$procs | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name "Owner" -Value $owners[$_.id.ToString()] -Force }
	$procs | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name "CommandLine" -Value $commandline[$_.id.ToString()] -Force }

	return $procs
}


function Get-LocalUsers {
<#
    .SYNOPSIS
    Pulls local users and some of their properties.
    .DESCRIPTION
    Uses the [ADSI] object type to query user objects for group membership, password expiration, etc
    .LINK
    This function borrows the ADSI code from the following link:
    http://www.bryanvine.com/2015/08/powershell-script-get-localusers.html
    #>

	$LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "Domain='$($env:ComputerName)'"

	# Pull some additional properties that we don't get through Win32_UserAccount
	$LocalUserProps = ([adsi]"WinNT://$env:computerName").Children | Where-Object { $_.SchemaClassName -eq 'user' } | ForEach-Object {
		$_ | Select-Object @{ n = 'UserName'; e = { $_.Name } },
		@{ n = 'Disabled'; e = { if (($_.userflags.value -band 2) -eq 2) { $true } else { $false } } },
		@{ n = 'PasswordExpired'; e = { if ($_.PasswordExpired) { $true } else { $false } } },
		@{ n = 'PasswordNeverExpires'; e = { if (($_.userflags.value -band 65536) -eq 65536) { $true } else { $false } } },
		@{ n = 'PasswordAge'; e = { if ($_.PasswordAge[0] -gt 0) { [datetime]::Now.AddSeconds(- $_.PasswordAge[0]) } else { $null } } },
		@{ n = 'LastLogin'; e = { $_.LastLogin } },
		@{ n = 'Description'; e = { $_.Description } },
		@{ n = 'UserFlags'; e = { $_.userflags } }
	}

	# Add PasswordAge and LastLogin properties to our users enumerated via WMI
	$passwordage = @{}
	$lastlogin = @{}

	$LocalUserProps | ForEach-Object { $passwordage[$_.USERNAME] = $_.PasswordAge }
	$LocalUserProps | ForEach-Object { $lastlogin[$_.USERNAME] = $_.LastLogin }

	$LocalUsers | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name "PasswordLastSet" -Value $passwordage[$_.Name] -Force }
	$Localusers | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name "LastLogin" -Value $lastlogin[$_.Name] -Force }

	$LocalUsers
}


function Get-UserGroupMembership {
<#
    .SYNOPSIS
    Pulls local group membership for the current user
    #>
	Write-Verbose "Enumerating current user local group membership..."

	$UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$CurrentUserSids = $UserIdentity.Groups | Select-Object -Expand value
	$Groups = foreach ($sid in $CurrentUserSids) {
		$SIDObj = New-Object System.Security.Principal.SecurityIdentifier ("$sid")
		$GroupObj = New-Object -TypeName PSObject -Property @{
			SID = $sid
			GroupName = $SIDObj.Translate([System.Security.Principal.NTAccount])
		}
		$GroupObj
	}
	$Groups
}


function Get-ActiveTCPConnections {
<#
    .SYNOPSIS
    Enumerates active TCP connections for IPv4 and IPv6
    Adapted from Beau Bullock's TCP code
    https://raw.githubusercontent.com/dafthack/HostRecon/master/HostRecon.ps1
    #>
	Write-Verbose "Enumerating active network connections..."
	$IPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
	$Connections = $IPProperties.GetActiveTcpConnections()
	foreach ($Connection in $Connections) {
		if ($Connection.LocalEndPoint.AddressFamily -eq "InterNetwork") { $IPType = "IPv4" } else { $IPType = "IPv6" }
		New-Object -TypeName PSobject -Property @{
			"LocalAddress" = $Connection.LocalEndPoint.Address
			"LocalPort" = $Connection.LocalEndPoint.Port
			"RemoteAddress" = $Connection.RemoteEndPoint.Address
			"RemotePort" = $Connection.RemoteEndPoint.Port
			"State" = $Connection.State
			"IPVersion" = $IPType
		}
	}
}


function Get-ActiveListeners {
<#
    .SYNOPSIS
    Enumerates active TCP/UDP listeners.
    #>
	Write-Verbose "Enumerating active TCP/UDP listeners..."
	$IPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
	$TcpListeners = $IPProperties.GetActiveTCPListeners()
	$UdpListeners = $IPProperties.GetActiveUDPListeners()

	foreach ($Connection in $TcpListeners) {
		if ($Connection.Address.AddressFamily -eq "InterNetwork") { $IPType = "IPv4" } else { $IPType = "IPv6" }
		New-Object -TypeName PSobject -Property @{
			"Protocol" = "TCP"
			"LocalAddress" = $Connection.Address
			"ListeningPort" = $Connection.Port
			"IPVersion" = $IPType
		}
	}
	foreach ($Connection in $UdpListeners) {
		if ($Connection.Address.AddressFamily -eq "InterNetwork") { $IPType = "IPv4" } else { $IPType = "IPv6" }
		New-Object -TypeName PSobject -Property @{
			"Protocol" = "UDP"
			"LocalAddress" = $Connection.Address
			"ListeningPort" = $Connection.Port
			"IPVersion" = $IPType
		}
	}
}

function Get-FirewallStatus {
<#
    .SYNOPSIS
    Enumerates local firewall status from registry
    #>
	$regkey = "HKLM:\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"
	New-Object -TypeName PSobject -Property @{
		Standard = if ((Get-ItemProperty $regkey\StandardProfile).EnableFirewall -eq 1) { "Enabled" } else { "Disabled" }
		DOMAIN = if ((Get-ItemProperty $regkey\DomainProfile).EnableFirewall -eq 1) { "Enabled" } else { "Disabled" }
		Public = if ((Get-ItemProperty $regkey\PublicProfile).EnableFirewall -eq 1) { "Enabled" } else { "Disabled" }
	}
}


function Get-InterestingRegistryKeys {
<#
    .SYNOPSIS
    Pulls potentially interesting registry keys
    #>

	Write-Verbose "Enumerating registry keys..."

	# Recently typed "run" commands
	"`n[+] Recent RUN Commands:`n"
	Get-ItemProperty "HKCU:\software\microsoft\windows\currentversion\explorer\runmru" | Out-String

	# HKLM SNMP Keys
	"`n[+] SNMP community strings:`n"
	Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" | Format-List | Out-String

	# HKCU SNMP Keys
	"`n[+] SNMP community strings for current user:`n"
	Get-ItemProperty "HKCU:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" | Format-List | Out-String

	# Putty Saved Session Keys
	"`n[+] Putty saved sessions:`n"
	Get-ItemProperty "HKCU:\Software\SimonTatham\PuTTY\Sessions\*" | Format-List | Out-String

	"`n[+] Windows Update Settings:`n"
	Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Format-List | Out-String

	"`n[+] Kerberos Settings:`n"
	Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" | Format-List | Out-String

	"`n[+] Wdigest Settings:`n"
	Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" | Format-List | Out-String

	"`n[+] Windows Installer Settings:`n"
	Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Installer" | Format-List | Out-String
	Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Installer" | Format-List | Out-String

	"`n[+] Windows Policy Settings:`n"
	Get-ChildItem registry::HKEY_LOCAL_MACHINE\Software\Policies -Recurse | Out-String
	Get-ChildItem registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies -Recurse | Out-String
	Get-ChildItem registry::HKEY_CURRENT_USER\Software\Policies -Recurse | Out-String
	Get-ChildItem registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies -Recurse | Out-String
}


function Get-IndexedFiles {
<#
    .SYNOPSIS
    Uses the Windows indexing service to search for interesting files and often includes Outlook e-mails.
    Code originally adapted from a Microsoft post, but can no longer locate the exact source. Doesn't work on all systems.
    #>
	param(
		[Parameter(Mandatory = $true)] [string]$Pattern)

	if ($Path -eq "") { $Path = $PWD; }

	$pattern = $pattern -replace "\*","%"
	$path = $path + "\%"

	$con = New-Object -ComObject ADODB.Connection
	$rs = New-Object -ComObject ADODB.Recordset

	# This directory indexing search doesn't work on some systems tested (i.e.Server 2K8r2)
	# Using Try/Catch to break the search in case the provider isn't available
	try { $con.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';") }
	catch { "[-] Indexed file search provider not available"; break }

	$rs.Open("SELECT System.ItemPathDisplay FROM SYSTEMINDEX WHERE System.FileName LIKE '" + $pattern + "' ",$con)

	while (-not $rs.EOF) {
		$rs.Fields.Item("System.ItemPathDisplay").value
		$rs.MoveNext()
	}
}


function Get-InterestingFiles {
<#
    .SYNOPSIS
    Local filesystem enumeration
    #>
	Write-Verbose "Enumerating interesting files..."

	# Get Indexed files containg $searchStrings (Experimental), edit this to desired list of "dirty words"
	$SearchStrings = "*secret*","*creds*","*credential*","*.vmdk","*confidential*","*proprietary*","*pass*","*credentials*","web.config","KeePass.config*","*.kdbx","*.key","tnsnames.ora","ntds.dit","*.dll.config","*.exe.config"
	$IndexedFiles = foreach ($String in $SearchStrings) { Get-IndexedFiles $string }

	"`n[+] Indexed File Search:`n"
	"`n[+] Search Terms ($SearchStrings)`n`n"
	$IndexedFiles | Format-List | Out-String -Width 300

	# Get Top Level file listing of all drives
	"`n[+] All 'FileSystem' Drives - Top Level Listing:`n"
	Get-PSDrive -PSProvider filesystem | ForEach-Object { Get-ChildItem $_.Root } | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -Width 300

	# Get Program Files
	"`n[+] System Drive - Program Files:`n"
	Get-ChildItem "$ENV:ProgramFiles\" | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -Width 300

	# Get Program Files (x86)
	"`n[+] System Drive - Program Files (x86):`n"
	Get-ChildItem "$ENV:ProgramFiles (x86)\" | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -Width 300

	# Get %USERPROFILE%\Desktop top level file listing
	"`n[+] Current User Desktop:`n"
	Get-ChildItem $ENV:USERPROFILE\Desktop | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -Width 300

	# Get %USERPROFILE%\Documents top level file listing
	"`n[+] Current User Documents:`n"
	Get-ChildItem $ENV:USERPROFILE\Documents | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -Width 300

	# Get Files in the %USERPROFILE% directory with certain extensions or phrases
	"`n[+] Current User Profile (*pass*,*diagram*,*.pdf,*.vsd,*.doc,*docx,*.xls,*.xlsx,*.kdbx,*.key,KeePass.config):`n"
	Get-ChildItem $ENV:USERPROFILE\ -Recurse -Include *pass*,*diagram*,*.pdf,*.vsd,*.doc,*docx,*.xls,*.xlsx,*.kdbx,*.key,KeePass.config | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -Width 300

	# Get Powershell History
	"`n[+] Current User Powershell Console History:`n`n"
	try {
		$PowershellHistory = (Get-PSReadLineOption).HistorySavePath
		(Get-Content $PowershellHistory -EA 0 | Select-Object -Last 50) -join "`r`n"
	}
	catch [System.Management.Automation.CommandNotFoundException]{
		(Get-Content $ENV:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt -EA 0 | Select-Object -Last 50) -join "`r`n"
	}

	# Get Host File
	"`n[+] Contents of Hostfile:`n`n"
	(Get-Content -Path "$($ENV:WINDIR)\System32\drivers\etc\hosts") -join "`r`n"
}


function Get-RecycleBin {
<#
    .SYNOPSIS
    Gets the contents of the Recycle Bin for the current user
    #>
	Write-Verbose "Enumerating deleted files in Recycle Bin..."
	try {
		$Shell = New-Object -ComObject Shell.Application
		$Recycler = $Shell.Namespace(0xa)
		if (($Recycler.Items().Count) -gt 0) {
			$Output += $Recycler.Items() | Sort ModifyDate -Descending | Select-Object Name,Path,ModifyDate,Size,Get-Content
		}
		else { Write-Verbose "No deleted items found in Recycle Bin!`n" }
	}
	catch { Write-Verbose "[-] Error getting deleted items from Recycle Bin! $($Error[0])`n" }

	return $Output
}

function Get-AVInfo {
<#
    .SYNOPSIS
    Gets the installed AV product and current status
    #>
	Write-Verbose "Enumerating installed AV product..."

	$AntiVirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ComputerName $env:computername

	switch ($AntiVirusProduct.productState) {
		"262144" { $defstatus = "Up to date"; $rtstatus = "Disabled" }
		"262160" { $defstatus = "Out of date"; $rtstatus = "Disabled" }
		"266240" { $defstatus = "Up to date"; $rtstatus = "Enabled" }
		"266256" { $defstatus = "Out of date"; $rtstatus = "Enabled" }
		"393216" { $defstatus = "Up to date"; $rtstatus = "Disabled" }
		"393232" { $defstatus = "Out of date"; $rtstatus = "Disabled" }
		"393488" { $defstatus = "Out of date"; $rtstatus = "Disabled" }
		"397312" { $defstatus = "Up to date"; $rtstatus = "Enabled" }
		"397328" { $defstatus = "Out of date"; $rtstatus = "Enabled" }
		"397584" { $defstatus = "Out of date"; $rtstatus = "Enabled" }
		"397568" { $defstatus = "Up to date"; $rtstatus = "Enabled" }
		"393472" { $defstatus = "Up to date"; $rtstatus = "Disabled" }
		default { $defstatus = "Unknown"; $rtstatus = "Unknown" }
	}

	# Create hash-table
	$ht = @{}
	$ht.Computername = $env:computername
	$ht.Name = $AntiVirusProduct.displayName
	$ht. 'Product GUID' = $AntiVirusProduct.instanceGuid
	$ht. 'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
	$ht. 'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
	$ht. 'Definition Status' = $defstatus
	$ht. 'Real-time Protection Status' = $rtstatus

	# Convert to PS object and then format as a string for file output
	$Output = New-Object -TypeName PSObject -Property $ht #|Format-List

	return $Output
}


function Get-McafeeLogs {
<#
    .SYNOPSIS
    Searches Application log for "McLogEvent" Provider associated with McAfee AV products and selects the first 50 events from the last 14 days
    #>
	Write-Verbose "Enumerating Mcafee AV events..."
	# Get events from the last two weeks
	$date = (Get-Date).AddDays(-14)
	$ProviderName = "McLogEvent"
	# Try to get McAfee AV event logs
	try {
		$McafeeLogs = Get-WinEvent -FilterHashTable @{ logname = "Application"; StartTime = $date; ProviderName = $ProviderName; }
		$McafeeLogs | Select-Object -First 50 ID,Providername,DisplayName,TimeCreated,Level,UserID,ProcessID,Message
	}
	catch { Write-Verbose "[-] Error getting McAfee AV event logs! $($Error[0])`n" }
}


function Get-AVProcesses {
<#
    .SYNOPSIS
    Returns suspected AV processes based on name matching
    AV process list adapted from Beau Bullock's HostRecon AV detection code
    https://raw.githubusercontent.com/dafthack/HostRecon/master/HostRecon.ps1
    #>
	Write-Verbose "Enumerating potential AV processes..."
	$processes = Get-Process

	$avlookuptable = @{
		#explorer                   = "Explorer (testing)"
		mcshield = "McAfee AV"
		FrameworkService = "McAfee AV"
		naPrdMgr = "McAfee AV"
		windefend = "Windows Defender AV"
		MSASCui = "Windows Defender AV"
		msmpeng = "Windows Defender AV"
		msmpsvc = "Windows Defender AV"
		WRSA = "WebRoot AV"
		savservice = "Sophos AV"
		TMCCSF = "Trend Micro AV"
		"symantec antivirus" = "Symantec AV"
		ccSvcHst = "Symantec Endpoint Protection"
		TaniumClient = "Tanium"
		mbae = "MalwareBytes Anti-Exploit"
		parity = "Bit9 application whitelisting"
		cb = "Carbon Black behavioral analysis"
		"bds-vision" = "BDS Vision behavioral analysis"
		Triumfant = "Triumfant behavioral analysis"
		CSFalcon = "CrowdStrike Falcon EDR"
		ossec = "OSSEC intrusion detection"
		TmPfw = "Trend Micro firewall"
		dgagent = "Verdasys Digital Guardian DLP"
		kvoop = "Forcepoint and others"
		xagt = "FireEye Endpoint Agent"
	}

	foreach ($process in $processes) {
		foreach ($key in $avlookuptable.keys) {

			if ($process.ProcessName -match $key) {
				New-Object -TypeName PSObject -Property @{
					AVProduct = ($avlookuptable).Get_Item($key)
					ProcessName = $process.ProcessName
					PID = $process.id
				}
			}
		}
	}
}

function Get-DomainAdmins {
<#
    .SYNOPSIS
    Enumerates admininistrator type accounts within the domain using code adapted from Dafthack HostRecon.ps1
    #>
	Write-Verbose "Enumerating Domain Administrators..."
	$Domain = [System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()

	try {
		$DAgroup = ([adsi]"WinNT://$domain/Domain Admins,group")
		$Members = @($DAgroup.psbase.Invoke("Members"))
		[array]$MemberNames = $Members | ForEach-Object { ([adsi]$_).InvokeGet("Name") }
		"`n[+] Domain Admins:`n"
		$MemberNames

		$EAgroup = ([adsi]"WinNT://$domain/Enterprise Admins,group")
		$Members = @($EAgroup.psbase.Invoke("Members"))
		[array]$MemberNames = $Members | ForEach-Object { ([adsi]$_).InvokeGet("Name") }
		"`n[+] Enterprise Admins:`n"
		$MemberNames

		$SAgroup = ([adsi]"WinNT://$domain/Schema Admins,group")
		$Members = @($DAgroup.psbase.Invoke("Members"))
		[array]$MemberNames = $Members | ForEach-Object { ([adsi]$_).InvokeGet("Name") }
		"`n[+] Schema Admins:`n"
		$MemberNames

		$DAgroup = ([adsi]"WinNT://$domain/Administrators,group")
		$Members = @($DAgroup.psbase.Invoke("Members"))
		[array]$MemberNames = $Members | ForEach-Object { ([adsi]$_).InvokeGet("Name") }
		"`n[+] Administrators:`n"
		$MemberNames
	}
	catch { Write-Verbose "[-] Error connecting to the domain while retrieving group members." }
}


function Get-DomainAccountPolicy {
<#
    .SYNOPSIS
    Enumerates account policy from the domain with code adapted from Dafthack HostRecon.ps1
    #>

	Write-Verbose "Enumerating domain account policy"
	$Domain = [System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()

	try {
		$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext ("domain",$domain)
		$DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
		$CurrentDomain = [adsi]"WinNT://$env:USERDOMAIN"
		$Name = @{ Name = "DomainName"; Expression = { $_.Name } }
		$MinPassLen = @{ Name = "Minimum Password Length"; Expression = { $_.MinPasswordLength } }
		$MinPassAge = @{ Name = "Minimum Password Age (Days)"; Expression = { $_.MinPasswordAge.value / 86400 } }
		$MaxPassAge = @{ Name = "Maximum Password Age (Days)"; Expression = { $_.MaxPasswordAge.value / 86400 } }
		$PassHistory = @{ Name = "Enforce Password History (Passwords remembered)"; Expression = { $_.PasswordHistoryLength } }
		$AcctLockoutThreshold = @{ Name = "Account Lockout Threshold"; Expression = { $_.MaxBadPasswordsAllowed } }
		$AcctLockoutDuration = @{ Name = "Account Lockout Duration (Minutes)"; Expression = { if ($_.AutoUnlockInterval.value -eq -1) { 'Account is locked out until administrator unlocks it.' } else { $_.AutoUnlockInterval.value / 60 } } }
		$ResetAcctLockoutCounter = @{ Name = "Observation Window"; Expression = { $_.LockoutObservationInterval.value / 60 } }

		$CurrentDomain | Select-Object $Name,$MinPassLen,$MinPassAge,$MaxPassAge,$PassHistory,$AcctLockoutThreshold,$AcctLockoutDuration,$ResetAcctLockoutCounter
	}
	catch { Write-Verbose "[-] Error connecting to the domain while retrieving password policy." }
}



function Get-UserSPNS {
<#
    .SYNOPSIS
    # Edits by Tim Medin
    # File:     GetUserSPNS.ps1
    # Contents: Query the domain to find SPNs that use User accounts
    # Comments: This is for use with Kerberoast https://github.com/nidem/kerberoast
    #           The password hash used with Computer accounts are infeasible to
    #           crack; however, if the User account associated with an SPN may have
    #           a crackable password. This tool will find those accounts. You do not
    #           need any special local or domain permissions to run this script.
    #           This script on a script supplied by Microsoft (details below).
    # History:  2016/07/07     Tim Medin    Add -UniqueAccounts parameter to only get unique SAMAccountNames
    #>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False,Position = 1)] [string]$GCName,
		[Parameter(Mandatory = $False)] [string]$Filter,
		[Parameter(Mandatory = $False)] [switch]$Request,
		[Parameter(Mandatory = $False)] [switch]$UniqueAccounts
	)
	Write-Verbose "Enumerating user SPNs for potential Kerberoast cracking..."
	Add-Type -AssemblyName System.IdentityModel

	$GCs = @()

	if ($GCName) {
		$GCs += $GCName
	}
	else { # find them
		$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
		$CurrentGCs = $ForestInfo.FindAllGlobalCatalogs()
		foreach ($GC in $CurrentGCs) {
			#$GCs += $GC.Name
			$GCs += $ForestInfo.ApplicationPartitions[0].SecurityReferenceDomain
		}
	}

	if (-not $GCs) {
		# no Global Catalogs Found
		Write-Output "`n[-] No Global Catalogs Found!"
		return
	}

	foreach ($GC in $GCs) {
		$searcher = New-Object System.DirectoryServices.DirectorySearcher
		$searcher.SearchRoot = "LDAP://" + $GC
		$searcher.PageSize = 1000
		$searcher.Filter = "(&(!objectClass=computer)(servicePrincipalName=*))"
		$Null = $searcher.PropertiesToLoad.Add("serviceprincipalname")
		$Null = $searcher.PropertiesToLoad.Add("name")
		$Null = $searcher.PropertiesToLoad.Add("samaccountname")
		#$Null = $searcher.PropertiesToLoad.Add("userprincipalname")
		#$Null = $searcher.PropertiesToLoad.Add("displayname")
		$Null = $searcher.PropertiesToLoad.Add("memberof")
		$Null = $searcher.PropertiesToLoad.Add("pwdlastset")
		#$Null = $searcher.PropertiesToLoad.Add("distinguishedname")

		$searcher.SearchScope = "Subtree"

		$results = $searcher.FindAll()

		[System.Collections.ArrayList]$accounts = @()

		foreach ($result in $results) {
			foreach ($spn in $result.Properties["serviceprincipalname"]) {
				$o = Select-Object -InputObject $result -Property `
 					@{ Name = "ServicePrincipalName"; Expression = { $spn.ToString() } },`
 					@{ Name = "Name"; Expression = { $result.Properties["name"][0].ToString() } },`
 					#@{Name="UserPrincipalName";   Expression={$result.Properties["userprincipalname"][0].ToString()} }, `
				@{ Name = "SAMAccountName"; Expression = { $result.Properties["samaccountname"][0].ToString() } },`
 					#@{Name="DisplayName";         Expression={$result.Properties["displayname"][0].ToString()} }, `
				@{ Name = "MemberOf"; Expression = { $result.Properties["memberof"][0].ToString() } },`
 					@{ Name = "PasswordLastSet"; Expression = { [datetime]::FromFileTime($result.Properties["pwdlastset"][0]) } } #, `
				#@{Name="DistinguishedName";   Expression={$result.Properties["distinguishedname"][0].ToString()} }
				if ($UniqueAccounts) {
					if (-not $accounts.Contains($result.Properties["samaccountname"][0].ToString())) {
						$Null = $accounts.Add($result.Properties["samaccountname"][0].ToString())
						$o
						if ($Request) {
							$Null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn.ToString()
						}
					}
				}
				else {
					$o
					if ($Request) {
						$Null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn.ToString()
					}
				}
			}
		}
	}
}


# Execute local enumeration functions and format for report
"`n[+] Host Summary`n"
$Results = Get-Sysinfo
$Results | Format-List
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Host Summary</H2>" -As list | Out-File -Append $HTMLReportFile


# Get Installed software, check for 64-bit applications
"`n[+] Installed Software:`n"
$Results = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,InstallDate,DisplayVersion,Publisher,InstallLocation
if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq "64-bit") {
	$Results += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,InstallDate,DisplayVersion,Publisher,InstallLocation
}

$Results = $Results | Where-Object { $_.displayName } | Sort-Object DisplayName
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Installed Software</H2>" | Out-File -Append $HTMLReportFile


# Get installed patches
"`n[+] Installed Patches:`n"
$Results = Get-WmiObject -Class Win32_quickfixengineering | Select-Object HotFixID,Description,InstalledBy,InstalledOn | Sort-Object InstalledOn -Descending
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Installed Patches</H2>" | Out-File -Append $HTMLReportFile


# Process Information
"`n[+] Running Processes`n"
$Results = Get-ProcessInfo
$Results | Format-Table ID,Name,Owner,Path,CommandLine -auto
$Results | ConvertTo-Html -Fragment -Property ID,Name,Owner,MainWindowTitle,Path,CommandLine -PreContent "<H2>Process Information</H2>" | Out-File -Append $HTMLReportFile


# Services
"`n[+] Installed Services:`n"
$Results = Get-WmiObject win32_service | Select-Object Name,DisplayName,State,PathName
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Installed Services</H2>" | Out-File -Append $HTMLReportFile


# Environment variables
"`n[+] Environment Variables:`n"
$Results = Get-ChildItem -Path env:* | Select-Object Name,Value | Sort-Object name
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Environment Variables</H2>" | Out-File -Append $HTMLReportFile


# BIOS information
"`n[+] BIOS Information:`n"
$Results = Get-WmiObject -Class win32_bios | Select-Object SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber,Version
$Results | Format-List
$Results | ConvertTo-Html -Fragment -PreContent "<H2>BIOS Information</H2>" -As List | Out-File -Append $HTMLReportFile


# Physical Computer Information
"`n[+] Computer Information:`n"
$Results = Get-WmiObject -Class Win32_ComputerSystem | Select-Object Domain,Manufacturer,Model,Name,PrimaryOwnerName,TotalPhysicalMemory,@{ Label = "Role"; Expression = { ($_.Roles) -join "," } }
$Results | Format-List
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Physical Computer Information</H2>" -As List | Out-File -Append $HTMLReportFile


# System Drives (Returns mapped drives too, but not their associated network path)
"`n[+] System Drives:`n"
$Results = Get-PSDrive -PSProvider filesystem | Select-Object Name,Root,Used,Free,Description,CurrentLocation
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>System Drives</H2>" | Out-File -Append $HTMLReportFile


# Mapped Network Drives
"`n[+] Mapped Network Drives:`n"
$Results = Get-WmiObject -Class Win32_MappedLogicalDisk | Select-Object Name,Caption,VolumeName,FreeSpace,ProviderName,FileSystem
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Mapped Network Drives</H2>" | Out-File -Append $HTMLReportFile


## Local Network Configuration

# Network Adapters
"`n[+] Network Adapters:`n"
$Results = Get-WmiObject -Class Win32_NetworkAdapterConfiguration |
Select-Object Description,@{ Label = "IPAddress"; Expression = { ($_.IPAddress) -join ", " } },@{ Label = "IPSubnet"; Expression = { ($_.IPSubnet) -join ", " } },@{ Label = "DefaultGateway"; Expression = { ($_.DefaultIPGateway) -join ", " } },MACaddress,DHCPServer,DNSHostname | Sort-Object IPAddress -Descending
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Network Adapters</H2>" | Out-File -Append $HTMLReportFile


# DNS Cache
"`n[+] DNS Cache:`n"
$Results = Get-WmiObject -Query "Select * from MSFT_DNSClientCache" -Namespace "root\standardcimv2" | Select-Object Entry,Name,Data
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>DNS Cache</H2>" | Out-File -Append $HTMLReportFile

# Network Shares
"`n[+] Network Shares:`n"
$Results = Get-WmiObject -Class Win32_Share | Select-Object Name,Path,Description,Caption,Status
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Network Shares</H2>" | Out-File -Append $HTMLReportFile

# TCP Network Connections
"`n[+] Active TCP Connections:`n"
$Results = Get-ActiveTCPConnections | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,IPVersion
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Active TCP Connections</H2>" | Out-File -Append $HTMLReportFile


# IP Listeners
"`n[+] TCP/UDP Listeners:`n"
$Results = Get-ActiveListeners | Where-Object { $_.ListeningPort -lt 50000 } | Select-Object Protocol,LocalAddress,ListeningPort,IPVersion
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>TCP/UDP Listeners</H2>" | Out-File -Append $HTMLReportFile


# Firewall Status
"`n[+] Firewall Status:`n"
$Results = Get-FirewallStatus
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Firewall Status</H2>" | Out-File -Append $HTMLReportFile


# WMI Routing Table
"`n[+] Routing Table:`n"
$Results = Get-WmiObject -Class "Win32_IP4RouteTable" -Namespace "root\CIMV2" | Select-Object Destination,Mask,Nexthop,InterfaceIndex,Metric1,Protocol,Get-Content
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Routing Table</H2>" | Out-File -Append $HTMLReportFile


# WMI Net Sessions
"`n[+] Net Sessions:`n"
$Results = Get-WmiObject win32_networkconnection | Select-Object LocalName,RemoteName,RemotePath,Name,Status,ConnectionState,Persistent,UserName,Description
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Network Sessions</H2>" | Out-File -Append $HTMLReportFile


# Proxy Information
"`n[+] Proxy Configuration:`n"
$regkey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$Results = New-Object -TypeName PSObject -Property @{
	Enabled = if ((Get-ItemProperty -Path $regkey).proxyEnable -eq 1) { "True" } else { "False" }
	ProxyServer = (Get-ItemProperty -Path $regkey).ProxyServer
	AutoConfigURL = (Get-ItemProperty -Path $regkey).AutoConfigURL
}

$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Proxy Configuration</H2>" | Out-File -Append $HTMLReportFile


## Local User and Group Enumeration
#######################

# Local User Accounts
"`n[+] Local users:`n"
$Results = Get-LocalUsers | Sort-Object SID -Descending | Select-Object Name,SID,AccountType,PasswordExpires,Disabled,Lockout,Status,PasswordLastSet,LastLogin,Description
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Local Users</H2>" | Out-File -Append $HTMLReportFile


# Local Administrators
"`n[+] Local Administrators:`n"
$Results = Get-WmiObject -Class Win32_groupuser -Filter "GroupComponent=""Win32_Group.Domain='$env:COMPUTERNAME',Name='Administrators'""" |
ForEach-Object { [wmi]$_.PartComponent } | Select-Object Name,Domain,SID,AccountType,PasswordExpires,Disabled,Lockout,Status,Description

$Results | Format-Table -auto -Wrap
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Local Administrators</H2>" | Out-File -Append $HTMLReportFile


# Local Groups
"`n[+] Local Groups:`n"
$Results = Get-WmiObject -Class Win32_Group -Filter "Domain='$($env:ComputerName)'" | Select-Object Name,SID,Description
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Local Groups</H2>" | Out-File -Append $HTMLReportFile


# Local Group Membership
"`n[+] Local Group Membership:`n"
$Groups = Get-WmiObject -Class Win32_Group -Filter "Domain='$($env:ComputerName)'" | Select-Object -Expand Name

foreach ($Group in $Groups) {
	$results = $Null
	$Results = Get-WmiObject -Class Win32_groupuser -Filter "GroupComponent=""Win32_Group.Domain='$env:COMPUTERNAME',Name='$Group'""" | ForEach-Object { [wmi]$_.PartComponent } | Select-Object Name,Domain,SID,AccountType,PasswordExpires,Disabled,Lockout,Status,Description
	"[+] $Group - Members"
	$Results | Format-Table -auto

	$Results | ConvertTo-Html -Fragment -PreContent "<H2>Local Group Membership - $Group</H2>" | Out-File -Append $HTMLReportFile

}


## AV Products
#########################
"`n[+] Installed AV Product`n"
$Results = Get-AVInfo
$Results | Format-List
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Installed AV Product</H2>" -As list | Out-File -Append $HTMLReportFile


# Potential Running AV Processes
"`n[+] Potential AV Processes`n"
$Results = Get-AVProcesses
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Potential AV Processes</H2>" | Out-File -Append $HTMLReportFile

#Potential EDR Products
$Results = Get-EDRCheck
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Potential EDR Products</H2>" | Out-File -Append $HTMLReportFile


# If McAfee is installed then pull some recent logs
if ($Results.displayName -match "mcafee") {
	$Results = Get-McafeeLogs
	$Results | Format-List

	$Results | ConvertTo-Html -Fragment -PreContent "<H2>Recent McAfee AV Logs</H2>" -As list | Out-File -Append $HTMLReportFile

}
## Interesting Locations
#############################
"`n[+] Registry Keys`n"
$Results = Get-InterestingRegistryKeys
$Results
ConvertTo-Html -Fragment -PreContent "<H2>Interesting Registry Keys</H2>`n<table><tr><td><PRE>$Results</PRE></td></tr></table>" -As list | Out-File -Append $HTMLReportFile


# Interesting File Search (String formatted due to odd formatting issues with file listings)
"`n[+] Interesting Files:`n"
$Results = Get-InterestingFiles
$Results

ConvertTo-Html -Fragment -PreContent "<H2>Interesting Files</H2>`n<table><tr><td><PRE>$Results</PRE></td></tr></table>" | Out-File -Append $HTMLReportFile


## Current User Enumeration
############################
# Group Membership for Current User
"`n[+] Group Membership - $($Env:UserName)`n"
$Results = Get-UserGroupMembership | Sort-Object SID
$Results | Format-Table -auto

$Results | ConvertTo-Html -Fragment -PreContent "<H2>Group Membership - $($env:username)</H2>" | Out-File -Append $HTMLReportFile




# Recycle Bin Files
"`n`n[+] Recycle Bin Contents - $($Env:UserName)`n"
$Results = Get-RecycleBin
$Results | Format-Table -auto
$Results | ConvertTo-Html -Fragment -PreContent "<H2>Recycle Bin Contents - $($Env:UserName)</H2>" | Out-File -Append $HTMLReportFile


# Clipboard Contents
Add-Type -Assembly PresentationCore
"`n[+] Clipboard Contents - $($Env:UserName):`n"
$Results = ''
$Results = ([Windows.Clipboard]::GetText()) -join "`r`n" | Out-String
$Results
ConvertTo-Html -Fragment -PreContent "<H2>Clipboard Contents - $($Env:UserName)</H2><table><tr><td><PRE>$Results</PRE></td></tr></table>" | Out-File -Append $HTMLReportFile

#Wifi Passwords
"`n`n[+] Wifi Passwords - $($ENV:COMPUTERNAME)`n"
$Results = (netsh wlan show profiles) | Select-String ?\:(.+)$? | ForEach-Object { $name = $_.Matches.Groups[1].value.Trim(); $_ } | ForEach-Object { (netsh wlan show profile name=?$name? key=clear) } | Select-String ?Key Content\W+\:(.+)$? | ForEach-Object { $pass = $_.Matches.Groups[1].value.Trim(); $_ } | ForEach-Object { [pscustomobject]@{ PROFILE_NAME = $name; PASSWORD = $pass } }
$Results | ConvertTo-Html -Fragment -PreContent "<H2>WIFI Passwords - $($ENV:COMPUTERNAME)</H2>" | Out-File -Append $HTMLReportFile

if ((gwmi win32_computersystem).partofdomain) {
	# Simple Domain Enumeration
	ConvertTo-Html -Fragment -PreContent "<H1>Domain Report - $($env:USERDOMAIN)</H1><div class='aLine'></div>" | Out-File -Append $HTMLReportFile
	Write-Verbose "Enumerating Windows Domain..."
	"`n[+] Domain Mode`n"
	$Results = ([System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()).DomainMode
	$Results

	ConvertTo-Html -Fragment -PreContent "<H2>Domain Mode: $Results</H2>" | Out-File -Append $HTMLReportFile


	# DA Level Accounts
	"`n[+] Domain Administrators`n"
	$Results = Get-DomainAdmins
	$Results
	ConvertTo-Html -Fragment -PreContent "<H2>Domain Administrators</H2><table><tr><td><PRE>$Results</PRE></td></tr></table>" | Out-File -Append $HTMLReportFile


	# Domain account password policy
	"`n[+] Domain Account Policy`n"
	$Results = Get-DomainAccountPolicy
	$Results | Format-List
	$Results | ConvertTo-Html -Fragment -PreContent "<H2>Domain Account Policy</H2>" -As List | Out-File -Append $HTMLReportFile


	# Domain Controllers
	"`n[+] Domain Controllers:`n"
	$Results = ([System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()).DomainControllers | Select-Object Name,OSVersion,Domain,Forest,SiteName,IpAddress
	$Results | Format-Table -auto
	$Results | ConvertTo-Html -Fragment -PreContent "<H2>Domain Controllers</H2>" | Out-File -Append $HTMLReportFile


	# Domain Trusts
	"`n[+] Domain Trusts:`n"
	$Results = ([System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
	$Results | Format-List
	$Results | ConvertTo-Html -Fragment -PreContent "<H2>Domain Trusts</H2>" -As List | Out-File -Append $HTMLReportFile


	# Domain Users
	"`n[+] Domain Users:`n"
	$Results = Get-WmiObject -Class Win32_UserAccount | Select-Object Name,Caption,SID,Fullname,Disabled,Lockout,Description | Sort-Object SID
	$Results | Format-Table -auto
	$Results | ConvertTo-Html -Fragment -PreContent "<H2>Domain Users</H2>" | Out-File -Append $HTMLReportFile

	# Domain Groups
	"`n[+] Domain Groups:`n"
	$Results = Get-WmiObject -Class Win32_Group | Select-Object Name,SID,Description | Sort-Object SID
	$Results | Format-Table -auto
	$Results | ConvertTo-Html -Fragment -PreContent "<H2>Domain Groups</H2>" | Out-File -Append $HTMLReportFile


	# Domain Admins, Enterprise Admins, Server Admins, Backup Operators
	# Get User SPNS
	"`n[+] User Account SPNs`n"
	$Results = $null
	$Results = Get-UserSPNS -UniqueAccounts | Sort-Object PasswordLastSet -Unique
	$Results | Format-Table -auto

	$Results | ConvertTo-Html -Fragment -PreContent "<H2>User Account SPNs</H2>" | Out-File -Append $HTMLReportFile
}

else {
	"`n[-] Host is not a member of a domain. Skipping domain checks...`n"
	ConvertTo-Html -Fragment -PreContent "<H2>Host is not a member of a domain. Domain checks skipped.</H2>" | Out-File -Append $HTMLReportFile
}

$Duration = New-TimeSpan -Start $Time -End ((Get-Date).ToUniversalTime())
# Print report location and finish execution
"`n"
"[+] FILE:`t$HTMLReportFile"
"[+] FILESIZE:`t$((Get-Item $HTMLReportFile).length) Bytes"
"[+] DURATION:`t$Duration"
"[+] InitalScript Complete!"

