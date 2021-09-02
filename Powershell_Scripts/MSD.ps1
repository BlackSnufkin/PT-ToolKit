$dir = Read-Host -Prompt "`n[?] Enter Path to Passwords list to MERGE"
Write-Host "`n"
$outFile = Join-Path $dir "01-All_merged.txt"
$sw = [System.Diagnostics.Stopwatch]::StartNew();

# Build the file list
$fileList = Get-ChildItem -Path $dir\* -Include *.txt -Exclude $outFile -File

# Get the header info from the first file
Get-Content $fileList[0] | select -First 2 | Out-File -FilePath $outfile -Encoding ascii
# Cycle through and get the data (sans header) from all the files in the list

foreach ($file in $filelist)
{
   
    $corrent_file = (Get-Item $file).BaseName + (Get-Item $file).Extension
    Write-Host -ForegroundColor Magenta "[+] Now Adding $corrent_file " 
    Get-Content $file  | Out-File -FilePath $outfile -Encoding ascii -Append
}

$sw.Stop();
Write-Host -ForegroundColor Yellow ("`n[!] Merging All files took {0}" -f $sw.Elapsed);


$hs = new-object System.Collections.Generic.HashSet[string]
$sw = [System.Diagnostics.Stopwatch]::StartNew();
$reader = [System.IO.File]::OpenText($outFile)
try {
    while (($line = $reader.ReadLine()) -ne $null)
    {
        $t = $hs.Add($line)
    }
}
finally {
    $reader.Close()
}
$sw.Stop();
Write-Host -ForegroundColor Yellow ("[!] Read-Uniq Lines took {0}" -f $sw.Elapsed);

$sw = [System.Diagnostics.Stopwatch]::StartNew();
$ls = new-object system.collections.generic.List[string] $hs;
$ls.Sort();
$sw.Stop();
Write-Host -ForegroundColor Yellow ("[!] Sorting All Lines took {0}" -f $sw.Elapsed);
$sorted_file = Join-Path $dir "01-All_Sorted.txt"
$sw = [System.Diagnostics.Stopwatch]::StartNew();
try
{
    $f = New-Object System.IO.StreamWriter $sorted_file;
    foreach ($s in $ls)
    {
        $f.WriteLine($s);
    }
}
finally
{
    $f.Close();
} 
$sw.Stop();

Write-Host -ForegroundColor White "[*] " -NoNewline;Write-Host -ForegroundColor Yellow ("Writing Sorted File to disk took {0}" -f $sw.Elapsed);
Write-Host -ForegroundColor White "[!] " -NoNewline;Write-Host -ForegroundColor Red ("Total Time took {0}" -f $tt.Elapsed);
Write-Host -ForegroundColor White "`n[+] " -NoNewline;Write-Host -ForegroundColor Green "New MSD file saved to:"
Get-Item $sorted_file
Remove-Item $outfile
