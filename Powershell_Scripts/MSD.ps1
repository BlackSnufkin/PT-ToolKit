$dir = Read-Host -Prompt "`n[?] Enter Path to Passwords list to MERGE"
Write-Host "`n"
$tt = [System.Diagnostics.Stopwatch]::StartNew();
$dir_name = Split-Path $dir -Leaf
$outFile = Join-Path $dir ("01-{0}_Merged.txt" -f $dir_name);

# Build the file list
$fileList = Get-ChildItem -Path $dir\* -Include *.txt -Exclude $outFile -File

# Get the header info from the first file
Get-Content $fileList[0] | select -First 2 | Out-File -FilePath $outfile -Encoding ascii
# Cycle through and get the data (sans header) from all the files in the list
$Writer = [System.IO.StreamWriter]::new($outFile)
$sw = [System.Diagnostics.Stopwatch]::StartNew();
foreach ($file in $filelist)
{
   
    $corrent_file = (Get-Item $file).BaseName + (Get-Item $file).Extension
    Write-Host -ForegroundColor White "[+] " -NoNewline;Write-Host -ForegroundColor Magenta "Now Adding $corrent_file "
    $reader = New-Object System.IO.StreamReader($file)
    $content = $reader.ReadToEnd()
    $Writer.Write($content)
    
}
$Writer.close()
$Reader.close()
$sw.Stop();
Write-Host -ForegroundColor White "`n[*] " -NoNewline;Write-Host -ForegroundColor Yellow ("Merging All files took {0}" -f $sw.Elapsed);

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
Write-Host -ForegroundColor White "[*] " -NoNewline;Write-Host -ForegroundColor Yellow ("Read-Uniq Lines took {0}" -f $sw.Elapsed);

$sw = [System.Diagnostics.Stopwatch]::StartNew();
$ls = new-object system.collections.generic.List[string] $hs;
$ls.Sort();
$sw.Stop();
Write-Host -ForegroundColor White "[*] " -NoNewline;Write-Host -ForegroundColor Yellow ("Sorting All Lines took {0}" -f $sw.Elapsed);
$sorted_file = Join-Path $dir ("01-{0}_MSD.txt" -f $dir_name); 
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
$tt.Stop();
Write-Host -ForegroundColor White "[*] " -NoNewline;Write-Host -ForegroundColor Yellow ("Writing Sorted File to disk took {0}" -f $sw.Elapsed);
Write-Host -ForegroundColor White "`n[+] " -NoNewline;Write-Host -ForegroundColor Green "New MSD file saved to:"
Get-Item $sorted_file
Remove-Item $outfile
Write-Host -ForegroundColor White "`n[!] " -NoNewline;Write-Host -ForegroundColor Red ("Total Time took {0}" -f $tt.Elapsed);
