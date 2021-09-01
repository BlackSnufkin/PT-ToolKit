$dir = "E:\Kraken VM\Kraken-VM\Passwords List\All_Passwords_File\07"
$outFile = Join-Path $dir "07-PassFile.txt"
$sw = [System.Diagnostics.Stopwatch]::StartNew();
# Build the file list
$fileList = Get-ChildItem -Path $dir\* -Include *.txt -Exclude $outFile -File
# Get the header info from the first file
Get-Content $fileList[0] | select -First 2 | Out-File -FilePath $outfile -Encoding ascii
# Cycle through and get the data (sans header) from all the files in the list
foreach ($file in $filelist)
{
    Get-Content $file | select -Skip 2 | Out-File -FilePath $outfile -Encoding ascii -Append
}
$sw.Stop();
Write-Output ("merging took {0}" -f $sw.Elapsed);

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
Write-Output ("read-uniq took {0}" -f $sw.Elapsed);

$sw = [System.Diagnostics.Stopwatch]::StartNew();
$ls = new-object system.collections.generic.List[string] $hs;
$ls.Sort();
$sw.Stop();
Write-Output ("sorting took {0}" -f $sw.Elapsed);
$soted_out = Join-Path $dir "07-PassFile_sorted.txt"
$sw = [System.Diagnostics.Stopwatch]::StartNew();
try
{
    $f = New-Object System.IO.StreamWriter $soted_out;
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
Write-Output ("saving took {0}" -f $sw.Elapsed);
Remove-Item $outfile
