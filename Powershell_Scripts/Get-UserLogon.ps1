function Get-UserLogon {
 
<# 
 
.SYNOPSIS 

Get-UserLogon is an advanced Powershell function. 
 
.DESCRIPTION 

Uses quser and Invoke-Command to retrieve logged on users.
 
.PARAMETER ComputerName
 
Enter the ComputerName.
 
.PARAMETER OU 
Provide the Name of the OU.

.PARAMETER All 
Queries all Computer accounts. This is a switch Parameter. Do not provide a value.
 
.EXAMPLE 
Get-UserLogon -ComputerName PC100
Get-UserLogon -All
Get-UserLogon -OU "OU=Workstations,DC=sid-500,DC=com"
 
.NOTES 
Author: Patrick Gruenauer 
Web: 
https://sid-500.com 
 
.LINK 
None. 
 
.INPUTS 
None. 
 
.OUTPUTS 
None. #>
 
[CmdletBinding()]
 
param
 
(
 
[Parameter ()]
[String]$Computer,
 
[Parameter ()]
[String]$OU,

[Parameter ()]
[Switch]$All
 
)

$ErrorActionPreference="SilentlyContinue"

$result=@()

If ($Computer) {

Invoke-Command -ComputerName $Computer -ScriptBlock {quser} | Select-Object -Skip 1 | Foreach-Object {

$b=$_.trim() -replace '\s+',' ' -replace '>','' -split '\s'

If ($b[2] -like 'Disc*') {

            $array= ([ordered]@{
                'User' = $b[0]
                'Computer' = $Computer
                'Date' = $b[4]
                'Time' = $b[5..6] -join ' '
                })
    
            $result+=New-Object -TypeName PSCustomObject -Property $array
            
            
    }

    else {

            $array= ([ordered]@{
                'User' = $b[0]
                'Computer' = $Computer
                'Date' = $b[5]
                'Time' = $b[6..7] -join ' '
                })
    
            $result+=New-Object -TypeName PSCustomObject -Property $array
            
           
}
}
}

If ($OU) {

    $comp=Get-ADComputer -Filter * -SearchBase "$OU" -Properties operatingsystem

    $count=$comp.count

    If ($count -gt 20) {

    Write-Warning "Search $count computers. This may take some time ... About 4 seconds for each computer"

    }

    foreach ($u in $comp) {

    Invoke-Command -ComputerName $u.Name -ScriptBlock {quser} | Select-Object -Skip 1 |  ForEach-Object {
    
    $a=$_.trim() -replace '\s+',' ' -replace '>','' -split '\s'

    If ($a[2] -like '*Disc*') {

            $array= ([ordered]@{
                'User' = $a[0]
                'Computer' = $u.Name
                'Date' = $a[4]
                'Time' = $a[5..6] -join ' '
                })
    
            $result+=New-Object -TypeName PSCustomObject -Property $array
    }

    else {

        $array= ([ordered]@{
                'User' = $a[0]
                'Computer' = $u.Name
                'Date' = $a[5]
                'Time' = $a[6..7] -join ' '
                })
    
            $result+=New-Object -TypeName PSCustomObject -Property $array
}
   
}

}

}

If ($All) {

    $comp=Get-ADComputer -Filter * -Properties operatingsystem

    $count=$comp.count

    If ($count -gt 20) {

    Write-Warning "Search $count computers. This may take some time ... About 4 seconds for each computer ..."

    }

    foreach ($u in $comp) {

    Invoke-Command -ComputerName $u.Name -ScriptBlock {quser} | Select-Object -Skip 1 |  ForEach-Object {
    
    $a=$_.trim() -replace '\s+',' ' -replace '>','' -split '\s'

    If ($a[2] -like '*Disc*') {

            $array= ([ordered]@{
                'User' = $a[0]
                'Computer' = $u.Name
                'Date' = $a[4]
                'Time' = $a[5..6] -join ' '
                })
    
            $result+=New-Object -TypeName PSCustomObject -Property $array
            
    }

    else {

        $array= ([ordered]@{
                'User' = $a[0]
                'Computer' = $u.Name
                'Date' = $a[5]
                'Time' = $a[6..7] -join ' '
                })
    
            $result+=New-Object -TypeName PSCustomObject -Property $array
          
}
   
}

}
}
Write-Output $result
}
