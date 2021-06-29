function Invoke-CheckForAzureAD {
    param ($DomainName)
    
    $req = (invoke-webrequest "https://login.microsoftonline.com/getuserrealm.srf?login=username@$DomainName.onmicrosoft.com&xml=1" | Select-Object -Property Content).content
    if($req -like "*Managed*")
    {Write-Host  " [+] The Domain: $DomainName has Azure-AD" -ForegroundColor 'Green'}
    else { Write-Host "[-] The Domain: $DomainName as no Azure AD" -ForegroundColor 'Red' }
}
