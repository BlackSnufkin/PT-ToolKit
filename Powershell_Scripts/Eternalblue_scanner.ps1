#Created by Daniel Card @ Xservus Limited
#checks for SMB.SRV version as per https://support.microsoft.com/en-ca/help/4023262/how-to-verify-that-ms17-010-is-installed
#14/05/2018


#search AD for server objects
$domainserver = Read-Host -Prompt "Please enter name of domain controller to querry"
$creds = Get-Credential -Message "Please enter credentials for endpoints"

$computers = Get-ADComputer -Credential $creds -Server $domainserver -Filter {OperatingSystem -Like 'Windows Server*'}


foreach($computer in $computers){

write-host "Name: " $computer.Name
write-host "LDAP Path: " $computer

try{
$SMBv1Version = Get-WmiObject -Credential $creds CIM_Datafile -ComputerName $computer.DNSHostName -Filter "Name='c:\\windows\\system32\\Drivers\\srv.sys'" -ErrorAction Stop

write-host "c:\windows\system32\drivers\srv.sys Version = " $SMBv1Version.Version

#check sub version for Windows 7 or Server 2008 R2
if($SMBv1Version.Version.ToString() -like "6.1.*"){


write-host "Server 2008 R2 or Windows 7 Identified" -ForegroundColor DarkRed
    if($SMBv1Version.Version.ToString() -lt "6.1.7601.23689"){

    write-host "Vulnerable to EternalBlue - Reccomend you patch MS17-010 immediatley" -ForegroundColor Red

    }

}

#check sub version for Windows 2012
if($SMBv1Version.Version.ToString() -like "6.2.*"){


write-host "Windows 2012 Identified" -ForegroundColor DarkRed
    if($SMBv1Version.Version.ToString() -lt "6.2.9200.2209"){

    write-host "Vulnerable to EternalBlue - Reccomend you patch MS17-010 immediatley" -ForegroundColor Red
    $vulnerablecount = $vulnerablecount + 1
    }

}

#check sub version for Windows 2012 R2 or Windowws 8.1
if($SMBv1Version.Version.ToString() -like "6.3.*"){


write-host "Windows 2012 R2 or Windowws 8.1 Identified" -ForegroundColor DarkRed
    if($SMBv1Version.Version.ToString() -lt "6.3.9600.18604"){

    write-host "Vulnerable to EternalBlue - Reccomend you patch MS17-010 immediatley" -ForegroundColor Red
    $vulnerablecount = $vulnerablecount + 1
    }

}

#check sub version for Windows 10 or Server 2016
if($SMBv1Version.Version.ToString() -like "10.0.*"){


write-host "Windows Windows 10 or Server 2016 Identified" -ForegroundColor DarkRed
    if($SMBv1Version.Version.ToString() -lt "10.0.10240.17319"){

    write-host "Vulnerable to EternalBlue - Reccomend you patch MS17-010 immediatley" -ForegroundColor Red
    $vulnerablecount = $vulnerablecount + 1
    }

}







}

catch{
write-host "Error Encountered Enumerating SMB Version" -ForegroundColor DarkGreen

}
finally{



}




}
