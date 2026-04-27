# CRTO Study Notes 2026  

<img src="/images/crto_study_c2_pathways.png" width=800>  

## OPSEC ROBOT  

🔴 UNSAFE  
🟠 CAUTION  
🟢 SAFE  

* **Red Team Ops** remain ***undetected*** and avoiding security ***triggers***.  
* Perform **stealthy** techniques that blends into normal activity, maintain a low profile.  
* Leverage trusted processes and native tools living off the land.  
* Reuse credentials, impersonating legitimate users, and mimicking normal behavior to **evade antivirus**.  
* **Bypass** endpoint defenses without alerting defenders.  

## Labs & Challenges    

* [Cobalt Strike Prepare & Initial Beacon](/labs/2-Cobalt-Strike-Primer.md)  
  * [Defence Evasion Lab + Malleable C2 Profile](/labs/defence-evasion-lab-Malleable.md)  
  * [AppLocker Challenge](/labs/applocker-challenge.md)  
  * [Initial Access Lab + Process Hollowing](/labs/Initial-Access-lab.md)  
  
* [Post-Exploitation](/cheatsheets/post-exploitation.md)  
  * Local Enumeration  
  * [Persistence lab](/labs/Persistence-lab.md)  
  * [Credential Access Challenge](/labs/credential-access-challenge-commands.md)
  * [Privilege Escalation lab](/labs/Privilege-Escalation-lab.md)  
  * [User Impersonation Lab](/labs/User-Impersonation-lab.md)  
  
* Domain Dominance  
  * [Active Directory Recon Discovery Lab](/labs/Discovery-lab.md)  
  * [User Impersonation Lab](/labs/User-Impersonation-lab.md)
  * [Lateral Movement Lab](/labs/Lateral-Movement-lab.md)  
  * [Persistence lab](/labs/Persistence-lab.md)  
  * [Elevated Persistence lab](/labs/Elevated-Persistence-lab.md)  

* [SOCKS Pivoting Tunnels Lab](/labs/pivoting-SOCKS-lab.md)  

* Kerberos  
  * [Kerberos - Unconstrained Delegation Lab](/labs/Unconstrained-Delegation-Kerberos-lab.md)  
  * [Kerberos - Constrained Delegation - Protocol Transition Lab](/labs/Constrained-Delegation-kerberos-lab.md)  
  * [Kerberos - Constrained Delegation - Service Name Substitution Lab](/labs/Service-Name-Substitution-Kerberos-lab.md)  
  * [Kerberos - S4U2self](/labs/S4U2self-lab.md)  
  * [Kerberos - Resource-Based Constrained Delegation Lab](/labs/RBCD-lab.md)  
  * [Kerberos Challenge](/labs/kerberos-challenge.md)  

* [SQL Servers Lab](labs/SQL-Servers-lab.md)  

* ADCS  
  * [ESC1 Misconfigured Client Authentication Templates](/labs/esc1.md)  
  * [ESC8 NTLM Relay to ADCS HTTP Endpoints](/labs/esc8.md)  
  * [DPERSIST1 Golden Certificates](/labs/dpersist1.md)  

* Domains & Forests
  * [Parent-Child Trust Lab](/labs/Parent-Child-Trusts.md)  
  * [Inbound Trust Lab](/labs/Inbound-Trusts-lab.md)  
  * [Outbound Trust Lab](/labs/Outbound-Trusts-lab.md)  

----  

## Red Team Ops Phases    

* [Cobalt Strike Primer](/cheatsheets/cobalt-strike-primer.md)  
* [AppLocker](/cheatsheets/applocker.md)  
* [Defence Evasion](/cheatsheets/defense-evasion.md)  
* [Initial Access](/cheatsheets/initial-access.md)  
* [Persistence](/cheatsheets/persistence.md)  
* [Post-Exploitation](/cheatsheets/post-exploitation.md)  
* [Privilege Escalation](/cheatsheets/privilege-escalation.md)  
* [Elevated Persistence](/cheatsheets/elevated-persistence.md)  
* [Credential Access](/cheatsheets/credential-access.md)  
* [User Impersonation](/cheatsheets/user-impersonation.md)  
* [Discovery](/cheatsheets/discovery.md)  
* [Lateral Movement](/cheatsheets/lateral-movement.md)  
* [Pivoting](/cheatsheets/pivoting.md)
* [Kerberos](/cheatsheets/kerberos.md)  
* [Microsoft SQL Server](/cheatsheets/ms-sql-server.md)  
* [Domain Dominance](/cheatsheets/domain-dominance.md)  
* [Active Directory Certificate Services ADCS](/cheatsheets/adcs.md)  
* [Forest & Domain Trusts](/cheatsheets/forest-domain-trusts.md)  

----  

## Exam Context  

* [Zero Point Security Red Team Ops Course Content](https://www.zeropointsecurity.co.uk/course/red-team-ops)  
* [Exam Instructions](/notes/Exam-Instructions.md)  
* [CRTO Fast Reference Methodology on Exam Day](/crto-fast-reference-methodology-exam-day.md)  
* [Command Library](/crto-command-library.md)  

----  

## Resources  

* [ThreadCheck- Artifact Kit](https://github.com/rasta-mouse/ThreatCheck)  
* [.NET Marshal.Copy method called to copy Beacon shellcode](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.copy)  
* [native WriteProcessMemory API](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)  
* [obfuscation Invoke-obfuscation script](https://github.com/danielbohannon/Invoke-Obfuscation)  
* [Beacon Memory - export raw Beacon DLL before obfuscations applied](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_hooks.htm#BEACON_RDLL_GENERATE)
* [Beacon Command Behaviour - Beacon Object Files BOF custom command import](https://github.com/trustedsec/CS-Situational-Awareness-BOF)  
* [Cobalt Strike User Guide - PowerShell_Command & _Compress](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_hooks.htm#POWERSHELL_COMMAND)  
* [Elevate Kit](https://github.com/Cobalt-Strike/ElevateKit)  
* [Cobalt Strike User Guide - beacon_exploit_register](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#beacon_exploit_register)  
* [DLL side loading Payload Template](https://github.com/FuzzySecurity/DLL-Template)  
* [Rasta Mouse - .NET Startup Hooks](https://rastamouse.me/net-startup-hooks/)  
* [GadgetToJScript used to create JavaScript dropper out of a .NET assembly](https://github.com/med0x2e/GadgetToJScript)  
* [double click batch command file exploit](https://github.com/frostb1ten/CVE-2024-24576-PoC)  
* [GrimResource use crafted .msc file and unpatched XSS flaw trigger JavaScript code execution via mmc](https://gist.github.com/joe-desimone/2b0bbee382c9bdfcac53f2349a379fa4)  
* [CyberChef - payload](https://gchq.github.io/CyberChef/#recipe=URL_Encode(false)&input=PD94bWwgdmVyc2lvbj0nMS4wJz8%2BDQo8c3R5bGVzaGVldA0KICAgIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L1hTTC9UcmFuc2Zvcm0iIHhtbG5zOm1zPSJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOnhzbHQiDQogICAgeG1sbnM6dXNlcj0icGxhY2Vob2xkZXIiDQogICAgdmVyc2lvbj0iMS4wIj4NCiAgICA8b3V0cHV0IG1ldGhvZD0idGV4dCIvPg0KICAgIDxtczpzY3JpcHQgaW1wbGVtZW50cy1wcmVmaXg9InVzZXIiIGxhbmd1YWdlPSJWQlNjcmlwdCI%2BDQogICAgPCFbQ0RBVEFbDQogICAgICAgIFNldCB3c2hzaGVsbCA9IENyZWF0ZU9iamVjdCgiV1NjcmlwdC5TaGVsbCIpDQogICAgICAgIHdzaHNoZWxsLnJ1biAiQzpcXFdpbmRvd3NcXFN5c3RlbTMyXFxjbWQuZXhlIg0KXV0%2BPC9tczpzY3JpcHQ%2BDQo8L3N0eWxlc2hlZXQ%2B&ieol=CRLF&oeol=CRLF)  
* [SharpUp GhostPack](https://github.com/GhostPack/SharpUp)  
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)  
* [Ghidra](https://github.com/NationalSecurityAgency/ghidra)  
* [IDA free](https://hex-rays.com/ida-free)  
* [dotPeek jetbrains decompiler](https://www.jetbrains.com/decompiler/)  
* [dnSpy](https://github.com/dnSpy/dnSpy)  
* [ysoserial](https://github.com/pwntester/ysoserial.net)  
* [ired.team notes](https://www.ired.team/)  
* [Kerbeus-BOF Beacon Object Files for Kerberos abuse](https://github.com/RalfHacker/Kerbeus-BOF)  
* [BOFHound parse output from ldapsearch and pyldapsearch into BloodHound-compatible JSON files](https://github.com/coffeegist/bofhound)  
* [pyldapsearch](https://github.com/Tw1sm/pyldapsearch)
* [ldapsearch](https://github.com/trustedsec/CS-Situational-Awareness-BOF/tree/master)  
* [Cloud AzureHound](https://bloodhound.specterops.io/collect-data/ce-collection/azurehound)  
* [RustHound-CE](https://github.com/g0h4n/RustHound-CE)  
* [LOLBAS - Living Off The Land Binaries, Scripts and Libraries](https://lolbas-project.github.io/)  
* [BOF Version of SCShell for Cobalt Strike instead of psExec](https://github.com/Mr-Un1k0d3r/SCShell/tree/master/CS-BOF)  
* [OPSEC Consideration for Beacon Commands](https://www.cobaltstrike.com/blog/opsec-considerations-for-beacon-commands)  
* [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)  
* [SQLRecon](https://github.com/skahwah/SQLRecon)  
* [SQL-BOF](https://github.com/Tw1sm/SQL-BOF)  
* [go sqlcmd](https://github.com/microsoft/go-sqlcmd)  
* [HeidiSQL](https://github.com/heidisql/heidisql)  
* [SSMS](https://learn.microsoft.com/en-us/ssms/install/install)  


## AdaptixC2  
  
* [AdaptixC2 Framework Github](https://github.com/Adaptix-Framework/AdaptixC2)  
* [AdaptixC2 Guide Setup Instructions](https://adaptix-framework.gitbook.io/adaptix-framework)

<img src="/images/RedTeamOperationsPractitioner.png" width=400>  

🇿🇦 26April2026 🇿🇦  
