# CRTO Study Notes 2026  

<img src="/images/crto_study_c2_pathways.png" width=800>  

## Steal and OPSEC Mission  

>The goal of a red team operation is to emulate a real-world adversary while remaining ***undetected*** by minimizing noise and avoiding security triggers.  
>OPSEC is used to describe the likelihood of actions being ***detected*** by enemy intelligence. Red team actions is to be not observed and subsequently interrupted by the defenders.  
>This involves performing ***stealthy*** enumeration that blends into normal activity, maintaining a low profile on compromised systems, and operating through trusted processes and native tools living off the land.  
>By reusing credentials, impersonating legitimate users, and mimicking normal behavior, the operator seeks to ***evade antivirus*** and endpoint defenses while achieving objectives without alerting defenders.  

>[CRTO](https://www.zeropointsecurity.co.uk/course/red-team-ops) Zero Point Security Study Notes for the Red Team Ops Exam  

## Attack Chain Section Phases  

* [Cobalt Strike Primer](/cheatsheets/cobalt-strike-primer.md)  
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
* [AppLocker](/cheatsheets/applocker.md)  

## Labs & Challenges  

* [Cobalt Strike Initial Commands Lab](/labs/2-Cobalt-Strike-Primer.md)  
* [Defence-evasion-lab-Malleable.md](/labs/defence-evasion-lab-Malleable.md)  
* [Initial Access Lab](/labs/Initial-Access-lab.md)  
* [Persistence lab](/labs/Persistence-lab.md)  
* [Privilege Escalation lab](/labs/Privilege-Escalation-lab.md)  
* [Elevated Persistence lab](/labs/Elevated-Persistence-lab.md)  
* [Credential Access Challenge](/labs/credential-access-challenge-commands.md)  
* [User Impersonation Lab](/labs/user-impersonation-lab.md)  
* [Discovery Lab](/labs/Discovery-lab.md)  

## Scripts, Payloads & Code

>[Ready to use scripts, payloads & code sample templates in CRTO exam](/code)  

----  

## References  

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



## AdaptixC2  
  
* [AdaptixC2 Framework Github](https://github.com/Adaptix-Framework/AdaptixC2)  
* [AdaptixC2 Guide Setup Instructions](https://adaptix-framework.gitbook.io/adaptix-framework)

