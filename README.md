# CRTO Study Notes 2026  

<img src="/images/crto_study_c2_pathways.png" width=800>  

>[CRTO](https://www.zeropointsecurity.co.uk/course/red-team-ops) Zero Point Security Study Notes and my preparation for the Red Team Exam  

## Cheatsheet Sections    

* [Claude Context](/CLAUDE.md)  
* [Cobalt Strike Primer - Beacon Interface Commands](/cheatsheets/cobalt-strike.md)
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


## Labs  

* [Cobalt Strike Initial Commands Lab](/labs/2-Cobalt-Strike-Primer.md)  
* [Defence-evasion-lab-Malleable.md](/labs/defence-evasion-lab-Malleable.md)  
* [Initial Access Lab](/labs/Initial-Access-lab.md)  
* [Persistence lab](/labs/Persistence-lab.md)  
* [Privilege Escalation lab](/labs/Privilege-Escalation-lab.md)  

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

## Other  

* [Private - Windows Evasion Techniques](https://github.com/botesjuan/Hacking-HackTheBox-OffSec/blob/d1c2989ee0b1311a1a63f6ecdb2bddc3abd22a43/module/Windows-Evasion-Techniques.md)  
* [Private - Antivirus Evasion Intro AVINTRO](https://github.com/botesjuan/Hacking-HackTheBox-OffSec/blob/d1c2989ee0b1311a1a63f6ecdb2bddc3abd22a43/module/offsec-pen300-avintro.md)  
* [ired.team notes](https://www.ired.team/)  
* [Adaptix C2 Framework](https://github.com/Adaptix-Framework/AdaptixC2)  

