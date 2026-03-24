# Lessons learned from other students that failed the CRTO exam  

## First attempt: 
- payloads kept getting caught. 
- I understood AMSI bypass theory but couldn't implement effective evasion under exam conditions. 
- Defender flagged my beacons within minutes.

## Second attempt: 
- Better payload generation, but poor C2 infrastructure management. 
- properly configure my Cobalt Strike Malleable C2 profiles. 
- artifacts got detected during post-exploitation.

## What changed:

Evasion research:
* Custom artifact kits with modified implementations
* Rewrote default resource scripts
* Studied AMSI internals not just patch techniques 
* Built detection-resistant payload templates from scratch
* Tested everything against ThreatCheck before deployment

C2 operational security:
* Proper Malleable C2 profile configuration 
* Arsenal kit customization for artifact generation 
* Modified pipe names, process injection techniques 
* Sleep obfuscation and jitter implementation 
* Understanding what signatures actually trigger alerts

Active Directory exploitation:
* RBCD attacks when constrained delegation exists 
* Cross-domain trust abuse techniques
* Diamond/Sliver/Golden tickets for persistence 
* Kerberos delegation chains across forest trusts
 
The real lesson:

You can know every attack path, but if Defender catches your beacon on first execution, you fail. 
CRTO isn't just about AD exploitation, it's about doing it without getting caught.

Most courses teach you the attack. 
CRTO forces you to evade detection while executing it.

Failure wasn't about lacking knowledge.
Failure was about operational execution under defensive pressure.

Preparing: 
- Don't just learn the techniques. 
- Learn why your payloads get detected and how to fix them before exam day.

CRTO certification that actually tests real-world red team capabilities.

