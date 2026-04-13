# Shadow Credentials to Ransomware Kill Chain

## Monday morning  

A phishing email lands in an HR employee's inbox. She clicks a link, enters her credentials into a fake login page. The attacker now has her username and password — but her account has MFA, so the password alone is useless.

## Fothold  

⚠️ *The attacker doesn't panic. He has a foothold via a macro in the attachment she also opened.*

## Enumeration   

💬 **The attacker is now a low-privilege user on her workstation.**

He runs BloodHound quietly in the background. The graph lights up. He finds something interesting — a service account named `svc_backup` has **GenericWrite** permission over a domain computer object called `FS01` (the file server).

He doesn't know the password for `svc_backup`. He doesn't need to.

👉 **Here's where Shadow Credentials enters the story.**

Think of every computer and user account in Active Directory as having a small lockbox on it. Normally only the domain knows what key opens that lockbox — it's a secret stored as a password hash.

But Microsoft added a newer feature to AD called **Key Trust** (for passwordless login). It lets you attach *an extra key* to any account's lockbox. The account will accept *either* the original password **or** this new extra key.

## Exploitation  

The attacker abuses his `GenericWrite` permission on `FS01` to **add his own key to FS01's lockbox** — without touching or changing the original password. Nobody notices. No password was reset. No alerts fire.

🏢 He now has a key that the file server `FS01` will accept as proof of identity.

**He uses his forged key to request a Kerberos ticket for FS01.**

The domain controller sees a valid key, hands over a TGT (a golden pass for that machine), and the attacker extracts the `NTLM hash` of the machine account from that ticket.

Now he has the machine account credential for `FS01` — the file server — **without ever logging into it, touching LSASS, or making noise.**

## Persistence  

**Machine accounts are trusted inside the domain.**

🧱 With `FS01$`'s credential, he performs a **DCSync-style** attack — machine accounts with certain roles can pull credential data from the domain controller. He dumps the `krbtgt` hash and several domain admin hashes.

He now owns the domain. Quietly. No brute force. No service creation. No loud lateral movement.

**Friday night. The ransomware deploys.**

## Ransomware  

🎯 With DA credentials he moves to every server simultaneously — backup servers first, then production. He deletes shadow copies, encrypts file shares, and drops a ransom note.

By the time IT arrives Monday morning, 3,000 file shares are encrypted and the backup server is gone.

---

## Why Shadow Credentials Was the Turning Point

| Stage | What happened |
|---|---|
| Initial access | Phishing → low-priv foothold |
| Pivoting point | Found `GenericWrite` on a computer object |
| **Shadow Credential abuse** | **Added a rogue key to FS01 — silent, no password change** |
| Escalation | Used rogue key → Kerberos TGT → extracted machine NTLM hash |
| Domain compromise | Machine hash → DCSync → domain admin hashes |
| Impact | Ransomware deployed domain-wide |

---

## The Key Insight (Non-Technical)

> Shadow Credentials is like making a **copy of a building's master key** by exploiting a feature designed for convenience — and nobody in the building knows an extra copy exists, because the original key was never touched and the lock was never changed.

The defender looks for password changes, new accounts, failed logins. None of those happened. The attacker just *added a silent spare key to a door they had permission to modify* — and walked in through the back whenever they wanted.

---

## Detection Remediation

🎂 Blue team catches this via:
- `Event ID 5136` — DS Object Modified (`msDS-KeyCredentialLink` attribute changed)
- Anomalous Kerberos PKINIT requests for machine accounts
- BloodHound edge: `AddKeyCredentialLink`
