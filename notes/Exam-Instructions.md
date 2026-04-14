# Exam Instructions

## Launching the Exam

Click **Red Team Operator Exam** lesson in the course menu.

> Do NOT navigate away from the exam page while it is running. Open course material in a separate tab/window.

The lab ID number is shown at the bottom of the instructions panel — include it in any support contact.

---

## Exam Scenario

- **Assume-breach** scenario — no pre-running Beacon, but access to a foothold machine on the internal network.
- You must deploy a Beacon manually. **This may require bypassing host-based defences first.**
- The instruction panel presents the **operational objective** and **rules of engagement** (off-limit hosts, restrictions).

---

## Scoring

| Component | Points |
|-----------|--------|
| Operational objective | 50 pts |
| OPSEC discipline | 50 pts |
| **Minimum to pass** | **85 pts** |

> **Achieving the objective alone is not enough to pass. You need both.**
> **You will fail if OPSEC score drops too low, even if the objective is complete.**

---

## OPSEC Scoring Criteria — Know These Cold

| Criterion | What Triggers a Deduction | Mitigation |
|-----------|--------------------------|------------|
| **Blocked by Defender / AppLocker** | AV blocking payload execution at any stage | Artifact Kit + Resource Kit clean before exam start |
| **Outbound from unusual processes** | Beacon HTTP callback from a process that doesn't legitimately make web requests | Run Beacon inside browser, svchost, dllhost — set `spawnto` and `ppid` |
| **Default CS indicators** | Default named pipe names, default injection technique | Customise `post-ex.pipename` and `process-inject` block in Malleable C2 profile |
| **Suspicious lateral movement** | `jump psexec` / service creation event logs | Prefer `jump winrm64` → `remote-exec wmi` → psexec only as last resort |
| **Suspicious LSASS handles** | Direct LSASS handle from non-system process | Use `nanodump` BOF — never Mimikatz direct against LSASS |
| **Disabling security controls** | Turning off Defender or Windows Firewall | **Never disable Defender or Firewall — automatic deduction** |

---

## Off-Limit Hosts — Instant Fail

> *"You will fail the exam if you generate an alert on an off-limit host, even if you achieve the operational objective."*

**Read the rules of engagement before touching anything.**
Enumerate scope before any lateral move. Do not assume all visible hosts are in scope.

---

## Time Limits

| Limit | Value |
|-------|-------|
| Lab runtime | 24 hours total (across all sessions) |
| Calendar window | 7 days to complete and submit |
| Cooldown between attempts | 7 days |
| Active time before Save becomes available | 15–20 minutes |

---

## Saving Progress — Critical UI Distinction

<img src="/images/save-progress-in-exam.png" width=860>

| Button | Result |
|--------|--------|
| **Exit Lab → Save Progress And Exit** | VMs saved, environment paused — **safe** |
| **Exit Lab → End Lab** | **Instant, permanent, irreversible destruction of exam attempt** |

> **You must be active in the environment for 15–20 minutes before Save Progress And Exit becomes available.**
> Do not launch unless you are ready to work immediately — launching and immediately closing terminates the environment and still counts as an attempt.

---

## Persistence is Required — Do Not Rely on Save Progress

> *"You should not rely on this feature to preserve your running Beacons, particularly those in a P2P chain. Make sure you have proper persistence setup as you would in the real world."*

When you resume after saving, any SMB/P2P Beacon chain will be dead. Persistence must survive reboot. Set persistence **before** taking a break.

---

## Submission and Grading

- Click **Submit** at the bottom of the instructions panel to end the exam for grading.
- **Submit is permanent** — do not click accidentally.
- Do not navigate away or close the page while grading is in progress (takes several minutes).
- After grading, click **"Update & Close"** to post your score to the course platform — **failure to do this means you cannot claim the certification.**

---

## Pre-Exam Checklist

```
[ ] Read rules of engagement — identify off-limit hosts before touching anything
[ ] SSH to team server → update Malleable C2 profile (stage, post-ex, process-inject)
[ ] Patch Artifact Kit (patch.c) → build → ThreatCheck clean
[ ] Build Resource Kit → fix template.x64.ps1 → ThreatCheck AMSI clean
[ ] Load artifact.cna + resources.cna in CS Script Manager
[ ] c2lint against profile → zero errors → docker restart team server
[ ] Test beacon callback with Defender ON before engaging targets
[ ] Set spawnto away from default rundll32.exe
[ ] Set custom named pipe pattern in post-ex.pipename
[ ] Have persistence technique ready to deploy after first beacon checks in
```
