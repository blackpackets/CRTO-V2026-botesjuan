# Post-CRTO Exam — Customer Engagement Structure (Deferred)

> **Status:** Deferred — implement after CRTO exam pass.
> **Action:** Ask Claude Code to build out this structure in full.

---

## 1. Claude Code Mechanics to Configure

### Hooks (via `update-config` skill)
Automated behaviours configured in `.claude/settings.json` — run without prompting:

- **PostToolUse on Write/Edit** → auto `git add` changed file so nothing is lost mid-session
- **Stop hook** → print reminder to push to GitHub at session end
- **PreToolUse on Bash** → warn before running `shell`/`run` beacon commands outside a code block (catch copy-paste mistakes)

To activate: tell Claude Code "set up a stop hook that reminds me to git push" → invokes `update-config` skill.

### Reduce Permission Prompts
Run `/fewer-permission-prompts` after a few engagement sessions. It reads transcript history and whitelists read-only Bash/tool calls used constantly (git, find, file reads). Less friction, same safety.

### Memory to Add for Engagement Work
- `feedback_engagement_style.md` — how command output should be formatted for engagement reports vs. study notes
- `reference_tool_locations.md` — key tool paths (Rubeus, BOFs, CNA scripts) so Claude doesn't guess

---

## 2. Repo Directory Structure to Add

```
crto-study-notes/
├── engagements/                  ← one subdir per customer engagement
│   └── _template/
│       ├── scope.md              ← targets, OOB, creds given, start/end dates
│       ├── roe.md                ← rules of engagement, escalation contacts
│       ├── attack-chain.md       ← live planning doc updated as you go
│       ├── opsec-log.md          ← every technique run + OPSEC tier used
│       └── flags-and-findings.md ← evidence + findings for reporting
├── templates/                    ← reusable skeletons
│   ├── malleable-c2-profile.md   ← profile checklist per engagement type
│   ├── beacon-setup-checklist.md
│   └── reporting-snippet.md      ← pre-formatted finding blocks
└── cheatsheets/                  ← existing, keep as-is
```

---

## 3. CLAUDE.md Additions — Engagement Mode Block

Add a second behaviour mode below the existing CRTO study directives:

```markdown
## ENGAGEMENT MODE

When I say **"engagement: <client-name>"**:
- Switch context to `engagements/<client-name>/`
- All command outputs logged to `engagements/<client-name>/opsec-log.md`
- Scope check: before any lateral movement command, confirm target is in `scope.md`
- Report-ready output: format findings as Integrity360 report blocks, not exam cheatsheet blocks

When I say **"scope check <target>"**:
- Read `engagements/<active>/scope.md`
- Confirm IP/hostname is in-scope
- Flag if near OOB boundaries
- Output: IN-SCOPE / OUT-OF-SCOPE / VERIFY-MANUALLY
```

---

## 4. Skills to Use for Engagement Workflow

| Skill | When |
|-------|------|
| `/review` | After drafting a technique chain — second-pass OPSEC check before running |
| `/security-review` | Before committing engagement notes — catch accidental credential leakage |
| `/schedule` | Weekly "what labs or techniques haven't been re-tested in 30 days" sweep |
| `/fewer-permission-prompts` | After first few engagement sessions to whitelist common tool calls |
| `/update-config` | To set up the auto-log and commit-reminder hooks |

---

## Implementation Order (when ready)

1. Ask Claude Code: "build the engagement template structure from the post-exam notes"
2. Run `/fewer-permission-prompts`
3. Add engagement mode block to `CLAUDE.md`
4. Run `/update-config` to set up session hooks
5. Clone `engagements/_template/` → `engagements/<first-client>/` for first real engagement
