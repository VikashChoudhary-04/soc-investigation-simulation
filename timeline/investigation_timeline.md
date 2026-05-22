# Investigation Timeline

- This timeline documents the sequence of investigative activities and observed telemetry during the SOC investigation simulation.

- The investigation focused on:
  - authentication activity
  - privileged logons
  - process execution telemetry
  - suspicious command execution
  - threat hunting workflows
  - analyst assessment

---

## Timeline Overview

- The investigation simulated a structured SOC workflow involving:
  - alert triage
  - event correlation
  - authentication monitoring
  - process analysis
  - ATT&CK mapping
  - incident reporting

---

## Timeline Events

| Approximate Activity | Description | Relevant Event ID | Investigation Notes |
|---|---|---|---|
| Authentication Review Initiated | Successful and failed authentication activity reviewed | 4624 / 4625 | Baseline authentication telemetry analyzed |
| Failed Login Analysis | Failed authentication telemetry investigated | 4625 | No brute force indicators identified |
| Successful Authentication Analysis | Successful logon events reviewed | 4624 | Activity appeared consistent with expected Windows behavior |
| Privileged Activity Investigation | Elevated authentication activity investigated | 4672 | SYSTEM and privileged activity reviewed |
| Process Creation Investigation | Process execution telemetry analyzed | 4688 | Standard Windows process behavior observed |
| Threat Hunting Activity | PowerShell and LOLBin review performed | 4688 | No suspicious execution identified |
| ATT&CK Mapping Review | Investigation findings mapped to ATT&CK | Multiple | ATT&CK-aligned analysis completed |
| Analyst Assessment Completed | Investigation findings documented | Multiple | No confirmed malicious activity identified |

---

## Investigation Sequence

---

### Phase 1 — Alert Triage

- The investigation began with reviewing:
  - failed authentication alerts
  - process execution telemetry
  - privileged authentication activity

- The goal was to:
  - validate alerts
  - assess suspicious indicators
  - determine escalation requirements

---

### Phase 2 — Authentication Analysis

- Authentication telemetry was reviewed to identify:
  - failed logins
  - suspicious authentication patterns
  - brute force indicators
  - unauthorized access attempts

- Primary Event IDs:
  - 4624
  - 4625

---

### Phase 3 — Privileged Activity Review

- Privileged logon activity was analyzed to investigate:
  - elevated sessions
  - administrative access
  - SYSTEM activity
  - privilege escalation indicators

- Primary Event ID:
  - 4672

---

### Phase 4 — Process Execution Investigation

- Process creation telemetry was analyzed for:
  - suspicious binaries
  - PowerShell execution
  - LOLBin activity
  - anomalous command execution

- Primary Event ID:
  - 4688

---

### Phase 5 — Threat Hunting

- Threat hunting focused on:
  - PowerShell abuse
  - cmd.exe execution
  - rundll32.exe usage
  - mshta.exe activity

- No confirmed malicious execution behavior was identified.

---

## ATT&CK Timeline Mapping

| Timeline Activity | ATT&CK Technique |
|---|---|
| Failed Login Investigation | T1110 - Brute Force |
| Successful Authentication Analysis | T1078 - Valid Accounts |
| PowerShell Hunting | T1059.001 - PowerShell |
| LOLBin Monitoring | T1218 - Signed Binary Proxy Execution |
| Process Investigation | T1059 - Command and Scripting Interpreter |

---

## Timeline Assessment

- The reviewed telemetry primarily reflected:
  - baseline Windows activity
  - expected authentication behavior
  - normal privileged operations
  - standard process initialization

- No confirmed evidence of:
  - compromise
  - malicious persistence
  - privilege escalation
  - attacker execution
  - credential abuse

was identified during investigation.

---

## Key Lessons Learned

- Key lessons learned from timeline analysis included:

  - Timeline reconstruction improves SOC investigations
  - Event sequencing provides analytical context
  - Authentication telemetry is critical for investigations
  - Threat hunting requires structured reasoning
  - ATT&CK mapping improves analytical consistency
  - SOC investigations depend on contextual analysis

---

## Final Timeline Conclusion

- The investigation timeline demonstrated a structured SOC investigation workflow involving:
  - alert triage
  - authentication monitoring
  - process analysis
  - threat hunting
  - ATT&CK mapping
  - analytical reporting

- No confirmed malicious compromise or attacker activity was identified within the reviewed dataset.
