# Alert Triage Documentation

- This document simulates SOC analyst alert triage workflows using Splunk, Windows Security Event Logs, and threat hunting methodology.

- The goal of alert triage is to:
  - identify suspicious activity
  - prioritize alerts
  - assess severity
  - determine escalation requirements
  - reduce false positives
  - guide investigation workflows

---

## Triage Methodology

- The investigation process followed these steps:

  1. Identify the alert
  2. Validate the telemetry
  3. Review event context
  4. Assess suspicious indicators
  5. Correlate related activity
  6. Determine severity
  7. Recommend next actions

---

## Simulated Alerts

---

### Alert 1 — Multiple Failed Authentication Attempts

#### Alert Description

- High volume of failed authentication attempts identified.

---

#### Relevant Event ID

| Event ID | Description |
|---|---|
| 4625 | Failed Logon |

---

#### Investigation Query

```spl
index=main "4625"
| stats count by host
| sort - count
````

---

#### Why This Could Be Suspicious

- Potential indicators:

  * brute force activity
  * password spraying
  * credential abuse
  * repeated authentication failures

---

#### Evidence Reviewed

- Reviewed:

  * failed login frequency
  * targeted accounts
  * authentication timing
  * host telemetry

- No significant failed authentication spikes were identified in the current dataset.

---

#### Severity Assessment

| Category            | Value |
| ------------------- | ----- |
| Severity            | Low   |
| Confidence          | Low   |
| Escalation Required | No    |

---

#### Analyst Assessment

- No confirmed brute force activity was identified during investigation.

- The observed telemetry did not indicate:

  * large-scale login failures
  * suspicious authentication bursts
  * credential attack behavior

---

### Alert 2 — Suspicious PowerShell Activity

#### Alert Description

- Potential suspicious PowerShell or command execution activity detected.

---

#### Relevant Event ID

| Event ID | Description      |
| -------- | ---------------- |
| 4688     | Process Creation |

---

#### Investigation Query

```spl id="6yzn0q"
index=main ("powershell" OR "cmd.exe" OR "rundll32" OR "mshta")
```

---

#### Why This Could Be Suspicious

- Attackers frequently abuse:

  * PowerShell
  * cmd.exe
  * rundll32.exe
  * mshta.exe

for:

  * payload execution
  * defense evasion
  * persistence
  * malicious scripting

---

#### Evidence Reviewed

- Reviewed:

  * suspicious process execution
  * command activity
  * LOLBin usage
  * PowerShell indicators

- No confirmed malicious PowerShell execution or LOLBin abuse was identified.

---

#### Severity Assessment

| Category            | Value  |
| ------------------- | ------ |
| Severity            | Medium |
| Confidence          | Low    |
| Escalation Required | No     |

---

#### Analyst Assessment

- Observed process activity primarily reflected:

  * baseline Windows behavior
  * normal system operations
  * expected initialization activity

- No confirmed attacker command execution was identified.

---

### Alert 3 — Privileged Authentication Activity

#### Alert Description

- Privileged authentication activity detected.

---

#### Relevant Event ID

| Event ID | Description      |
| -------- | ---------------- |
| 4672     | Privileged Logon |

---

#### Investigation Query

```spl id="m0p3xu"
index=main "4672"
| stats count by host
| sort - count
```

---

#### Why This Could Be Suspicious

- Privileged logons may indicate:

  * administrative activity
  * privilege escalation
  * elevated access abuse
  * unauthorized privileged sessions

---

#### Evidence Reviewed

- Reviewed:

  * SYSTEM logons
  * elevated authentication activity
  * privileged account telemetry
  * login behavior

- Observed activity appeared consistent with standard Windows administrative and system operations.

---

#### Severity Assessment

| Category            | Value  |
| ------------------- | ------ |
| Severity            | Medium |
| Confidence          | Low    |
| Escalation Required | No     |

---

#### Analyst Assessment

- No evidence of:

  * suspicious privilege escalation
  * malicious administrative activity
  * unauthorized elevated access

was identified during investigation.

---

## Alert Triage Summary

| Alert                              | Severity | Escalation |
| ---------------------------------- | -------- | ---------- |
| Failed Authentication Monitoring   | Low      | No         |
| Suspicious PowerShell Activity     | Medium   | No         |
| Privileged Authentication Activity | Medium   | No         |

---

## Key SOC Concepts Demonstrated

- This triage simulation demonstrates:

  * SIEM investigation workflows
  * Alert prioritization
  * Threat hunting methodology
  * Event correlation
  * Authentication monitoring
  * Analyst reasoning
  * Evidence-based assessment
  * SOC operational workflows

---

## Lessons Learned

- Key triage lessons included:

  * Not all alerts indicate compromise
  * Baseline analysis is critical
  * Context improves investigation accuracy
  * Threat hunting requires structured reasoning
  * SIEM alerts require validation and correlation
  * SOC analysts must balance detection and false positives

---

## Final Analyst Conclusion

- The reviewed telemetry primarily reflected baseline Windows operating system activity and expected authentication behavior.

- No confirmed malicious compromise or active attacker behavior was identified during the simulated SOC investigation.
