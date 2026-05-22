# Final Incident Investigation Report

## Incident Title

- SOC Investigation Simulation — Authentication and Process Activity Analysis

---

## Executive Summary

- A simulated SOC investigation was conducted using Splunk and Windows Security Event Logs to analyze suspicious authentication activity, privileged logons, process execution telemetry, and potential attacker-related behavior.

- The investigation focused on:
  - failed authentication attempts
  - successful logons
  - privileged activity
  - suspicious PowerShell execution
  - process creation telemetry
  - event correlation
  - ATT&CK-based analysis

- No confirmed malicious compromise or active attacker behavior was identified in the reviewed dataset. However, the investigation successfully demonstrated realistic SOC investigation workflows, threat hunting methodology, alert triage reasoning, and analytical incident reporting practices.

---

## Investigation Scope

| Category | Details |
|---|---|
| SIEM Platform | Splunk Free |
| Log Source | Windows Security Logs |
| Investigation Type | SOC Investigation Simulation |
| Investigation Focus | Authentication & Process Activity |
| Host | Vikash |

---

## Event IDs Investigated

| Event ID | Description |
|---|---|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4672 | Privileged Logon |
| 4688 | Process Creation |

---

## Investigation Workflow

- The investigation process included:

  1. Alert triage
  2. Authentication monitoring
  3. Failed login analysis
  4. Privileged activity review
  5. Process execution investigation
  6. Threat hunting
  7. Event correlation
  8. ATT&CK mapping
  9. Timeline analysis
  10. Analyst assessment

---

## Investigation Findings

---

### 1. Failed Authentication Monitoring

#### SPL Query

```spl
index=main "4625"
| stats count by host
| sort - count
````

---

#### Purpose

- Review failed authentication telemetry and identify brute force indicators.

---

#### Findings

- No significant failed authentication activity was identified within the reviewed dataset.

- No evidence of:

  * brute force attacks
  * password spraying
  * credential abuse
  * large-scale authentication failures

was observed during investigation.

---

#### ATT&CK Mapping

| Technique   | ID    |
| ----------- | ----- |
| Brute Force | T1110 |

---

### 2. Successful Authentication Analysis

#### SPL Query

```spl id="yl7t83"
index=main "4624"
| stats count by host
| sort - count
```

---

#### Purpose

- Review successful authentication activity and identify suspicious login behavior.

---

#### Findings

- Multiple successful logons were identified and reviewed.

- Observed authentication activity appeared consistent with:

  * baseline Windows behavior
  * expected login activity
  * standard operating system processes

- No confirmed unauthorized authentication activity was identified.

---

#### ATT&CK Mapping

| Technique      | ID    |
| -------------- | ----- |
| Valid Accounts | T1078 |

---

### 3. Privileged Logon Investigation

#### SPL Query

```spl id="oblsdx"
index=main "4672"
| stats count by host
| sort - count
```

---

#### Purpose

- Monitor elevated authentication activity and privileged access behavior.

---

#### Findings

- Privileged authentication activity was reviewed for:

  * administrative access
  * elevated sessions
  * privilege escalation indicators
  * SYSTEM account activity

- Observed telemetry primarily reflected:

  * standard Windows operations
  * expected administrative activity
  * normal system initialization

- No suspicious privilege escalation activity was identified.

---

#### ATT&CK Mapping

| Technique      | ID    |
| -------------- | ----- |
| Valid Accounts | T1078 |

---

### 4. Process Creation Investigation

#### SPL Query

```spl id="a0r9kb"
index=main "4688"
| stats count by host
| sort - count
```

---

#### Purpose

- Review process execution telemetry and identify suspicious activity.

---

#### Findings

- Process creation events were analyzed for:

  * PowerShell execution
  * LOLBin usage
  * suspicious binaries
  * anomalous command execution

- Observed activity primarily reflected:

  * standard Windows initialization
  * expected operating system processes
  * baseline execution behavior

- No confirmed malicious process execution was identified.

---

#### ATT&CK Mapping

| Technique                         | ID    |
| --------------------------------- | ----- |
| Command and Scripting Interpreter | T1059 |

---

### 5. Threat Hunting Investigation

#### SPL Query

```spl id="crz61l"
index=main ("powershell" OR "cmd.exe" OR "rundll32" OR "mshta")
```

---

#### Purpose

- Perform threat hunting for suspicious command execution and LOLBin activity.

---

#### Findings

- Threat hunting activities focused on:

  * PowerShell abuse
  * cmd.exe execution
  * rundll32.exe usage
  * mshta.exe activity

- No confirmed malicious PowerShell execution or LOLBin abuse was identified during the investigation.

---

#### ATT&CK Mapping

| Technique                     | ID        |
| ----------------------------- | --------- |
| PowerShell                    | T1059.001 |
| Signed Binary Proxy Execution | T1218     |

---

## Timeline Summary

| Investigation Phase        | Description                                   |
| -------------------------- | --------------------------------------------- |
| Alert Review               | Authentication and process alerts reviewed    |
| Authentication Analysis    | Successful and failed logons analyzed         |
| Privileged Activity Review | Elevated authentication activity investigated |
| Process Investigation      | Process creation telemetry analyzed           |
| Threat Hunting             | PowerShell and LOLBin hunting performed       |
| Analyst Assessment         | Findings reviewed and documented              |

---

## Analyst Assessment

- The reviewed telemetry primarily reflected:

  * baseline Windows operating system activity
  * expected authentication behavior
  * normal privileged operations
  * standard process execution patterns

- No confirmed indicators of:

  * compromise
  * malicious persistence
  * privilege escalation
  * attacker command execution
  * credential abuse

were identified during investigation.

- The investigation successfully demonstrated:

  * SOC analyst workflows
  * SIEM investigation methodology
  * threat hunting logic
  * event correlation
  * ATT&CK-based analysis
  * alert triage reasoning
  * analytical reporting practices

---

## Future improments

- Future improvements include:

  * Sysmon telemetry integration
  * Threat intelligence enrichment
  * Detection automation
  * SIEM dashboard creation
  * IOC correlation
  * Sentinel/KQL investigation workflows
  * Detection tuning and baselining

---

## Lessons Learned

- Key lessons learned during this investigation included:

  * Effective SOC investigations require structured reasoning
  * SIEM alerts must be validated with contextual evidence
  * Threat hunting improves analytical visibility
  * ATT&CK mapping strengthens investigation consistency
  * Baseline knowledge is essential for identifying anomalies
  * Analytical reporting is critical for SOC operations

---

## Final Conclusion

- No confirmed malicious compromise or active attacker behavior was identified within the reviewed dataset.

- This capstone project successfully demonstrated a realistic SOC investigation simulation using Splunk, Windows Security Event Logs, ATT&CK mapping, alert triage methodology, and structured analytical reporting workflows.

