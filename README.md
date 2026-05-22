# SOC Investigation Simulation

## Overview

- This project demonstrates a full SOC investigation simulation using Splunk, Windows Security Event Logs, threat hunting methodology, alert triage workflows, and MITRE ATT&CK analysis.

- The project simulates how SOC analysts:
  - review alerts
  - investigate suspicious activity
  - analyze telemetry
  - correlate events
  - perform threat hunting
  - document findings
  - assess escalation requirements

---

## Objectives

### Primary Goal

- Simulate a realistic SOC investigation workflow involving:
  - authentication monitoring
  - suspicious process analysis
  - alert triage
  - threat hunting
  - incident reporting
  - ATT&CK mapping

---

## Investigation Areas

- This project investigates:

  - Failed authentication attempts
  - Successful logon activity
  - Privileged logons
  - Process creation events
  - Suspicious PowerShell activity
  - Potential brute force indicators
  - Threat hunting telemetry

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Splunk Free | SIEM investigation platform |
| Windows Security Logs | Security telemetry |
| SPL | Investigation queries |
| MITRE ATT&CK | Threat mapping |
| Sigma Concepts | Detection methodology |

---

## Event IDs Investigated

| Event ID | Description |
|---|---|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4672 | Privileged Logon |
| 4688 | Process Creation |

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Brute Force | T1110 | Credential Access |
| Valid Accounts | T1078 | Defense Evasion |
| PowerShell | T1059.001 | Execution |
| Command and Scripting Interpreter | T1059 | Execution |
| Signed Binary Proxy Execution | T1218 | Defense Evasion |

---

## SOC Investigation Workflow

- The simulated workflow included:

  1. Alert triage
  2. Authentication analysis
  3. Privileged activity review
  4. Process execution investigation
  5. Threat hunting
  6. Event correlation
  7. Timeline analysis
  8. Analyst assessment
  9. Incident documentation

---

## Example SPL Queries

### Failed Authentication Monitoring

```spl
index=main "4625"
| stats count by host
| sort - count
````

### Process Creation Investigation

```spl
index=main "4688"
| stats count by host
| sort - count
```

### Suspicious PowerShell Hunting

```spl
index=main ("powershell" OR "cmd.exe" OR "rundll32" OR "mshta")
```

---

## Key Investigation Concepts

- This project demonstrates:

  * SIEM investigation workflows
  * Alert triage methodology
  * Threat hunting logic
  * Authentication monitoring
  * Event correlation
  * ATT&CK-based analysis
  * Incident reporting
  * Analytical decision-making

---

## Investigation Findings

- The reviewed telemetry primarily reflected:

  * baseline Windows activity
  * standard authentication behavior
  * expected system processes
  * normal privileged operations

- No confirmed malicious compromise was identified in the reviewed dataset.

- The project focused on:

  * structured investigation methodology
  * analytical reasoning
  * SOC workflow simulation
  * threat hunting practices

---

## SOC Skills Demonstrated

* Splunk investigation workflows
* Log analysis
* Threat hunting
* SIEM operations
* Alert triage
* Detection engineering
* ATT&CK mapping
* Incident reporting
* Windows event analysis

---

## Future Improvements

- Potential future enhancements include:

  * Sysmon integration
  * Threat intelligence enrichment
  * Automated detections
  * Sentinel/KQL integration
  * Dashboard creation
  * IOC enrichment
  * Detection tuning

---

## Project Status

- Completed SOC investigation simulation project focused on:

  * investigation workflows
  * analytical reasoning
  * incident response methodology
  * threat hunting
  * ATT&CK analysis
