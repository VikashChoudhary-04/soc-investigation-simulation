# Splunk Investigation Queries

- This document contains SPL queries used during the SOC investigation simulation.

- The investigation focused on:
  - authentication monitoring
  - failed login analysis
  - privileged authentication activity
  - process execution telemetry
  - suspicious command execution
  - threat hunting workflows

---

## Investigation Goals

- The queries were designed to support:

  - SOC investigations
  - alert triage
  - threat hunting
  - authentication monitoring
  - event correlation
  - process analysis
  - ATT&CK-based investigations

---

## Authentication Investigation Queries

---

### Failed Authentication Monitoring

#### Purpose

- Identify failed login activity and potential brute force indicators.

---

#### Relevant Event ID

| Event ID | Description |
|---|---|
| 4625 | Failed Logon |

---

#### SPL Query

```spl
index=main "4625"
| stats count by host
| sort - count
````

---

#### Investigation Focus

- This query helps identify:

  * repeated login failures
  * authentication spikes
  * brute force indicators
  * credential abuse attempts

---

### Successful Authentication Monitoring

#### Purpose

- Review successful authentication activity and identify suspicious logons.

---

#### Relevant Event ID

| Event ID | Description      |
| -------- | ---------------- |
| 4624     | Successful Logon |

---

#### SPL Query

```spl id="9v07mk"
index=main "4624"
| stats count by host
| sort - count
```

---

#### Investigation Focus

- This query helps review:

  * successful logins
  * authentication baselines
  * account activity
  * login telemetry

---

### Authentication Timeline Analysis

#### Purpose

- Visualize authentication activity over time.

---

#### SPL Query

```spl id="8cqqq9"
index=main ("4624" OR "4625")
| timechart count
```

---

#### Investigation Focus

- This query helps identify:

  * authentication spikes
  * suspicious login patterns
  * login frequency changes
  * authentication anomalies

---

## Privileged Activity Investigation

---

### Privileged Logon Monitoring

#### Purpose

- Review elevated authentication activity and privileged access telemetry.

---

#### Relevant Event ID

| Event ID | Description      |
| -------- | ---------------- |
| 4672     | Privileged Logon |

---

#### SPL Query

```spl id="75mx4g"
index=main "4672"
| stats count by host
| sort - count
```

---

#### Investigation Focus

- This query helps identify:

  * privileged sessions
  * administrative activity
  * elevated authentication behavior
  * privilege escalation indicators

---

## Process Creation Investigation

---

### Process Execution Monitoring

#### Purpose

- Review process creation telemetry and identify suspicious execution activity.

---

#### Relevant Event ID

| Event ID | Description      |
| -------- | ---------------- |
| 4688     | Process Creation |

---

#### SPL Query

```spl id="d4sn3r"
index=main "4688"
| stats count by host
| sort - count
```

---

#### Investigation Focus

- This query helps identify:

  * suspicious process execution
  * abnormal binaries
  * unusual command activity
  * attacker execution behavior

---

### Process Timeline Analysis

#### Purpose

- Visualize process creation activity over time.

---

#### SPL Query

```spl id="44y76j"
index=main "4688"
| timechart count
```

---

#### Investigation Focus

- This query helps identify:

  * execution spikes
  * suspicious execution timing
  * process anomalies
  * unusual activity patterns

---

## Threat Hunting Queries

---

### PowerShell Hunting

#### Purpose

- Identify suspicious PowerShell activity and scripting behavior.

---

#### SPL Query

```spl id="5wz7e9"
index=main ("powershell" OR "cmd.exe")
```

---

#### Investigation Focus

- This query helps identify:

  * PowerShell execution
  * suspicious scripting
  * encoded commands
  * attacker execution behavior

---

### LOLBin Hunting

#### Purpose

- Review commonly abused Windows binaries.

---

#### SPL Query

```spl id="f80ezy"
index=main ("rundll32" OR "mshta" OR "cmd.exe")
```

---

#### Investigation Focus

- This query helps identify:

  * LOLBin abuse
  * proxy execution
  * suspicious binaries
  * defense evasion behavior

---

## Correlation Queries

---

### Authentication Correlation

#### Purpose

- Review combined successful and failed authentication activity.

---

#### SPL Query

```spl id="0f39a8"
index=main ("4624" OR "4625")
| stats count by host
```

---

#### Investigation Focus

- This query helps correlate:

  * login failures
  * successful authentication
  * suspicious account behavior
  * authentication anomalies

---

## Key Investigation Concepts

- These queries demonstrate:

  * SIEM investigation workflows
  * Authentication monitoring
  * Event correlation
  * Threat hunting
  * Alert triage
  * Process analysis
  * Detection-oriented reasoning
  * SOC analytical methodology

---

## Key Lessons Learned

- Key lessons learned during SPL investigation included:

  * SIEM queries support structured investigations
  * Event correlation improves analytical visibility
  * Authentication telemetry is critical for SOC workflows
  * Threat hunting requires contextual analysis
  * Baseline behavior is essential for identifying anomalies
  * Effective investigations combine multiple telemetry sources

---

## Final Query Assessment

- The investigation queries successfully demonstrated:

  * practical Splunk investigation workflows
  * authentication monitoring
  * process analysis
  * threat hunting methodology
  * SOC analytical reasoning
  * ATT&CK-oriented investigation practices
