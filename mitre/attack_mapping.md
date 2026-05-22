# MITRE ATT&CK Mapping

- This document maps the investigation findings and threat hunting activities from the SOC investigation simulation to the MITRE ATT&CK framework.

- The purpose of ATT&CK mapping is to:
  - standardize investigations
  - classify attacker behavior
  - improve threat hunting consistency
  - strengthen detection engineering workflows
  - support SOC analytical methodology

---

## ATT&CK Techniques Investigated

| Technique | ATT&CK ID | Tactic |
|---|---|---|
| Brute Force | T1110 | Credential Access |
| Valid Accounts | T1078 | Defense Evasion |
| Command and Scripting Interpreter | T1059 | Execution |
| PowerShell | T1059.001 | Execution |
| Signed Binary Proxy Execution | T1218 | Defense Evasion |

---

## Technique Analysis

---

### T1110 — Brute Force

#### ATT&CK Tactic

- Credential Access

---

#### Investigation Focus

- The investigation reviewed failed authentication telemetry to identify:
  - repeated login failures
  - password spraying behavior
  - brute force indicators
  - credential abuse attempts

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

#### Investigation Findings

- Reviewed authentication telemetry did not indicate:

  * large-scale login failures
  * suspicious authentication spikes
  * brute force patterns
  * credential abuse activity

- No confirmed brute force behavior was identified.

---

### T1078 — Valid Accounts

#### ATT&CK Tactic

- Defense Evasion

---

#### Investigation Focus

- The investigation reviewed:

  * successful authentication activity
  * privileged logons
  * elevated access telemetry
  * administrative sessions

to identify suspicious account usage.

---

#### Relevant Event IDs

| Event ID | Description      |
| -------- | ---------------- |
| 4624     | Successful Logon |
| 4672     | Privileged Logon |

---

#### SPL Queries

```spl id="75eyww"
index=main "4624"
| stats count by host
| sort - count
```

```spl id="n5nhix"
index=main "4672"
| stats count by host
| sort - count
```

---

#### Investigation Findings

- Observed authentication activity appeared consistent with:

  * expected Windows behavior
  * standard privileged operations
  * baseline administrative activity

- No unauthorized account usage or suspicious privileged activity was identified.

---

### T1059 — Command and Scripting Interpreter

#### ATT&CK Tactic

Execution

---

#### Investigation Focus

- Process creation telemetry was analyzed to identify:

  * suspicious command execution
  * scripting activity
  * abnormal process behavior
  * potential attacker execution techniques

---

#### Relevant Event ID

| Event ID | Description      |
| -------- | ---------------- |
| 4688     | Process Creation |

---

#### SPL Query

```spl id="6dksix"
index=main "4688"
| stats count by host
| sort - count
```

---

#### Investigation Findings

- Reviewed process telemetry primarily reflected:

  * standard Windows processes
  * expected operating system activity
  * baseline execution behavior

- No confirmed malicious command execution was identified.

---

### T1059.001 — PowerShell

#### ATT&CK Tactic

- Execution

---

#### Investigation Focus

- Threat hunting activities focused on identifying:

  * suspicious PowerShell execution
  * encoded commands
  * malicious scripting indicators
  * PowerShell abuse patterns

---

#### SPL Query

```spl id="mpshru"
index=main ("powershell" OR "cmd.exe")
```

---

#### Investigation Findings

- No confirmed malicious PowerShell execution or suspicious scripting behavior was identified during investigation.

- Observed activity appeared consistent with baseline system behavior.

---

### T1218 — Signed Binary Proxy Execution

#### ATT&CK Tactic

- Defense Evasion

---

#### Investigation Focus

- Threat hunting reviewed LOLBins commonly abused by attackers, including:

  * rundll32.exe
  * mshta.exe
  * cmd.exe

---

#### SPL Query

```spl id="5s9t4u"
index=main ("rundll32" OR "mshta" OR "cmd.exe")
```

---

#### Investigation Findings

- Reviewed process execution activity did not indicate:

  * suspicious LOLBin abuse
  * malicious proxy execution
  * attacker execution chains

- No confirmed abuse of signed binaries was identified.

---

## ATT&CK Mapping Summary

| ATT&CK Technique                          | Investigation Result                        |
| ----------------------------------------- | ------------------------------------------- |
| T1110 - Brute Force                       | No confirmed brute force activity           |
| T1078 - Valid Accounts                    | No suspicious account usage identified      |
| T1059 - Command and Scripting Interpreter | No confirmed malicious execution identified |
| T1059.001 - PowerShell                    | No suspicious PowerShell abuse identified   |
| T1218 - Signed Binary Proxy Execution     | No LOLBin abuse identified                  |

---

## Why ATT&CK Mapping Matters

- MITRE ATT&CK mapping improves:

  * detection engineering
  * SOC investigation consistency
  * analytical workflows
  * threat hunting methodology
  * security reporting
  * adversary behavior understanding

- ATT&CK provides a structured framework for understanding attacker techniques and investigation logic.

---

## Key Lessons Learned

- Key lessons learned from ATT&CK mapping included:

  * ATT&CK improves structured investigations
  * Threat hunting benefits from standardized frameworks
  * Event correlation strengthens analytical accuracy
  * Baseline analysis is critical for identifying anomalies
  * ATT&CK mapping supports SIEM investigations and detection workflows

---

## Final ATT&CK Assessment

- The reviewed telemetry primarily reflected:

  * baseline Windows operations
  * expected authentication activity
  * standard process execution behavior

- No confirmed malicious attacker behavior was identified within the reviewed dataset.

- The investigation successfully demonstrated:

  * ATT&CK-based analysis
  * SOC investigation workflows
  * threat hunting methodology
  * analytical mapping practices
  * structured detection-oriented reasoning
