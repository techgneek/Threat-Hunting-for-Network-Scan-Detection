# 🚨 Network Scanning Detection Lab: Threat Hunt on `win10vm`

## :bookmark_tabs: Overview
This lab simulates a threat hunting scenario triggered by reports of internal network slowdowns. Using KQL queries, Microsoft Defender telemetry, and MITRE ATT&CK mapping, I investigated connection anomalies, uncovered a PowerShell-based port scan, and identified the responsible user.

---

## :world_map: Incident Summary
The VM `win10vm` showed symptoms of failing multiple connection requests internally. A hunt was launched to:
- Detect suspicious connection failures and patterns
- Identify port scan behavior and root cause
- Attribute actions to specific processes and accounts
- Map findings to MITRE ATT&CK techniques

---

## :mag_right: Investigation Timeline & KQL Queries

### 1. Identify Devices with Excessive Connection Failures
```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```

**ConnectionFailure counts per device**

<img width="635" alt="Screen Shot 2025-04-13 at 12 18 15 PM" src="https://github.com/user-attachments/assets/a119ce96-6c84-42a5-809a-3f6e735d2989" />


### 2. Observe Connection Attempts from Suspicious IP
```kql
let IPInQuestion = "10.0.0.111";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```
**Sequential failed port attempts from 10.0.0.111**

<img width="635" alt="Screen Shot 2025-04-13 at 3 47 20 PM" src="https://github.com/user-attachments/assets/9b72abb7-f15c-4147-881b-8bfdfa889595" />

### 3. Check Total Failed Ports by Remote Port
```kql
let IPInQuestion = "10.0.0.111";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, RemotePort, LocalIP
| order by FailedConnectionsAttempts desc
```
**Remote port summary suggesting scanning**

<img width="635" alt="Screen Shot 2025-04-13 at 3 51 51 PM" src="https://github.com/user-attachments/assets/bc9e08b1-4f2f-411c-af69-03c4837d4f02" />

### 4. Pivot to Process Events Around Scan Start Time
```kql
let VMName = "win10vm";
let specificTime = datetime(2025-04-13T16:48:30.6153939Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
**PowerShell launching portscan.ps1**

<img width="634" alt="Screen Shot 2025-04-13 at 4 03 53 PM" src="https://github.com/user-attachments/assets/135141b6-b672-4a40-8bd5-4d98ec1ad89f" />

**PowerShell script (portscan.ps1) that was launched on Azure VM "win10vm"**

<img width="634" alt="Screen Shot 2025-04-13 at 2 13 23 PM" src="https://github.com/user-attachments/assets/5f26782f-c701-4cd4-84b3-b5a362b7bf79" />

---

## :shield: Conclusion
The analysis confirmed that `win10vm` was executing a PowerShell-based port scanning script named `portscan.ps1`. The account used to launch it, `Cyberlab123`, was not an approved administrator, indicating misuse of valid credentials.

---

## :bulb: Recommendations
- Restrict PowerShell usage via AppLocker or Defender policies
- Monitor internal scanning with Defender & custom KQL alerts
- Disable unnecessary accounts and enforce least privilege
- Reimage affected device to prevent lingering backdoors

---

## :memo: MITRE ATT&CK Mapping
| Tactic             | Technique                                  | ID         | Description |
|--------------------|--------------------------------------------|------------|-------------|
| Discovery          | Network Service Scanning                   | T1046      | Probing internal IPs via failed connections |
| Discovery          | Network Service Scanning                   | T1046      | Sequential port probing via script |
| Execution          | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell script used to perform scan |
| Execution / Initial Access | Valid Accounts                     | T1078      | Cyberlab123 account used for script execution |

---

## :toolbox: Lab Process Summary
### 1. **Preparation**
- Hypothesis: Network slowness could indicate port scanning or large file transfers.

### 2. **Data Collection**
- Pulled logs from `DeviceNetworkEvents` and `DeviceProcessEvents`

### 3. **Analysis**
- Detected sequential failed connections and scanning behavior

### 4. **Investigation**
- Identified `portscan.ps1` and mapped behavior to MITRE ATT&CK

### 5. **Response**
- Isolated the VM, ran a malware scan, escalated for reimaging

### 6. **Documentation**
- Report created with queries, screenshots, and findings

### 7. **Improvement**
- Enforce PowerShell restrictions and internal alerting on failed connection spikes

---

> **Created with Microsoft Defender for Endpoint, Azure Monitor, and KQL**  
> **Project by James Moore | [GitHub](https://github.com/techgneek) | [YouTube](https://youtube.com/@techgneek)**

