# Windows Event Log Monitoring & Threat Detection with Splunk Enterprise

## Architecture Overview
### Environment Components:
- Windows Host
  - Splunk Universal Forwarder collects and forwards logs
  - Generates Windows event logs
 
- Splunk Indexer (Ubuntu VM)
  - Receives forwarded events (TCP 9997)
  - Stores, indexes, and searches events

## Data Sources Collected
 |Source        |Description        |
 |--------------|-------------------|
 |Security logs | Windows security audit events |
 |System logs | Windows system notifications |
 |Application logs | Application-level events |

## Detection Scenarios
### Authentication Abuse:
- Detect multiple failed login attempts, suggesting brute force or anomalous account activity.

Detection logic:
```
index=* sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, host
| where count >= 5
```

### Anomalous Logon Behavior:
- Successful logins outside of expected hours.

Detection logic:
```
index=* sourcetype=WinEventLog:Security EventCode=4624
| eval hour = strftime(_time, "%H")
| where hour < 7 OR hour > 19
```

### Anti-Forensic Security Log Clearance:
- Auditing integrity compromised with cleared logs.

Detection logic:
```
index=* sourcetype=WinEventLog:Security EventCode=1102
```

## SOC Dashboard Panels

|Panel            |Purpose            |
|------------|------------|
|Failed Logins Over Time | Visualizes spike in activity |
|Top Accounts with Failures | Identifies targeted accounts |
|Off-Hours Logins | Detects anomalous login patterns |
|Security Log Clears | Flags anti-forensic events |
|New Service Installation | Persistence tactics |

## Setup & Installation
### Windows Host
- Installed Splunk Universal Forwarder
- Enabled monitoring of Security, System, Application logs
- Set forwarding to Splunk server (VM)

Forwarder inputs:
- Security.evtx
- System.evtx
- Application.evtx

### Splunk Indexer
- Installed Splunk Enterprise
- Enabled receiving on TCP 9997
- Confirmed forwarder connection

## Generating Test Events
### Detection validation
- Triggered false logons
- Cleared Security log via Event Viewer
- Created test ```MaliciousService```
- Various actions to generate Security/System events





 



