# Windows Security Monitoring Lab — Splunk SIEM

## Project Overview
Built a virtualized SOC lab using Splunk Enterprise and
Splunk Universal Forwarder to collect and analyze Windows
Security Event Logs.

## Lab Architecture
SOC-Windows
      ↓
Splunk Universal Forwarder
      ↓
Host-Only Network
      ↓
SOC-Splunk (Ubuntu)
      ↓
Splunk Enterprise
      ↓
Security Event Analysis

## Technologies Used
- Splunk Enterprise 10.4.2
- Splunk Universal Forwarder 10.4.2
- Ubuntu 24.04 LTS
- Windows
- VirtualBox
- Windows Event Logs
- PowerShell
- SPL (Splunk Search Processing Language)

## Objectives
- Deploy a Splunk SIEM environment
- Configure Windows log collection
- Forward Windows Security Events to Splunk
- Verify log ingestion
- Investigate authentication events
- Create security detections

## Results
Successfully configured Windows Security Event Logs
to be collected by Splunk and verified log ingestion
through Splunk Search & Reporting.

## Investigations
- Failed Windows logons (Event ID 4625)
- Successful logons (Event ID 4624)
- Privileged logons (Event ID 4672)
- Process creation (Event ID 4688)

## Future Improvements
- Create Splunk dashboards
- Build brute-force detection
- Generate controlled security events
- Add alerting
- Document investigation findings
