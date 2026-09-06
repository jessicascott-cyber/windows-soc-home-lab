# Windows SOC Home Lab — Splunk SIEM

## Project Overview

This project is a hands-on cybersecurity home lab designed to practice Security Operations Center (SOC) monitoring and investigation techniques.

The lab uses a Windows workstation and Splunk Enterprise to collect and analyze Windows Security Event Logs. The primary investigation focuses on identifying and analyzing repeated failed login attempts.

## Lab Architecture

The lab was built using virtual machines in Oracle VirtualBox.

```text
SOC-Windows
Windows 11
     |
     | Windows Security Event Logs
     |
     v
Splunk Universal Forwarder
     |
     | Host-Only Network
     |
     v
SOC-Splunk
Ubuntu 24.04 LTS
Splunk Enterprise
     |
     v
Security Event Analysis
## Technologies Used

- Splunk Enterprise 10.4.2
- Splunk Universal Forwarder 10.4.2
- Ubuntu 24.04 LTS
- Windows 11
- Oracle VirtualBox
- Windows Security Event Logs
- PowerShell
- SPL (Splunk Search Processing Language)

## Project Objectives

- Build a basic virtualized SOC environment
- Configure Windows Security Event Log collection
- Forward Windows security events to Splunk
- Verify that Windows events are successfully ingested
- Use SPL to search and filter security events
- Investigate failed authentication attempts
- Analyze security event details
- Document investigation findings and recommendations

## Investigation: Failed Windows Logons

### Investigation Overview

The investigation focused on Windows Security Event ID 4625, which records failed logon attempts.

The goal was to determine:

- Which accounts were involved
- How many failed attempts occurred
- When the attempts occurred
- Where the attempts originated
- Why the authentication attempts failed
- Whether the activity appeared suspicious

### Splunk Search — Failed Logons

The following SPL query was used to identify failed Windows logon events:

```spl
index=* EventCode=4625
| table _time host Account_Name Account_Domain Failure_Reason Logon_Type Source_Network_Address
| sort - _time
