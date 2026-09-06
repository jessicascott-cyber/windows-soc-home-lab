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
```

## Technologies Used

- Splunk Enterprise 10.4.2
- Splunk Universal Forwarder 10.4.2
- Ubuntu 24.04 LTS
- Windows 11
- Oracle VirtualBox
- Windows Security Event Logs
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
```

### Splunk Search — Repeated Failed Attempts

The following query was used to identify repeated authentication attempts:

```spl
index=* EventCode=4625
| stats count as failed_attempts earliest(_time) as first_attempt latest(_time) as last_attempt by Account_Name Source_Network_Address
| where failed_attempts >= 3
| sort - failed_attempts
```

## Findings

The investigation identified repeated failed authentication attempts involving the following accounts:

- `FakeUser`
- `SOCAdmin`

Three failed attempts were observed for each account.

The source address associated with the events was:

```text
::1
```

The Windows failure reason was:

```text
Unknown user name or bad password.
```

The events occurred within a short period of time.

Further review of the Windows Security Event 4625 details showed that the authentication attempt involving `FakeUser` was initiated locally under the `SOCAdmin` account.

## Analysis

The repeated authentication failures initially appeared suspicious because multiple failed attempts occurred within a short period.

However, the source address `::1` is the IPv6 loopback address, which indicates that the activity originated from the local system rather than an external network address.

The activity was generated intentionally as part of a controlled security lab exercise. Based on the available evidence, the activity was classified as benign test activity rather than a confirmed security incident.

This investigation demonstrated the importance of reviewing the full event details and surrounding context before classifying an authentication alert as malicious.

## Recommended Actions

- Verify whether the authentication attempts were intentional.
- Review the affected account and authentication source.
- Continue monitoring for additional failed logon events.
- Investigate further if the number of attempts increases.
- Investigate further if authentication attempts begin originating from an external address.
- Correlate authentication activity with other security events when additional evidence is available.

## Evidence

Screenshots from the investigation are included in the `screenshots` folder.

The evidence includes:

1. Windows Security Event ID 4625
2. Splunk failed logon search results
3. Splunk results showing repeated failed attempts
4. Expanded Windows Security Event 4625 details

## Skills Demonstrated

- SIEM monitoring
- Splunk Enterprise
- SPL query development
- Windows Security Event Log analysis
- Event ID 4625 investigation
- Authentication investigation
- Security event triage
- Evidence analysis
- Incident assessment
- Security documentation

## Results

Successfully collected Windows Security Event Logs from the Windows 11 virtual machine into Splunk Enterprise.

Used Splunk SPL to identify repeated failed authentication attempts and analyzed the associated Windows Security Event 4625 details.

The investigation demonstrated the following SOC workflow:

**Detect → Investigate → Analyze → Assess → Recommend**

## Future Improvements

- Create additional Splunk security detections
- Build a basic SOC dashboard
- Add alerting for repeated authentication failures
- Investigate additional Windows Security Event IDs
- Expand the lab with additional simulated security events
