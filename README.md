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
