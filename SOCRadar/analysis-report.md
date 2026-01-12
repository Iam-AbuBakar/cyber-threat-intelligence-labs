SOCRadar Threat Intelligence and Risk Correlation Report

Tool Used
SOCRadar Free Tools and Labs

Modules Used
IOC Radar
CVE Radar
Threat Actor Intelligence

Date of Analysis
12 January 2026

--------------------------------------------------

1. Investigation Overview

This lab demonstrates how a SOC or CTI analyst uses SOCRadar to validate malicious indicators, correlate them with known vulnerabilities, associate activity with threat actors, map findings to MITRE ATT&CK, and decide appropriate SOC response actions.

--------------------------------------------------

2. IOC Investigation

Indicator Details
IOC Type: IP Address
IP Address: 185.220.101.1
Verdict: Malicious IP Address
Risk Score: 100 percent
Signal Strength: Slightly Noisy
First Seen: 26 August 2020
Last Seen: 07 December 2025

Observed Categories
Scanner
TOR Exit Node
Malware Distribution
VPN and Proxy Usage
Honeypot Interaction
Network Scanning and Brute Force Activity
Malicious Activity via TOR Exit Node

Analyst Interpretation

This IP shows persistent malicious behavior over multiple years, indicating that it is not a false positive. The infrastructure appears reusable and is likely part of anonymized attack campaigns.

--------------------------------------------------

3. MITRE ATT&CK Mapping at IOC Level

Mapped techniques observed via SOCRadar

T1059.003 SQL Injection
T1189 Drive-by Compromise
T1210 Exploitation of Remote Services
T1021.004 SSH
T1021.005 VNC
T1041 Exfiltration Over Command and Control Channel
T1592 Gather Victim Host Information

These techniques indicate active scanning and exploitation behavior rather than benign internet noise.

--------------------------------------------------

4. Vulnerability Correlation

CVE Analyzed
CVE ID: CVE-2021-26829
Severity: High
CVSS Version 3 Score: 5.4
EPSS Score: 0.17378
Exploitation Status: In the Wild
CISA KEV Listing: Yes

Vulnerability Summary

This vulnerability is a stored cross-site scripting issue affecting OpenPLC ScadaBR. Successful exploitation allows session hijacking, redirection, and compromise of the web interface.

Analyst Insight

Inclusion in the CISA Known Exploited Vulnerabilities catalog confirms real-world exploitation and indicates mandatory patching priority, especially for critical infrastructure environments.

--------------------------------------------------

5. Threat Actor Intelligence

Threat Actors Investigated
Lazarus Group
LockBit

Key Findings

These threat actors demonstrate global targeting across multiple industries and are commonly associated with credential harvesting, malware delivery, and ransomware operations. There is significant overlap in IOCs and CVEs, along with extensive MITRE ATT&CK coverage exceeding one hundred techniques.

Associated Malware Examples
Remote Access Trojans
Credential Stealers
Ransomware Loaders
Post-exploitation Frameworks

--------------------------------------------------

6. SOC Analyst Assessment

Risk Evaluation
IOC Risk: High
Threat Persistence: Long term
Exploit Readiness: Active
Attribution Confidence: Medium to High

SOC Action Recommendation

Block
Enforce blocking at firewall, proxy, and SIEM correlation rules

Monitor
Track TOR-based scanning patterns and repeated authentication failures

Hunt
Match indicators against internal logs and correlate with known CVE exposure

--------------------------------------------------

7. MITRE ATT&CK Summary at Campaign Level

T1595 Active Scanning
T1190 Exploit Public-Facing Application
T1059 Command and Scripting Interpreter
T1021 Remote Services
T1041 Exfiltration Over Command and Control
T1486 Data Encrypted for Impact
