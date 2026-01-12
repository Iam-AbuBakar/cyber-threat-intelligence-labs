GreyNoise Noise vs Threat Intelligence Report

Tool Used
GreyNoise Intelligence

Date of Analysis
12 January 2026

--------------------------------------------------

1. Investigation Overview

This lab focuses on enriching a suspicious IP address using GreyNoise Intelligence to determine whether the observed activity represents benign internet background noise or malicious behavior requiring SOC action.

GreyNoise helps SOC analysts reduce alert fatigue by distinguishing mass internet scanning from targeted attack activity.

--------------------------------------------------

2. IP Intelligence Summary

IP Address: 185.220.101.1
Classification: Malicious
Confidence Level: High (GreyNoise first-hand observation)
Actor Type: Unknown (TOR-based activity)
Spoofable: No
Network Type: TOR Exit Node
ASN: AS60729
Organization: Stiftung Erneuerbare Freiheit
Location: Berlin, Germany

--------------------------------------------------

3. Observed Activity

Protocols Observed
HTTP / HTTPS
TLS / SSL

Behavior Tags
CGI Script Scanner
ENV File Crawler
robots.txt Scanner
Web Crawler
Python Requests Client
Dahua Gen 2 Scanner
React Server Components Unsafe Deserialization
CVE-2025-55182 Remote Code Execution Attempt

Behavior Pattern
Internet-wide scanning
Vulnerability discovery
Active exploitation attempts

This activity goes beyond passive noise and indicates hostile reconnaissance and exploitation behavior.

--------------------------------------------------

4. Timeline Analysis

First Seen: 11 January 2026
Last Seen: 12 January 2026
Observation Frequency: High (continuous scanning)

The timeline shows persistent malicious activity rather than a one-time scan, indicating automation and attacker tooling.

--------------------------------------------------

5. Analyst Assessment

This IP represents an active malicious scanner using TOR for anonymity.

SOC Action Required
Block

Risk Level
High

Correlation with Previous Labs
Shodan: Yes (exposed services and scanning patterns observed)
URLhaus: Yes (associated with malicious infrastructure)
VirusTotal: Yes (flagged by multiple vendors)

This IP fits a cross-tool confirmed malicious profile.

--------------------------------------------------

6. Recommendations

Immediately block the IP at firewall, WAF, and SIEM level.
Alert on TOR exit node traffic.
Monitor for ENV file access attempts, CGI scanning, and RCE exploitation attempts.
Apply patches related to React Server Components CVE-2025-55182.
Use GreyNoise enrichment in SIEM to reduce false positives and prioritize real threats.

--------------------------------------------------

7. MITRE ATT&CK Mapping

T1595 Active Scanning
T1046 Network Service Discovery
T1190 Exploit Public-Facing Application
T1059 Command and Scripting Interpreter

