VirusTotal Threat Intelligence Analysis Report

Tool Used
VirusTotal (Community Edition)

Date of Analysis
12 January 2026

--------------------------------------------------

1. Investigation

Domain Analysis
Domain: mymilitarytravel.com
Detection Ratio: 7 / 93 security vendors
Threat Classification: Phishing / Malicious
Registrar: GoDaddy.com, LLC
Domain Age: Approximately 14 years
Last Analysis: 9 hours ago

Multiple reputable vendors including Kaspersky, SOCradar, Phishing Database, and Webroot flagged the domain as malicious, indicating phishing-related activity.

--------------------------------------------------

IP Address Analysis
IP Address: 185.220.101.1
Detection Ratio: 12 / 93 vendors
ASN: AS60729 (Stiftung Erneuerbare Freiheit)
Country: Germany
Tags: tor, suspicious-udp, self-signed

The IP address is associated with TOR infrastructure and has multiple malware and phishing detections, confirming its role as anonymized malicious infrastructure.

--------------------------------------------------

File Hash Analysis
SHA-256 Hash: 275a021bbf6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
File Name: eicar.com.png
Detection Ratio: 63 / 68 vendors
Threat Label: EICAR-Test-File
Distributor: Offensive Security
Category: Virus (Test Signature)

This file is a standardized EICAR test string used to validate antivirus detection. It is not real malware but confirms proper AV engine behavior.

--------------------------------------------------

2. Analysis

The domain demonstrates moderate-confidence phishing activity validated by multiple vendors.
The IP address represents high-risk TOR-based infrastructure frequently abused for malicious purposes.
The file analysis confirms expected detection behavior using an industry-standard test artifact.
Overall evidence suggests phishing support infrastructure rather than direct malware delivery.

--------------------------------------------------

3. Risk Assessment

Threat Type
Phishing Infrastructure

Confidence Level
Medium to High

Potential Impact
Credential harvesting
Malicious redirection
Anonymity-based evasion tactics

--------------------------------------------------

4. Recommendations

Block the domain and IP at firewall, proxy, and email gateways.
Add all indicators to SIEM and EDR platforms.
Monitor TOR exit node activity for related campaigns.
Conduct user awareness training on phishing indicators.

--------------------------------------------------

5. MITRE ATT&CK Mapping

TA0001 Initial Access
T1566 Phishing

TA0011 Command and Control
T1090 Proxy and Anonymization
