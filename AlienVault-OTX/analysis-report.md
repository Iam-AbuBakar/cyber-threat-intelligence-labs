Open Threat Exchange Threat Intelligence Analysis Report

Tool Used
Open Threat Exchange AlienVault OTX

Date of Analysis
12 January 2026

--------------------------------------------------

1. Investigation

IP Address Investigation
IP Address: 185.220.101.1
Location: Germany
ASN: AS208294 cia triad security llc
Reverse DNS: berlin01.tor-exit.artikel10.org
OTX Pulses: 50
Passive DNS Records: 14
Associated Files: 25

The IP address is heavily referenced in OTX user-created Pulses and is associated with TOR exit node infrastructure. Multiple passive DNS records show usage across security-awareness campaigns, scanning activity, and anonymized services.

--------------------------------------------------

Observed Activity

Web scanning and probing behavior
TOR SSL traffic detected
Historical association with malware families
Win64 TrojanX-gen
Win32 CrypterX-gen
Malware Ulise
Malware Bulz

IDS telemetry flags indicate possible TOR-based encrypted traffic.

--------------------------------------------------

Domain Investigation
Domain: mymilitarytravel.com
Registrar: GoDaddy.com LLC
Creation Date: 06 December 2011
Resolved IP: 72.167.68.133
OTX Pulses: 4
Associated URLs: 50
Indicator Tags
DGA domain
Running webserver
SPF record present

Historical URL data shows previous malware classifications and suspicious banner paths, suggesting domain reuse or compromise over time.

--------------------------------------------------

Pulse Correlation

The IP is included in multiple high-volume Pulses including
LCIA HoneyNet Data December 2025
Web scanner and brute-force activity Pulses
Honeypot collected infrastructure feeds

Pulse metadata confirms this IP as part of broad opportunistic malicious infrastructure rather than a targeted attack.

--------------------------------------------------

2. Analysis

The IP address represents shared attack infrastructure commonly seen in TOR exit nodes abused for anonymity.
Repeated Pulse inclusion over several years confirms long-term malicious relevance.
Domain activity suggests historical compromise or abuse rather than a newly registered phishing domain.
Correlation between VirusTotal detections and OTX community Pulses significantly increases confidence.

--------------------------------------------------

3. Risk Assessment

Threat Type
Phishing and Malware Infrastructure

Confidence Level
High

Threat Nature
Opportunistic large-scale scanning and phishing support

Primary Risks
Credential harvesting
Malware staging
Evasion using anonymized networks

--------------------------------------------------

4. Recommendations

Block the IP address and associated TOR exit ranges at perimeter controls.
Add indicators to SIEM for historical and future correlation.
Monitor OTX Pulse updates for newly linked infrastructure.
Use the OTX API for automated IOC enrichment in SOC workflows.

--------------------------------------------------

5. MITRE ATT&CK Mapping

TA0001 Initial Access
T1566 Phishing

TA0011 Command and Control
T1090 Proxy TOR Anonymization

TA0043 Reconnaissance
T1595 Active Scanning
