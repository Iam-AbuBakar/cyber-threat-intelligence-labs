URLhaus Live Malware Delivery Intelligence Report

Tool Used
URLhaus (abuse.ch)

Date of Analysis
12 January 2026

--------------------------------------------------

1. Investigation Overview

This lab analyzed an active malware-hosting IP using URLhaus to identify live malware delivery, payload characteristics, and associated infrastructure.

--------------------------------------------------

2. Host Infrastructure Analysis

Host IP: 87.121.84.49
ASN: AS215925
Hosting Provider: VPSVAULTHOST
Country: United States
Status: Active malware host
Spamhaus SBL: SBL683025

The host was observed actively distributing multiple malware payloads at the time of analysis.

--------------------------------------------------

3. Malware URL Analysis

Confirmed Malicious URL
URL: http://87.121.84.49/catgirl.armv6
URL Status: Online and actively spreading malware
Threat Type: Malware download
Date Added: 12 January 2026
Reporter: botnetkiller

Observed Malware URLs on Host
/router.linksys.sh
/router.netgear2.sh
/router.tenda.sh
/router.nexxt.sh

These URLs indicate targeted exploitation of consumer and SOHO network devices.

--------------------------------------------------

4. Payload Intelligence

Payload Type: ELF binary
Architecture: ARM (armv6)
Malware Family: Mirai
SHA256 Hash:
b682c0c90c6bf6c9d064da0281b1c5c1c58f583b714898560d7644abb77293fa

The payload characteristics confirm IoT-focused malware distribution consistent with Mirai botnet activity.

--------------------------------------------------

5. Threat Assessment

Threat Category
Active malware delivery

Confidence Level
High

Attack Vector
Direct HTTP download

Likely Targets
IoT devices
Routers
Embedded Linux systems

This infrastructure represents an immediate infection risk for exposed devices.

--------------------------------------------------

6. Analyst Assessment

The malware host serves multiple architecture- and vendor-specific payloads.
Use of simple HTTP delivery and wget-based retrieval indicates mass exploitation.
Infrastructure reuse suggests botnet-style automated deployment.

--------------------------------------------------

7. Recommended Actions

Block the malicious IP and associated URLs at the network perimeter.
Add the payload hash to EDR and threat-hunting platforms.
Monitor outbound HTTP requests to unknown IPs.
Share indicators with SOC and incident response teams for rapid containment.

--------------------------------------------------

8. MITRE ATT&CK Mapping

T1105 Ingress Tool Transfer
T1204 User Execution
T1059 Command and Scripting Interpreter
T1496 Resource Hijacking Botnet Activity
