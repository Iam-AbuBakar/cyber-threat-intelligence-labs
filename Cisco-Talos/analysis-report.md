Cisco Talos Intelligence Threat Analysis Report

Tool Used
Cisco Talos Intelligence Center

Date of Analysis
12 January 2026

--------------------------------------------------

1. Investigation

IP Address Reputation Analysis

IP Address: 213.209.159.158
Location: Augsburg, Germany
Sender IP Reputation: Untrusted
Web Reputation: Untrusted
Email Reputation: Poor
Forward and Reverse DNS Match: No

Cisco Talos classifies this IP address as untrusted for both web and email activity. Email telemetry shows repeated poor reputation across multiple IPs in the same subnet, indicating abusive sender infrastructure.

--------------------------------------------------

Email and Spam Telemetry

Multiple IPs in the 213.209.159.0/24 range exhibit the following characteristics:
Poor email reputation
No reverse DNS alignment
Historical email activity consistent with spam or phishing distribution

This pattern strongly suggests shared email-sending infrastructure rather than isolated misuse.

--------------------------------------------------

URL Reputation Analysis

URL: http://87.121.84.49/ipcam.vivotek.sh
Web Reputation: Untrusted
Threat Categories
Malware
Malicious Sites
Spam
Network Owner: Neterra Ltd

Cisco Talos explicitly flags this URL as malicious, confirming active threat status rather than historical reputation only.

--------------------------------------------------

2. Analysis

Cisco Talos confirms enterprise-level risk for both IP and URL indicators.
Email reputation telemetry indicates phishing or spam campaign support, which is critical for SOC blocking decisions.
The presence of entire IP ranges with poor reputation increases confidence in malicious intent.
URL categorization as malware validates immediate enforcement actions without further enrichment.

--------------------------------------------------

3. Risk Assessment

Threat Type
Phishing and Malware Distribution Infrastructure

Confidence Level
High

Primary Risks
Email-based phishing attacks
Malware delivery via malicious URLs
Abuse of hosting providers for campaign-scale attacks

--------------------------------------------------

4. Recommendations

Block the IP address 213.209.159.158 and the related /24 subnet at email gateways, secure web gateways, and firewalls.
Immediately block the malicious URL at proxy and DNS level.
Correlate Cisco Talos intelligence with VirusTotal and OTX for historical tracking.
Continuously monitor Talos reputation changes for potential reactivation.

--------------------------------------------------

5. MITRE ATT&CK Mapping

TA1566 Phishing
TA1598 Phishing for Information
TA0011 Command and Control
T1090 Proxy and Infrastructure Abuse
