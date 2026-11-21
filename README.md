# Phishing Email Analysis: Microsoft Impersonation (MediSure Health Network)

I investigated a suspected credential-phishing email as a SOC analyst: I analysed the email headers, enriched the indicators with threat intelligence, correlated them against logs in Splunk, and recommended response actions.

> **Note:** This is a **simulated** investigation completed as a training project. MediSure Health Network, its users (Alice and Bob), and the log data are fictional or provided for the exercise. No live client data is included.

**Analyst:** Chisom Paschal-Ndubuisi
**Incident type:** Suspected phishing / Microsoft impersonation
**Severity:** High
**My classification:** Highly suspicious, with confirmed user interaction and possible credential exposure

---

## Scenario

An employee at MediSure Health Network received an email claiming to be from the "Microsoft account team". It warned of an unusual sign-in from Russia and told the recipient to "secure your account immediately" using an embedded link. My task was to work out whether the email was malicious, whether anyone interacted with it, and what response was needed.

## Tools I used

| Tool | How I used it |
| --- | --- |
| MXToolbox Header Analyzer | Email header, relay path, SPF/DKIM/DMARC checks, tracking pixel location |
| VirusTotal | URL, domain, and IP reputation; files referencing an IP |
| AbuseIPDB | IP abuse reports and confidence score |
| Splunk | Correlating proxy, firewall, and authentication logs against the IOCs |

## My approach

1. **Initial email assessment:** I looked at the sender identity, urgency language, and embedded link.
2. **Header analysis:** I reviewed the From, Reply-To, Received chain, and Authentication-Results fields.
3. **Authentication checks:** I checked SPF, DKIM, DMARC, and alignment.
4. **URL and IP investigation:** I enriched the indicators with VirusTotal and AbuseIPDB.
5. **Log analysis in Splunk:** I ingested the logs and searched for who visited the domains, which hosts connected to the IPs, and any suspicious logins.
6. **Tracking pixel analysis:** I found a hidden third-party domain in the email HTML and checked its reputation.
7. **Response and recommendations:** I documented containment, remediation, recovery, monitoring, and playbook improvements.

## What I found

**In the email**
- The display name claimed Microsoft, but the real sender domain was `access-accsecurity[.]com`, which is not a Microsoft domain.
- The Reply-To address was an unrelated Gmail account. I found this mismatch the most revealing detail, because it directly contradicted the identity shown to the recipient.
- SPF failed, DKIM was not present, and MXToolbox found no DMARC record.
- The HTML contained a hidden tracking pixel from `thebandalisty[.]com`, which multiple vendors flagged as phishing or malicious.

**In threat intelligence**
- `sign[.]in` returned mixed results: one malicious detection (Webroot), one suspicious (alphaMountain.ai), and the rest clean.
- `64.190.63.222` had 139 AbuseIPDB reports but only a 16% confidence score, so I did not treat reputation alone as conclusive.
- `103.225.77.255` (the "Russian" login IP in the email) had 0/89 direct detections, but 103 files reference it, including an executable with 55/70 detections. It also geolocated to India, not Russia, which contradicts the email's claim.

**In Splunk**
- Proxy logs showed that both Alice and Bob accessed the suspicious domains.
- Firewall logs showed internal hosts connecting to the originating IP `89.144.44.41`.
- Authentication logs showed a failed Russia-based login against Bob's account.
- 5 events matched the IOCs in total (Alice: 2, Bob: 3).

## What the evidence does and does not show

I was careful to separate what the evidence supports from what it doesn't.

| Supported by the evidence | Not established |
| --- | --- |
| The email is a Microsoft-impersonation phishing attempt | That credentials were successfully stolen |
| Two users interacted with the suspicious domains | That any account was successfully compromised |
| A failed login from Russia followed against Bob's account | That sensitive data was accessed or exfiltrated |
| No bulk data transfers or malware found in the reviewed logs | The attacker's full intent |

## Response actions I documented

- **Containment:** email quarantine, blocking domains and IPs at the email gateway, firewall and DNS, forced password resets and session revocation, and host isolation for forensic imaging
- **Eradication:** malware scans, proxy and DNS log review, updated SIEM correlation searches, stricter spam filtering and URL sandboxing
- **Recovery:** accounts re-enabled after password reset and MFA re-enrolment, hosts restored after validation, 30-day enhanced monitoring
- **Follow-up:** mailbox rule and OAuth audits, MFA and Conditional Access review, lookalike-domain detection

## What I'd improve in the SOC playbook

- Standardise proxy and DNS telemetry enrichment so user, host, and destination activity can be correlated.
- Include immediate session revocation in the response procedure when credential compromise is suspected.
- Keep improving SIEM searches for failed email authentication and outbound traffic to flagged infrastructure.
- Run user-awareness activities that encourage verifying security alerts through trusted channels.

## Splunk searches I used

The dataset name and field names come from the exercise environment, so check them against your own before reuse.

```spl
# 1. Users who visited the phishing domains (proxy logs)
source="medisure_phishing_combined_logs.csv" log_type=proxy
(url_domain="sign.in" OR url_domain="access-accsecurity.com")
| stats count by user, src_ip, url_domain

# 2. Outbound connections to suspicious IPs (firewall logs)
source="medisure_phishing_combined_logs.csv" log_type=firewall
(dest_ip="89.144.44.41" OR dest_ip="103.225.77.255")
| stats count by src_ip, dest_ip

# 3. Suspicious logins by geolocation (auth logs)
source="medisure_phishing_combined_logs.csv" log_type=auth location="Russia"
| stats count by user, result, location

# 4. All phishing-related events by user (summary)
source="medisure_phishing_combined_logs.csv"
(url_domain="sign.in" OR url_domain="access-accsecurity.com"
 OR dest_ip="89.144.44.41" OR dest_ip="103.225.77.255" OR location="Russia")
| stats count by user
```

## Repository contents

```
.
├── README.md
├── iocs.md                  Defanged indicators of compromise with verdicts
├── report/                  Full investigation report (PDF)
└── evidence/                Screenshots (header, threat intel, Splunk)
```

## Skills demonstrated

Email header analysis · SPF/DKIM/DMARC · Threat intelligence enrichment · SIEM log correlation (Splunk) · IOC extraction · Incident response (NIST SP 800-61 lifecycle) · Technical report writing

## References

- NIST, *Computer Security Incident Handling Guide* (SP 800-61r2)
- CISA, *Phishing Awareness Resources*

---

**Safety note:** All indicators in this repository are defanged (`hxxp`, `[.]`). Do not visit them from a production machine.
