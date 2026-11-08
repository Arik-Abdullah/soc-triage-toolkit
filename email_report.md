# Phishing Email Triage Report

- Source: `phish.eml`
- Subject: URGENT: Your account will be suspended within 24 hours
- From: ExamplePay Security <alerts@examplepay-secure-login.example>
- Reply-To: helpdesk@mail-collector.example
- Risk score: 16
- **Verdict: MALICIOUS - quarantine, block sender/URLs, notify reporter**
- ATT&CK: T1566 Phishing

## Findings
- Reply-To domain (mail-collector.example) differs from From domain (examplepay-secure-login.example)
- Return-Path domain (mail-collector.example) differs from From domain (examplepay-secure-login.example)
- SPF result: fail
- DKIM result: none
- DMARC result: fail
- URL points to raw IP: 203.0.113.80
- URL shortener used: bit.ly
- Urgency / credential-harvesting language in body

## Indicators of Compromise (IOCs)
- URL: `http://203.0.113.80/secure/login`
- URL: `http://bit.ly/3abcXYZ`
- Domain: `203.0.113.80`
- Domain: `bit.ly`

## Suggested actions
- Search mail logs for other recipients of the same sender/URL
- Check IOCs in VirusTotal / URLhaus
- Reply to the reporting user with basic security guidance
- Record the incident and closure in the ticketing system
