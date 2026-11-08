# SOC Alert Triage Toolkit

A small, dependency-free Python toolkit that automates two routine Level-1 SOC tasks and writes analyst-ready Markdown reports.

| Command | What it does |
|---|---|
| `python triage.py auth auth.log` | Detects SSH brute-force and password-spraying, flags a successful login after repeated failures, and recommends escalation to L2 |
| `python triage.py email phish.eml` | Triages a reported phishing email: sender mismatch, SPF/DKIM/DMARC results, URL shorteners, raw-IP links, punycode domains, risky attachments (with SHA-256), urgency language |

Both reports map findings to MITRE ATT&CK (T1110 Brute Force, T1110.003 Password Spraying, T1566 Phishing) and list IOCs ready to look up in VirusTotal, AbuseIPDB or URLhaus.

## Why I built it

SOC analysts spend much of their shift triaging alerts, investigating suspicious emails, identifying indicators of compromise and writing shift reports. This project practices that workflow end to end: **detect -> investigate -> classify -> escalate -> document**.

## Quick start

```bash
python make_sample_data.py          # creates synthetic auth.log and phish.eml
python triage.py auth auth.log      # prints the SSH triage report
python triage.py email phish.eml    # prints the phishing triage report
python triage.py auth auth.log -o auth_report.md   # save a report to file
```

Options for `auth`: `--threshold 5` (failures needed to alert) and `--window 5` (minutes).

Requires Python 3.8+. Standard library only.

## Example output

See [`auth_report.md`](auth_report.md) and [`email_report.md`](email_report.md).

## Detection logic

**SSH (`auth`)**
- Sliding-window count of `Failed password` events per source IP
- Password spraying = many distinct usernames from one IP
- Severity HIGH if the same IP later has an `Accepted` login (possible compromise), otherwise MEDIUM

**Email (`email`)**
- Risk score from weighted indicators; verdict is Likely benign / Suspicious / Malicious
- Verdict maps to an action: close, escalate to L2, or quarantine and block

## Limitations and next steps

- Rules are heuristics, not a replacement for a SIEM; scores are tuned for demonstration
- Tested on synthetic data only (documentation-range IPs, `.example` domains)
- Planned: Windows Event Log (4625/4624) support, VirusTotal API enrichment, CSV/JSON output, unit tests, and a Wazuh/Splunk rule equivalent for each detection

## Author

Arik Abdullah - [github.com/Arik-Abdullah](https://github.com/Arik-Abdullah)
