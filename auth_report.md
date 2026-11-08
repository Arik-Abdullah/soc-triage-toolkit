# SSH Authentication Triage Report

- Source: `auth.log`
- Lines parsed: 38
- Alerts raised: 2

## Alert 1: HIGH - suspicious SSH activity from 203.0.113.45

- ATT&CK: T1110 Brute Force
- Failed logins: 14 total, 14 within 5 min
- Accounts targeted (1): root
- First/last seen: 01:30:00 / 01:31:44
- **Successful login** as `root` at 01:32:00 from the same IP
- Recommended action: ESCALATE to L2: successful login from the attacking IP after repeated failures.
- IOC to check: IP reputation (AbuseIPDB / VirusTotal), other hosts contacted by this IP

## Alert 2: MEDIUM - suspicious SSH activity from 198.51.100.7

- ATT&CK: T1110 Brute Force (T1110.003 Password Spraying)
- Failed logins: 8 total, 8 within 5 min
- Accounts targeted (8): admin, git, guest, oracle, pi, postgres, test, ubuntu
- First/last seen: 01:50:00 / 01:52:20
- Recommended action: Block/monitor IP, check for other targets, close with notes if no success.
- IOC to check: IP reputation (AbuseIPDB / VirusTotal), other hosts contacted by this IP

