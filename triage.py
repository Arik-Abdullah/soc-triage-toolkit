#!/usr/bin/env python3
"""SOC Alert Triage Toolkit

Two L1-style triage helpers that produce analyst-ready Markdown reports:

  python triage.py auth  auth.log   -> SSH brute-force / password-spray / possible-compromise detection
  python triage.py email phish.eml  -> phishing email triage (headers, auth results, URLs, attachments, IOCs)

Standard library only.
"""
import argparse
import hashlib
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

# ---------------------------------------------------------------- auth.log ---
FAIL_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
OK_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s"
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_ts(s):
    return datetime.strptime(f"{datetime.now().year} {s}", "%Y %b %d %H:%M:%S")


def analyze_auth(path, threshold=5, window_min=5):
    fails, oks = defaultdict(list), defaultdict(list)
    total = 0
    with open(path, errors="replace") as fh:
        for line in fh:
            total += 1
            m = FAIL_RE.search(line)
            if m:
                fails[m["ip"]].append((parse_ts(m["ts"]), m["user"]))
                continue
            m = OK_RE.search(line)
            if m:
                oks[m["ip"]].append((parse_ts(m["ts"]), m["user"]))

    alerts = []
    for ip, events in fails.items():
        events.sort()
        best, start, j = 0, 0, 0
        for i in range(len(events)):
            while events[i][0] - events[j][0] > timedelta(minutes=window_min):
                j += 1
            if i - j + 1 > best:
                best, start = i - j + 1, j
        if best < threshold:
            continue
        users = sorted({u for _, u in events})
        first = events[start][0]
        later_ok = [s for s in oks.get(ip, []) if s[0] >= first]
        spray = len(users) >= threshold
        if later_ok:
            sev, action = "HIGH", "ESCALATE to L2: successful login from the attacking IP after repeated failures."
        else:
            sev, action = "MEDIUM", "Block/monitor IP, check for other targets, close with notes if no success."
        alerts.append({
            "ip": ip, "failures": len(events), "peak_in_window": best, "window_min": window_min,
            "users": users, "spray": spray, "first_seen": events[start][0], "last_seen": events[-1][0],
            "success": later_ok, "severity": sev, "action": action,
        })
    alerts.sort(key=lambda a: (a["severity"] != "HIGH", -a["failures"]))
    return total, alerts


def auth_report(path, total, alerts):
    out = [f"# SSH Authentication Triage Report", "",
           f"- Source: `{path}`", f"- Lines parsed: {total}", f"- Alerts raised: {len(alerts)}", ""]
    if not alerts:
        out.append("No brute-force activity above threshold. Close as benign.")
    for n, a in enumerate(alerts, 1):
        out += [f"## Alert {n}: {a['severity']} - suspicious SSH activity from {a['ip']}", "",
                f"- ATT&CK: T1110 Brute Force" + (" (T1110.003 Password Spraying)" if a["spray"] else ""),
                f"- Failed logins: {a['failures']} total, {a['peak_in_window']} within {a['window_min']} min",
                f"- Accounts targeted ({len(a['users'])}): {', '.join(a['users'][:10])}",
                f"- First/last seen: {a['first_seen']:%H:%M:%S} / {a['last_seen']:%H:%M:%S}"]
        if a["success"]:
            ts, u = a["success"][0]
            out.append(f"- **Successful login** as `{u}` at {ts:%H:%M:%S} from the same IP")
        out += [f"- Recommended action: {a['action']}",
                "- IOC to check: IP reputation (AbuseIPDB / VirusTotal), other hosts contacted by this IP", ""]
    return "\n".join(out)


# ------------------------------------------------------------------- email ---
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rebrand.ly", "cutt.ly"}
RISKY_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".iso", ".lnk", ".docm", ".xlsm", ".html", ".htm", ".zip", ".rar"}


def domain_of(addr):
    return addr.rsplit("@", 1)[-1].strip(" >").lower() if addr and "@" in addr else ""


def analyze_email(path):
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)
    findings, score = [], 0

    def flag(text, pts):
        nonlocal score
        findings.append(text)
        score += pts

    frm, reply, ret = msg.get("From", ""), msg.get("Reply-To", ""), msg.get("Return-Path", "")
    fd, rd, retd = domain_of(frm), domain_of(reply), domain_of(ret)
    if rd and rd != fd:
        flag(f"Reply-To domain ({rd}) differs from From domain ({fd})", 2)
    if retd and retd != fd:
        flag(f"Return-Path domain ({retd}) differs from From domain ({fd})", 2)

    auth = (msg.get("Authentication-Results", "") or "").lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth)
        if m and m.group(1) not in ("pass",):
            flag(f"{mech.upper()} result: {m.group(1)}", 2)
        elif not m:
            flag(f"{mech.upper()} result missing", 1)

    body = msg.get_body(preferencelist=("plain", "html"))
    text = body.get_content() if body else ""
    urls = sorted(set(URL_RE.findall(text)))
    domains = set()
    for u in urls:
        host = (urlparse(u).hostname or "").lower()
        domains.add(host)
        if host in SHORTENERS:
            flag(f"URL shortener used: {host}", 2)
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            flag(f"URL points to raw IP: {host}", 3)
        if "xn--" in host:
            flag(f"Punycode (possible homograph) domain: {host}", 3)
        if fd and host != fd and not host.endswith("." + fd) and any(k in host for k in ("login", "verify", "secure", "account")):
            flag(f"Credential-style lure domain: {host}", 2)

    if re.search(r"urgent|immediately|suspended|verify your|password expires|within 24 hours", text, re.I):
        flag("Urgency / credential-harvesting language in body", 1)

    attachments = []
    for part in msg.iter_attachments():
        data = part.get_payload(decode=True) or b""
        name = part.get_filename() or "unnamed"
        sha = hashlib.sha256(data).hexdigest()
        attachments.append((name, sha))
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in RISKY_EXT:
            flag(f"Risky attachment type: {name}", 3)
        if name.lower().count(".") >= 2:
            flag(f"Double extension in attachment name: {name}", 3)

    verdict = "MALICIOUS - quarantine, block sender/URLs, notify reporter" if score >= 6 else \
              "SUSPICIOUS - escalate to L2 for review" if score >= 3 else "LIKELY BENIGN - close with notes"
    return {"from": frm, "reply": reply, "subject": msg.get("Subject", ""), "findings": findings,
            "score": score, "verdict": verdict, "urls": urls, "domains": sorted(domains), "attachments": attachments}


def email_report(path, r):
    out = ["# Phishing Email Triage Report", "", f"- Source: `{path}`", f"- Subject: {r['subject']}",
           f"- From: {r['from']}", f"- Reply-To: {r['reply'] or 'n/a'}", f"- Risk score: {r['score']}",
           f"- **Verdict: {r['verdict']}**", "- ATT&CK: T1566 Phishing", "", "## Findings"]
    out += [f"- {f}" for f in r["findings"]] or ["- None"]
    out += ["", "## Indicators of Compromise (IOCs)"]
    out += [f"- URL: `{u}`" for u in r["urls"]]
    out += [f"- Domain: `{d}`" for d in r["domains"]]
    out += [f"- Attachment: `{n}` SHA256 `{h}`" for n, h in r["attachments"]]
    out += ["", "## Suggested actions", "- Search mail logs for other recipients of the same sender/URL",
            "- Check IOCs in VirusTotal / URLhaus", "- Reply to the reporting user with basic security guidance",
            "- Record the incident and closure in the ticketing system"]
    return "\n".join(out)


# -------------------------------------------------------------------- main ---
def main():
    p = argparse.ArgumentParser(description="SOC alert triage toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("auth", help="analyze an SSH auth.log")
    a.add_argument("file")
    a.add_argument("--threshold", type=int, default=5)
    a.add_argument("--window", type=int, default=5, help="minutes")
    a.add_argument("-o", "--output")
    e = sub.add_parser("email", help="triage a .eml file")
    e.add_argument("file")
    e.add_argument("-o", "--output")
    args = p.parse_args()

    if args.cmd == "auth":
        total, alerts = analyze_auth(args.file, args.threshold, args.window)
        report = auth_report(args.file, total, alerts)
    else:
        report = email_report(args.file, analyze_email(args.file))

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(report + "\n")
        print(f"Report written to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    sys.exit(main())
