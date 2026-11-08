"""Generates SYNTHETIC test data (documentation-range IPs, example domains). No real systems involved."""
import random
from datetime import datetime, timedelta

random.seed(7)
t = datetime.now().replace(hour=1, minute=0, second=0, microsecond=0)
lines = []


def ts(dt):
    return dt.strftime("%b %e %H:%M:%S")


def add(dt, msg):
    lines.append((dt, f"{ts(dt)} web01 sshd[{random.randint(1000, 9999)}]: {msg}"))


# benign noise
for i in range(12):
    add(t + timedelta(minutes=i * 7), f"Accepted publickey for deploy from 192.0.2.{random.randint(10, 20)} port 50{i:03d} ssh2")
for i in range(3):
    add(t + timedelta(minutes=20 + i), "Failed password for deploy from 192.0.2.15 port 40000 ssh2")

# attack 1: brute force on root then successful login
for i in range(14):
    add(t + timedelta(minutes=30, seconds=i * 8), f"Failed password for root from 203.0.113.45 port {41000 + i} ssh2")
add(t + timedelta(minutes=32), "Accepted password for root from 203.0.113.45 port 41999 ssh2")

# attack 2: password spraying, no success
for i, u in enumerate(["admin", "test", "oracle", "ubuntu", "postgres", "git", "guest", "pi"]):
    add(t + timedelta(minutes=50, seconds=i * 20), f"Failed password for invalid user {u} from 198.51.100.7 port {52000 + i} ssh2")

lines.sort()
with open("auth.log", "w") as fh:
    fh.write("\n".join(l for _, l in lines) + "\n")

eml = """From: "ExamplePay Security" <alerts@examplepay-secure-login.example>
Reply-To: helpdesk@mail-collector.example
Return-Path: <bounce@mail-collector.example>
To: employee@company.example
Subject: URGENT: Your account will be suspended within 24 hours
Authentication-Results: mx.company.example; spf=fail; dkim=none; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Dear user, we detected unusual activity. Verify your account immediately:
http://203.0.113.80/secure/login
or http://bit.ly/3abcXYZ
Failing to act will result in your account being suspended.
"""
with open("phish.eml", "w") as fh:
    fh.write(eml)
print("Wrote auth.log and phish.eml (synthetic)")
