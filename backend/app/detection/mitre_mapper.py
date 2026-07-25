import re

# Subset of the MITRE ATT&CK Enterprise matrix covering the techniques
# exercised by the bundled Sigma rules / synthetic datasets.
TECHNIQUES: dict[str, str] = {
    "T1110": "Brute Force",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1078": "Valid Accounts",
    "T1136": "Create Account",
    "T1021": "Remote Services",
    "T1053": "Scheduled Task/Job",
    "T1547": "Boot or Logon Autostart Execution",
    "T1003": "OS Credential Dumping",
    "T1018": "Remote System Discovery",
    "T1046": "Network Service Discovery",
    "T1595": "Active Scanning",
    "T1190": "Exploit Public-Facing Application",
    "T1071": "Application Layer Protocol",
    "T1105": "Ingress Tool Transfer",
    "T1027": "Obfuscated Files or Information",
    "T1082": "System Information Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1499": "Endpoint Denial of Service",
    "T1486": "Data Encrypted for Impact",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1204": "User Execution",
    "T1566": "Phishing",
    "T1087": "Account Discovery",
    "T1213": "Data from Information Repositories",
    "T1055": "Process Injection",
    "T1218": "System Binary Proxy Execution",
    "T1595.001": "Scanning IP Blocks",
    "T1505.003": "Web Shell",
    "T1568": "Dynamic Resolution",
}

_TAG_RE = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def extract_mitre(tags: list[str]) -> tuple[str, str]:
    """Pull the first MITRE technique id/name pair out of a Sigma rule's tags."""
    for tag in tags:
        m = _TAG_RE.match(str(tag))
        if m:
            technique_id = f"T{m.group(1)}"
            name = TECHNIQUES.get(technique_id, "Unknown Technique")
            return technique_id, name
    return "", ""
