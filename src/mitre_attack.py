"""Curated MITRE ATT&CK Enterprise reference data.

Sigma rule YAML tags encode ATT&CK info as free-text strings like
`attack.execution` (tactic name) and `attack.t1059`/`attack.t1059.001`
(technique/sub-technique ID) -- there is no structured field anywhere in a
rule. This module provides a static technique-ID -> (name, tactic) lookup so
that tag can be turned into something a coverage report can group and count.

The technique list is intentionally curated, not the full ATT&CK matrix: it
covers the techniques Sigma rules actually tag against in practice (mostly
top-level techniques plus the handful of sub-techniques SigmaHQ rules commonly
use), not the complete ~600-entry framework. A technique ID seen in a rule but
missing from TECHNIQUES still surfaces (see techniques_for_tags below) --
just without a friendly name, grouped under the "Unmapped" pseudo-tactic --
so an out-of-date table degrades gracefully instead of hiding coverage.
"""
import re

# The 14 MITRE ATT&CK Enterprise tactics, in their canonical kill-chain order.
TACTICS = [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact',
]

TACTIC_LABELS = {
    'reconnaissance': 'Reconnaissance',
    'resource-development': 'Resource Development',
    'initial-access': 'Initial Access',
    'execution': 'Execution',
    'persistence': 'Persistence',
    'privilege-escalation': 'Privilege Escalation',
    'defense-evasion': 'Defense Evasion',
    'credential-access': 'Credential Access',
    'discovery': 'Discovery',
    'lateral-movement': 'Lateral Movement',
    'collection': 'Collection',
    'command-and-control': 'Command and Control',
    'exfiltration': 'Exfiltration',
    'impact': 'Impact',
    'unmapped': 'Unmapped',
}

# technique_id -> (name, tactic). IDs are lowercase, no leading "t" -- e.g. the
# key for T1059.001 is '1059.001'. Sub-techniques fall back to their parent's
# tactic when the parent is listed but the sub-technique isn't (see lookup()).
TECHNIQUES = {
    '1595': ('Active Scanning', 'reconnaissance'),
    '1592': ('Gather Victim Host Information', 'reconnaissance'),
    '1589': ('Gather Victim Identity Information', 'reconnaissance'),
    '1590': ('Gather Victim Network Information', 'reconnaissance'),
    '1598': ('Phishing for Information', 'reconnaissance'),

    '1583': ('Acquire Infrastructure', 'resource-development'),
    '1586': ('Compromise Accounts', 'resource-development'),
    '1584': ('Compromise Infrastructure', 'resource-development'),
    '1587': ('Develop Capabilities', 'resource-development'),
    '1588': ('Obtain Capabilities', 'resource-development'),

    '1189': ('Drive-by Compromise', 'initial-access'),
    '1190': ('Exploit Public-Facing Application', 'initial-access'),
    '1133': ('External Remote Services', 'initial-access'),
    '1200': ('Hardware Additions', 'initial-access'),
    '1566': ('Phishing', 'initial-access'),
    '1566.001': ('Spearphishing Attachment', 'initial-access'),
    '1566.002': ('Spearphishing Link', 'initial-access'),
    '1091': ('Replication Through Removable Media', 'initial-access'),
    '1195': ('Supply Chain Compromise', 'initial-access'),
    '1199': ('Trusted Relationship', 'initial-access'),
    '1078': ('Valid Accounts', 'initial-access'),

    '1059': ('Command and Scripting Interpreter', 'execution'),
    '1059.001': ('PowerShell', 'execution'),
    '1059.003': ('Windows Command Shell', 'execution'),
    '1059.004': ('Unix Shell', 'execution'),
    '1059.005': ('Visual Basic', 'execution'),
    '1059.006': ('Python', 'execution'),
    '1059.007': ('JavaScript', 'execution'),
    '1106': ('Native API', 'execution'),
    '1053': ('Scheduled Task/Job', 'execution'),
    '1053.005': ('Scheduled Task', 'execution'),
    '1129': ('Shared Modules', 'execution'),
    '1072': ('Software Deployment Tools', 'execution'),
    '1204': ('User Execution', 'execution'),
    '1204.001': ('Malicious Link', 'execution'),
    '1204.002': ('Malicious File', 'execution'),
    '1047': ('Windows Management Instrumentation', 'execution'),

    '1098': ('Account Manipulation', 'persistence'),
    '1547': ('Boot or Logon Autostart Execution', 'persistence'),
    '1547.001': ('Registry Run Keys / Startup Folder', 'persistence'),
    '1037': ('Boot or Logon Initialization Scripts', 'persistence'),
    '1176': ('Browser Extensions', 'persistence'),
    '1554': ('Compromise Client Software Binary', 'persistence'),
    '1136': ('Create Account', 'persistence'),
    '1543': ('Create or Modify System Process', 'persistence'),
    '1543.003': ('Windows Service', 'persistence'),
    '1546': ('Event Triggered Execution', 'persistence'),
    '1546.003': ('WMI Event Subscription', 'persistence'),
    '1133b': ('External Remote Services', 'persistence'),
    '1574': ('Hijack Execution Flow', 'persistence'),
    '1574.002': ('DLL Side-Loading', 'persistence'),
    '1525': ('Implant Internal Image', 'persistence'),
    '1556': ('Modify Authentication Process', 'persistence'),
    '1137': ('Office Application Startup', 'persistence'),
    '1542': ('Pre-OS Boot', 'persistence'),
    '1053b': ('Scheduled Task/Job', 'persistence'),
    '1505': ('Server Software Component', 'persistence'),
    '1205': ('Traffic Signaling', 'persistence'),
    '1078b': ('Valid Accounts', 'persistence'),

    '1548': ('Abuse Elevation Control Mechanism', 'privilege-escalation'),
    '1548.002': ('Bypass User Account Control', 'privilege-escalation'),
    '1134': ('Access Token Manipulation', 'privilege-escalation'),
    '1611': ('Escape to Host', 'privilege-escalation'),
    '1068': ('Exploitation for Privilege Escalation', 'privilege-escalation'),
    '1055': ('Process Injection', 'privilege-escalation'),
    '1055.001': ('Dynamic-link Library Injection', 'privilege-escalation'),
    '1055.012': ('Process Hollowing', 'privilege-escalation'),

    '1548c': ('Abuse Elevation Control Mechanism', 'defense-evasion'),
    '1140': ('Deobfuscate/Decode Files or Information', 'defense-evasion'),
    '1006': ('Direct Volume Access', 'defense-evasion'),
    '1484': ('Domain or Tenant Policy Modification', 'defense-evasion'),
    '1480': ('Execution Guardrails', 'defense-evasion'),
    '1211': ('Exploitation for Defense Evasion', 'defense-evasion'),
    '1222': ('File and Directory Permissions Modification', 'defense-evasion'),
    '1564': ('Hide Artifacts', 'defense-evasion'),
    '1564.001': ('Hidden Files and Directories', 'defense-evasion'),
    '1574c': ('Hijack Execution Flow', 'defense-evasion'),
    '1562': ('Impair Defenses', 'defense-evasion'),
    '1562.001': ('Disable or Modify Tools', 'defense-evasion'),
    '1070': ('Indicator Removal', 'defense-evasion'),
    '1070.001': ('Clear Windows Event Logs', 'defense-evasion'),
    '1070.004': ('File Deletion', 'defense-evasion'),
    '1202': ('Indirect Command Execution', 'defense-evasion'),
    '1036': ('Masquerading', 'defense-evasion'),
    '1036.005': ('Match Legitimate Name or Location', 'defense-evasion'),
    '1556c': ('Modify Authentication Process', 'defense-evasion'),
    '1112': ('Modify Registry', 'defense-evasion'),
    '1601': ('Modify System Image', 'defense-evasion'),
    '1599': ('Network Boundary Bridging', 'defense-evasion'),
    '1027': ('Obfuscated Files or Information', 'defense-evasion'),
    '1542c': ('Pre-OS Boot', 'defense-evasion'),
    '1055c': ('Process Injection', 'defense-evasion'),
    '1620': ('Reflective Code Loading', 'defense-evasion'),
    '1207': ('Rogue Domain Controller', 'defense-evasion'),
    '1014': ('Rootkit', 'defense-evasion'),
    '1218': ('System Binary Proxy Execution', 'defense-evasion'),
    '1218.011': ('Rundll32', 'defense-evasion'),
    '1218.010': ('Regsvr32', 'defense-evasion'),
    '1216': ('System Script Proxy Execution', 'defense-evasion'),
    '1221': ('Template Injection', 'defense-evasion'),
    '1205c': ('Traffic Signaling', 'defense-evasion'),
    '1127': ('Trusted Developer Utilities Proxy Execution', 'defense-evasion'),
    '1550': ('Use Alternate Authentication Material', 'defense-evasion'),
    '1078c': ('Valid Accounts', 'defense-evasion'),
    '1497': ('Virtualization/Sandbox Evasion', 'defense-evasion'),
    '1220': ('XSL Script Processing', 'defense-evasion'),

    '1110': ('Brute Force', 'credential-access'),
    '1110.001': ('Password Guessing', 'credential-access'),
    '1110.003': ('Password Spraying', 'credential-access'),
    '1555': ('Credentials from Password Stores', 'credential-access'),
    '1212': ('Exploitation for Credential Access', 'credential-access'),
    '1187': ('Forced Authentication', 'credential-access'),
    '1606': ('Forge Web Credentials', 'credential-access'),
    '1056': ('Input Capture', 'credential-access'),
    '1056.001': ('Keylogging', 'credential-access'),
    '1557': ('Adversary-in-the-Middle', 'credential-access'),
    '1556d': ('Modify Authentication Process', 'credential-access'),
    '1003': ('OS Credential Dumping', 'credential-access'),
    '1003.001': ('LSASS Memory', 'credential-access'),
    '1003.002': ('Security Account Manager', 'credential-access'),
    '1528': ('Steal Application Access Token', 'credential-access'),
    '1558': ('Steal or Forge Kerberos Tickets', 'credential-access'),
    '1558.003': ('Kerberoasting', 'credential-access'),
    '1539': ('Steal Web Session Cookie', 'credential-access'),
    '1552': ('Unsecured Credentials', 'credential-access'),
    '1552.001': ('Credentials In Files', 'credential-access'),

    '1087': ('Account Discovery', 'discovery'),
    '1010': ('Application Window Discovery', 'discovery'),
    '1217': ('Browser Bookmark Discovery', 'discovery'),
    '1580': ('Cloud Infrastructure Discovery', 'discovery'),
    '1526': ('Cloud Service Dashboard', 'discovery'),
    '1538': ('Cloud Service Discovery', 'discovery'),
    '1613': ('Container and Resource Discovery', 'discovery'),
    '1482': ('Domain Trust Discovery', 'discovery'),
    '1083': ('File and Directory Discovery', 'discovery'),
    '1615': ('Group Policy Discovery', 'discovery'),
    '1046': ('Network Service Discovery', 'discovery'),
    '1135': ('Network Share Discovery', 'discovery'),
    '1040': ('Network Sniffing', 'discovery'),
    '1201': ('Password Policy Discovery', 'discovery'),
    '1069': ('Permission Groups Discovery', 'discovery'),
    '1057': ('Process Discovery', 'discovery'),
    '1012': ('Query Registry', 'discovery'),
    '1018': ('Remote System Discovery', 'discovery'),
    '1518': ('Software Discovery', 'discovery'),
    '1518.001': ('Security Software Discovery', 'discovery'),
    '1082': ('System Information Discovery', 'discovery'),
    '1614': ('System Location Discovery', 'discovery'),
    '1016': ('System Network Configuration Discovery', 'discovery'),
    '1049': ('System Network Connections Discovery', 'discovery'),
    '1033': ('System Owner/User Discovery', 'discovery'),
    '1007': ('System Service Discovery', 'discovery'),
    '1124': ('System Time Discovery', 'discovery'),
    '1497b': ('Virtualization/Sandbox Evasion', 'discovery'),

    '1210': ('Exploitation of Remote Services', 'lateral-movement'),
    '1534': ('Internal Spearphishing', 'lateral-movement'),
    '1570': ('Lateral Tool Transfer', 'lateral-movement'),
    '1563': ('Remote Service Session Hijacking', 'lateral-movement'),
    '1021': ('Remote Services', 'lateral-movement'),
    '1021.001': ('Remote Desktop Protocol', 'lateral-movement'),
    '1021.002': ('SMB/Windows Admin Shares', 'lateral-movement'),
    '1021.004': ('SSH', 'lateral-movement'),
    '1021.006': ('Windows Remote Management', 'lateral-movement'),
    '1091b': ('Replication Through Removable Media', 'lateral-movement'),
    '1072b': ('Software Deployment Tools', 'lateral-movement'),
    '1080': ('Taint Shared Content', 'lateral-movement'),
    '1550b': ('Use Alternate Authentication Material', 'lateral-movement'),

    '1560': ('Archive Collected Data', 'collection'),
    '1123': ('Audio Capture', 'collection'),
    '1119': ('Automated Collection', 'collection'),
    '1185': ('Browser Session Hijacking', 'collection'),
    '1115': ('Clipboard Data', 'collection'),
    '1530': ('Data from Cloud Storage', 'collection'),
    '1602': ('Data from Configuration Repository', 'collection'),
    '1213': ('Data from Information Repositories', 'collection'),
    '1005': ('Data from Local System', 'collection'),
    '1039': ('Data from Network Shared Drive', 'collection'),
    '1025': ('Data from Removable Media', 'collection'),
    '1074': ('Data Staged', 'collection'),
    '1114': ('Email Collection', 'collection'),
    '1056b': ('Input Capture', 'collection'),
    '1113': ('Screen Capture', 'collection'),
    '1125': ('Video Capture', 'collection'),

    '1071': ('Application Layer Protocol', 'command-and-control'),
    '1071.001': ('Web Protocols', 'command-and-control'),
    '1071.004': ('DNS', 'command-and-control'),
    '1092': ('Communication Through Removable Media', 'command-and-control'),
    '1132': ('Data Encoding', 'command-and-control'),
    '1001': ('Data Obfuscation', 'command-and-control'),
    '1568': ('Dynamic Resolution', 'command-and-control'),
    '1573': ('Encrypted Channel', 'command-and-control'),
    '1008': ('Fallback Channels', 'command-and-control'),
    '1105': ('Ingress Tool Transfer', 'command-and-control'),
    '1104': ('Multi-Stage Channels', 'command-and-control'),
    '1095': ('Non-Application Layer Protocol', 'command-and-control'),
    '1571': ('Non-Standard Port', 'command-and-control'),
    '1572': ('Protocol Tunneling', 'command-and-control'),
    '1090': ('Proxy', 'command-and-control'),
    '1219': ('Remote Access Software', 'command-and-control'),
    '1205b': ('Traffic Signaling', 'command-and-control'),
    '1102': ('Web Service', 'command-and-control'),

    '1020': ('Automated Exfiltration', 'exfiltration'),
    '1030': ('Data Transfer Size Limits', 'exfiltration'),
    '1048': ('Exfiltration Over Alternative Protocol', 'exfiltration'),
    '1041': ('Exfiltration Over C2 Channel', 'exfiltration'),
    '1011': ('Exfiltration Over Other Network Medium', 'exfiltration'),
    '1052': ('Exfiltration Over Physical Medium', 'exfiltration'),
    '1567': ('Exfiltration Over Web Service', 'exfiltration'),
    '1029': ('Scheduled Transfer', 'exfiltration'),
    '1537': ('Transfer Data to Cloud Account', 'exfiltration'),

    '1531': ('Account Access Removal', 'impact'),
    '1485': ('Data Destruction', 'impact'),
    '1486': ('Data Encrypted for Impact', 'impact'),
    '1565': ('Data Manipulation', 'impact'),
    '1491': ('Defacement', 'impact'),
    '1561': ('Disk Wipe', 'impact'),
    '1499': ('Endpoint Denial of Service', 'impact'),
    '1495': ('Firmware Corruption', 'impact'),
    '1490': ('Inhibit System Recovery', 'impact'),
    '1498': ('Network Denial of Service', 'impact'),
    '1496': ('Resource Hijacking', 'impact'),
    '1489': ('Service Stop', 'impact'),
    '1529': ('System Shutdown/Reboot', 'impact'),
}

# A handful of technique IDs collide across tactics in ATT&CK itself (e.g. T1548
# "Abuse Elevation Control Mechanism" belongs to both Privilege Escalation and
# Defense Evasion). TECHNIQUES above disambiguates those with a throwaway suffix
# (e.g. '1548c') purely as a dict key; DISPLAY_ID strips it back to the real ID.
def _display_id(key):
    return re.sub(r'[a-z]+$', '', key)

_TECH_TAG_RE = re.compile(r'^attack\.t(\d{4})(?:\.(\d{3}))?$', re.IGNORECASE)


def lookup(technique_id):
    """Look up a technique ID like '1059.001' or '1059'. Returns (name, tactic)
    or (None, 'unmapped') if not in the curated table. Falls back to the
    parent technique's tactic when only the sub-technique is unlisted."""
    for key, (name, tactic) in TECHNIQUES.items():
        if _display_id(key) == technique_id:
            return name, tactic
    if '.' in technique_id:
        parent = technique_id.split('.', 1)[0]
        for key, (name, tactic) in TECHNIQUES.items():
            if _display_id(key) == parent:
                return None, tactic
    return None, 'unmapped'


def techniques_for_tags(tags):
    """Extract MITRE technique IDs from a Sigma rule's parsed tag list.
    Returns a list of {id, name, tactic} dicts, one per distinct technique
    tag found (tactic-name-only tags like 'attack.execution' are ignored --
    those don't identify a specific technique to count)."""
    out = []
    seen = set()
    for tag in tags or []:
        m = _TECH_TAG_RE.match((tag or '').strip())
        if not m:
            continue
        tid = m.group(1) + (f'.{m.group(2)}' if m.group(2) else '')
        if tid in seen:
            continue
        seen.add(tid)
        name, tactic = lookup(tid)
        out.append({'id': tid, 'name': name, 'tactic': tactic})
    return out
