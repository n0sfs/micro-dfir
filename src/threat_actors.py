"""Curated threat-actor / malware-family reference data (MISP threat-actor galaxy
pattern) -- a small, hand-picked set of well-known names and aliases mapped to the
ATT&CK techniques they're commonly associated with. Purely informational enrichment
(cross-referencing what's already sitting in the synced IOC feed against known TTPs)
-- never used for scoring, alerting, or automated correlation.

Technique IDs deliberately reuse the same curated set already in mitre_attack.py so
lookups resolve to a real name/tactic instead of falling through to 'unmapped'.
"""
import re

ACTORS = [
    {'name': 'Emotet', 'aliases': ['Heodo'], 'type': 'malware',
     'description': 'Modular loader delivered via malspam, commonly an initial-access broker for follow-on ransomware.',
     'techniques': ['1566.001', '1059.001', '1547.001']},
    {'name': 'TrickBot', 'aliases': [], 'type': 'malware',
     'description': 'Banking trojan and post-exploitation loader, frequently a precursor to Ryuk/Conti deployment.',
     'techniques': ['1055', '1082', '1071.001']},
    {'name': 'QakBot', 'aliases': ['QBot', 'Pinkslipbot'], 'type': 'malware',
     'description': 'Banking trojan/worm delivered via malspam threads, used for lateral movement and ransomware staging.',
     'techniques': ['1566.001', '1059.001', '1021.002']},
    {'name': 'Cobalt Strike', 'aliases': ['CobaltStrike'], 'type': 'tool',
     'description': 'Commercial red-team C2 framework, widely abused post-exploitation for beaconing and lateral movement.',
     'techniques': ['1071.001', '1055', '1027', '1105']},
    {'name': 'LockBit', 'aliases': [], 'type': 'ransomware',
     'description': 'Ransomware-as-a-service; encrypts and exfiltrates before deploying a ransom note.',
     'techniques': ['1486', '1490', '1070.001']},
    {'name': 'Conti', 'aliases': [], 'type': 'ransomware',
     'description': 'Ransomware-as-a-service historically deployed via TrickBot/QakBot access.',
     'techniques': ['1486', '1490', '1021.002']},
    {'name': 'BlackCat', 'aliases': ['ALPHV'], 'type': 'ransomware',
     'description': 'Rust-based ransomware-as-a-service known for aggressive double-extortion.',
     'techniques': ['1486', '1490', '1567']},
    {'name': 'Ryuk', 'aliases': [], 'type': 'ransomware',
     'description': 'Targeted ransomware historically deployed via TrickBot/Emotet access.',
     'techniques': ['1486', '1490']},
    {'name': 'APT28', 'aliases': ['Fancy Bear', 'Sofacy'], 'type': 'actor',
     'description': 'Russia-linked state actor known for spearphishing and credential-access operations.',
     'techniques': ['1566.002', '1071.001', '1003.001']},
    {'name': 'APT29', 'aliases': ['Cozy Bear', 'NOBELIUM'], 'type': 'actor',
     'description': 'Russia-linked state actor known for stealthy, long-dwell-time supply-chain and cloud intrusions.',
     'techniques': ['1566.001', '1071.001', '1550']},
    {'name': 'Lazarus Group', 'aliases': ['Hidden Cobra'], 'type': 'actor',
     'description': 'North Korea-linked state actor spanning espionage, financial theft, and destructive operations.',
     'techniques': ['1566.001', '1105', '1486']},
    {'name': 'FIN7', 'aliases': [], 'type': 'actor',
     'description': 'Financially motivated group targeting retail/hospitality via spearphishing and point-of-sale malware.',
     'techniques': ['1566.001', '1059.005', '1055']},
    {'name': 'Mimikatz', 'aliases': [], 'type': 'tool',
     'description': 'Open-source credential-dumping tool for extracting plaintext passwords, hashes, and Kerberos tickets.',
     'techniques': ['1003.001', '1558.003']},
    {'name': 'AgentTesla', 'aliases': ['Agent Tesla'], 'type': 'malware',
     'description': '.NET-based infostealer/keylogger commonly distributed via malspam.',
     'techniques': ['1056.001', '1005']},
    {'name': 'RedLine Stealer', 'aliases': ['RedLine'], 'type': 'malware',
     'description': 'Commodity infostealer targeting browser-stored credentials and session cookies.',
     'techniques': ['1555', '1539']},
    {'name': 'Ursnif', 'aliases': ['Gozi'], 'type': 'malware',
     'description': 'Banking trojan family with a long history of malspam-driven campaigns.',
     'techniques': ['1566.001', '1055']},
    {'name': 'IcedID', 'aliases': ['BokBot'], 'type': 'malware',
     'description': 'Modular banking trojan/loader, frequently a precursor to ransomware deployment.',
     'techniques': ['1566.001', '1055', '1071.001']},
    {'name': 'Dridex', 'aliases': [], 'type': 'malware',
     'description': 'Banking trojan delivered via malicious Office macros, linked to Evil Corp.',
     'techniques': ['1566.001', '1055']},
    {'name': 'njRAT', 'aliases': ['Bladabindi'], 'type': 'malware',
     'description': 'Widely-used remote access trojan popular with lower-sophistication threat actors.',
     'techniques': ['1547.001', '1056.001']},
    {'name': 'AsyncRAT', 'aliases': [], 'type': 'malware',
     'description': 'Open-source remote access trojan commonly delivered via phishing and malvertising.',
     'techniques': ['1547.001', '1071.001']},
]

_INDEX = None


def _build_index():
    global _INDEX
    if _INDEX is not None:
        return _INDEX
    idx = {}
    for actor in ACTORS:
        idx[actor['name'].lower()] = actor
        for alias in actor.get('aliases', []):
            idx[alias.lower()] = actor
    _INDEX = idx
    return idx


def find_actor_context(text):
    """Whole-word, case-insensitive scan of free text (an IOC name/description) for
    a known actor/malware/tool name or alias. Returns the matching ACTORS entry, or
    None. O(known names) per call -- fine for a curated ~20-entry table."""
    if not text:
        return None
    lowered = text.lower()
    for key, actor in _build_index().items():
        if re.search(r'\b' + re.escape(key) + r'\b', lowered):
            return actor
    return None
