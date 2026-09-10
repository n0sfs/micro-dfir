#!/usr/bin/env python3
"""Template verification per CLAUDE.md's testing standard, steps 1-2:

1. Jinja compile-check the template through a real jinja2.Environment.
2. Extract every inline <script>...</script> block, stub Jinja {{ }}/{% %}
   tags with harmless placeholders, and run `node --check` on the result.

This does NOT replace steps 3-5 of the testing standard (real SQLite fixture
tests, Node vm-context behavioral tests -- see tools/vm_test_harness.js --
and live-verification). It only collapses the two purely mechanical checks
that get re-run, unchanged, on every touched template.

Usage:
    python tools/check_template.py templates/cases.html [templates/other.html ...]

Exits non-zero if any template fails either check.
"""
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = REPO_ROOT / 'templates'


def jinja_check(rel_path):
    import jinja2
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)))
    env.get_template(rel_path)


def extract_and_stub_scripts(text):
    scripts = re.findall(r'<script(?:\s[^>]*)?>(.*?)</script>', text, re.S)
    out = []
    for s in scripts:
        if not s.strip():
            continue  # an external <script src="..."></script> has no body to check
        stubbed = re.sub(r'{{.*?}}', '""', s, flags=re.S)
        stubbed = re.sub(r'{%.*?%}', '', stubbed, flags=re.S)
        out.append(stubbed)
    return out


def node_check(script_text, label):
    result = subprocess.run(['node', '--check'], input=script_text, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[node --check FAILED] {label}\n{result.stderr}", file=sys.stderr)
        return False
    return True


def to_template_relpath(arg):
    path = Path(arg)
    abs_path = path if path.is_absolute() else (REPO_ROOT / path)
    try:
        rel = abs_path.resolve().relative_to(TEMPLATES_DIR.resolve())
    except ValueError:
        raise SystemExit(f"{arg}: not under templates/ -- pass a path like templates/cases.html")
    return abs_path, str(rel).replace('\\', '/')


def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/check_template.py <template-path> [...]", file=sys.stderr)
        sys.exit(2)
    ok = True
    for arg in sys.argv[1:]:
        abs_path, rel_str = to_template_relpath(arg)
        try:
            jinja_check(rel_str)
            print(f"[jinja OK] {rel_str}")
        except Exception as e:
            print(f"[jinja FAILED] {rel_str}: {e}", file=sys.stderr)
            ok = False
            continue
        text = abs_path.read_text(encoding='utf-8')
        scripts = extract_and_stub_scripts(text)
        if not scripts:
            print(f"[node --check] {rel_str}: no inline <script> body found, skipped")
            continue
        for idx, s in enumerate(scripts):
            label = f"{rel_str} (script #{idx + 1})" if len(scripts) > 1 else rel_str
            if node_check(s, label):
                print(f"[node OK] {label}")
            else:
                ok = False
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
