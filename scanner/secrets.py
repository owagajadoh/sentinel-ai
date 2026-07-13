"""
Detector: Hardcoded Secrets

Regex-based (not AST) because secrets are string-literal patterns, not
code structure. Covers common key formats plus a generic
"suspicious variable name assigned a long string literal" fallback.
"""

import re
from scanner.base import Finding

# Known secret formats — high confidence, name the provider explicitly
KNOWN_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{16,}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9a-zA-Z]{36,}")),
    ("Generic Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
]

# Fallback: suspiciously-named variable assigned a long quoted literal,
# e.g. DATABASE_PASSWORD = "admin123"
GENERIC_ASSIGNMENT = re.compile(
    r"(?i)[a-zA-Z_][a-zA-Z0-9_]*(secret|password|passwd|api[_-]?key|token|access[_-]?key)"
    r"[a-zA-Z0-9_]*\s*=\s*[\"']([^\"']{6,})[\"']"
)


def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        return findings

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue  # skip comments to reduce false positives

        matched = False
        for label, pattern in KNOWN_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    severity="CRITICAL",
                    category="Secrets Exposure",
                    file=filepath,
                    line=line_no,
                    code_snippet=stripped,
                    description=f"{label} found hardcoded in source. Anyone with "
                                 f"repo access (or a leaked copy of this file) "
                                 f"can use this credential directly.",
                ))
                matched = True

        if not matched:
            m = GENERIC_ASSIGNMENT.search(line)
            if m:
                findings.append(Finding(
                    severity="HIGH",
                    category="Secrets Exposure",
                    file=filepath,
                    line=line_no,
                    code_snippet=stripped,
                    description=f"Variable name suggests a secret ('{m.group(1)}') "
                                 f"assigned a hardcoded value. Should be loaded "
                                 f"from environment variables or a secrets manager.",
                ))

    return findings
