"""
SentinelAI scanner engine.
Walks a target directory, runs every registered detector against every
.py file, and writes the combined findings to findings.json.

Usage:
    python -m scanner.engine <target_dir> [output.json]
"""

import json
import os
import sys

from scanner import dangerous_functions, secrets, sql_injection

# Registry of detectors. Each entry is (name, module_with_scan_file_function).
# Add new detectors here as they're built (weak_crypto, security_hygiene next)
DETECTORS = [
    ("dangerous_functions", dangerous_functions),
    ("secrets", secrets),
    ("sql_injection", sql_injection),
]


def find_python_files(target_dir):
    py_files = []
    for root, _, files in os.walk(target_dir):
        for fname in files:
            if fname.endswith(".py"):
                py_files.append(os.path.join(root, fname))
    return py_files


def run_scan(target_dir):
    all_findings = []
    py_files = find_python_files(target_dir)

    for filepath in py_files:
        for name, module in DETECTORS:
            findings = module.scan_file(filepath)
            all_findings.extend(findings)

    return all_findings


def summarize(findings):
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    return severity_counts


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m scanner.engine <target_dir> [output.json]", file=sys.stderr)
        sys.exit(1)

    target_dir = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "findings.json"

    findings = run_scan(target_dir)
    summary = summarize(findings)

    report = {
        "target": target_dir,
        "total_findings": len(findings),
        "severity_counts": summary,
        "findings": [f.to_dict() for f in findings],
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Scanned {target_dir}")
    print(f"Found {len(findings)} issue(s): {summary}")
    print(f"Report written to {output_path}")


if __name__ == "__main__":
    main()
