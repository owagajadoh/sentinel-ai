"""
SentinelAI reasoning layer.

Takes a raw static-analysis Finding (from scanner/*.py) and produces the
"security engineer" narrative: why it matters, how an attacker would think
about it, how a defender fixes it, business impact, and a one-line lesson.

--- IMPORTANT: PROTOTYPE NOTICE ---
analyze_finding() below is currently a TEMPLATE-BASED PROTOTYPE, not a real
GPT-5.6 call. It's built so the interface is final: same input shape, same
output shape you'd get from a real model call. To wire in the real thing in
Codex, replace the body of analyze_finding() with an actual GPT-5.6 API call
using the prompt in build_prompt() below — everything else (engine.py,
Streamlit UI) stays identical.
"""

import json


def build_prompt(finding):
    """
    This is the prompt you'd actually send to GPT-5.6 in the Codex build.
    Kept here now so the swap-in later is a copy-paste, not a redesign.
    """
    return f"""You are a senior AppSec engineer reviewing a security finding.

Finding:
- Category: {finding['category']}
- Severity: {finding['severity']}
- File: {finding['file']}
- Line: {finding['line']}
- Code: {finding['code_snippet']}

Respond with a JSON object with these exact keys:
- why_it_matters: 1-2 sentences, plain language, no jargon
- attacker_reasoning: 2-3 sentences written in first person as an attacker
  explaining how they'd exploit this specific line
- defender_reasoning: 2-3 sentences, first person, how you'd fix it and why
  that fix works (not just what to do)
- business_impact: 1 sentence naming a concrete consequence (data leak,
  account takeover, service outage, compliance violation)
- secure_patch: a short code snippet showing the fixed version
- lesson: 1 sentence, the general principle a developer should remember
"""


# --- Template-based prototype (stand-in for the GPT-5.6 call above) -------

_TEMPLATES = {
    "Dangerous Code Execution": {
        "why_it_matters": "This line runs code or shell commands that could be "
                           "influenced by user input, which means an attacker "
                           "could get the server to run commands of their choosing.",
        "attacker_reasoning": "If I control any part of the input reaching this "
                               "line, I can inject my own code or shell commands "
                               "instead of the data the developer expected. I'd "
                               "start by submitting something harmless-looking "
                               "with a command separator to see if it executes.",
        "defender_reasoning": "I would remove the dynamic execution entirely and "
                               "replace it with an explicit allow-list of safe "
                               "operations, because the fix isn't sanitizing "
                               "input — it's never treating input as code in the "
                               "first place.",
        "business_impact": "Full remote code execution on the server, "
                            "potentially exposing the entire application and "
                            "any data it can access.",
        "lesson": "Never let user-controlled data be interpreted as code or "
                  "shell commands, no matter how it's sanitized first.",
    },
    # Fallback used for any category we don't have a specific template for yet
    # (SQL injection, secrets, weak crypto, hygiene — added as those detectors ship)
    "_default": {
        "why_it_matters": "This pattern is a known security anti-pattern that "
                           "commonly leads to exploitation in production apps.",
        "attacker_reasoning": "I'd look for a way to control the input feeding "
                               "into this code path, then craft input designed "
                               "to break the assumption the developer made.",
        "defender_reasoning": "I'd apply the standard secure pattern for this "
                               "category of issue and add a regression test so "
                               "it can't silently reappear.",
        "business_impact": "Depending on exploitation, this could lead to data "
                            "exposure, unauthorized access, or service disruption.",
        "lesson": "Treat all external input as untrusted until validated.",
    },
}


def _fake_patch(finding):
    """Very small patch templates just for the one detector we have so far."""
    code = finding["code_snippet"]
    if "eval(" in code:
        return "# Replace eval() with a safe, explicit parser for the " \
               "expected input format (e.g. ast.literal_eval for literals, " \
               "or a small allow-listed operation set)."
    if "os.system(" in code or "os.popen(" in code:
        return "subprocess.run(['ping', '-c', '1', host], shell=False, check=True)"
    if "shell=True" in code:
        return "subprocess.run(['tar', '-czf', 'backup.tar.gz', filename], shell=False)"
    return "# Manual review recommended for this pattern."


def analyze_finding(finding):
    """
    finding: dict matching scanner.base.Finding.to_dict()
    returns: dict with why_it_matters / attacker_reasoning / defender_reasoning /
             business_impact / secure_patch / lesson
    """
    template = _TEMPLATES.get(finding["category"], _TEMPLATES["_default"])
    result = dict(template)  # copy so we don't mutate the shared template
    result["secure_patch"] = _fake_patch(finding)
    return result


def analyze_all(findings):
    """findings: list of dicts (from findings.json['findings'])"""
    enriched = []
    for finding in findings:
        analysis = analyze_finding(finding)
        enriched.append({**finding, "analysis": analysis})
    return enriched


if __name__ == "__main__":
    import sys
    input_path = sys.argv[1] if len(sys.argv) > 1 else "findings.json"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "enriched_findings.json"

    with open(input_path) as f:
        report = json.load(f)

    report["findings"] = analyze_all(report["findings"])

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Enriched {len(report['findings'])} finding(s) -> {output_path}")
