"""
Detector: Dangerous Code Execution

Flags calls to eval(), exec(), os.system(), and subprocess calls with
shell=True — the classic remote-code-execution-via-user-input pattern.

Uses Python's ast module rather than regex, so it understands actual call
structure (e.g. won't false-positive on a variable named `eval_score`,
and correctly finds `subprocess.call(cmd, shell=True)` regardless of
argument order).
"""

import ast
from scanner.base import Finding

DANGEROUS_CALL_NAMES = {"eval", "exec"}
DANGEROUS_OS_CALLS = {("os", "system"), ("os", "popen")}


def _get_call_name(node):
    """Return ('eval',) for eval(...), or ('os', 'system') for os.system(...)."""
    func = node.func
    if isinstance(func, ast.Name):
        return (func.id,)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return (func.value.id, func.attr)
    return None


def _has_shell_true(node):
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r") as f:
            source = f.read()
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, UnicodeDecodeError):
        return findings

    lines = source.splitlines()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        name_parts = _get_call_name(node)
        if name_parts is None:
            continue

        line_no = node.lineno
        snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""

        if name_parts[0] in DANGEROUS_CALL_NAMES and len(name_parts) == 1:
            findings.append(Finding(
                severity="CRITICAL",
                category="Dangerous Code Execution",
                file=filepath,
                line=line_no,
                code_snippet=snippet,
                description=f"Call to {name_parts[0]}() detected. If any argument "
                             f"is influenced by user input, this allows arbitrary "
                             f"code execution.",
            ))
        elif name_parts in DANGEROUS_OS_CALLS:
            findings.append(Finding(
                severity="CRITICAL",
                category="Dangerous Code Execution",
                file=filepath,
                line=line_no,
                code_snippet=snippet,
                description=f"Call to {'.'.join(name_parts)}() detected. If any "
                             f"argument is influenced by user input, this allows "
                             f"arbitrary shell command execution.",
            ))
        elif name_parts[-1] in ("run", "call", "Popen") and _has_shell_true(node):
            findings.append(Finding(
                severity="CRITICAL",
                category="Dangerous Code Execution",
                file=filepath,
                line=line_no,
                code_snippet=snippet,
                description="subprocess call with shell=True detected. Combined "
                             "with user-controlled input, this allows shell "
                             "command injection.",
            ))

    return findings
