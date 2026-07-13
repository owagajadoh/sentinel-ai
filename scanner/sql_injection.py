"""
Detector: SQL Injection

AST-based. Flags calls to execute()/executemany() where the query argument
is dynamically built (string concat, f-string, or .format()) — either
inline in the call, OR assigned to a variable earlier in the same function
and then passed by name (the far more common real-world pattern).

This does lightweight, function-scoped taint tracking: it does not follow
data across function boundaries. That's an intentional scope limit, not
an oversight — full interprocedural taint analysis is a much bigger
project, and this catches the pattern where it actually matters: at the
call site, within the function that builds and runs the query.
"""

import ast
from scanner.base import Finding

EXECUTE_METHOD_NAMES = {"execute", "executemany"}


def _is_dynamic_expr(node):
    """True if this expression is built via string concat, f-string, or .format()."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    if isinstance(node, ast.JoinedStr):  # f-string
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":  # "...".format(...)
            return True
    return False


def _scan_scope(stmts, lines, filepath, findings):
    """Walk statements in a single function/module scope, tracking which
    variable names were assigned a dynamically-built string."""
    tainted_vars = set()

    for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
        if isinstance(node, ast.Assign) and _is_dynamic_expr(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    tainted_vars.add(target.id)

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in EXECUTE_METHOD_NAMES and node.args:
                arg = node.args[0]
                is_inline_dynamic = _is_dynamic_expr(arg)
                is_tainted_var = isinstance(arg, ast.Name) and arg.id in tainted_vars

                if is_inline_dynamic or is_tainted_var:
                    line_no = node.lineno
                    snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""
                    findings.append(Finding(
                        severity="HIGH",
                        category="SQL Injection",
                        file=filepath,
                        line=line_no,
                        code_snippet=snippet,
                        description="Query passed to "
                                     f"{node.func.attr}() is built dynamically "
                                     "(concatenation, f-string, or .format()) "
                                     "rather than using parameterized "
                                     "placeholders. If any part of it is "
                                     "user-controlled, an attacker can alter "
                                     "the query's logic.",
                    ))


def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r") as f:
            source = f.read()
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, UnicodeDecodeError):
        return findings

    lines = source.splitlines()

    # Scan module-level scope, plus each function body as its own scope
    _scan_scope(tree.body, lines, filepath, findings)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_scope(node.body, lines, filepath, findings)

    # Dedupe: module-level walk + per-function walk can double-count nested cases
    seen = set()
    deduped = []
    for f in findings:
        key = (f.file, f.line)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped
