"""
Shared types for all SentinelAI scanner modules.
Every detector returns a list of Finding objects with this exact shape,
so the engine, the GPT-5.6 reasoning layer, and the Streamlit UI can all
consume findings from any detector identically.
"""

from dataclasses import dataclass, asdict


@dataclass
class Finding:
    severity: str       # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    category: str        # e.g. "Dangerous Code Execution"
    file: str
    line: int
    code_snippet: str
    description: str     # short, factual, no GPT reasoning yet

    def to_dict(self):
        return asdict(self)
