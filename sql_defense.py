"""
sql_defense.py — SQL Injection detection & prevention (Layer 1 of double-layer security).

Detection strategy:
  1. Pattern matching against known SQLi signatures
  2. Token analysis — dangerous keyword density
  3. Structural analysis — quote imbalance, comment sequences
  4. Encode-bypass detection — URL / HTML / hex encoded attacks

All user inputs pass through sanitize() before reaching the DB layer.
The DB layer uses parameterised queries as Layer 2 (see database.py).
"""

import re
from typing import Tuple


# ── Known SQLi attack patterns ─────────────────────────────────────────────────
_PATTERNS = [
    # Classic tautologies
    r"(\b(or|and)\b\s+[\w'\"]+\s*=\s*[\w'\"]+)",
    r"(\b(or|and)\b\s+\d+\s*=\s*\d+)",
    # UNION-based injection
    r"(union\s+(all\s+)?select)",
    # Stacked / batched queries
    r";\s*(drop|delete|insert|update|create|alter|exec|execute)",
    # Comment sequences used to truncate queries
    r"(--|#|\/\*|\*\/)",
    # Blind injection functions
    r"\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(",
    # Information schema probing
    r"\b(information_schema|sys\.tables|sysobjects|pg_tables)\b",
    # Dangerous SQL keywords in user input
    r"\b(drop\s+table|drop\s+database|truncate\s+table)\b",
    # xp_cmdshell / stored proc abuse
    r"\b(xp_cmdshell|exec\s*\(|execute\s*\(|sp_executesql)\b",
    # Hex / char encoding tricks
    r"(0x[0-9a-f]{2,})",
    r"\bchar\s*\(\s*\d+",
    # Subquery injection
    r"\bselect\b.+\bfrom\b",
    # Blind boolean
    r"\b(if|case)\s*\(.+select",
    # Load file / into outfile
    r"\b(load_file|into\s+outfile|into\s+dumpfile)\b",
]

_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _PATTERNS]

# Dangerous standalone keywords that raise suspicion score
_KEYWORDS = {
    "select", "insert", "update", "delete", "drop", "alter",
    "create", "exec", "union", "having", "group by", "order by",
    "sleep", "benchmark", "cast", "convert",
}


def detect(user_input: str) -> Tuple[bool, str]:
    """
    Analyse user_input for SQL injection signals.
    Returns (True, attack_description) if an attack is detected, else (False, "").
    """
    if not user_input:
        return False, ""

    text = user_input.strip()

    # ── 1. Pattern matching ────────────────────────────────────────────
    for pattern in _COMPILED:
        match = pattern.search(text)
        if match:
            return True, f"SQLi pattern detected: '{match.group()}'"

    # ── 2. Keyword density check ───────────────────────────────────────
    lower = text.lower()
    tokens = re.findall(r"\b\w+\b", lower)
    if tokens:
        hits = sum(1 for t in tokens if t in _KEYWORDS)
        density = hits / len(tokens)
        if density > 0.35 and len(tokens) > 3:
            return True, f"High SQL keyword density ({density:.0%}) — possible injection"

    # ── 3. Quote imbalance ─────────────────────────────────────────────
    single_quotes = text.count("'")
    double_quotes = text.count('"')
    if single_quotes % 2 != 0:
        return True, "Unbalanced single quotes — possible string termination attack"
    if double_quotes % 2 != 0:
        return True, "Unbalanced double quotes — possible string termination attack"

    # ── 4. URL-encoded attack bypass detection ─────────────────────────
    url_decoded = re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
    if url_decoded != text:
        is_attack, reason = detect(url_decoded)
        if is_attack:
            return True, f"URL-encoded SQLi: {reason}"

    return False, ""


def sanitize(user_input: str) -> Tuple[str, bool, str]:
    """
    Returns (sanitized_value, was_attack_detected, reason).
    If an attack is detected the sanitized value is an empty string.
    Otherwise special characters are escaped for safe display.
    """
    is_attack, reason = detect(user_input)
    if is_attack:
        return "", True, reason

    # Escape HTML special chars and single quotes for display safety
    safe = (
        user_input
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
    return safe, False, ""


def get_attack_level(user_input: str) -> str:
    """Classify the severity of the detected attack for logging."""
    lower = user_input.lower()
    if any(k in lower for k in ("drop", "truncate", "delete", "xp_cmdshell")):
        return "CRITICAL"
    if any(k in lower for k in ("union", "select", "insert", "update")):
        return "HIGH"
    if any(k in lower for k in ("--", "#", "/*", "sleep", "benchmark")):
        return "MEDIUM"
    return "LOW"
