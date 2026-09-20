"""Known prompt-injection / hidden-instruction patterns.

Each entry: (id, description, regex, weight)
weight is used for risk scoring (1-3).
"""
import re

PATTERNS = [
    (
        "ignore-instructions",
        "Tries to override prior instructions",
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions", re.IGNORECASE),
        3,
    ),
    (
        "disregard-system",
        "Tries to disregard system/developer prompt",
        re.compile(r"(disregard|forget|override|bypass)\s+(the\s+)?(system|developer|guardrail|policy|policies|safety)\s+(prompt|instructions|rules|filter|settings)?", re.IGNORECASE),
        3,
    ),
    (
        "role-override",
        "Tries to assume a new role/persona",
        re.compile(r"(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as|from\s+now\s+on\s+you\s+are)\b", re.IGNORECASE),
        2,
    ),
    (
        "secrecy",
        "Instructs model to hide behavior",
        re.compile(r"(do\s+not\s+(reveal|mention|disclose|tell|show)|keep\s+(this\s+)?(secret|hidden|confidential)|don't\s+(reveal|tell|mention))", re.IGNORECASE),
        2,
    ),
    (
        "system-fake-tag",
        "Fake system/developer block",
        re.compile(r"(\[system\]|\[developer\]|\[admin\]|<system>|<\|system\|>|###\s*(system|instruction|hidden))", re.IGNORECASE),
        3,
    ),
    (
        "exfiltration",
        "Instructs data to be sent out",
        re.compile(r"(send|email|e-mail|exfiltrate|upload|post|transmit)\s+(all\s+|the\s+)?(data|document|file|password|secret|key|conversation|transcript|context)\s+(to|at)\b", re.IGNORECASE),
        3,
    ),
    (
        "jailbreak-keywords",
        "Common jailbreak markers",
        re.compile(r"\b(DAN\s+mode|developer\s+mode|jailbreak|unfiltered|without\s+restrictions|no\s+policy)\b", re.IGNORECASE),
        2,
    ),
    (
        "tool-abuse",
        "Tries to invoke tools / execute code",
        re.compile(r"(run\s+(this\s+)?(code|command|script|payload)|execute\s+(the\s+)?(following|code|command)|call\s+the\s+(tool|function|api))", re.IGNORECASE),
        2,
    ),
    (
        "approval-bypass",
        "Tries to force approval / safe verdict",
        re.compile(r"(approve\s+(this|everything)|mark\s+(this\s+)?(as\s+)?safe|give\s+a\s+positive\s+(review|score)|hire\s+this\s+candidate)", re.IGNORECASE),
        2,
    ),
    (
        "generic-instruction",
        "Generic hidden instruction to AI",
        re.compile(r"\b(for\s+(ai|chatgpt|Muse|gemini|copilot|llm)\s*[:\-]|instruction\s+for\s+(ai|llm|model)|prompt\s+injection)\b", re.IGNORECASE),
        1,
    ),
]
