import re
from urllib.parse import unquote_plus
from .rules import RULES

def detect_attack(text):
    if not text:
        return None
    normalized = unquote_plus(text).lower()
    for rule in RULES:
        if re.search(rule["pattern"], normalized, re.I):
            return rule
    return None