RULES = [
    {
        "id": "SQLI-001",
        "category": "SQL Injection",
        "pattern": r"(?i)(\bunion\b.*\bselect\b|'\s*or\s*'1'='1|--|\bor\b\s+1=1)",
        "severity": "High",
        "action": "block"
    },
    {
        "id": "XSS-001",
        "category": "XSS",
        "pattern": r"(?i)(<script|javascript:|onerror=|onload=)",
        "severity": "High",
        "action": "block"
    },
    {
        "id": "LFI-001",
        "category": "LFI / Directory Traversal",
        "pattern": r"(\.\./|/etc/passwd|boot\.ini|win\.ini)",
        "severity": "High",
        "action": "block"
    },
    {
    "id": "CMDI-001",
    "category": "Command Injection",
    "pattern": r"(?i)(;|\||&&)\s*(cat|whoami|id|ls|pwd|uname|curl|wget|nc|bash|sh)\b",
    "severity": "Critical",
    "action": "block"
    },
    {
        "id": "SCAN-001",
        "category": "Scanner",
        "pattern": r"(?i)(sqlmap|nikto|nmap|acunetix|nessus)",
        "severity": "Medium",
        "action": "flag"
    }
]