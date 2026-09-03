import sys
import argparse
import os
import re
import math
from collections import Counter

# ANSI Color Codes
COLORS = {
    "HEADER": "\033[95m", "BLUE": "\033[94m", "CYAN": "\033[96m",
    "GREEN": "\033[92m", "WARNING": "\033[93m", "FAIL": "\033[91m",
    "BOLD": "\033[1m", "ENDC": "\033[0m"
}

# 1. Known Secret Patterns (Regex)
KNOWN_PATTERNS = [
    {"name": "AWS Access Key", "regex": r"AKIA[0-9A-Z]{16}"},
    {"name": "GitHub Token", "regex": r"ghp_[A-Za-z0-9_]{36}"},
    {"name": "Azure Storage Key", "regex": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"},
    {"name": "Private Key", "regex": r"-----BEGIN [A-Z]+ PRIVATE KEY-----"},
    {"name": "Generic API Key", "regex": r"(?i)(api[_-]?key|apikey)\s*=\s*['\"]([A-Za-z0-9_\-]{20,})['\"]"}
]

# 2. Shannon Entropy Calculator (The "Hard" Computer Science Part)
def calculate_entropy(data):
    """Calculates Shannon Entropy of a string from scratch."""
    if not data:
        return 0
    entropy = 0
    counter = Counter(data)
    length = len(data)
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

def scan_file(filepath):
    print(f"{COLORS['BLUE']}[*] Scanning {filepath}...{COLORS['ENDC']}")
    findings = []
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"{COLORS['FAIL']}[!] Error reading {filepath}: {e}{COLORS['ENDC']}")
        return findings

    for line_num, line in enumerate(lines, 1):
        # Check 1: Known Patterns
        for pattern in KNOWN_PATTERNS:
            matches = re.finditer(pattern["regex"], line)
            for match in matches:
                findings.append({
                    "line": line_num,
                    "type": "Known Pattern",
                    "severity": "CRITICAL",
                    "description": f"{pattern['name']} detected",
                    "snippet": match.group(0)[:20] + "..." if len(match.group(0)) > 20 else match.group(0)
                })

        # Check 2: High Entropy Strings (Obfuscated Secrets)
        # Extract all strings of length 16-64 that look like base64 or random tokens
        potential_secrets = re.findall(r'\b[A-Za-z0-9+/=]{16,64}\b', line)
        for secret in potential_secrets:
            # Ignore common non-secret words
            if secret.lower() in ["true", "false", "null", "undefined"]:
                continue
            
            entropy = calculate_entropy(secret)
            # Shannon entropy > 4.5 usually indicates a random/secret string
            if entropy > 4.5:
                findings.append({
                    "line": line_num,
                    "type": "High Entropy",
                    "severity": "HIGH",
                    "description": f"High-entropy string detected (Entropy: {entropy:.2f})",
                    "snippet": secret[:20] + "..."
                })

    return findings

def main():
    parser = argparse.ArgumentParser(description="Secrets-Sweep: Zero-Dependency Secret & Entropy Scanner")
    parser.add_argument("target", help="File or directory to scan")
    args = parser.parse_args()

    print(f"\n{COLORS['HEADER']}{COLORS['BOLD']}🛡️  INITIALIZING SECRETS-SWEEP (v1.0.0){COLORS['ENDC']}\n")
    
    all_findings = []
    if os.path.isfile(args.target):
        all_findings.extend(scan_file(args.target))
    elif os.path.isdir(args.target):
        for root, _, files in os.walk(args.target):
            if ".git" in root: continue # Skip .git directory
            for file in files:
                if file.endswith((".py", ".js", ".json", ".yaml", ".yml", ".env", ".txt", ".conf", ".cfg")):
                    all_findings.extend(scan_file(os.path.join(root, file)))
    else:
        print(f"{COLORS['FAIL']}[!] Invalid target path.{COLORS['ENDC']}")
        sys.exit(1)

    if all_findings:
        print(f"{COLORS['FAIL']}{COLORS['BOLD']}[!] Scan Complete. Found {len(all_findings)} potential secrets:{COLORS['ENDC']}\n")
        for f in all_findings:
            print(f" -> {COLORS['WARNING']}Line {f['line']}{COLORS['ENDC']} | {f['type']} ({f['severity']})")
            print(f"    Details: {f['description']}")
            print(f"    Snippet: {COLORS['CYAN']}{f['snippet']}{COLORS['ENDC']}\n")
        print(f"{COLORS['FAIL']}[!] CI/CD Pipeline Failed: Leaked secrets detected.{COLORS['ENDC']}")
        sys.exit(1)
    else:
        print(f"{COLORS['GREEN']}{COLORS['BOLD']}[+] Scan Complete. No secrets detected. Safe to commit.{COLORS['ENDC']}")
        sys.exit(0)

if __name__ == "__main__":
    main()