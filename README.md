Here is the complete, formatted `README.md` for your **Secrets-Sweep** project. You can copy the entire code block below directly into your file.

```markdown
# 🛡️ Secrets-Sweep: Zero-Dependency Secret & Entropy Scanner

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-brightgreen.svg)](#)
[![CI/CD Ready](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-orange.svg)](#)

> **A deterministic, zero-dependency DevSecOps tool** that detects leaked credentials using both deterministic Regex patterns and a custom, from-scratch **Shannon Entropy** algorithm to catch obfuscated secrets.

---

## ⚡ The Challenge
Hardcoded secrets in source code are the #1 cause of enterprise supply-chain breaches. Traditional scanners rely entirely on Regex (e.g., looking for `AKIA` for AWS keys). However, attackers and careless developers often obfuscate secrets, rename variables, or use custom tokens that don't match known Regex patterns, allowing them to slip past standard CI/CD gates.

##  The Solution
**Secrets-Sweep** combines deterministic pattern matching with **Information Theory**. Built entirely with Python’s standard library, it implements the **Shannon Entropy algorithm from scratch** (no external math libraries) to mathematically measure the "randomness" of strings. If a string's entropy exceeds a calculated threshold, it is flagged as a highly probable obfuscated secret, catching what Regex misses.

---

## 🏗️ System Architecture

```mermaid
graph TD
    A["Source Code / Config Files"] -->|"Read Lines"| B["Scanner Engine"]
    B -->|"Regex Matching"| C["Known Pattern Detector"]
    B -->|"Extract Strings"| D["Shannon Entropy Calculator"]
    D -->|"Calculate Math.randomness"| E{Entropy > 4.5?}
    C --> F["Security Findings Report"]
    E -->|"Yes"| F
    E -->|"No"| G["Ignore"]
    F -->|"sys.exit 1"| H["🔴 Block CI/CD Pipeline"]
    
    style D fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#fff
    style H fill:#dc2626,stroke:#fff,stroke-width:1px,color:#fff
```

---

## 🔧 Installation & Usage

**Zero external dependencies required.** Built entirely with Python standard libraries (`re`, `math`, `collections`, `os`, `sys`).

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/secrets-sweep.git
cd secrets-sweep

# 2. Run the scanner against a file or directory
python scanner.py sample_secrets.txt
```

### 📊 Sample Detection Output
```text
🛡️  INITIALIZING SECRETS-SWEEP (v1.0.0)

[*] Scanning sample_secrets.txt...
[!] Scan Complete. Found 3 potential secrets:

 -> Line 5 | Known Pattern (CRITICAL)
    Details: AWS Access Key detected
    Snippet: AKIAIOSFODNN7EXAMPLE

 -> Line 8 | High Entropy (HIGH)
    Details: High-entropy string detected (Entropy: 5.00)
    Snippet: 8f4e2d1c9b7a6f5e4d...

 -> Line 11 | Known Pattern (CRITICAL)
    Details: GitHub Token detected
    Snippet: ghp_1234567890abcdef...

[!] CI/CD Pipeline Failed: Leaked secrets detected.
```

---

## 🛡️ Why This Matters for Enterprise DevSecOps
1.  **Catches Obfuscated Secrets**: The custom Shannon Entropy algorithm detects random tokens that lack standard prefixes (like `AKIA` or `ghp_`).
2.  **Computer Science Fundamentals**: Proves deep understanding of Information Theory applied to practical security, rather than just gluing together third-party libraries.
3.  **Supply-Chain Hardened**: Zero third-party `pip` dependencies eliminate the risk of malicious package injection.
4.  **CI/CD Native**: Automatically returns `sys.exit(1)` to fail builds when secrets are detected.

---

## 🤝 Contributing
Contributions are welcome! To add a new detection rule:
1.  Fork the repository.
2.  Add a new dictionary to the `KNOWN_PATTERNS` list in `scanner.py`.
3.  Submit a Pull Request.

## 📄 License
This project is licensed under the MIT License.

---
*Built for DevSecOps Engineers, AppSec Teams, and Secure Software Developers.*