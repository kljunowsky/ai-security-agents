# Security Agents

A curated collection of security-focused **AGENTS.md** that supercharge your prompt workflows.  
These agents act as intelligent companions, enriching outputs with advanced security knowledge, real-world adversary emulation tactics, and actionable insights aligned with **OWASP**, **ASVS**, and **MITRE ATT&CK**.

Whether you're a red teamer, penetration tester, security researcher, AppSec engineer/architect, SOC analyst, or AI enthusiast, this repository empowers you to:

- ⚡ **Boost** prompt responses with context-aware security expertise.  
- 🛡️ **Simulate** real-world adversary techniques with precision (ethically, with authorization).  
- 🔍 **Explore** ethical hacking methodologies, best practices, and compliance-aware guidance.  
- 🧠 **Extend** your LLM prompts with domain-specific intelligence for security, DevSecOps, and threat hunting use cases.

---

## Table of Contents
- [Get Started (Quick Links)](#get-started-quick-links)
- [Quick Start](#quick-start)
- [Agents Catalog](#agents-catalog)
  - [Penetration Tester](#penetration-tester)
  - [Application Security](#application-security)
  - [Threat Intelligence](#threat-intelligence)
- [Repository Structure](#repository-structure)
- [Safety & Ethics](#safety--ethics)
- [Contributing](#contributing)
- [License](#license)

---

## Get Started (Quick Links)

- **Open Web App Pentester** → [`Penetration-Tester/Penetration-Tester-Web-App.md`](./Penetration-Tester/Penetration-Tester-Web-App.md)  
- **Open AppSec Architect – Platform Security** → [`Application-Security-Engineer/Application-Security-Architect-Platform-Security.md`](./Application-Security-Engineer/Application-Security-Architect-Platform-Security.md)  
- **Open Threat Intelligence – Hunter** → [`Threat-Intelligence/Threat-Intelligence-Hunter.md`](./Threat-Intelligence/Threat-Intelligence-Hunter.md)

> Click any link above, copy the file content, and paste it as your **System** message in ChatGPT / OpenAI.

---

## Quick Start

### Use in ChatGPT (UI)
1. Open a new chat.  
2. **Paste an agent file** (from links below) as the first message (acts like a *System* prompt).  
3. Provide your scope, goals, and constraints.  
4. Ask task-specific questions or drop artifacts (logs, requests, code) to analyze.

### Use with OpenAI API (Python)
```python
from openai import OpenAI

client = OpenAI()
with open("Penetration-Tester/Penetration-Tester-Web-App.md", "r", encoding="utf-8") as f:
    system_msg = f.read()

resp = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": system_msg},
        {"role": "user", "content": "Assess the password reset flow for security weaknesses: <details>..."}
    ]
)
print(resp.choices[0].message.content)
```

> **Tip:** Use one agent per chat for the clearest results. For multi-role workflows, summarize output and start a new chat with the next agent.

---

## Agents Catalog

### Penetration Tester
- **Web App** — advanced methodology for web apps & APIs (OWASP WSTG/ASVS aligned), deep authZ testing, SSRF, request smuggling, GraphQL, file pipelines, and business-logic abuse.  
  → **Open:** [`Penetration-Tester/Penetration-Tester-Web-App.md`](./Penetration-Tester/Penetration-Tester-Web-App.md)

### Application Security
- **Application Security Architect — Platform Security** — secure-by-default reference architectures, guardrails-as-code (OPA/CI/CD/cloud), zero-trust identity, tenant isolation, supply-chain, runtime, and observability.  
  → **Open:** [`Application-Security-Engineer/Application-Security-Architect-Platform-Security.md`](./Application-Security/Application-Security-Architect-Platform-Security.md)

### Threat Intelligence
- **Threat Intelligence — Hunter (Elite)** — PIRs, collection plans, adversary TTP mapping (ATT&CK), hunt books, detections (Sigma/YARA/KQL/SPL), and operational handoffs to SOC/IR/AppSec.  
  → **Open:** [`Threat-Intelligence/Threat-Intelligence-Hunter.md`](./Threat-Intelligence/Threat-Intelligence-Hunter.md)

> More agents and specializations coming soon (e.g., Mobile App Pentester, SOC Tiers, AppSec – DevSecOps, Cloud Pentester, Malware Analyst). Contributions welcome!



## Safety & Ethics

- These agents are designed for **ethical, authorized** security work only.  
- Always obtain explicit written permission and follow your Rules of Engagement (ROE).  
- Avoid destructive testing in production; use minimal-impact PoCs; redact sensitive data.  
- Comply with laws, contracts, and organizational policies at all times.

---

## Contributing

1. Create a feature branch.  
2. Add or improve an agent following the existing structure and tone.  
3. Include a brief rationale and, where relevant, references.  
4. Open a PR—describe scope, testing notes, and expected outcomes.


## License

MIT — see `LICENSE` for details.
