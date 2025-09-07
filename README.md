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
- **Open AppSec Architect – Platform Security** → [`Application-Security/Application-Security-Architect-Platform-Security.md`](./Application-Security/Application-Security-Architect-Platform-Security.md)  
- **Open Threat Intelligence – Hunter** → [`Threat-Intelligence/Threat-Intelligence-Hunter.md`](./Threat-Intelligence/Threat-Intelligence-Hunter.md)

> Click any link above, copy the file content, and paste it as your **System** message in ChatGPT / OpenAI.

---

## Quick Start

### Use in ChatGPT (UI)
Start a fresh chat (this keeps the agent instructions clean).

Open one agent file and copy its entire contents:

→ **Open:** [`Penetration-Tester/Penetration-Tester-Web-App.md`](./Penetration-Tester/Penetration-Tester-Web-App.md)

→ **Open:** [`Application-Security-Engineer/Application-Security-Architect-Platform-Security.md`](./Application-Security/Application-Security-Architect-Platform-Security.md)

 → **Open:** [`Threat-Intelligence/Threat-Intelligence-Hunter.md`](./Threat-Intelligence/Threat-Intelligence-Hunter.md)

Paste it as the very first message. (This acts like “system” guidance for the session.)

Ask for an acknowledgment so the model locks in the role (e.g., “Summarize your mission and list the first 5 actions you’ll take based on my scope.”).

Provide scope, constraints, and artifacts (URLs, logs, requests, code).

One agent per chat. For multi‑role workflows, paste a short summary into a new chat with the next agent.

>Tip: If you use ChatGPT’s “Create a GPT”, paste the agent file into the Instructions field to make a reusable GPT persona.

### Use with OpenAI API (Python)

>Works with the official openai Python SDK (pip install openai python-dotenv).
The SDK defaults to reading OPENAI_API_KEY from your environment; .env is optional but recommended for local dev

#### 1) Set your API key (one‑time)

***macOS / Linux (bash/zsh):***

```
export OPENAI_API_KEY="sk-...your_key..."
```

***Windows (PowerShell):***

```
setx OPENAI_API_KEY "sk-...your_key..."
# Restart your terminal to pick up the change
```

***Optional (.env) for local dev:***
```
echo 'OPENAI_API_KEY=sk-...your_key...' > .env
```

#### 2) Minimal example (Chat Completions)
```python
# pip install openai python-dotenv
import os
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI

# Load .env if present (OPENAI_API_KEY)
load_dotenv()

# Read an agent file (pick one)
AGENT_PATH = Path("Penetration-Tester/Penetration-Tester-Web-App.md")
agent_instructions = AGENT_PATH.read_text(encoding="utf-8")

client = OpenAI(  # The SDK will automatically read OPENAI_API_KEY
    api_key=os.environ.get("OPENAI_API_KEY")  # explicit for clarity
)

# Your task for the agent
user_task = """<task for agent>"""

resp = client.chat.completions.create(  # Chat Completions is supported indefinitely
    model="gpt-4o", # Choose a different model
    messages=[
        {"role": "system", "content": agent_instructions},
        {"role": "user", "content": user_task},
    ],
    temperature=0.2,
)

print(resp.choices[0].message.content)
```
#### 3) Streaming (optional) — print tokens as they arrive
```python
from openai import OpenAI
from pathlib import Path
from dotenv import load_dotenv; load_dotenv()

agent = Path("Threat-Intelligence/Threat-Intelligence-Hunter.md").read_text(encoding="utf-8")
client = OpenAI()

with client.chat.completions.with_streaming_response.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": agent},
        {"role": "user", "content": "Draft a PIR + hunt plan for OAuth consent phishing in our SaaS stack."}
    ],
) as stream_resp:
    for line in stream_resp.iter_lines():
        # Each line is an SSE event fragment; print raw or parse as needed
        print(line)
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
