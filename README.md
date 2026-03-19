<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-light.svg"/>
    <source media="(prefers-color-scheme: light)" srcset="assets/logo-dark.svg"/>
    <img src="assets/logo-dark.svg" alt="Humanbound" width="280"/>
  </picture>
</p>

<h3 align="center">hb-scan</h3>

<p align="center">
  AI session security scanner -- detect secrets, unsafe code, and data leakage in your AI tool conversations.
  <br/>
  <strong>151 rules</strong> &middot; <strong>70+ credential providers</strong> &middot; <strong>8 compliance frameworks</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#what-it-scans">What It Scans</a> &middot;
  <a href="#scoring">Scoring</a> &middot;
  <a href="#compliance">Compliance</a> &middot;
  <a href="docs/user-guide.md">User Guide</a> &middot;
  <a href="docs/contributing.md">Contributing</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/hb-scan/"><img src="https://img.shields.io/pypi/v/hb-scan?style=flat-square&color=FD9506" alt="PyPI version"/></a>
  <a href="https://pypi.org/project/hb-scan/"><img src="https://img.shields.io/pypi/dm/hb-scan?style=flat-square&color=FD9506" alt="Downloads"/></a>
  <a href="https://github.com/humanbound/hb-scan/actions"><img src="https://img.shields.io/github/actions/workflow/status/humanbound/hb-scan/ci.yml?style=flat-square&color=FD9506" alt="Build"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-FD9506?style=flat-square" alt="License"/></a>
  <a href="https://humanbound.ai"><img src="https://img.shields.io/badge/humanbound.ai-platform-FD9506?style=flat-square" alt="Platform"/></a>
</p>

---

## Quick Start

```bash
pip install hb-scan
hb-scan
```

That's it. hb-scan discovers AI tool sessions on your machine, scans them with 139 regex rules, and produces an AI hygiene report with a compliance-mapped score.

> **Want the full HTML report?** hb-scan generates one automatically in your current directory. Open `hb-scan-report.html` in any browser.

---

## What It Does

```
$ hb-scan --since 7d

hb-scan v0.1.0

  [1/4] Searching for AI tool footprints...
  ✓ Found 100 sessions (Claude Code)
  [2/4] Analysing conversations for secrets...
  [3/4] Crunching the numbers...
  [4/4] Building your report...
  ○ A few opportunities to improve.

┌──────────────────────── hb-scan — AI Hygiene Report ─────────────────────────┐
│ Mar 12 — Mar 19, 2026                                                        │
└──────────────────────────────────────────────────────────────────────────────┘
  Tool: Claude Code
  Sessions scanned: 100

  ⚠  Credential Exposure — 1 active credential
  ✓  Sensitive Data — Clean
  ✓  Code Security — Clean
  ✓  Commands — Clean
  ✓  Package Safety — Clean
  ✓  IP / Trade Secret — Clean
  ◌  Regulatory Data — requires LLM judge
  ○  Human Oversight Index — HOI 0.97

┌───────────────────────── HYGIENE SCORE ──────────────────────────────────────┐
│  80/100 (Grade B)                                                            │
└──────────────────────────────────────────────────────────────────────────────┘
  Rules: 139/151 active (12 require LLM judge)
```

---

## What It Scans

Nine threat classes backed by international standards. Each maps to specific controls in OWASP, NIST, ISO, CIS, MITRE, and the EU AI Act.

| ID | Threat Class | Rules | Detection | Key Standards |
|---|---|---|---|---|
| DH-01 | Secret Exposure | 104 | regex | OWASP LLM02, MITRE AML.T0051 |
| DH-02 | Unsafe Code Acceptance | 6 + 3 LLM | regex + llm | OWASP LLM05, NIST SP 800-218A |
| DH-03 | Dangerous Command Execution | 8 | regex | OWASP LLM06, SANS IDEsaster |
| DH-04 | Sensitive Data Sharing | 6 + 1 LLM | regex + llm | ISO 42001 A.7, MITRE AML.T0024 |
| DH-05 | Supply Chain Risk | 6 | regex | OWASP LLM03, ENISA Slopsquatting |
| DH-06 | Scope Violation | 5 | regex | OWASP Agentic ASI03, CIS Control 6 |
| DH-07 | IP / Trade Secret Leakage | 3 + 2 LLM | regex + llm | DTSA, EU Trade Secrets Directive |
| DH-08 | Regulatory Data Exposure | 0 + 6 LLM | llm only | GDPR, HIPAA, SOX, ABA Opinion 512 |
| DH-09 | Excessive Reliance | 1 | heuristic | EU AI Act Art. 14, NIST AI RMF |

> **104 credential patterns** sourced from gitleaks and TruffleHog covering AWS, Azure, GCP, OpenAI, Anthropic, GitHub, Slack, Stripe, and 60+ more providers.

See [docs/taxonomy.md](docs/taxonomy.md) for the full reference with standards citations.

---

## Scoring

hb-scan uses **control-based scoring**, not per-finding counting. This mirrors how ISO 42001 and CIS Controls work: each category is a control that either passes or fails.

```
Score = 100 - sum(category penalties)

Category penalty:
  0     if clean (no findings)
  100%  if high-severity findings present
  50%   if medium-severity findings present
  25%   if low-severity findings present
```

| Category | Weight | What it means |
|---|---|---|
| Secret Exposure | 20 | Credentials found in AI conversations |
| Sensitive Data | 15 | Private files shared with AI tools |
| IP / Trade Secret | 15 | Proprietary content shared with AI |
| Regulatory Data | 15 | GDPR/HIPAA/SOX data in AI sessions |
| Code Security | 12 | Vulnerable AI-generated code accepted |
| Dangerous Commands | 10 | Risky shell commands via AI |
| Supply Chain | 8 | Unvetted packages installed via AI |
| Scope Violation | 5 | AI accessing files outside project |

10 leaked API keys = same score as 1 leaked API key. The control is failing either way.

---

## Compliance

The HTML report maps every finding to specific controls in 8 international frameworks:

<table>
<tr>
<td width="50%">

**AI-Specific Frameworks**
- OWASP Top 10 for LLM Applications 2025
- OWASP Top 10 for Agentic Applications 2026
- NIST AI RMF & SP 800-218A
- EU AI Act (Art. 14, 15)
- MITRE ATLAS

</td>
<td width="50%">

**General Security Frameworks**
- ISO/IEC 42001:2023 (AI Management)
- ISO/IEC 27001:2022 (Information Security)
- CIS Controls v8.1

</td>
</tr>
</table>

Each framework shows an alignment score with pass/fail/partial status per control. Use the report as an audit artifact.

---

## Human Oversight Index

The HOI score (0.0 - 1.0) measures how actively you supervise AI tool actions. Sessions with 50+ tool executions and fewer than 3 substantive user interactions are flagged as auto-pilot.

```
HOI 1.0   = Full oversight (all sessions supervised)
HOI 0.9+  = Good
HOI 0.7+  = Attention needed
HOI < 0.5 = Significant over-reliance
```

> 88% of accepted AI-generated code is retained without modification (GitHub/Accenture 2025). EU AI Act Article 14 requires awareness of "automation bias."

---

## Architecture

```
hb-scan
  |
  ├── Discover ────── Find AI tool sessions on disk
  |                    └── Claude Code (v1), Cursor, Aider... (plugins)
  |
  ├── Normalize ───── Convert to common Session / Message / ToolCall schema
  |
  ├── Match ────────── Run YAML rules against normalized sessions
  |                    ├── 139 regex rules (active in Tier 1.1)
  |                    └── 12 LLM rules (deferred to Tier 1.2)
  |
  ├── Enrich ────────  JWT expiry detection, severity adjustments
  |
  ├── Aggregate ───── Group findings into insight sections
  |
  ├── Score ────────── Control-based posture calculation
  |
  └── Report ────────  Terminal summary + branded HTML report
```

---

## CLI Reference

```bash
hb-scan                          # Full scan, terminal + HTML report
hb-scan --since 7d               # Last 7 days only
hb-scan --since 24h              # Last 24 hours
hb-scan --tool claude-code       # Specific tool only
hb-scan --project /path/to/repo  # Specific project only
hb-scan --rules ./my-rules/      # Add custom YAML rules directory
hb-scan --format json            # Machine-readable JSON output
hb-scan --output report.html     # Custom report path
hb-scan --no-telemetry           # Disable anonymous usage telemetry

hb-scan discover                 # List discovered AI tools
hb-scan rules                    # List all rules and their status
```

---

## Supported AI Tools

| Tool | Status | Data Source |
|---|---|---|
| Claude Code | **Supported** | `~/.claude/projects/` (JSONL sessions) |

Support for additional AI tools (Cursor, GitHub Copilot, Aider, Continue.dev, ChatGPT Desktop, Windsurf, and others) is in progress. This list will grow as new discoverers are added.

> Adding a new tool = one Python file implementing `BaseDiscoverer`. See [contributing guide](docs/contributing.md#adding-a-new-ai-tool-discoverer).

---

## Tiers

<table>
<tr>
<td width="33%">

**Tier 1.1 -- Current**

Regex-based rules. Fully offline. Open source.

```bash
pip install hb-scan
hb-scan
```

</td>
<td width="33%">

**Tier 1.2 -- Coming**

Bring your own LLM judge. Regulatory data detection. Semantic analysis.

```bash
hb-scan --llm
```

</td>
<td width="34%">

**Tier 2 -- Platform**

Org-wide governance. Device fleet scanning. Posture dashboard.

[humanbound.ai](https://humanbound.ai)

</td>
</tr>
</table>

---

## Contributing

We welcome contributions in four areas:

- **Rules** -- detection patterns for new credential types or vulnerability patterns
- **Discoverers** -- support for new AI tools (Cursor, Aider, Continue.dev)
- **Compliance** -- control mappings from additional frameworks
- **Core** -- false positive improvements, scoring refinements, report enhancements

See [docs/contributing.md](docs/contributing.md) for architecture, development setup, and PR guidelines.

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

<p align="center">
  <a href="https://humanbound.ai">humanbound.ai</a> &middot;
  <a href="https://github.com/humanbound/hb-scan">GitHub</a>
</p>

<p align="center">
  <sub>For organisation-wide AI governance, connect hb-scan to the <a href="https://humanbound.ai">Humanbound platform</a>.</sub>
</p>
