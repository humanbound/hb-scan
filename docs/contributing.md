# Contributing to hb-scan

## Architecture overview

hb-scan follows a six-stage pipeline:

```
discover --> normalize --> match --> enrich --> aggregate --> score --> report
```

1. **Discover**: Find AI tool session files on disk. Each tool has a discoverer (e.g., `claude.py`) that knows where the tool stores its data.
2. **Normalize**: Convert tool-specific session formats into a common `Session` model with `Message` objects containing roles, text, and tool calls.
3. **Match**: The rule engine loads YAML rules and runs regex patterns (or session heuristics) against normalized sessions, producing `Finding` objects.
4. **Enrich**: Findings are enriched with metadata -- credential expiry detection, severity adjustment, deduplication.
5. **Aggregate**: Findings are grouped into section-level insights (credentials, sensitive data, code, commands, packages, IP, regulatory, scope, oversight) for reporting.
6. **Score**: The posture model calculates a control-based score (0-100) with category weights and severity multipliers.
7. **Report**: Terminal summary (Rich), HTML report (Jinja2), or JSON output.

## Project structure

```
src/hb_scan/
    __init__.py              # Package version
    cli.py                   # Click CLI entry point
    compliance.py            # Compliance framework mappings
    enrichments.py           # Finding enrichment (expiry, dedup)
    insights.py              # Aggregate findings into section summaries
    messages.py              # Randomized progress messages

    discover/
        __init__.py
        base.py              # BaseDiscoverer abstract class
        claude.py            # Claude Code discoverer
        registry.py          # Discoverer registration

    models/
        __init__.py
        session.py           # Session, Message, ToolCall models
        finding.py           # Finding model and redaction
        posture.py           # PostureScore and scoring logic

    normalize/               # Session normalization utilities

    report/
        __init__.py
        terminal.py          # Rich terminal output
        html.py              # Jinja2 HTML report
        json_report.py       # JSON output

    rules/
        __init__.py
        engine.py            # RuleEngine: load YAML, compile regex, match
        schema.py            # Rule, RuleMatch, RuleExclude dataclasses
        builtin/
            credential_patterns.yml   # 102 credential rules from gitleaks/trufflehog
            dh01_secret_exposure.yml  # DH-01 supplementary rules
            dh02_unsafe_code.yml      # DH-02 unsafe code rules
            dh03_dangerous_commands.yml
            dh04_sensitive_data.yml
            dh05_supply_chain.yml
            dh06_scope_violation.yml
            dh07_ip_leakage.yml
            dh08_regulatory_data.yml
            dh09_excessive_reliance.yml

    scoring/                 # Score calculation utilities
    telemetry/               # Anonymous usage telemetry

tests/                       # pytest test suite
```

## How the rule engine works

Rules are defined in YAML files. Each file can contain multiple rules separated by `---`. The engine loads all `.yml` and `.yaml` files from the built-in directory and any custom directories.

### Rule format

```yaml
id: my-rule-id
version: 1
category: secret_exposure          # Maps to a DH category
severity: high                     # critical, high, medium, low, info
detection: regex                   # regex, llm, or hybrid
experimental: false                # Optional, default false
description: "What this rule detects"
mitigation: |
  1. Step one to fix
  2. Step two to fix

match:
  target: user_prompt              # Where to look (see below)
  pattern: "regex-pattern-here"    # Regex (Python re module, case-insensitive)
  tool_filter: Bash                # Optional: only match in this tool's calls

exclude:                           # Patterns that suppress matches
  - pattern: "(test|example|fake)"
  - pattern: "(os\\.getenv|environ)"

references:                        # Optional standards references
  - standard: "OWASP LLM02:2025"
    url: "https://example.com"
```

### Match targets

The `target` field controls which part of the conversation is scanned:

| Target | What it scans |
|--------|--------------|
| `user_prompt` | Text the user typed or pasted |
| `assistant_response` | Text the AI returned |
| `tool_input` | Input/arguments to tool calls (e.g., Bash commands, file paths) |
| `tool_output` | Output returned from tool calls |
| `tool_name` | Name of the tool being called |
| `any` | All of the above |

### Tool filter

The optional `tool_filter` restricts matching to a specific tool. For example, `tool_filter: Bash` means the rule only checks Bash tool calls, not Read or Edit calls. This reduces false positives for command-specific rules.

### Detection types

| Type | Tier | Description |
|------|------|-------------|
| `regex` | 1.1 | Standard regex matching. Runs offline. |
| `llm` | 1.2 | Requires an LLM judge for semantic analysis. Skipped in Tier 1.1. |
| `hybrid` | 1.1+ | Has a regex pattern that runs in 1.1, plus an LLM judge for refinement in 1.2. |

### Session heuristics

DH-09 uses a special match type for session-level analysis:

```yaml
match:
  type: session_heuristic
  condition: tool_executions >= 50 AND user_messages <= 3
```

The condition is a simple expression using `tool_executions`, `user_messages`, `AND`, `OR`, and numeric comparisons.

### Exclusion patterns

Exclusions are regex patterns that, if they match the context around a finding, suppress it. This is the primary mechanism for reducing false positives. The exclusion is checked against the match context (the matched text plus ~80 characters of surrounding context), not the entire message.

Common exclusion patterns:
- Test/example values: `(test|example|fake|dummy|placeholder|changeme)`
- Environment variable references: `(os\\.getenv|environ|process\\.env|\\$\\{)`
- Meta-discussions: `(should we|how to|detect|scan|category|taxonomy)`

## How to write custom rules

### Step 1: Create a YAML file

Create a `.yml` file in a directory of your choice:

```yaml
# my-rules/custom-check.yml

id: internal-url-leak
version: 1
category: ip_trade_secret_leakage
severity: medium
detection: regex
description: "Internal staging/dev URL shared with AI"
match:
  target: user_prompt
  pattern: "https?://(staging|dev|internal)\\.[a-z]+\\.example\\.com"
exclude:
  - pattern: "(example\\.com/docs|how to|should we)"
mitigation: |
  1. Avoid sharing internal URLs with public AI tools
  2. Use placeholder URLs when discussing infrastructure
references:
  - standard: "ISO 27001 A.5.14"
    url: "https://www.iso.org/standard/27001"
```

### Step 2: Run with your rules

```bash
hb-scan --rules /path/to/my-rules/
```

Custom rules are loaded alongside the built-in rules. They follow the same format and go through the same engine.

### Step 3: Test your rules

Write a test that creates a session with known content and verifies your rule triggers (or does not trigger for excluded content):

```python
from hb_scan.rules import RuleEngine
from hb_scan.models.session import Session, Message
from pathlib import Path

def test_custom_rule():
    engine = RuleEngine(rules_dirs=[Path("my-rules")])

    session = Session(
        id="test-1",
        tool="claude-code",
        messages=[
            Message(role="user", text="Check https://staging.api.example.com/health"),
        ],
    )

    findings = engine.scan_session(session)
    assert len(findings) == 1
    assert findings[0].rule_id == "internal-url-leak"
```

## How to add a new AI tool discoverer

To add support for a new AI tool, implement the `BaseDiscoverer` interface.

### Step 1: Create the discoverer

Create a new file in `src/hb_scan/discover/`, e.g., `cursor.py`:

```python
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from hb_scan.discover.base import BaseDiscoverer
from hb_scan.models.session import Session


class CursorDiscoverer(BaseDiscoverer):
    name = "cursor"
    display_name = "Cursor"

    def get_default_paths(self) -> List[Path]:
        """Return paths where Cursor stores session data."""
        # Platform-specific paths
        return [
            Path.home() / ".cursor" / "sessions",
            # Add other OS paths as needed
        ]

    def is_installed(self) -> bool:
        """Check if Cursor data exists on disk."""
        return any(p.exists() for p in self.get_default_paths())

    def discover_sessions(
        self,
        since: Optional[datetime] = None,
        project_filter: Optional[str] = None,
    ) -> List[Session]:
        """Find and parse Cursor sessions into normalized Session objects."""
        sessions = []
        for data_path in self.get_default_paths():
            if not data_path.exists():
                continue
            # Parse Cursor's session format
            # Normalize into Session objects with Message/ToolCall models
            # Apply since and project_filter
            ...
        return sessions
```

### Step 2: Register the discoverer

Add your discoverer to `src/hb_scan/discover/registry.py` so it is included in `discover_all()` and `get_discoverers()`.

### Step 3: Test it

Write tests that verify:
- `is_installed()` returns True when test data exists
- `discover_sessions()` produces valid `Session` objects
- Time filtering (`since`) works correctly
- Project filtering works correctly

## How the scoring model works

The scoring model is in `src/hb_scan/models/posture.py`. Key concepts:

**Category weights** define how much each control area can reduce the score:

| Category | Weight |
|----------|--------|
| secret_exposure | 20 |
| sensitive_data_sharing | 15 |
| ip_trade_secret_leakage | 15 |
| regulatory_data_exposure | 15 |
| unsafe_code_acceptance | 12 |
| dangerous_command | 10 |
| supply_chain_risk | 8 |
| scope_violation | 5 |
| excessive_reliance | 0 (informational) |

**Severity multipliers** determine what fraction of the weight is deducted:

| Severity | Multiplier |
|----------|-----------|
| high | 1.0 (full weight) |
| medium | 0.5 |
| low | 0.25 |
| info | 0.0 (no penalty) |

**Formula**: `score = 100 - sum(weight * multiplier for each failing category)`

Only the worst severity in each category matters. Having multiple findings in the same category does not increase the penalty.

## How the compliance mapping works

The compliance module (`src/hb_scan/compliance.py`) maps DH categories to specific controls in 8 international frameworks:

1. OWASP Top 10 for LLM Applications 2025
2. OWASP Top 10 for Agentic Applications 2026
3. NIST AI RMF and SP 800-218A
4. ISO/IEC 42001:2023
5. ISO/IEC 27001:2022
6. CIS Controls v8.1
7. EU AI Act
8. MITRE ATLAS

Each framework control maps to one or more DH categories. The control's status is determined by:
- **pass**: All mapped categories are clean
- **fail**: Any mapped category has findings
- **partial**: Some mapped categories are clean, some need LLM assessment
- **not_assessed**: All mapped categories require LLM

The alignment score for each framework is the fraction of assessed controls that pass, with partial counting as 0.5.

## Running tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=hb_scan

# Run a specific test file
pytest tests/test_rules.py
```

## Code style and conventions

- Python 3.10+ with type annotations
- Dataclasses for models (no Pydantic dependency in core)
- Click for CLI
- Rich for terminal output
- PyYAML for rule loading
- Jinja2 for HTML reports (optional dependency)
- No global state -- all state flows through function arguments
- Findings are immutable after creation
- Sensitive values are redacted at the Finding level, not the report level

## PR process

1. Fork the repository
2. Create a feature branch from `main`
3. Write tests for new functionality
4. Ensure all tests pass: `pytest`
5. Submit a pull request with a clear description of what and why
6. PRs require review before merge

### What makes a good contribution

- New credential patterns for providers not yet covered
- New discoverers for AI tools beyond Claude Code
- Improved exclusion patterns to reduce false positives
- Documentation improvements
- Bug fixes with regression tests

### Licensing

All contributions are under the Apache 2.0 license. By submitting a PR, you agree to license your contribution under the same terms.
