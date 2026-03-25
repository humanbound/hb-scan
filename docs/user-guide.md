# hb-scan User Guide

## What is hb-scan?

hb-scan is a free, open-source tool that checks whether you have accidentally shared sensitive information with your AI coding assistant.

When you use AI tools like Claude Code to help write code, those conversations are stored on your computer. Over time, you may have pasted API keys, passwords, database credentials, or confidential business data into those conversations without realizing the risk. hb-scan finds those issues and tells you what to do about them.

Everything runs locally on your machine. Your data never leaves your computer.

## Why do I need this?

AI coding tools are powerful, but they introduce new security risks that traditional tools do not catch:

- **Credential leaks**: You paste an API key into a prompt to debug an issue. That key is now stored in a conversation log, and may have been sent to a cloud API.
- **Data exposure**: You share your .env file contents or database connection strings so the AI can help configure something.
- **Unsafe code**: The AI generates code with security vulnerabilities like SQL injection or eval() on user input.
- **Supply chain risks**: The AI suggests installing a package that does not actually exist (a "hallucinated" package), which an attacker could register.
- **Scope creep**: The AI reads files outside your project -- your SSH keys, AWS credentials, or shell configuration.

hb-scan detects all of these and gives you a clear report with specific steps to fix each issue.

## Installation

### Using pip (recommended)

```bash
pip install hb-scan
```

To include the HTML report feature:

```bash
pip install "hb-scan[html]"
```

You need Python 3.10 or later. Check your version with:

```bash
python3 --version
```

### Verify installation

```bash
hb-scan --version
```

You should see something like `hb-scan 0.1.0`.

## Running your first scan

Open a terminal and run:

```bash
hb-scan
```

That is all you need. hb-scan will:

1. Find your AI tool sessions on disk (currently supports Claude Code)
2. Scan them against 140 security rules
3. Show a summary in your terminal
4. Generate an HTML report called `hb-scan-report.html` in your current directory

### Scanning a specific time window

If you only want to check recent sessions:

```bash
hb-scan --since 7d     # Last 7 days
hb-scan --since 24h    # Last 24 hours
hb-scan --since 30d    # Last 30 days
```

### Scanning a specific project

```bash
hb-scan --project /path/to/your/project
```

### Saving the report to a specific location

```bash
hb-scan --output ~/Desktop/my-report.html
```

## Understanding the terminal output

When you run hb-scan, you will see output like this:

```
hb-scan v0.1.0

  [1/4] Discovering AI tool sessions...
  Found 42 sessions (Claude Code)
  [2/4] Scanning with 140 rules...
  [3/4] Scoring posture...
  [4/4] Building your report...

  Developer Hygiene Score: 74 / 100 (Grade B)

  Credentials         3 unique (2 active, 1 expired)
  Sensitive Data       .env contents shared in 1 session
  Code Security        No issues
  Commands             sudo used in 2 sessions
  Packages             1 install from git URL
  IP / Trade Secrets   No issues
  Regulatory           Not assessed (requires LLM)
  Scope                Home config accessed in 1 session
  Oversight            No issues

  Full report: hb-scan-report.html
```

Here is what each line means:

- **Developer Hygiene Score**: Your overall security posture on a 0-100 scale. Higher is better. See "Understanding your score" below.
- **Credentials**: API keys, passwords, and tokens found in your conversations. "Active" means they may still be valid and should be rotated.
- **Sensitive Data**: Environment files, SSH keys, or database connection strings that were shared with the AI.
- **Code Security**: Security problems in code the AI generated (eval, SQL injection, etc.). Some of these checks require an LLM and may show "Not assessed."
- **Commands**: Dangerous commands the AI ran, like sudo or rm -rf on broad paths.
- **Packages**: Risky package installations the AI performed -- installs from git URLs, curl-pipe-bash patterns, or potentially hallucinated packages.
- **IP / Trade Secrets**: Content marked as confidential, financial figures, or internal URLs shared with the AI.
- **Regulatory**: Personal data (GDPR), health information (HIPAA), or payment card data (PCI). Most of these checks require an LLM and may show "Not assessed."
- **Scope**: Cases where the AI accessed files outside your project directory, like your SSH keys or shell configuration.
- **Oversight**: Sessions where the AI ran many commands with very little human interaction (potential "auto-pilot" sessions).

## Understanding the HTML report

Open the `hb-scan-report.html` file in your browser. The report has several sections:

### Posture score

A large score (0-100) with a letter grade. This is your overall AI security hygiene rating.

### Category breakdown

Each of the 9 security categories gets its own section showing:
- Whether the category passed or failed
- How many findings were detected
- The worst severity level in that category

### Findings detail

Each individual finding shows:
- What was found (with sensitive values redacted)
- Which session it appeared in
- Severity level (high, medium, low, info)
- Specific steps you should take to fix the issue

### Compliance alignment

The report maps your results to international security standards:
- OWASP Top 10 for LLM Applications
- OWASP Top 10 for Agentic Applications
- NIST AI Risk Management Framework
- ISO/IEC 42001 (AI Management)
- ISO/IEC 27001 (Information Security)
- CIS Controls
- EU AI Act
- MITRE ATLAS

For each standard, you can see which controls you pass and which you fail based on the scan results.

## Understanding what each section checks

### DH-01: Credentials / Secret Exposure

This is the highest-impact category. hb-scan checks for 102 credential patterns from 70+ providers, including:

- AWS access keys and secret keys
- Google Cloud, Azure, and DigitalOcean tokens
- GitHub, GitLab, and Bitbucket tokens
- Stripe, Twilio, SendGrid, and other SaaS API keys
- Database connection strings with embedded passwords
- JWT tokens and bearer tokens
- SSH private keys and PGP private keys

If hb-scan finds a credential, it means that credential value appeared in your AI conversation. Even if you trust the AI provider, the credential is now stored in a conversation log on disk and may have been transmitted to a cloud API.

**What to do**: Rotate any active credentials immediately. Use environment variables or a secrets manager instead of pasting values directly.

### DH-02: Unsafe Code

Checks for security vulnerabilities in code the AI generated:
- Use of eval() or exec() on untrusted input
- SQL queries built with string concatenation (SQL injection risk)
- Hardcoded credentials in generated code

Most of these rules require an LLM judge to distinguish real vulnerabilities from harmless discussions about security. They will show "Not assessed" in Tier 1.1.

### DH-03: Dangerous Commands

Checks for risky commands the AI executed through its tools:
- sudo (privileged execution)
- rm -rf on broad or system paths
- chmod 777 (world-writable permissions)
- Writing to system directories

**What to do**: Review whether each privileged command was necessary. Consider using containers for development.

### DH-04: Sensitive Data

Checks for sensitive information you shared in prompts:
- .env file contents with real values
- SSH private key files read by the AI
- Database connection strings with passwords
- Cloud credentials (AWS, GCP, Azure config files)

**What to do**: Never share .env file contents with AI tools. Reference environment variables by name, not by value. Exclude sensitive files from AI tool access.

### DH-05: Supply Chain

Checks for risky package installations:
- pip/npm install from git URLs instead of official registries
- curl-pipe-bash patterns (downloading and executing remote scripts)
- Packages that may be hallucinated (AI-suggested packages that do not exist)

Research shows that roughly 20% of packages suggested by AI tools do not actually exist. An attacker could register these names and distribute malware.

**What to do**: Always verify that a package exists on the official registry (PyPI, npm) before installing it.

### DH-06: Scope Violation

Checks for the AI accessing files outside your project:
- Home directory config files (.bashrc, .npmrc, .gitconfig)
- SSH configuration and keys
- AWS/GCP/Azure credential files
- Kubernetes configs

**What to do**: Configure your AI tool with explicit project boundaries. Exclude sensitive directories.

### DH-07: IP / Trade Secret Leakage

Checks for business-sensitive content shared with the AI:
- Content with CONFIDENTIAL or PROPRIETARY markings
- Financial figures (revenue, profit, EBITDA with dollar amounts)
- Internal URLs and infrastructure details

Sharing trade secrets with a public AI tool may destroy legal protection under the Defend Trade Secrets Act.

**What to do**: Never share content marked as confidential with public AI tools. Use anonymized or rounded figures when discussing financials.

### DH-08: Regulatory Data

Checks for regulated data shared with the AI:
- GDPR personal data (names with email, phone, address, national ID)
- HIPAA protected health information (patient data, diagnoses)
- PCI cardholder data (credit card numbers)

Most of these checks require an LLM judge and will show "Not assessed" in Tier 1.1.

**What to do**: De-identify personal data before using AI tools. Ensure your AI vendor has appropriate data processing agreements.

### DH-09: Oversight (Human Oversight Index)

Checks for sessions where the AI operated with minimal human oversight -- specifically, sessions with 50 or more tool executions and fewer than 3 substantive user messages. This is informational only and does not reduce your score.

Research shows that 88% of AI-generated code suggestions are accepted without modification. Maintaining active oversight reduces the risk of errors and security issues.

**What to do**: Stay actively engaged in AI conversations. Review outputs before accepting them.

## Understanding your score

hb-scan uses **control-based scoring**. This means:

- Each of the 9 categories is treated as a "control" (like a compliance checklist item)
- A control either passes or fails -- it does not matter how many individual findings there are
- One leaked API key and ten leaked API keys produce the same score impact
- Each category has a weight reflecting its relative importance:

| Category | Weight |
|----------|--------|
| Credentials | 20 |
| Sensitive Data | 15 |
| IP / Trade Secrets | 15 |
| Regulatory | 15 |
| Unsafe Code | 12 |
| Dangerous Commands | 10 |
| Supply Chain | 8 |
| Scope Violation | 5 |
| Oversight | 0 (informational) |

The penalty for a failing control depends on the worst severity found:
- **High severity**: full category weight deducted
- **Medium severity**: 50% of category weight deducted
- **Low/info severity**: 25% of category weight deducted

Your score is 100 minus the total penalties. Grades work like school:
- **A** (90-100): Low risk. Good hygiene practices.
- **B** (75-89): Medium risk. Some issues to address.
- **C** (60-74): High risk. Multiple categories need attention.
- **D** (40-59): High risk. Significant security gaps.
- **F** (0-39): Critical risk. Immediate action needed.

## Compliance alignment

The compliance section in the HTML report maps your scan results to specific controls in international standards. This tells you which formal requirements you are meeting (or not meeting) based on your AI tool usage.

This is not a formal audit. It is a directional assessment based on what hb-scan can observe locally. For a full compliance assessment, see [Humanbound](https://humanbound.ai) for enterprise governance.

## Common questions

**Does hb-scan send my data anywhere?**
No. All scanning happens locally on your machine. hb-scan reads your local AI session files, processes them in memory, and writes the report to disk. An anonymous telemetry ping (no conversation data) is sent by default. Disable it with `--no-telemetry`.

**What AI tools does hb-scan support?**
Currently Claude Code. Support for additional tools (Cursor, Aider, GitHub Copilot, etc.) is planned through the plugin system.

**What if hb-scan finds no sessions?**
Make sure you have used the AI tool at least once. Run `hb-scan discover` to see which tools are detected and where their data is stored.

**Can I write my own rules?**
Yes. Create a directory of YAML files following the rule format and pass it with `--rules /path/to/rules/`. See [docs/contributing.md](contributing.md) for the rule format.

**What about false positives?**
Each rule includes exclusion patterns to reduce false positives. For example, credential rules exclude test/example/placeholder values and environment variable references. If you encounter a false positive, you can write a custom rule with additional exclusions.

**Will hb-scan affect my AI tool?**
No. hb-scan is read-only. It reads session files but never modifies them.

**What is "Not assessed (requires LLM)"?**
Some security checks (like detecting whether code actually has a vulnerability vs. just discussing one) require semantic understanding that regex cannot provide. These rules will activate in Tier 1.2, where you can bring your own LLM API key.

## How to fix findings

Each finding in the HTML report includes specific remediation steps. The most common actions are:

1. **Rotate credentials**: If hb-scan found an API key or password, generate a new one and revoke the old one.
2. **Use environment variables**: Instead of pasting secret values, reference them by name: "Use the value from the DATABASE_URL environment variable."
3. **Exclude sensitive files**: Configure your AI tool to not access .env, .ssh, .aws, and similar directories.
4. **Verify packages**: Before installing any AI-suggested package, check that it exists on the official registry.
5. **Review commands**: Check whether privileged commands (sudo, rm -rf) were actually necessary for the task.

## Next steps

- Run `hb-scan` regularly -- after each development sprint or weekly
- Set up a pre-commit hook or CI step to scan periodically
- For organization-wide governance and policy enforcement, visit [humanbound.ai](https://humanbound.ai)
