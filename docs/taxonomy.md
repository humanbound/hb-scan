# Developer Hygiene (DH) Threat Taxonomy

Reference for the 9 threat classes scanned by hb-scan. Each class maps to international standards and contains specific detection rules.

---

## DH-01: Secret Exposure

**Category ID**: `secret_exposure`
**Severity**: High
**Score Weight**: 20 / 100

### Description

Detects credentials -- API keys, tokens, passwords, private keys -- that appear in AI tool conversations. This is the highest-impact category because a single exposed credential can lead to account compromise, data breach, or financial loss.

### What it detects

- **102 provider-specific credential patterns** covering 70+ services (AWS, GCP, Azure, GitHub, Stripe, Twilio, OpenAI, Anthropic, and many more). Sourced from gitleaks, TruffleHog, detect-secrets, and GitGuardian.
- Generic API key assignments (`api_key = "AKIAIOSFODNN7EXAMPLE"`)
- Password assignments with real values
- Bearer tokens
- JWT tokens
- SSH and PGP private keys

### Exclusions

Rules exclude test/placeholder values (`example`, `fake`, `test`, `changeme`, `your_`), environment variable references (`os.getenv`, `process.env`), and variable names that look like schema definitions.

### Standards mapping

| Standard | Control |
|----------|---------|
| OWASP LLM Top 10 2025 | LLM02 -- Sensitive Information Disclosure |
| NIST AI 600-1 | Section 2.4 -- Data Privacy, Memorisation Risks |
| ISO/IEC 42001 | A.8 -- Information and Transparency |
| ISO/IEC 27001 | A.5.14 -- Information Transfer |
| CIS Controls v8.1 | Control 3 -- Data Protection |
| MITRE ATLAS | AML.T0051.002 -- LLM Data Leakage |

### Example rules

- `aws-access-key-id`: Matches AWS keys with AKIA/ASIA/ABIA/ACCA prefix
- `github-pat`: Matches GitHub personal access tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefixes)
- `stripe-secret-key`: Matches Stripe secret keys (`sk_live_`, `sk_test_` prefixes)
- `generic-api-key`: Matches generic `api_key = "value"` patterns in user prompts
- `bearer-token`: Matches `Bearer` authorization tokens

---

## DH-02: Unsafe Code Acceptance

**Category ID**: `unsafe_code_acceptance`
**Severity**: High
**Score Weight**: 12 / 100

### Description

Detects security vulnerabilities in code generated or suggested by the AI. Research from Veracode (2025) found that 45% of AI-generated code contains OWASP Top 10 vulnerabilities. CSA reports 62% of AI-generated code has security flaws.

### What it detects

- eval() or exec() usage on untrusted input
- SQL queries built via string concatenation (SQL injection)
- Hardcoded credentials in generated code
- Command injection patterns
- Insecure deserialization
- Path traversal
- CORS misconfiguration
- Missing authentication checks
- Disabled TLS verification

### Detection note

Most rules in this category use `detection: llm` because distinguishing real vulnerabilities from discussions about security requires semantic understanding. These rules are skipped in Tier 1.1 (regex only) and will activate in Tier 1.2.

### Standards mapping

| Standard | Control |
|----------|---------|
| OWASP LLM Top 10 2025 | LLM05 -- Improper Output Handling |
| OWASP Agentic Top 10 2026 | ASI05 -- Unexpected Code Execution |
| NIST SP 800-218A | PW.4 -- Secure Coding Practices |
| ISO/IEC 42001 | A.6 -- AI System Lifecycle |
| ISO/IEC 27001 | A.8.28 -- Secure Coding |
| CIS Controls v8.1 | Control 16 -- Application Software Security |
| EU AI Act | Article 15 -- Accuracy, Robustness, Cybersecurity |

### Example rules

- `eval-exec-usage`: AI-generated code using eval()/exec() (LLM detection)
- `sql-string-concatenation`: SQL built via string concatenation (LLM detection)
- `hardcoded-secret-in-code`: Credentials embedded in generated source code
- `disabled-tls-verify`: Code that sets `verify=False` or disables SSL

---

## DH-03: Dangerous Commands

**Category ID**: `dangerous_command`
**Severity**: High
**Score Weight**: 10 / 100

### Description

Detects dangerous commands executed by the AI through its tool-use capabilities. AI tools like Claude Code can run shell commands, and without proper oversight, they may execute privileged or destructive operations.

### What it detects

- sudo usage (privileged execution)
- rm -rf on broad or system paths (/, /*, ~/, /usr, /etc, etc.)
- chmod 777 (world-writable permissions)
- Writes to system directories (/etc, /usr, /System)
- curl piped to sh/bash (remote code execution)
- Network listeners (netcat, socat binds)
- Git force-push to main/master
- Docker with --privileged flag

### Match targeting

These rules use `tool_filter: Bash` to only scan Bash tool invocations, reducing false positives from code discussions.

### Standards mapping

| Standard | Control |
|----------|---------|
| OWASP LLM Top 10 2025 | LLM06 -- Excessive Agency |
| OWASP Agentic Top 10 2026 | ASI02 -- Tool Misuse and Exploitation |
| OWASP Agentic Top 10 2026 | ASI05 -- Unexpected Code Execution |
| ISO/IEC 42001 | A.6 -- AI System Lifecycle |
| CIS Controls v8.1 | Control 4 -- Secure Configuration |
| MITRE ATLAS | Agent Tool Invocation |

### Example rules

- `sudo-usage`: Any use of sudo (excludes apt-get update/install, brew, pip)
- `rm-rf-destructive`: rm -rf targeting /, ~, /usr, /etc, /var, and other system paths
- `chmod-world-writable`: chmod 777 or chmod a+rwx
- `git-force-push-main`: git push --force to main or master

---

## DH-04: Sensitive Data Sharing

**Category ID**: `sensitive_data_sharing`
**Severity**: High
**Score Weight**: 15 / 100

### Description

Detects sensitive configuration data and secrets shared in AI conversations, beyond individual credentials. This covers entire files or connection strings that contain multiple secrets.

### What it detects

- .env file contents pasted into prompts (checks for 40+ known secret variable names)
- SSH private key files read by the AI tool
- Database connection strings with embedded passwords
- Cloud provider configuration files (.aws/credentials, .gcp/credentials)
- Certificate private keys
- Kubernetes secrets and configs

### Standards mapping

| Standard | Control |
|----------|---------|
| OWASP LLM Top 10 2025 | LLM02 -- Sensitive Information Disclosure |
| NIST AI 600-1 | Section 2.4 -- Data Privacy |
| ISO/IEC 42001 | A.7 -- Data for AI Systems |
| ISO/IEC 27001 | A.5.14 -- Information Transfer |
| ISO/IEC 27001 | A.5.33 -- Protection of Records |
| CIS Controls v8.1 | Control 3 -- Data Protection |
| MITRE ATLAS | AML.T0051.002 -- LLM Data Leakage |

### Example rules

- `env-file-contents`: .env file with real secret values shared in prompts
- `ssh-key-path-shared`: SSH private key file read by the AI tool
- `database-connection-string`: Connection URI with embedded password
- `cloud-credentials-shared`: AWS/GCP/Azure credential files accessed

---

## DH-05: Supply Chain Risk

**Category ID**: `supply_chain_risk`
**Severity**: Medium to High
**Score Weight**: 8 / 100

### Description

Detects risky package installations performed or suggested by the AI. A 2025 USENIX study found that 19.7% of AI-suggested packages are "hallucinated" -- they do not exist on official registries. Attackers can register these names and distribute malware (slopsquatting).

### What it detects

- pip install from git/URL sources (bypasses registry verification)
- npm install from git/GitHub URLs
- curl piped to pip (remote script execution)
- pip install --extra-index-url (potential dependency confusion)
- npm with --ignore-scripts disabled
- Packages from unverified registries

### Standards mapping

| Standard | Control |
|----------|---------|
| OWASP LLM Top 10 2025 | LLM03 -- Supply Chain Vulnerabilities |
| NIST SP 800-218A | PW.3 -- Supply Chain Integrity |
| CIS Controls v8.1 | Control 2 -- Inventory and Control of Software Assets |
| EU AI Act | Article 15 -- Accuracy, Robustness, Cybersecurity |

### Example rules

- `pip-install-from-url`: pip install from git+ or https:// sources
- `npm-install-from-git`: npm install from git/GitHub URLs
- `curl-pipe-to-pip`: Remote script piped to pip
- `pip-extra-index`: pip with --extra-index-url (dependency confusion risk)

---

## DH-06: Scope Violation

**Category ID**: `scope_violation`
**Severity**: Medium to High
**Score Weight**: 5 / 100

### Description

Detects cases where the AI tool accessed files or directories outside the current project scope. AI coding tools should operate within project boundaries, but they can read files from anywhere on the filesystem.

### What it detects

- Home directory config files (.bashrc, .zshrc, .npmrc, .gitconfig, .docker)
- SSH configuration and key files
- AWS credentials and config (~/.aws/)
- GCP credentials (~/.config/gcloud/)
- Kubernetes config (~/.kube/config)

### Standards mapping

| Standard | Control |
|----------|---------|
| OWASP LLM Top 10 2025 | LLM06 -- Excessive Agency |
| OWASP Agentic Top 10 2026 | ASI03 -- Identity and Privilege Abuse |
| CIS Controls v8.1 | Control 6 -- Access Control Management |
| ISO/IEC 42001 | A.5 -- Assessing Impacts |
| MITRE ATLAS | Agent Tool Invocation |

### Example rules

- `home-config-access`: AI read ~/.bashrc, ~/.npmrc, or similar config files
- `ssh-config-access`: AI read ~/.ssh/config, known_hosts, or key files
- `aws-config-access`: AI read ~/.aws/credentials or config
- `kube-config-access`: AI read ~/.kube/config

---

## DH-07: IP and Trade Secret Leakage

**Category ID**: `ip_trade_secret_leakage`
**Severity**: High
**Score Weight**: 15 / 100

### Description

Detects intellectual property and trade secrets shared with AI tools. Under the Defend Trade Secrets Act (18 U.S.C. 1836), sharing trade secrets with a public AI service may destroy their legal protection. A 2024 Cisco study found that 48% of organizations enter non-public company information into generative AI tools.

### What it detects

- Content with CONFIDENTIAL, PROPRIETARY, TRADE SECRET, or UNDER NDA markings
- Financial metrics with real values (revenue, profit, EBITDA with dollar amounts)
- Internal infrastructure URLs (staging, dev, internal subdomains)
- Customer lists and deal data
- Patent-pending technical details

### Standards mapping

| Standard | Control |
|----------|---------|
| ISO/IEC 42001 | A.8 -- Information and Transparency |
| ISO/IEC 27001 | A.5.14 -- Information Transfer |
| CIS Controls v8.1 | Control 3 -- Data Protection |
| MITRE ATLAS | AML.T0024 -- Exfiltration via ML Inference API |
| Defend Trade Secrets Act | 18 U.S.C. 1836 |

### Example rules

- `confidential-keyword`: Content with CONFIDENTIAL/PROPRIETARY markings (LLM detection)
- `financial-data-sharing`: Revenue, profit, or EBITDA with dollar amounts
- `internal-url-sharing`: Internal/staging/dev infrastructure URLs
- `customer-data-sharing`: Customer lists or deal details

---

## DH-08: Regulatory Data Exposure

**Category ID**: `regulatory_data_exposure`
**Severity**: High
**Score Weight**: 15 / 100

### Description

Detects regulated personal data shared with AI tools. This includes data protected by GDPR, HIPAA, PCI-DSS, and other regulations. Italy fined OpenAI EUR 15 million for GDPR violations in 2024. Most public AI tools do not have the required data processing agreements for handling regulated data.

### What it detects

- GDPR personal data (names with email, phone, address, date of birth, national ID)
- HIPAA protected health information (patient data, diagnoses, prescriptions)
- PCI cardholder data (credit card numbers, CVVs)
- FERPA educational records
- CCPA consumer personal information
- SOX financial records

### Detection note

Most rules in this category use `detection: llm` because identifying real personal data (vs. test data, examples, or discussions about privacy) requires semantic understanding. These rules are skipped in Tier 1.1 and will activate in Tier 1.2.

### Standards mapping

| Standard | Control |
|----------|---------|
| NIST AI 600-1 | Section 2.4 -- Data Privacy |
| ISO/IEC 42001 | A.7 -- Data for AI Systems |
| ISO/IEC 27001 | A.5.33 -- Protection of Records |
| GDPR | Article 5(1)(c) -- Data Minimization |
| HIPAA | BAA Requirement |
| PCI-DSS | Requirement 3 -- Protect Stored Cardholder Data |

### Example rules

- `gdpr-personal-data`: Real personal data of real individuals (LLM detection)
- `hipaa-health-data`: Protected health information with patient identifiers (LLM detection)
- `pci-card-number`: Credit card numbers matching Luhn algorithm
- `ssn-pattern`: Social Security Number patterns

---

## DH-09: Excessive Reliance / Low Oversight

**Category ID**: `excessive_reliance`
**Severity**: Info
**Score Weight**: 0 / 100 (informational only, does not reduce score)

### Description

Detects sessions where the AI operated with minimal human oversight. This is an informational category designed to raise awareness about automation bias. Research shows that 88% of AI-generated code suggestions are accepted without modification (GitHub/Accenture 2024). Courts have held organizations liable for AI-generated outputs (Air Canada chatbot case, Mata v. Avianca).

### What it detects

- Auto-pilot sessions: 50+ tool executions with fewer than 3 substantive user messages
- This indicates the AI was executing commands in a largely autonomous fashion

### Detection method

This category uses a `session_heuristic` match type instead of regex. It evaluates session-level statistics rather than text patterns.

### Standards mapping

| Standard | Control |
|----------|---------|
| OWASP LLM Top 10 2025 | LLM09 -- Misinformation (Overreliance) |
| EU AI Act | Article 14 -- Human Oversight |
| NIST AI RMF | Measure 2.8 -- Human Oversight Statistics |
| ISO/IEC 42001 | A.5 -- Assessing Impacts |
| Mata v. Avianca | Lawyers sanctioned for citing AI-hallucinated cases |
| Air Canada chatbot | Company held liable for AI chatbot's fabricated policy |

### Example rules

- `auto-pilot-session`: Session with 50+ tool executions and fewer than 3 user messages

---

## Summary table

| ID | Category | Weight | Severity | Detection | Rule Count |
|----|----------|--------|----------|-----------|-----------|
| DH-01 | Secret Exposure | 20 | High | Regex | 105 |
| DH-02 | Unsafe Code | 12 | High | Mostly LLM | 9 |
| DH-03 | Dangerous Commands | 10 | High | Regex | 8 |
| DH-04 | Sensitive Data | 15 | High | Regex + LLM | 7 |
| DH-05 | Supply Chain | 8 | Medium-High | Regex | 6 |
| DH-06 | Scope Violation | 5 | Medium-High | Regex | 5 |
| DH-07 | IP / Trade Secrets | 15 | High | Regex + LLM | 5 |
| DH-08 | Regulatory Data | 15 | High | Mostly LLM | 6 |
| DH-09 | Oversight | 0 | Info | Heuristic | 1 |
| | **Total** | **100** | | | **152** |
