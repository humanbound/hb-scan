"""Scan progress messages — keeps the user engaged while scanning."""

import random

DISCOVERING = [
    "Searching for AI tool footprints...",
    "Checking your digital workspace...",
    "Looking for AI conversations...",
    "Scanning for AI tool data...",
    "Hunting for session histories...",
]

SCANNING = [
    "Analysing conversations for secrets...",
    "Checking for credential exposure...",
    "Looking for leaked API keys...",
    "Scanning for sensitive data patterns...",
    "Reviewing AI-generated code security...",
    "Checking command safety...",
    "Verifying package integrity...",
    "Analysing oversight patterns...",
    "Cross-referencing compliance frameworks...",
    "Running 139 security checks...",
]

SCORING = [
    "Calculating your AI hygiene score...",
    "Mapping findings to compliance frameworks...",
    "Crunching the numbers...",
    "Assessing your AI usage patterns...",
    "Evaluating compliance alignment...",
]

DONE_CLEAN = [
    "Looking good! Your AI hygiene is solid.",
    "Clean scan! Keep up the good practices.",
    "No major issues found. Well done!",
    "Your AI usage looks healthy.",
]

DONE_ISSUES = [
    "Found a few things to look at.",
    "Some items need your attention.",
    "Review complete — see findings below.",
    "A few opportunities to improve.",
]

TIPS = [
    "Tip: Use environment variables instead of pasting secrets into AI prompts.",
    "Tip: Run 'hb-scan --llm' to enable deeper regulatory data analysis.",
    "Tip: 19.7% of AI-suggested packages are hallucinated (USENIX 2025).",
    "Tip: 62% of AI-generated code contains security flaws (CSA 2025).",
    "Tip: GitGuardian found AI-assisted commits leak secrets at 2x the baseline rate.",
    "Tip: The EU AI Act requires human oversight awareness for AI tool users.",
    "Tip: Configure your AI tools with file exclusion patterns for .env files.",
    "Tip: Review AI-generated code like you'd review a junior developer's PR.",
]


def pick(category: list) -> str:
    return random.choice(category)
