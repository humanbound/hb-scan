"""Rich terminal report — insight-based summary."""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from hb_scan.insights import ScanInsights


_GRADE_COLORS = {
    "A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red",
}


def print_report(insights: ScanInsights, console: Console = None):
    """Print insight-based terminal summary."""
    if console is None:
        console = Console()

    c = console
    c.print()

    # Header
    c.print(Panel(
        f"[bold cyan]hb-scan[/bold cyan] — AI Hygiene Report\n"
        f"[dim]{insights.scan_period}[/dim]",
        border_style="cyan",
    ))

    # Usage overview
    c.print(f"  Tool: [bold]{insights.tool_display_name or insights.tool_name}[/bold]")
    c.print(f"  Sessions scanned: [bold]{insights.sessions_scanned}[/bold]")
    c.print()

    # Credential exposure
    creds = insights.credentials
    if creds.total_unique > 0:
        if creds.active_count > 0:
            c.print(f"  [red]⚠[/red]  [bold]Credential Exposure[/bold]")
            c.print(f"     {creds.total_unique} unique credential(s) found in conversations")
            c.print(f"     [red]→ {creds.active_count} may still be active[/red] (action needed)")
            if creds.expired_count > 0:
                c.print(f"     [dim]→ {creds.expired_count} expired (no action needed)[/dim]")
        else:
            c.print(f"  [yellow]○[/yellow]  [bold]Credential Exposure[/bold]")
            c.print(f"     {creds.total_unique} credential(s) found, all expired or test values")
        # Type breakdown
        if creds.by_type:
            types_str = ", ".join(f"{v}x {k}" for k, v in sorted(creds.by_type.items(), key=lambda x: -x[1]))
            c.print(f"     [dim]Types: {types_str}[/dim]")
    else:
        c.print(f"  [green]✓[/green]  [bold]Credential Exposure[/bold] — No credentials detected")
    c.print()

    # Sensitive data
    _print_section(c, "Sensitive Data", insights.sensitive_data)

    # Code security
    _print_section(c, "Code Security", insights.code_security)

    # Commands
    _print_section(c, "Commands", insights.commands)

    # Packages
    _print_section(c, "Package Safety", insights.packages)

    # IP leakage
    _print_section(c, "IP / Trade Secret", insights.ip_leakage)

    # Regulatory
    reg = insights.regulatory
    if reg.finding_count > 0:
        c.print(f"  [red]⚠[/red]  [bold]Regulatory Data[/bold] — {reg.finding_count} potential finding(s)")
        for d in reg.details[:3]:
            c.print(f"     [dim]→ {d}[/dim]")
    else:
        if insights.rules_skipped_llm > 0:
            c.print(f"  [dim]◌[/dim]  [bold]Regulatory Data[/bold] — requires LLM judge (run with --llm)")
        else:
            c.print(f"  [green]✓[/green]  [bold]Regulatory Data[/bold] — No regulated data detected")
    c.print()

    # Oversight
    ov = insights.oversight
    hoi_score = round(1.0 - ov.auto_pilot_rate, 2)
    if ov.auto_pilot_sessions > 0:
        c.print(f"  [yellow]○[/yellow]  [bold]Human Oversight Index[/bold] — HOI {hoi_score}")
        c.print(f"     {ov.auto_pilot_sessions} of {ov.total_sessions} sessions ran with minimal oversight")
    else:
        c.print(f"  [green]✓[/green]  [bold]Human Oversight Index[/bold] — HOI {hoi_score}")
    c.print()

    # Score
    gc = _GRADE_COLORS.get(insights.grade, "white")
    c.print(Panel(
        f"[{gc}]{insights.score}/100 (Grade {insights.grade})[/{gc}]",
        title="HYGIENE SCORE",
        border_style=gc.replace("bold ", ""),
        padding=(0, 2),
    ))

    # Penalty breakdown (if any)
    if insights.penalty_breakdown:
        parts = []
        for section, pts in sorted(insights.penalty_breakdown.items(), key=lambda x: -x[1]):
            if pts > 0:
                parts.append(f"{section}: -{pts}")
        if parts:
            c.print(f"  [dim]Penalty: {', '.join(parts)}[/dim]")

    # Rule coverage
    c.print()
    if insights.rules_skipped_llm > 0:
        c.print(f"  [dim]Rules: {insights.rules_active}/{insights.rules_total} active ({insights.rules_skipped_llm} require LLM judge)[/dim]")
    else:
        c.print(f"  [dim]Rules: {insights.rules_active}/{insights.rules_total} active[/dim]")

    # Random tip
    from hb_scan import messages
    c.print()
    c.print(f"  [dim italic]{messages.pick(messages.TIPS)}[/dim italic]")
    c.print()


def _print_section(c: Console, name: str, section):
    """Print a check section status line."""
    if section.clean:
        c.print(f"  [green]✓[/green]  [bold]{name}[/bold] — Clean")
    else:
        c.print(f"  [red]⚠[/red]  [bold]{name}[/bold] — {section.finding_count} finding(s)")
        for d in section.details[:3]:
            c.print(f"     [dim]→ {d}[/dim]")
        if len(section.details) > 3:
            c.print(f"     [dim]→ ...and {len(section.details) - 3} more (see full report)[/dim]")
    c.print()
