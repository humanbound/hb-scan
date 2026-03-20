"""hb-scan CLI — AI session security scanner."""

import sys
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from hb_scan import __version__
from hb_scan.discover import discover_all, get_discoverers
from hb_scan.rules import RuleEngine
from hb_scan.enrichments import enrich_findings
from hb_scan.insights import aggregate_findings
from hb_scan import messages
from hb_scan.report.terminal import print_report
from hb_scan.report.json_report import generate_json
from hb_scan.report.html import generate_html
from hb_scan.history import save_scan, load_history, get_latest_report, get_trend
from hb_scan.telemetry.anonymous import send_ping


console = Console()


def _parse_since(since: Optional[str]) -> Optional[datetime]:
    """Parse --since flag (e.g., '7d', '30d', '24h')."""
    if not since:
        return None
    since = since.strip().lower()
    try:
        if since.endswith("d"):
            return datetime.now(timezone.utc) - timedelta(days=int(since[:-1]))
        elif since.endswith("h"):
            return datetime.now(timezone.utc) - timedelta(hours=int(since[:-1]))
    except ValueError:
        pass
    raise click.BadParameter(f"Invalid --since format: {since}. Use '7d' or '24h'.")


def _format_period(since_dt: Optional[datetime]) -> str:
    """Format scan period for display."""
    now = datetime.now(timezone.utc)
    if since_dt:
        return f"{since_dt.strftime('%b %d')} — {now.strftime('%b %d, %Y')}"
    return f"All history through {now.strftime('%b %d, %Y')}"


@click.group(invoke_without_command=True)
@click.option("--tool", default=None, help="Scan specific tool only (e.g., claude-code)")
@click.option("--since", default=None, help="Scan sessions from last N days/hours (e.g., 7d, 24h)")
@click.option("--project", default=None, help="Scan specific project path only")
@click.option("--rules", "rules_dir", default=None, type=click.Path(exists=True), help="Additional rules directory")
@click.option("--output", "output_file", default=None, type=click.Path(), help="Write HTML report to file")
@click.option("--format", "output_format", default="terminal", type=click.Choice(["terminal", "json"]),
              help="Output format (terminal summary or JSON)")
@click.option("--no-telemetry", is_flag=True, help="Disable anonymous telemetry")
@click.option("--version", is_flag=True, help="Show version")
@click.pass_context
def main(ctx, tool, since, project, rules_dir, output_file, output_format, no_telemetry, version):
    """hb-scan — AI Session Security Scanner

    Scans local AI tool sessions for security risks and produces an AI hygiene report.

    \b
    Quick start:
      hb-scan                          # Scan and show terminal summary
      hb-scan --output report.html     # Generate detailed HTML report
      hb-scan --since 7d               # Last 7 days only
      hb-scan --format json            # Machine-readable output
      hb-scan schedule daily           # Schedule periodic scans
      hb-scan history                  # View score history
    """
    if version:
        click.echo(f"hb-scan {__version__}")
        return

    if ctx.invoked_subcommand is not None:
        return

    # Parse time filter
    since_dt = _parse_since(since)
    scan_period = _format_period(since_dt)

    # Discover sessions
    console.print()
    console.print("[bold cyan]hb-scan[/bold cyan] v" + __version__, style="dim")
    console.print()

    # Discover
    console.print(f"  [dim]\\[1/4] {messages.pick(messages.DISCOVERING)}[/dim]")
    sessions_by_tool = discover_all(
        tool_filter=tool,
        since=since_dt,
        project_filter=project,
    )

    all_sessions = [s for sessions in sessions_by_tool.values() for s in sessions]

    if not all_sessions:
        console.print("[yellow]  No AI tool sessions found.[/yellow]")
        console.print("[dim]  Supported tools: " + ", ".join(d.display_name for d in get_discoverers()) + "[/dim]")
        return

    # Determine primary tool info
    tool_name = list(sessions_by_tool.keys())[0] if sessions_by_tool else ""
    tool_display = ""
    for d in get_discoverers():
        if d.name == tool_name:
            tool_display = d.display_name
            break

    console.print(f"  [green]✓[/green] Found {len(all_sessions)} sessions ({tool_display})")

    # Load rules
    extra_dirs = [Path(rules_dir)] if rules_dir else []
    engine = RuleEngine(rules_dirs=extra_dirs)

    # Scan
    console.print(f"  [dim]\\[2/4] {messages.pick(messages.SCANNING)}[/dim]")
    findings = engine.scan_all(all_sessions)

    # Enrich
    console.print(f"  [dim]\\[3/4] {messages.pick(messages.SCORING)}[/dim]")
    findings = enrich_findings(findings)

    # Aggregate
    console.print(f"  [dim]\\[4/4] Building your report...[/dim]")
    insights = aggregate_findings(
        findings,
        sessions_scanned=len(all_sessions),
        tool_name=tool_name,
        tool_display_name=tool_display,
        scan_period=scan_period,
        rules_active=len(engine.active_rules),
        rules_total=len(engine.rules),
        rules_skipped_llm=len(engine.skipped_llm_rules),
    )

    # Quick result message
    if insights.credentials.active_count == 0 and all(
        s.clean for s in [insights.sensitive_data, insights.code_security,
                          insights.commands, insights.packages, insights.ip_leakage]
    ):
        console.print(f"  [green]✓[/green] {messages.pick(messages.DONE_CLEAN)}")
    else:
        console.print(f"  [yellow]○[/yellow] {messages.pick(messages.DONE_ISSUES)}")
    console.print()

    # Output
    if output_format == "json":
        from hb_scan.models.posture import PostureScore
        posture = PostureScore(
            score=insights.score, grade=insights.grade, risk_level=insights.risk_level,
            total_findings=len(findings), total_penalty=sum(insights.penalty_breakdown.values()),
            rules_active=insights.rules_active, rules_total=insights.rules_total,
            rules_skipped_llm=insights.rules_skipped_llm,
        )
        json_str = generate_json(findings, posture, {tool_name: len(all_sessions)})
        if output_file:
            Path(output_file).write_text(json_str)
            console.print(f"  JSON report: {output_file}")
        else:
            click.echo(json_str)
    else:
        # Terminal summary
        print_report(insights, console)

    # Generate HTML and save to history
    html_str = generate_html(insights)
    report_path = save_scan(insights, html_str)

    # Also write to explicit output or cwd if requested
    if output_file and output_format != "json":
        Path(output_file).write_text(html_str)
        console.print(f"  [dim]Report: {output_file}[/dim]")
    elif output_format == "terminal":
        console.print(f"  [dim]Report: {report_path}[/dim]")

    # Show trend if we have history
    trend = get_trend()
    if trend:
        console.print(f"  [dim]Trend: {trend}[/dim]")

    console.print(f"  [dim]History: hb-scan history[/dim]")
    console.print()

    # Telemetry
    if not no_telemetry:
        send_ping({
            "tools_found": list(sessions_by_tool.keys()),
            "session_count": len(all_sessions),
            "finding_count": len(findings),
            "categories_triggered": list(insights.penalty_breakdown.keys()),
            "score": insights.score,
        })


@main.command()
def discover():
    """List discovered AI tools and session counts."""
    console.print()
    console.print("[bold]Discovered AI Tools[/bold]")
    console.print()

    for d in get_discoverers():
        if d.is_installed():
            sessions = d.discover_sessions()
            console.print(f"  [green]✓[/green] {d.display_name}: {len(sessions)} sessions")
        else:
            console.print(f"  [dim]✗ {d.display_name}: not found[/dim]")
    console.print()


@main.command()
@click.argument("path", required=False, type=click.Path(exists=True))
def rules(path):
    """List available rules, or validate a custom rules directory."""
    extra_dirs = [Path(path)] if path else []
    engine = RuleEngine(rules_dirs=extra_dirs)

    console.print()
    console.print(f"[bold]Rules ({len(engine.rules)} total)[/bold]")
    console.print()

    by_cat = {}
    for r in engine.rules:
        by_cat.setdefault(r.category, []).append(r)

    for cat in sorted(by_cat.keys()):
        rules_list = by_cat[cat]
        active = [r for r in rules_list if r.is_runnable_regex()]
        llm_only = [r for r in rules_list if not r.is_runnable_regex()]

        status = "[green]✓[/green]" if len(active) == len(rules_list) else "[yellow]~[/yellow]"
        console.print(f"  {status} {cat}: {len(active)}/{len(rules_list)} rules active")

        if llm_only:
            for r in llm_only:
                console.print(f"      [dim]⊘ {r.id} (requires LLM judge)[/dim]")

    skipped = engine.skipped_llm_rules
    if skipped:
        console.print()
        console.print(f"  [dim]{len(skipped)} rules require LLM judge — run with --llm to enable[/dim]")
    console.print()


@main.command()
@click.option("--open", "open_latest", is_flag=True, help="Open the latest HTML report in browser")
@click.option("--last", "last_n", default=10, help="Number of entries to show (default: 10)")
def history(open_latest, last_n):
    """View scan history and score trends."""
    if open_latest:
        report = get_latest_report()
        if report:
            webbrowser.open(f"file://{report}")
            console.print(f"  Opened: {report}")
        else:
            console.print("[yellow]  No scan history found. Run hb-scan first.[/yellow]")
        return

    entries = load_history()
    if not entries:
        console.print()
        console.print("[yellow]  No scan history found. Run hb-scan first.[/yellow]")
        console.print()
        return

    console.print()
    console.print("[bold]hb-scan — Score History[/bold]")
    console.print()

    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
    table.add_column("Date", style="dim")
    table.add_column("Score", justify="right")
    table.add_column("Grade", justify="center")
    table.add_column("Findings", justify="right")
    table.add_column("HOI", justify="right")
    table.add_column("Creds", justify="right")
    table.add_column("Sessions", justify="right", style="dim")

    recent = entries[-last_n:]
    for e in reversed(recent):
        score = e["score"]
        grade = e["grade"]
        grade_color = "green" if grade in ("A", "B") else ("yellow" if grade == "C" else "red")
        table.add_row(
            e.get("date_short", ""),
            str(score),
            f"[{grade_color}]{grade}[/{grade_color}]",
            str(e.get("findings", 0)),
            str(e.get("hoi", "")),
            str(e.get("active_creds", 0)),
            str(e.get("sessions", "")),
        )

    console.print(table)

    trend = get_trend()
    if trend:
        console.print(f"\n  [dim]Trend: {trend}[/dim]")

    latest = get_latest_report()
    if latest:
        console.print(f"  [dim]Latest report: {latest}[/dim]")
        console.print(f"  [dim]Open it: hb-scan history --open[/dim]")

    console.print()


@main.command()
@click.argument("interval", default="daily",
                type=click.Choice(["hourly", "4h", "8h", "12h", "daily", "weekly"]))
def schedule(interval):
    """Schedule periodic scans.

    \b
    Intervals: hourly, 4h, 8h, 12h, daily, weekly
    Uses launchd (macOS) or systemd (Linux).
    """
    from hb_scan.scheduler import install, is_installed

    console.print()
    if is_installed():
        console.print("  [yellow]A schedule is already installed.[/yellow]")
        console.print("  [dim]Run 'hb-scan unschedule' to remove it first.[/dim]")
        console.print()
        return

    result = install(interval)
    console.print(f"  [green]✓[/green] {result}")
    console.print()
    console.print("  [dim]Reports saved to: ~/.hb-scan/reports/[/dim]")
    console.print("  [dim]View history: hb-scan history[/dim]")
    console.print("  [dim]Remove: hb-scan unschedule[/dim]")
    console.print()


@main.command()
def unschedule():
    """Remove scheduled periodic scans."""
    from hb_scan.scheduler import uninstall, is_installed

    console.print()
    if not is_installed():
        console.print("  [dim]No schedule installed.[/dim]")
        console.print()
        return

    result = uninstall()
    console.print(f"  [green]✓[/green] {result}")
    console.print()


if __name__ == "__main__":
    main()
