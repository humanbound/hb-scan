"""Branded HTML report generator for hb-scan.

Produces a single-file, self-contained HTML report with inline CSS and SVG
graphics. Uses Humanbound brand identity (#1E2323 dark, #FD9506 orange).
Progressive disclosure: scroll down for more detail.
"""

from datetime import datetime, timezone
import html as _html

from hb_scan.insights import ScanInsights, SectionStatus


# ---------------------------------------------------------------------------
# CSS — matches the branded template
# ---------------------------------------------------------------------------

_CSS = """<style>
  :root {
    --brand-dark: #1E2323;
    --brand-orange: #FD9506;
    --brand-orange-light: #FFF3E0;
    --bg: #ffffff;
    --surface: #f8f9fb;
    --surface-alt: #f0f2f5;
    --border: #e1e4e8;
    --border-light: #eef0f4;
    --text: #1f2328;
    --text-muted: #656d76;
    --text-dim: #8b949e;
    --green: #1a7f37;
    --green-bg: #dafbe1;
    --yellow: #9a6700;
    --yellow-bg: #fff8c5;
    --red: #cf222e;
    --red-bg: #ffebe9;
    --orange: #bc4c00;
    --orange-bg: #fff1e5;
  }
  @media print {
    body { padding: 20px; }
    .cover-bar { break-after: page; }
    .no-print { display: none; }
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', Helvetica, Arial, sans-serif;
    color: var(--text); line-height: 1.6; background: var(--bg);
  }
  .container { max-width: 960px; margin: 0 auto; padding: 0 40px; }

  /* Cover bar */
  .cover-bar {
    background: var(--brand-dark);
    color: #fff;
    padding: 48px 0 40px;
    margin-bottom: 0;
  }
  .cover-inner { max-width: 960px; margin: 0 auto; padding: 0 40px; display: flex; align-items: center; justify-content: space-between; }
  .cover-left { display: flex; align-items: center; gap: 20px; }
  .cover-logo svg { height: 36px; }
  .cover-title { font-size: 13px; letter-spacing: 3px; text-transform: uppercase; color: var(--brand-orange); font-weight: 700; }
  .cover-subtitle { font-size: 26px; font-weight: 700; margin-top: 4px; color: #fff; }
  .cover-right { text-align: right; font-size: 13px; color: rgba(255,255,255,0.6); line-height: 1.8; }
  .cover-right strong { color: rgba(255,255,255,0.9); }

  /* Score hero */
  .score-hero-wrap {
    background: linear-gradient(135deg, var(--brand-dark) 0%, #2a3030 100%);
    padding: 0 0 48px;
    margin-bottom: 40px;
  }
  .score-hero {
    max-width: 960px; margin: 0 auto; padding: 0 40px;
    display: flex; align-items: center; gap: 48px;
  }
  .score-ring-wrap { position: relative; flex-shrink: 0; }
  .score-ring-text {
    position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
    text-align: center;
  }
  .score-ring-grade { font-size: 48px; font-weight: 800; color: #fff; line-height: 1; }
  .score-ring-num { font-size: 14px; color: rgba(255,255,255,0.6); margin-top: 2px; }
  .score-stats { display: flex; gap: 40px; }
  .score-stat { text-align: center; }
  .score-stat-val { font-size: 28px; font-weight: 700; color: #fff; }
  .score-stat-label { font-size: 12px; color: rgba(255,255,255,0.5); text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }

  /* Quick status */
  .status-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 40px; }
  .status-card {
    background: var(--surface); border-radius: 10px; padding: 16px 18px;
    border: 1px solid var(--border-light); display: flex; align-items: center; gap: 12px;
    transition: box-shadow 0.2s;
  }
  .status-card:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
  .status-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .dot-green { background: var(--green); }
  .dot-orange { background: var(--brand-orange); }
  .dot-red { background: var(--red); }
  .dot-grey { background: var(--text-dim); }
  .status-card-label { font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
  .status-card-value { font-size: 13px; color: var(--text); margin-top: 2px; }

  /* Sections */
  .section { margin-bottom: 40px; }
  .section-header {
    display: flex; align-items: center; gap: 12px;
    margin-bottom: 16px; padding-bottom: 12px; border-bottom: 2px solid var(--brand-orange);
  }
  .section-header h2 { font-size: 20px; font-weight: 700; }
  .section-badge {
    display: inline-block; padding: 3px 12px; border-radius: 20px;
    font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
  }
  .badge-pass { background: var(--green-bg); color: var(--green); }
  .badge-fail { background: var(--orange-bg); color: var(--orange); }
  .badge-info { background: var(--surface-alt); color: var(--text-dim); }
  .section-desc { font-size: 14px; color: var(--text-muted); margin-bottom: 16px; line-height: 1.7; }
  .section-refs { font-size: 12px; color: var(--text-dim); margin-top: 12px; }

  /* Tables */
  table { width: 100%; border-collapse: collapse; font-size: 14px; margin: 12px 0; }
  th { text-align: left; padding: 10px 12px; background: var(--surface); border-bottom: 2px solid var(--border);
    font-weight: 600; font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 10px 12px; border-bottom: 1px solid var(--border-light); vertical-align: middle; }
  tr:hover { background: var(--surface); }

  /* Badges */
  .sev-badge { display: inline-block; padding: 2px 10px; border-radius: 4px; font-weight: 600; font-size: 11px; text-transform: uppercase; }
  .sev-high { background: var(--orange-bg); color: var(--orange); }
  .sev-medium { background: var(--yellow-bg); color: var(--yellow); }
  .sev-low { background: var(--surface-alt); color: var(--text-dim); }
  .sev-pass { background: var(--green-bg); color: var(--green); }

  /* Finding cards */
  .finding-card {
    background: var(--surface); border-radius: 10px; padding: 20px;
    margin-bottom: 12px; border-left: 4px solid var(--brand-orange);
  }
  .finding-card .finding-title { font-weight: 600; font-size: 14px; margin-bottom: 6px; }
  .finding-card .finding-meta { font-size: 13px; color: var(--text-muted); margin-bottom: 10px; }
  .evidence-block {
    background: var(--brand-dark); color: #e6edf3; border-radius: 8px; padding: 14px 16px;
    font-family: 'SF Mono', 'Fira Code', Consolas, monospace; font-size: 13px; line-height: 1.5;
    margin: 10px 0; max-height: 140px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;
  }
  .remediation-block {
    background: var(--green-bg); border-radius: 8px; padding: 12px 16px;
    font-size: 13px; margin-top: 10px; line-height: 1.6;
  }
  .remediation-block strong { color: var(--green); }

  /* Compliance tags */
  .compliance-tags { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
  .tag {
    display: inline-block; background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; padding: 2px 8px; font-size: 11px; color: var(--text-muted);
  }

  /* Compliance framework cards */
  .fw-card {
    background: var(--surface); border-radius: 12px; padding: 24px;
    margin-bottom: 16px; border: 1px solid var(--border-light);
  }
  .fw-header { display: flex; align-items: center; gap: 20px; margin-bottom: 16px; }
  .fw-name { font-size: 16px; font-weight: 700; }
  .fw-meta { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
  .fw-url { font-size: 12px; color: var(--brand-orange); text-decoration: none; }
  .fw-url:hover { text-decoration: underline; }

  /* Progress bars */
  .progress-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .progress-label { width: 160px; font-size: 13px; font-weight: 600; text-align: right; flex-shrink: 0; }
  .progress-track { flex: 1; height: 22px; background: var(--surface-alt); border-radius: 11px; overflow: hidden; }
  .progress-fill {
    height: 100%; border-radius: 11px;
    display: flex; align-items: center; justify-content: flex-end; padding-right: 10px;
    font-size: 11px; font-weight: 700; color: #fff; min-width: 44px;
    transition: width 0.5s ease;
  }

  /* Recommendation cards */
  .rec-card {
    background: var(--surface); border-radius: 10px; padding: 18px 20px;
    margin-bottom: 10px; border-left: 4px solid var(--brand-orange);
    display: flex; justify-content: space-between; align-items: start; gap: 16px;
  }
  .rec-card .rec-title { font-weight: 600; font-size: 14px; margin-bottom: 4px; }
  .rec-card .rec-desc { font-size: 13px; color: var(--text-muted); line-height: 1.6; }
  .rec-priority {
    display: inline-block; padding: 3px 12px; border-radius: 4px;
    font-size: 11px; font-weight: 700; text-transform: uppercase; white-space: nowrap; flex-shrink: 0;
  }
  .priority-high { background: var(--orange-bg); color: var(--orange); }
  .priority-medium { background: var(--yellow-bg); color: var(--yellow); }

  /* HOI section */
  .hoi-hero {
    background: var(--surface); border-radius: 12px; padding: 28px 32px;
    display: flex; align-items: center; gap: 32px; margin-bottom: 16px;
    border: 1px solid var(--border-light);
  }
  .hoi-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }

  /* Risk callout */
  .callout {
    background: var(--surface); border-left: 4px solid var(--brand-orange);
    padding: 16px 20px; border-radius: 0 10px 10px 0;
    font-size: 14px; line-height: 1.7; color: var(--text-muted); margin: 16px 0;
  }
  .callout-green { border-left-color: var(--green); }

  /* Footer */
  .footer-bar {
    background: var(--brand-dark); color: rgba(255,255,255,0.5);
    padding: 24px 0; text-align: center; font-size: 13px; margin-top: 48px;
  }
  .footer-bar a { color: var(--brand-orange); text-decoration: none; }
</style>"""


# ---------------------------------------------------------------------------
# Inline SVG helpers
# ---------------------------------------------------------------------------

_BRAND_LOGO = """<svg viewBox="240 670 170 150" style="height:40px;" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path fill="#FD9506" d="M273.128,685.417c11.235,19.438,22.453,38.878,33.676,58.317c1.187,2.056,1.801,4.089,1.829,6.168
    c0.028,2.097-0.543,4.136-1.725,6.184l-7.389,12.798l-0.005-0.003c-8.671,15.021-17.338,30.043-26.01,45.063
    c-0.804,1.392-0.377,2.44,1.186,2.44h12.175h14.079c3.536,0,4.632-0.713,6.412-3.797c8.784-15.215,17.563-30.42,26.342-45.626
    c2.916-5.052,6.959-10.088,13.297-10.097c6.41-0.008,10.406,5.068,13.308,10.096l7.762,13.443c1.236,2.141,2.05,2.415,3.498,2.415
    h27.96c1.736,0,2.223-1.341,1.533-2.536l-6.582-11.399v-0.012l-8.002-13.859c-1.094-1.896-1.61-3.452-1.573-5.151
    c0.047-2.154,0.948-3.79,1.974-5.568c4.729-8.192,9.453-16.384,14.183-24.577c0.953-1.651,0.387-2.537-1.161-2.537h-28.785
    c-1.749,0-1.762,0.192-2.853,2.082l-8.605,14.904c-3.772,6.535-6.525,8.96-12.66,8.943c-5.744-0.014-9.954-4.274-12.65-8.943
    c-8.996-15.581-18.324-30.967-26.979-46.741c-1.713-3.123-2.888-3.81-6.419-3.81h-26.254
    C273.075,683.615,272.216,683.839,273.128,685.417"/>
  <path fill="rgba(255,255,255,0.9)" d="M265.614,688.634c-4.361,7.549-8.718,15.1-13.079,22.653
    c-0.709,1.228-1.403,2.651-1.349,4.106c0.062,1.643,1.018,3.311,1.826,4.711l14.866,25.748c1.421,2.462,1.417,5.841-0.003,8.301
    l-14.625,25.328c-0.899,1.557-1.997,3.351-2.063,5.125c-0.054,1.455,0.64,2.879,1.349,4.106c4.371,7.572,8.74,15.149,13.112,22.723
    c0.622,1.077,1.737,1.05,2.464-0.208c11.192-19.386,22.383-38.769,33.576-58.155c0.554-0.959,0.933-1.971,0.918-3.089
    c-0.016-1.16-0.449-2.242-1.022-3.235c-11.222-19.438-22.429-38.886-33.672-58.311
    C266.864,686.628,266.474,687.146,265.614,688.634"/>
  <path fill="rgba(255,255,255,0.9)" d="M346.257,687.826l-15.852,27.456c3.046,5.285,6.106,10.579,9.16,15.865
    c1.466,2.538,4.12,5.926,7.441,5.935c3.305,0.008,5.967-3.418,7.42-5.935c2.712-4.694,5.422-9.379,8.134-14.076
    c0.952-1.65,0.971-1.884,0.078-3.431l-15.004-25.989C347.317,687.102,346.714,687.02,346.257,687.826"/>
  <path fill="rgba(255,255,255,0.9)" d="M346.257,812.174l-15.852-27.456l9.16-15.866c0.791-1.368,1.821-2.822,3.058-3.95
    c3.296-3.013,6.545-2.429,9.45,0.695c0.927,0.998,1.717,2.152,2.354,3.256c2.712,4.693,5.422,9.379,8.134,14.075
    c0.952,1.65,0.971,1.885,0.078,3.432l-15.004,25.989C347.317,812.898,346.714,812.98,346.257,812.174"/>
  <path fill="rgba(255,255,255,0.9)" d="M352.976,684.848l6.675,11.563l6.324,10.953c1.182,2.046,2.543,3.716,5.134,3.716h28.187
    c1.158,0,1.551-0.59,0.947-1.638c-4.09-7.085-8.173-14.169-12.264-21.254c-1.133-1.963-2.143-3.125-3.337-3.739
    c-1.24-0.638-2.956-0.833-5.427-0.833H367.04h-13.372C352.792,683.615,352.531,684.078,352.976,684.848z"/>
  <path fill="rgba(255,255,255,0.9)" d="M366.727,791.347c-4.644,8.043-9.2,15.923-13.843,23.966c-0.302,0.522-0.053,1.072,0.511,1.072
    h25.364h0.456c2.5,0,4.998-0.03,6.858-1.922c4.153-7.193,8.3-14.387,12.453-21.581c0.34-0.589,0.072-1.302-1.141-1.302H371.11
    C369.432,788.92,367.639,789.95,366.727,791.347z"/>
</svg>"""


def _render_evidence(evidence: list) -> str:
    """Render conversation evidence as a chat-style block."""
    if not evidence:
        return ""

    turns = []
    for e in evidence:
        role = e.get("role", "")
        text = _esc(e.get("text", ""))[:400]
        is_match = e.get("is_match", False)

        role_style = {
            "user": "background:var(--orange-bg);color:var(--orange);",
            "assistant": "background:#ddf4ff;color:#0969da;",
            "system": "background:var(--surface-alt);color:var(--text-dim);",
        }.get(role, "background:var(--surface-alt);color:var(--text-dim);")

        highlight = "border-left:3px solid var(--brand-orange);padding-left:12px;" if is_match else ""

        turns.append(
            f'<div style="margin-bottom:8px;{highlight}">'
            f'<span style="display:inline-block;padding:1px 8px;border-radius:3px;'
            f'font-size:11px;font-weight:700;text-transform:uppercase;{role_style}">{_esc(role)}</span>'
            f'<div style="font-size:13px;color:var(--text-muted);margin-top:4px;'
            f'white-space:pre-wrap;word-break:break-word;line-height:1.5;">{text}</div>'
            f'</div>'
        )

    return (
        '<details style="margin:10px 0;">'
        '<summary style="cursor:pointer;font-size:13px;color:var(--brand-orange);font-weight:600;">'
        'View conversation context</summary>'
        f'<div style="background:var(--surface);border-radius:8px;padding:16px;margin-top:8px;'
        f'border:1px solid var(--border-light);">{"".join(turns)}</div>'
        '</details>'
    )


def _esc(t):
    return _html.escape(str(t)) if t else ""


def _score_color(score):
    if score >= 75:
        return "var(--green)"
    if score >= 50:
        return "var(--brand-orange)"
    return "var(--red)"


def _svg_ring(pct, color, size):
    r = (size - 10) / 2
    circ = 2 * 3.14159 * r
    offset = circ * (1 - pct / 100)
    return (
        f'<svg width="{size}" height="{size}" style="flex-shrink:0;">'
        f'<circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="8"/>'
        f'<circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none" stroke="{color}" stroke-width="8"'
        f' stroke-dasharray="{circ}" stroke-dashoffset="{offset}" stroke-linecap="round"'
        f' transform="rotate(-90 {size/2} {size/2})"/>'
        f'</svg>'
    )


def _status_card(label, value, dot):
    return (
        f'<div class="status-card">'
        f'<div class="status-dot dot-{dot}"></div>'
        f'<div><div class="status-card-label">{_esc(label)}</div>'
        f'<div class="status-card-value">{_esc(value)}</div></div></div>'
    )


def _rec_card(title, desc, priority, tags):
    tag_html = "".join(f'<span class="tag">{_esc(t)}</span>' for t in tags)
    tags_div = f'<div class="compliance-tags">{tag_html}</div>' if tags else ""
    return (
        f'<div class="rec-card"><div>'
        f'<div class="rec-title">{_esc(title)}</div>'
        f'<div class="rec-desc">{desc}</div>'
        f'{tags_div}'
        f'</div><span class="rec-priority priority-{priority}">{priority}</span></div>'
    )


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _cover(i):
    now = datetime.now(timezone.utc).strftime("%B %d, %Y")
    tool = _esc(i.tool_display_name or i.tool_name or "Unknown")
    period = _esc(i.scan_period)
    return (
        f'<div class="cover-bar"><div class="cover-inner">'
        f'<div class="cover-left">{_BRAND_LOGO}'
        f'<div><div class="cover-title">hb-scan</div>'
        f'<div class="cover-subtitle">AI Hygiene Report</div></div></div>'
        f'<div class="cover-right"><div>{period}</div>'
        f'<div><strong>{tool}</strong> &middot; {i.sessions_scanned} sessions</div>'
        f'<div>Generated {now}</div></div>'
        f'</div></div>'
    )


def _score_hero(i):
    gc = _score_color(i.score)
    hoi = round(1.0 - i.oversight.auto_pilot_rate, 2)
    total_findings = len([f for f in i.all_findings if not f.experimental])
    ring = _svg_ring(i.score, gc, 140)
    return (
        f'<div class="score-hero-wrap"><div class="score-hero">'
        f'<div class="score-ring-wrap">{ring}'
        f'<div class="score-ring-text">'
        f'<div class="score-ring-grade">{i.grade}</div>'
        f'<div class="score-ring-num">{i.score}/100</div></div></div>'
        f'<div class="score-stats">'
        f'<div class="score-stat"><div class="score-stat-val">{i.sessions_scanned}</div><div class="score-stat-label">Sessions</div></div>'
        f'<div class="score-stat"><div class="score-stat-val">{i.credentials.active_count}</div><div class="score-stat-label">Active Creds</div></div>'
        f'<div class="score-stat"><div class="score-stat-val">{total_findings}</div><div class="score-stat-label">Findings</div></div>'
        f'<div class="score-stat"><div class="score-stat-val">{hoi}</div><div class="score-stat-label">HOI Score</div></div>'
        f'<div class="score-stat"><div class="score-stat-val">{i.rules_active}</div><div class="score-stat-label">Rules Active</div></div>'
        f'</div></div></div>'
    )


def _quick_status(i):
    hoi = round(1.0 - i.oversight.auto_pilot_rate, 2)
    cards = [
        _status_card("Credentials", i.credentials.status_text,
                      "red" if i.credentials.active_count > 0 else ("orange" if i.credentials.total_unique > 0 else "green")),
        _status_card("Sensitive Data", "Clean" if i.sensitive_data.clean else f"{i.sensitive_data.finding_count} issue(s)",
                      "green" if i.sensitive_data.clean else "red"),
        _status_card("Code Security", "Clean" if i.code_security.clean else f"{i.code_security.finding_count} issue(s)",
                      "green" if i.code_security.clean else "orange"),
        _status_card("Commands", "Clean" if i.commands.clean else f"{i.commands.finding_count} issue(s)",
                      "green" if i.commands.clean else "orange"),
        _status_card("Packages", "Clean" if i.packages.clean else f"{i.packages.finding_count} issue(s)",
                      "green" if i.packages.clean else "orange"),
        _status_card("IP / Trade Secret", "Clean" if i.ip_leakage.clean else f"{i.ip_leakage.finding_count} issue(s)",
                      "green" if i.ip_leakage.clean else "red"),
        _status_card("Regulatory",
                      "LLM required" if i.rules_skipped_llm > 0 and i.regulatory.clean else
                      ("Clean" if i.regulatory.clean else f"{i.regulatory.finding_count} issue(s)"),
                      "grey" if i.rules_skipped_llm > 0 and i.regulatory.clean else
                      ("green" if i.regulatory.clean else "red")),
        _status_card("Oversight", f"HOI {hoi}",
                      "green" if hoi >= 0.9 else ("orange" if hoi >= 0.7 else "red")),
    ]
    return f'<div class="container"><div class="status-grid">{"".join(cards)}</div></div>'


def _credentials_section(i):
    creds = i.credentials
    badge = '<span class="section-badge badge-pass">Pass</span>' if creds.total_unique == 0 else '<span class="section-badge badge-fail">Attention</span>'

    if creds.total_unique == 0:
        return (
            f'<div class="container"><div class="section" id="credentials">'
            f'<div class="section-header"><h2>Credential Exposure</h2>{badge}</div>'
            f'<div class="callout callout-green">No credentials detected in your AI tool conversations.</div>'
            f'</div></div>'
        )

    rows = []
    for c in sorted(creds.credentials, key=lambda c: (c.is_expired, c.credential_type)):
        status = '<span class="sev-badge sev-high">Active</span>' if not c.is_expired else '<span class="sev-badge sev-low">Expired</span>'
        preview = _esc(c.redacted_preview[:60])
        evidence_html = _render_evidence(c.evidence) if c.evidence else ""
        rows.append(
            f'<tr><td>{_esc(c.credential_type)}</td><td>{status}</td>'
            f'<td><code style="font-size:12px;color:var(--text-muted);">{preview}</code></td>'
            f'<td>{c.first_seen or ""}</td></tr>'
        )
        if evidence_html:
            rows.append(f'<tr><td colspan="4" style="padding:0 12px 12px;">{evidence_html}</td></tr>')

    action = ""
    if creds.active_count > 0:
        action = (
            '<div class="remediation-block">'
            f'<strong>Action needed:</strong> {creds.active_count} credential(s) may still be active. '
            'Rotate them and use environment variables or a secrets manager.</div>'
        )

    return (
        f'<div class="container"><div class="section" id="credentials">'
        f'<div class="section-header"><h2>Credential Exposure</h2>{badge}</div>'
        f'<p class="section-desc">{creds.total_unique} unique credential(s) found.'
        f'{f" {creds.expired_count} expired." if creds.expired_count > 0 else ""}</p>'
        f'{action}'
        f'<table><thead><tr><th>Type</th><th>Status</th><th>Preview</th><th>First Seen</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
        f'<div class="section-refs">OWASP LLM02:2025 &middot; GitGuardian 2026 &middot; CIS Control 3</div>'
        f'</div></div>'
    )


def _section_card(title, anchor, section, desc, refs):
    badge = '<span class="section-badge badge-pass">Pass</span>' if section.clean else '<span class="section-badge badge-fail">Attention</span>'

    if section.clean:
        return (
            f'<div class="container"><div class="section" id="{anchor}">'
            f'<div class="section-header"><h2>{_esc(title)}</h2>{badge}</div>'
            f'<div class="callout callout-green">No issues detected. {_esc(desc)}</div>'
            f'<div class="section-refs">{_esc(refs)}</div></div></div>'
        )

    cards = []
    for f in section.findings[:8]:
        match_block = f'<div class="evidence-block">{_esc(f.match_context)}</div>' if f.match_context else ""
        evidence_block = _render_evidence(f.evidence) if f.evidence else ""
        mitigation = f'<div class="remediation-block"><strong>Fix:</strong> {_esc(f.mitigation)}</div>' if f.mitigation else ""
        ref_tags = "".join(f'<span class="tag">{_esc(r.get("standard", ""))}</span>' for r in f.references if r.get("standard"))
        tags_div = f'<div class="compliance-tags">{ref_tags}</div>' if ref_tags else ""
        cards.append(
            f'<div class="finding-card">'
            f'<div class="finding-title"><span class="sev-badge sev-{f.severity}">{f.severity}</span> {_esc(f.description)}</div>'
            f'<div class="finding-meta">Session: {f.session_id[:8]}... &middot; {_esc(f.project_path)}</div>'
            f'{match_block}{evidence_block}{mitigation}{tags_div}</div>'
        )

    more = f'<p style="color:var(--text-dim);font-size:13px;">...and {len(section.findings) - 8} more</p>' if len(section.findings) > 8 else ""
    return (
        f'<div class="container"><div class="section" id="{anchor}">'
        f'<div class="section-header"><h2>{_esc(title)}</h2>{badge}</div>'
        f'<p class="section-desc">{_esc(desc)}</p>'
        f'{"".join(cards)}{more}'
        f'<div class="section-refs">{_esc(refs)}</div></div></div>'
    )


def _regulatory_section(i):
    if i.regulatory.clean and i.rules_skipped_llm > 0:
        return (
            f'<div class="container"><div class="section" id="regulatory">'
            f'<div class="section-header"><h2>Regulatory Data</h2><span class="section-badge badge-info">LLM Required</span></div>'
            f'<div class="callout">Regulatory data detection (GDPR, HIPAA, SOX, attorney-client) requires semantic analysis. '
            f'Run <code>hb-scan --llm</code> with your own LLM endpoint to enable {i.rules_skipped_llm} additional rules.</div>'
            f'<div class="section-refs">GDPR Art. 5/6/28 &middot; HIPAA BAA &middot; ABA Opinion 512 &middot; SEC Rule 10b-5</div>'
            f'</div></div>'
        )
    return _section_card("Regulatory Data", "regulatory", i.regulatory,
        "GDPR personal data, HIPAA PHI, financial MNPI, attorney-client privilege.",
        "GDPR &middot; HIPAA &middot; SOX &middot; ABA Opinion 512")


def _oversight_section(i):
    ov = i.oversight
    hoi = round(1.0 - ov.auto_pilot_rate, 2)
    hoi_color = "var(--green)" if hoi >= 0.9 else ("var(--brand-orange)" if hoi >= 0.7 else "var(--red)")
    ring = _svg_ring(round(hoi * 100), hoi_color, 100)
    badge = f'<span class="section-badge {"badge-pass" if hoi >= 0.9 else "badge-fail"}">HOI {hoi}</span>'

    return (
        f'<div class="container"><div class="section" id="oversight">'
        f'<div class="section-header"><h2>Human Oversight Index</h2>{badge}</div>'
        f'<p class="section-desc">Measures how actively you supervise AI tool actions. 1.0 = full oversight. '
        f'Sessions with 50+ tool actions and &lt;3 user interactions are auto-pilot.</p>'
        f'<div class="hoi-hero"><div style="text-align:center;">{ring}'
        f'<div style="position:relative;top:-68px;font-size:28px;font-weight:800;color:{hoi_color};">{hoi}</div>'
        f'<div style="position:relative;top:-68px;" class="hoi-label">HOI</div></div>'
        f'<div style="flex:1;"><div style="display:flex;gap:40px;">'
        f'<div><div style="font-size:24px;font-weight:700;">{ov.total_sessions}</div><div class="hoi-label">Total Sessions</div></div>'
        f'<div><div style="font-size:24px;font-weight:700;">{ov.auto_pilot_sessions}</div><div class="hoi-label">Auto-pilot</div></div>'
        f'<div><div style="font-size:24px;font-weight:700;">{ov.total_sessions - ov.auto_pilot_sessions}</div><div class="hoi-label">Supervised</div></div>'
        f'</div></div></div>'
        f'<div class="callout">88% of accepted AI-generated code is retained without modification (GitHub/Accenture 2025). '
        f'EU AI Act Article 14 requires awareness of &ldquo;automation bias.&rdquo;</div>'
        f'<div class="section-refs">OWASP LLM09:2025 &middot; EU AI Act Art. 14 &middot; NIST AI RMF Measure 2.8</div>'
        f'</div></div>'
    )


def _compliance_section(frameworks):
    # Overview bars
    bars = []
    for fw in frameworks:
        pct = round(fw.alignment_score * 100)
        color = "var(--green)" if pct >= 80 else ("var(--brand-orange)" if pct >= 50 else "var(--red)")
        short = fw.framework_name.split(" — ")[0].split(" 2025")[0].split(" 2026")[0].split(" 2023")[0].split(" 2022")[0]
        bars.append(
            f'<div class="progress-bar"><div class="progress-label">{_esc(short)}</div>'
            f'<div class="progress-track"><div class="progress-fill" style="width:{max(pct,8)}%;background:{color};">{pct}%</div></div></div>'
        )

    # Framework detail cards
    fw_cards = []
    for fw in frameworks:
        pct = round(fw.alignment_score * 100)
        color = "var(--green)" if pct >= 80 else ("var(--brand-orange)" if pct >= 50 else "var(--red)")
        ring = _svg_ring(pct, color, 72)

        ctrl_rows = []
        for c in fw.controls:
            st = {"pass": ("\u2713", "var(--green)", "Pass"), "fail": ("\u2717", "var(--red)", "Fail"),
                  "partial": ("\u25d0", "var(--brand-orange)", "Partial"), "not_assessed": ("\u2014", "var(--text-dim)", "N/A")}
            icon, scolor, slabel = st.get(c.status, ("\u00b7", "var(--text-dim)", ""))
            ctrl_rows.append(
                f'<tr><td><code style="font-size:12px;">{_esc(c.control_id)}</code></td>'
                f'<td>{_esc(c.control_name)}</td>'
                f'<td style="color:{scolor};font-weight:600;text-align:center;">{icon} {slabel}</td>'
                f'<td style="font-size:12px;color:var(--text-muted);">{_esc(c.notes[:100])}</td></tr>'
            )

        short = fw.framework_name.split(" — ")[0]
        fw_cards.append(
            f'<div class="fw-card"><div class="fw-header">'
            f'<div style="position:relative;">{ring}'
            f'<div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:16px;font-weight:800;color:{color};">{pct}%</div></div>'
            f'<div><div class="fw-name">{_esc(short)}</div>'
            f'<div class="fw-meta">{fw.controls_passed} pass &middot; {fw.controls_failed} fail &middot; {fw.controls_partial} partial &middot; {fw.controls_not_assessed} N/A</div>'
            f'<a class="fw-url" href="{_esc(fw.url)}">{_esc(fw.url)}</a></div></div>'
            f'<table style="font-size:13px;"><thead><tr><th style="width:110px;">Control</th><th>Requirement</th>'
            f'<th style="width:90px;text-align:center;">Status</th><th>Action</th></tr></thead>'
            f'<tbody>{"".join(ctrl_rows)}</tbody></table></div>'
        )

    return (
        f'<div class="container"><div class="section" id="compliance">'
        f'<div class="section-header"><h2>Compliance Alignment</h2></div>'
        f'<p class="section-desc">Scan results mapped to international AI governance and security frameworks. '
        f'Alignment reflects how well your AI usage practices comply with each framework.</p>'
        f'<div style="background:var(--surface);border-radius:12px;padding:24px;margin-bottom:24px;border:1px solid var(--border-light);">'
        f'{"".join(bars)}</div>'
        f'{"".join(fw_cards)}</div></div>'
    )


def _recommendations(i, frameworks):
    recs = []

    if i.credentials.active_count > 0:
        recs.append(_rec_card(
            f"Rotate {i.credentials.active_count} active credential(s)",
            "Steps: 1) Identify each credential in the findings above. "
            "2) Rotate/regenerate each key in the provider's dashboard. "
            "3) Update your project to use environment variables: <code>export API_KEY=new_value</code>. "
            "4) For teams, use a secrets manager (AWS SSM, HashiCorp Vault, 1Password). "
            "5) Add .env to your AI tool's exclusion list to prevent future exposure.",
            "high", ["OWASP LLM02", "ISO 27001 A.5.14", "CIS Control 3"]))

    if not i.code_security.clean:
        recs.append(_rec_card(
            "Review AI-generated code before committing",
            "Steps: 1) Install a SAST tool: <code>pip install semgrep</code> or <code>pip install bandit</code>. "
            "2) Run it on changed files: <code>semgrep scan --config auto</code>. "
            "3) Add pre-commit hooks: <code>pre-commit install</code>. "
            "4) Review AI-generated code like a junior developer's PR.",
            "high", ["OWASP LLM05", "NIST SP 800-218A", "ISO 27001 A.8.28"]))

    if not i.sensitive_data.clean:
        recs.append(_rec_card(
            "Restrict sensitive file access in AI tools",
            "Steps: 1) Create a .claudeignore or equivalent exclusion file. "
            "2) Add patterns: <code>.env*, *.pem, credentials.json</code>. "
            "3) Use environment variables instead of credential files.",
            "high", ["ISO 42001 A.7", "MITRE AML.T0024", "CIS Control 3"]))

    if not i.ip_leakage.clean:
        recs.append(_rec_card(
            "Avoid sharing proprietary content with public AI tools",
            "Steps: 1) Use enterprise AI with data processing agreements. "
            "2) Update NDAs to address AI tool usage. "
            "3) Note: sharing trade secrets with AI may destroy legal protection under DTSA.",
            "high", ["DTSA 18 U.S.C. \u00a71836", "EU Trade Secrets Directive", "ISO 27001 A.5.14"]))

    if i.oversight.auto_pilot_rate > 0.1:
        recs.append(_rec_card(
            "Increase human oversight in AI sessions",
            "Steps: 1) Review AI actions before approving, especially file writes and commands. "
            "2) Break large tasks into smaller steps with review checkpoints. "
            "3) Remember: 88% of accepted AI code is retained without modification.",
            "medium", ["EU AI Act Art. 14", "NIST Measure 2.8", "ISO 42001 A.5"]))

    if i.rules_skipped_llm > 0:
        recs.append(_rec_card(
            "Enable deeper analysis with LLM judge",
            f"Steps: {i.rules_skipped_llm} rules for regulatory data detection (GDPR, HIPAA, SOX, "
            "attorney-client) require semantic analysis. This feature is coming in hb-scan v1.2. "
            "In the meantime: 1) Manually audit conversations with client data or financial information. "
            "2) Use enterprise AI tools with HIPAA BAAs or GDPR DPAs for regulated work. "
            "3) Watch for updates at github.com/humanbound/hb-scan.",
            "medium", ["GDPR Art. 5/6/28", "HIPAA BAA", "ABA Opinion 512"]))

    if not recs:
        recs.append(_rec_card(
            "Maintain current practices",
            "Your AI hygiene is strong. Run hb-scan regularly and keep credentials out of conversations.",
            "medium", []))

    return (
        f'<div class="container"><div class="section" id="recommendations">'
        f'<div class="section-header"><h2>Recommendations</h2></div>'
        f'<p class="section-desc">Prioritised actions mapped to compliance frameworks.</p>'
        f'{"".join(recs)}</div></div>'
    )


def _footer():
    try:
        from hb_scan import __version__
        v = __version__
    except Exception:
        v = "0.1.0"
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")
    return (
        f'<div class="footer-bar">Generated by '
        f'<a href="https://github.com/humanbound/hb-scan">hb-scan</a> v{v}'
        f' &middot; {now}<br>'
        f'For organisation-wide AI governance &rarr; <a href="https://humanbound.ai">humanbound.ai</a></div>'
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_html(insights: ScanInsights) -> str:
    """Generate a complete, self-contained HTML report."""
    from hb_scan.compliance import assess_compliance
    frameworks = assess_compliance(insights)

    parts = [
        _cover(insights),
        _score_hero(insights),
        _quick_status(insights),
        _credentials_section(insights),
        _section_card("Sensitive Data", "sensitive-data", insights.sensitive_data,
            "Sensitive files (SSH keys, cloud credentials, PII) shared with AI tools.",
            "OWASP LLM02 \u00b7 MITRE AML.T0024 \u00b7 ISO 42001 A.7"),
        _section_card("Code Security", "code-security", insights.code_security,
            "AI-generated code with known vulnerability patterns.",
            "OWASP LLM05 \u00b7 NIST SP 800-218A \u00b7 CSA 2025"),
        _section_card("Commands", "commands", insights.commands,
            "Dangerous or privileged commands executed through AI tools.",
            "OWASP LLM06 \u00b7 OWASP Agentic ASI02 \u00b7 SANS IDEsaster"),
        _section_card("Package Safety", "packages", insights.packages,
            "AI-suggested packages from unvetted or hallucinated sources.",
            "OWASP LLM03 \u00b7 ENISA Slopsquatting \u00b7 USENIX 2025"),
        _section_card("IP / Trade Secret", "ip-leakage", insights.ip_leakage,
            "Proprietary business information shared with AI tools.",
            "DTSA 18 U.S.C. \u00a71836 \u00b7 EU Trade Secrets Directive"),
        _regulatory_section(insights),
        _oversight_section(insights),
        _compliance_section(frameworks),
        _recommendations(insights, frameworks),
        _footer(),
    ]

    return (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
        '<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        '<title>hb-scan &mdash; AI Hygiene Report</title>\n'
        f'{_CSS}\n</head>\n<body>\n\n'
        + "\n".join(parts)
        + "\n\n</body>\n</html>"
    )
