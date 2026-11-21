"""Render a recorded AI run (ai-run/<timestamp>/run.json) as a screenshot for the deck: header, question, the model's
verbatim answer table and its proposed searches with what each returned in the lab. Nothing in the answer is edited.

    python3 render_ai_run.py ai-run/<timestamp>
"""

import html
import json
import re
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).parent


def md_inline(text):
    text = html.escape(text)
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", text)


def table_html(md):
    rows = [r.strip().strip("|").split("|") for r in md.strip().splitlines() if r.strip().startswith("|")]
    rows = [r for r in rows if not set("".join(r)) <= set("-: ")]
    head, body = rows[0], rows[1:]
    out = ["<table><tr>" + "".join(f"<th>{md_inline(c.strip())}</th>" for c in head) + "</tr>"]
    for r in body:
        cells = [c.strip() for c in r]
        cls = {"Not detectable": "no", "Partial": "part", "Detectable": "yes"}.get(cells[1], "")
        out.append("<tr>" + "".join(f'<td class="{cls if i == 1 else ""}">{md_inline(c)}</td>' for i, c in enumerate(cells)) + "</tr>")
    return "\n".join(out) + "</table>"


def main(run_dir):
    run_dir = Path(run_dir)
    rec = json.loads((run_dir / "run.json").read_text())
    answer = rec["answer"]
    table_md = "\n".join(l for l in answer.splitlines() if l.strip().startswith("|"))
    checks = rec.get("proving_searches", [])
    check_rows = "".join(
        f"<tr><td><code>{html.escape(c['spl'])}</code></td><td class='n'>{c.get('row_count', '–')}</td></tr>" for c in checks)
    page = f"""<!doctype html><meta charset="utf-8"><style>
    body {{ margin:0; background:#0b1a2e; color:#e6eaef; font:15px/1.35 -apple-system, 'Helvetica Neue', sans-serif; width:1500px; }}
    .wrap {{ padding:22px 26px; }}
    .bar {{ font:13px Menlo, monospace; color:#8fa3b8; border-bottom:1px solid #2a3d55; padding-bottom:10px; margin-bottom:12px; }}
    .bar b {{ color:#02c8ff; font-weight:500; }}
    .q {{ font-size:18px; margin:6px 0 14px; }} .q span {{ color:#02c8ff; }}
    table {{ border-collapse:collapse; width:100%; margin-bottom:14px; }}
    th {{ text-align:left; font-weight:500; color:#8fa3b8; font-size:12px; text-transform:uppercase; letter-spacing:.04em; padding:6px 8px; border-bottom:1px solid #2a3d55; }}
    td {{ vertical-align:top; padding:7px 8px; border-bottom:1px solid #1d3048; font-size:13.5px; }}
    td:first-child {{ width:23%; }} td:nth-child(2) {{ width:10%; font-weight:600; white-space:nowrap; }}
    td.no {{ color:#eb4651; }} td.part {{ color:#ff9000; }} td.yes {{ color:#45991f; }}
    code {{ font:12.5px Menlo, monospace; color:#ffb866; }}
    h3 {{ font-size:12px; color:#8fa3b8; text-transform:uppercase; letter-spacing:.04em; font-weight:500; margin:6px 0; }}
    td.n {{ text-align:right; width:12%; font:13px Menlo, monospace; }}
    </style><div class="wrap">
    <div class="bar">$ python3 ai_readiness_run.py &nbsp;·&nbsp; model <b>{rec['model']}</b> via Ollama {rec.get('ollama_version', '')}, on this laptop
    &nbsp;·&nbsp; temperature 0 &nbsp;·&nbsp; {rec['generation_seconds']:.0f} s &nbsp;·&nbsp; input: {len(rec['evidence'])} read-only lab searches &nbsp;·&nbsp; {rec['started'].replace('_', ' ')}</div>
    <div class="q"><span>Q:</span> Based on the telemetry in this Splunk environment, which AA26-281A behaviours can we detect, which can't we, and why?</div>
    <h3>Model answer, verbatim</h3>
    {table_html(table_md)}
    <h3>Searches the model proposed, run back against the lab</h3>
    <table><tr><th>Proposed SPL (verbatim)</th><th style="text-align:right">Rows</th></tr>{check_rows}</table>
    </div>"""
    out = HERE / "screenshots" / "ai_local_run.png"
    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome")
        pg = b.new_page(viewport={"width": 1500, "height": 900}, device_scale_factor=2)
        pg.set_content(page)
        pg.locator("body").screenshot(path=str(out))
        b.close()
    print(out)


if __name__ == "__main__":
    main(sys.argv[1])
