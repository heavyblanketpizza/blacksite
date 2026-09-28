"""The solution Blacksite hands back: Markdown, a self-contained HTML report, and a manifest.

The HTML opens offline in any browser on any OS (no scripts, no external files) and
quotes each cited log line, so the reader can check the guide without the sandbox,
which is wiped after export.
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .agent.guide import parse_reference
from .evidence.store import Evidence, EvidenceError
from .keys import group

EXCERPT_CONTEXT = 2
EXCERPT_MAX_LINES = 14

LABELS = {
    "en": {
        "title": "Blacksite solution", "confidence": "Confidence", "summary": "Summary", "root": "Root cause",
        "evidence": "Evidence", "steps": "Steps", "expected": "Expected", "undo": "Undo", "verify": "Verify",
        "unknowns": "Still unknown", "security": "Security notes", "checks": "Automatic checks",
        "excerpts": "Cited log lines", "source": "Source", "generated": "Generated", "model": "Model",
        "files": "Evidence files", "note": "Written offline by a local model. Commands were checked by code for "
        "risk; read every step before running it.",
        "read-only": "read-only", "low": "low", "high": "high",
        "conf-high": "high", "conf-medium": "medium", "conf-low": "low",
        "signed": "Signed by Blacksite key {fingerprint}. Check this folder with: blacksite verify <folder>",
    },
    "ko": {
        "title": "Blacksite 해결 가이드", "confidence": "신뢰도", "summary": "요약", "root": "근본 원인",
        "evidence": "증거", "steps": "단계", "expected": "예상 결과", "undo": "되돌리기", "verify": "확인",
        "unknowns": "아직 모르는 것", "security": "보안 참고", "checks": "자동 검사",
        "excerpts": "인용한 로그 줄", "source": "출처", "generated": "작성 시각", "model": "모델",
        "files": "증거 파일", "note": "로컬 모델이 오프라인으로 작성했습니다. 명령의 위험도는 코드로 검사했지만, "
        "실행하기 전에 모든 단계를 읽어 보세요.",
        "read-only": "읽기 전용", "low": "낮음", "high": "높음",
        "conf-high": "높음", "conf-medium": "보통", "conf-low": "낮음",
        "signed": "Blacksite 키 {fingerprint}로 서명했습니다. 이 폴더는 다음 명령으로 확인하세요: blacksite verify <폴더>",
    },
}

# Day: ink on grey-white paper, as in the web demo. Night: Tokyo Night. Chosen by the reader's system setting.
_CSS = """
:root{--bg:#fafafa;--panel:#efeff0;--ink:#161616;--text:#161616;--muted:#454547;--rule:#d0d0d3;
--accent:#3760bf;--ok:#436028;--warn:#834d00;--bad:#ad3139;--code:#161616;--code-ink:#ececec;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#1a1b26;--panel:#16161e;--ink:#7aa2f7;--text:#c0caf5;
--muted:#9aa5ce;--rule:#292e42;--accent:#7aa2f7;--ok:#9ece6a;--warn:#e0af68;--bad:#f7768e;--code:#0f0f14;
--code-ink:#c0caf5;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Apple SD Gothic Neo","Malgun Gothic",
"Noto Sans KR",sans-serif;padding:32px 20px}
main{max-width:860px;margin:0 auto}:lang(ko) main{word-break:keep-all}
h1{color:var(--ink);font-size:26px;line-height:1.25;margin:4px 0 10px}
h2{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:28px 0 10px;
border-bottom:1px solid var(--rule);padding-bottom:6px}
h3{font-size:16px;margin:0 0 6px}
.kicker{color:var(--muted);font-size:13px}
.badge{display:inline-block;font-size:12px;font-weight:700;border-radius:5px;padding:1px 8px;border:1px solid}
.read-only,.ok{color:var(--ok)}.low,.warn{color:var(--warn)}.high,.error{color:var(--bad)}
code,pre{font-family:ui-monospace,"SF Mono",Menlo,Consolas,"Cascadia Mono","D2Coding",monospace}
code{font-size:13px}
pre{background:var(--code);color:var(--code-ink);border-radius:8px;padding:12px 14px;overflow-x:auto;
font-size:13px;line-height:1.5;margin:8px 0}
.step{display:grid;grid-template-columns:32px minmax(0,1fr);gap:10px;margin:0 0 18px}
.num{width:28px;height:28px;border-radius:50%;background:var(--ink);color:var(--bg);display:grid;
place-items:center;font-weight:700}
.num.high{background:var(--bad)}
dl{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:2px 12px;margin:6px 0 0}
dt{color:var(--muted);font-size:13px}dd{margin:0;min-width:0;overflow-wrap:anywhere}
ul{padding-left:20px}li{margin:3px 0}
.panel{background:var(--panel);border:1px solid var(--rule);border-radius:10px;padding:14px 16px}
.security{border-color:var(--bad)}
.excerpt{margin:0 0 14px}.excerpt b{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.focus{color:var(--warn)}
footer{margin-top:36px;color:var(--muted);font-size:13px}
@media print{body{background:#fff;color:#000}pre{background:#f4f4f4;color:#000}}
"""


def build_solution(evidence: Evidence, guide_event: dict[str, Any], language: str,
                   source: dict[str, Any] | None, model: str, provenance: dict[str, Any] | None = None,
                   public_pem: bytes | None = None, anchor: dict[str, Any] | None = None) -> dict[str, str]:
    """Files for the solution folder: guide.md, guide.html, manifest.json, and, when the guide
    is signed, provenance.json, the public key, and the ledger anchor that ``blacksite verify`` checks."""
    label = LABELS.get(language, LABELS["en"])
    guide = guide_event["guide"]
    checks = guide_event.get("checks", [])
    excerpts = _excerpts(evidence, [item["ref"] for item in guide["evidence"]])
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")

    markdown = guide_event.get("markdown", "").rstrip() + "\n"
    if excerpts:
        markdown += f"\n## {label['excerpts']}\n"
        for ref, lines in excerpts:
            body = "\n".join(f"{number:>6}{'>' if focus else ' '} {text}" for number, text, focus in lines)
            markdown += f"\n`{ref}`\n\n```text\n{body}\n```\n"

    manifest = {
        "generator": f"blacksite {__version__}",
        "generated_at": generated,
        "model": model,
        "language": language,
        "incident": {"title": evidence.incident.title, "description": evidence.incident.description},
        "source": {key: source[key] for key in ("drive_label", "bundle", "imported_at") if key in source} if source else None,
        "evidence_files": (source or {}).get("files", []),
        "checks": checks,
        "guide": guide,
    }
    signed = None
    if provenance is not None and public_pem is not None:
        signed = label["signed"].format(fingerprint=group(provenance["key_id"]))
    files = {
        "guide.md": markdown,
        "guide.html": _html(guide, checks, excerpts, label, language, generated, model, source, signed),
        "manifest.json": json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
    }
    if signed is not None:
        files["provenance.json"] = json.dumps(provenance, ensure_ascii=False, indent=2) + "\n"
        files["blacksite-signing-key.pub"] = public_pem.decode("ascii")
        if anchor is not None:
            files["ledger-anchor.json"] = json.dumps(anchor, indent=2) + "\n"
    return files


def _excerpts(evidence: Evidence, refs: list[str]) -> list[tuple[str, list[tuple[int, str, bool]]]]:
    found = []
    for ref in dict.fromkeys(refs):
        parsed = parse_reference(ref)
        if parsed is None:
            continue
        file, spans = parsed
        first, last = spans[0][0], min(spans[0][1], spans[0][0] + EXCERPT_MAX_LINES)
        try:
            rows = evidence.read_lines(file, max(1, first - EXCERPT_CONTEXT), last + EXCERPT_CONTEXT)
        except EvidenceError:
            continue  # a runbook citation, not a log line
        focus = {n for start, end in spans for n in range(start, end + 1)}
        found.append((ref, [(row.line_no, row.text, row.line_no in focus) for row in rows]))
    return found


_CODE = re.compile(r"`([^`\n]+)`")
_BOLD = re.compile(r"\*\*([^*\n]+)\*\*")


def _inline(text: str) -> str:
    """Escape, then show `code` and **bold** the way the model wrote them."""
    return _BOLD.sub(r"<strong>\1</strong>", _CODE.sub(r"<code>\1</code>", html.escape(text)))


def _html(guide: dict[str, Any], checks: list[dict[str, Any]], excerpts: list[Any], label: dict[str, str],
          language: str, generated: str, model: str, source: dict[str, Any] | None, signed: str | None = None) -> str:
    e = html.escape
    i = _inline
    parts = [f'<!doctype html><html lang="{e(language)}"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             f"<title>{e(guide['title'])}</title><style>{_CSS}</style></head><body><main>",
             f'<div class="kicker">{e(label["title"])} · {e(label["confidence"])}: '
             f'{e(label.get("conf-" + guide["confidence"], guide["confidence"]))}</div>',
             f"<h1>{e(guide['title'])}</h1><p>{i(guide['summary'])}</p>",
             f'<h2>{e(label["root"])}</h2><p>{i(guide["root_cause"])}</p>',
             f'<h2>{e(label["evidence"])}</h2><ul>']
    parts += [f"<li><code>{e(item['ref'])}</code> — {i(item['shows'])}</li>" for item in guide["evidence"]]
    parts.append(f'</ul><h2>{e(label["steps"])}</h2>')
    for number, step in enumerate(guide["steps"], 1):
        risk = step["risk"]
        parts.append(f'<div class="step"><div class="num {"high" if risk == "high" else ""}">{number}</div><div>'
                     f'<h3>{e(step["title"])} <span class="badge {e(risk)}">{e(label.get(risk, risk))}</span></h3>'
                     f'<div>{i(step["why"])}</div>')
        if step["commands"]:
            parts.append(f"<pre>{e(chr(10).join(step['commands']))}</pre>")
        parts.append(f'<dl><dt>{e(label["expected"])}</dt><dd>{i(step["expected"])}</dd>')
        if step.get("rollback"):
            parts.append(f'<dt>{e(label["undo"])}</dt><dd>{i(step["rollback"])}</dd>')
        parts.append("</dl></div></div>")
    for key, items, css in (("verify", guide["verify"], ""), ("unknowns", guide["unknowns"], ""),
                            ("security", guide["security_notes"], " security")):
        if items:
            parts.append(f'<h2>{e(label[key])}</h2><div class="panel{css}"><ul>')
            parts += [f"<li>{i(item)}</li>" for item in items]
            parts.append("</ul></div>")
    if checks:
        parts.append(f'<h2>{e(label["checks"])}</h2><ul>')
        parts += [f'<li class="{e(check["level"])}">{e(check["text"])}</li>' for check in checks]
        parts.append("</ul>")
    if excerpts:
        parts.append(f'<h2>{e(label["excerpts"])}</h2>')
        for ref, lines in excerpts:
            body = "\n".join(
                f'<span class="{"focus" if focus else ""}">{number:>6}{"&gt;" if focus else " "} {e(text)}</span>'
                for number, text, focus in lines)
            parts.append(f'<div class="excerpt"><b>{e(ref)}</b><pre>{body}</pre></div>')
    origin = f" · {e(label['source'])}: {e(source['drive_label'])}/{e(source['bundle'])}" if source else ""
    parts.append(f'<footer>{e(label["note"])}<br>{e(label["generated"])}: {e(generated)} · '
                 f'{e(label["model"])}: {e(model)}{origin}'
                 f'{"<br>" + e(signed) if signed else ""}</footer></main></body></html>')
    return "".join(parts)
