"""Specialist review agents + lead synthesizer."""

from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    agent: str
    severity: str  # info | warn | critical
    title: str
    detail: str
    line: int | None = None


@dataclass
class ReviewResult:
    mode: str
    findings: list[Finding] = field(default_factory=list)
    comment_markdown: str = ""
    agent_notes: dict[str, str] = field(default_factory=dict)


def _iter_py_files(files: dict[str, str]) -> list[tuple[str, str]]:
    return [(p, c) for p, c in files.items() if p.endswith(".py")]


def security_agent(files: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        (r"\beval\s*\(", "critical", "Use of eval()", "Avoid eval on untrusted input (CWE-95)."),
        (r"\bexec\s*\(", "critical", "Use of exec()", "Dynamic execution is a code-injection risk."),
        (r"pickle\.loads\s*\(", "critical", "Unsafe pickle.loads", "Pickle can execute arbitrary code."),
        (r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True", "critical", "shell=True subprocess", "Shell injection risk."),
        (r"(api[_-]?key|secret|password)\s*=\s*['\"][^'\"]+['\"]", "warn", "Hardcoded secret", "Move secrets to environment variables."),
        (r"verify\s*=\s*False", "warn", "TLS verification disabled", "Do not disable TLS verification in production."),
    ]
    for path, content in files.items():
        for i, line in enumerate(content.splitlines(), 1):
            for pat, sev, title, detail in patterns:
                if re.search(pat, line, re.I):
                    findings.append(
                        Finding("security", sev, title, f"{detail} (`{path}`)", line=i)
                    )
    return findings


def performance_agent(files: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for path, content in _iter_py_files(files):
        # nested loops heuristic
        try:
            tree = ast.parse(content)
        except SyntaxError:
            findings.append(
                Finding("performance", "info", "Unparseable Python", f"Could not AST-parse `{path}`")
            )
            continue

        class Visitor(ast.NodeVisitor):
            def visit_For(self, node: ast.For) -> None:
                for child in ast.walk(node):
                    if child is not node and isinstance(child, (ast.For, ast.While)):
                        findings.append(
                            Finding(
                                "performance",
                                "warn",
                                "Nested loop",
                                f"Nested iteration in `{path}` — check algorithmic complexity.",
                                line=getattr(node, "lineno", None),
                            )
                        )
                        break
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call) -> None:
                # time.sleep in request path
                if isinstance(node.func, ast.Attribute) and node.func.attr == "sleep":
                    findings.append(
                        Finding(
                            "performance",
                            "warn",
                            "Blocking sleep",
                            f"`sleep` call in `{path}` may block request handlers.",
                            line=getattr(node, "lineno", None),
                        )
                    )
                self.generic_visit(node)

        Visitor().visit(tree)

        if re.search(r"SELECT\s+\*\s+FROM", content, re.I):
            findings.append(
                Finding(
                    "performance",
                    "info",
                    "SELECT * detected",
                    f"Prefer explicit columns in `{path}` for hot query paths.",
                )
            )
    return findings


def style_agent(files: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for path, content in files.items():
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            if len(line) > 120:
                findings.append(
                    Finding(
                        "style",
                        "info",
                        "Long line",
                        f"Line exceeds 120 chars in `{path}`.",
                        line=i,
                    )
                )
            if line.rstrip() != line and line.strip():
                findings.append(
                    Finding(
                        "style",
                        "info",
                        "Trailing whitespace",
                        f"`{path}` has trailing whitespace.",
                        line=i,
                    )
                )
        if path.endswith(".py") and "import *" in content:
            findings.append(
                Finding("style", "warn", "Wildcard import", f"Avoid `import *` in `{path}`.")
            )
        if path.endswith(".py") and not content.strip().endswith("\n") and content.strip():
            findings.append(
                Finding("style", "info", "Missing final newline", f"Add trailing newline in `{path}`.")
            )
    # de-dupe noisy style
    seen: set[tuple[str, str, int | None]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.title, f.detail, f.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique[:40]


def lead_reviewer(findings: list[Finding], pr_title: str, mode: str) -> str:
    order = {"critical": 0, "warn": 1, "info": 2}
    findings = sorted(findings, key=lambda f: (order.get(f.severity, 9), f.agent, f.title))
    counts = {k: sum(1 for f in findings if f.severity == k) for k in ("critical", "warn", "info")}

    lines = [
        f"## Agentic PR review — {pr_title}",
        "",
        f"_Mode: `{mode}` · Security / Performance / Style agents → Lead Reviewer_",
        "",
        f"**Summary:** {counts['critical']} critical · {counts['warn']} warnings · {counts['info']} info",
        "",
    ]
    if not findings:
        lines += ["No issues detected by the specialist agents.", ""]
    else:
        lines.append("| Severity | Agent | Finding | Detail |")
        lines.append("| --- | --- | --- | --- |")
        for f in findings[:30]:
            loc = f" L{f.line}" if f.line else ""
            detail = f.detail.replace("|", "\\|")
            lines.append(f"| `{f.severity}` | {f.agent} | {f.title}{loc} | {detail} |")
        lines.append("")

    if counts["critical"]:
        lines.append("**Recommendation:** Request changes — address critical findings before merge.")
    elif counts["warn"]:
        lines.append("**Recommendation:** Approve with comments — resolve warnings when practical.")
    else:
        lines.append("**Recommendation:** Approve — only informational notes.")

    lines += [
        "",
        "<details><summary>Agent responsibilities</summary>",
        "",
        "- **Security** — injection, secrets, unsafe deserialization",
        "- **Performance** — nested loops, blocking calls, heavy SQL patterns",
        "- **Style** — line length, imports, formatting hygiene",
        "- **Lead Reviewer** — severity rollup + merge guidance",
        "",
        "</details>",
    ]
    return "\n".join(lines)


def _openai_enrich(files: dict[str, str], base_comment: str) -> str:
    from openai import OpenAI

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    snippet = {k: v[:4000] for k, v in list(files.items())[:8]}
    resp = client.chat.completions.create(
        model=model,
        temperature=0.2,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are the Lead Reviewer agent. Given deterministic specialist findings "
                    "and file snippets, write a short executive paragraph (max 120 words) to "
                    "prepend to the review. Do not invent vulnerabilities not supported by the findings."
                ),
            },
            {
                "role": "user",
                "content": json.dumps({"findings_markdown": base_comment, "files": snippet}),
            },
        ],
    )
    preface = (resp.choices[0].message.content or "").strip()
    return f"{preface}\n\n{base_comment}"


def run_review(files: dict[str, str], pr_title: str = "Pull Request") -> ReviewResult:
    force_mock = os.getenv("FORCE_MOCK", "0") == "1"
    has_key = bool(os.getenv("OPENAI_API_KEY"))
    mode = "mock" if force_mock or not has_key else "openai"

    findings = security_agent(files) + performance_agent(files) + style_agent(files)
    comment = lead_reviewer(findings, pr_title, mode)
    notes = {
        "security": f"{sum(1 for f in findings if f.agent=='security')} findings",
        "performance": f"{sum(1 for f in findings if f.agent=='performance')} findings",
        "style": f"{sum(1 for f in findings if f.agent=='style')} findings",
    }

    if mode == "openai":
        try:
            comment = _openai_enrich(files, comment)
        except Exception as exc:  # noqa: BLE001
            mode = "mock-fallback"
            comment = f"> LLM enrich failed (`{exc}`); showing deterministic review.\n\n{comment}"

    return ReviewResult(mode=mode, findings=findings, comment_markdown=comment, agent_notes=notes)
