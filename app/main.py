"""FastAPI — multi-agent PR review service."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from app.agents import run_review

load_dotenv()

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "sample_pr"

app = FastAPI(
    title="PR Review Agents",
    description="Multi-agent GitHub PR reviewer (Security, Performance, Style, Lead).",
    version="1.0.0",
)


class ReviewRequest(BaseModel):
    title: str = "Sample PR"
    files: dict[str, str] = Field(
        ...,
        description="Map of filepath → file content",
        examples=[{"app.py": "password = 'secret'\nfor i in range(10):\n    for j in range(10):\n        print(i*j)\n"}],
    )


def _load_sample_files() -> dict[str, str]:
    files: dict[str, str] = {}
    if SAMPLE.exists():
        for p in SAMPLE.rglob("*"):
            if p.is_file():
                files[str(p.relative_to(SAMPLE))] = p.read_text(encoding="utf-8", errors="replace")
    return files


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(
        """<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>PR Review Agents</title>
<style>
:root{--void:#090d10;--panel:#131921;--mist:#e1e6ef;--muted:#929db0;--line:#29313b;--signal:#53e2cb;--ember:#e5b477}
body{margin:0;font-family:IBM Plex Sans,Segoe UI,sans-serif;background:var(--void);color:var(--mist);line-height:1.6}
.shell{width:min(880px,calc(100% - 2rem));margin:0 auto;padding:2.5rem 0 4rem}
.kicker{font-family:ui-monospace,monospace;font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--signal)}
h1{letter-spacing:-.03em} .lead{color:var(--muted);max-width:60ch}
.panel{margin-top:1.2rem;padding:1.1rem;border:1px solid var(--line);border-radius:4px;background:var(--panel)}
button{border:1px solid var(--signal);background:var(--signal);color:#06241d;font-weight:600;border-radius:4px;padding:.65rem 1rem;cursor:pointer}
pre{white-space:pre-wrap;font-family:ui-monospace,monospace;font-size:13px;color:#c7d0de}
a{color:var(--signal)}
</style></head>
<body><div class="shell">
<p class="kicker">Multi-agent · GitHub PR · LangGraph-style roles</p>
<h1>PR Review Agents</h1>
<p class="lead">Security, Performance, and Style agents analyze a pull request. The Lead Reviewer synthesizes one actionable comment.</p>
<div class="panel">
<button id="btn">Review sample PR</button>
<pre id="out">Click the button to run the agent team on /sample_pr.</pre>
</div>
<p><a href="/docs">OpenAPI docs</a> · <a href="https://github.com/VagishSharma01/pr-review-agents">GitHub</a></p>
</div>
<script>
document.getElementById('btn').onclick = async () => {
  const out = document.getElementById('out');
  out.textContent = 'Agents running…';
  const res = await fetch('/api/review/sample', {method:'POST'});
  const data = await res.json();
  out.textContent = data.comment_markdown || JSON.stringify(data,null,2);
};
</script>
</body></html>"""
    )


@app.get("/health")
async def health():
    return {
        "ok": True,
        "mode": "mock" if os.getenv("FORCE_MOCK") == "1" or not os.getenv("OPENAI_API_KEY") else "openai",
    }


@app.post("/api/review")
async def review(body: ReviewRequest):
    result = run_review(body.files, body.title)
    return {
        "mode": result.mode,
        "agent_notes": result.agent_notes,
        "findings": [f.__dict__ for f in result.findings],
        "comment_markdown": result.comment_markdown,
    }


@app.post("/api/review/sample")
async def review_sample():
    files = _load_sample_files()
    if not files:
        raise HTTPException(500, "sample_pr/ is empty")
    result = run_review(files, "Sample insecure PR")
    return {
        "mode": result.mode,
        "agent_notes": result.agent_notes,
        "findings": [f.__dict__ for f in result.findings],
        "comment_markdown": result.comment_markdown,
    }


@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
):
    """Optional GitHub webhook — reviews PR opened/synchronize when token configured."""
    raw = await request.body()
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if secret:
        if not x_hub_signature_256:
            raise HTTPException(401, "missing signature")
        digest = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        expected = f"sha256={digest}"
        if not hmac.compare_digest(expected, x_hub_signature_256):
            raise HTTPException(401, "bad signature")

    if x_github_event not in {"pull_request", "ping"}:
        return {"ignored": True, "event": x_github_event}

    payload = json.loads(raw.decode() or "{}")
    if x_github_event == "ping":
        return {"ok": True, "zen": payload.get("zen")}

    action = payload.get("action")
    if action not in {"opened", "synchronize", "reopened"}:
        return {"ignored": True, "action": action}

    pr = payload["pull_request"]
    repo = payload["repository"]["full_name"]
    number = pr["number"]
    title = pr.get("title") or f"PR #{number}"
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        # Still run against empty fileset message — caller can use /api/review locally
        return JSONResponse(
            {
                "ok": False,
                "error": "GITHUB_TOKEN not set — cannot fetch PR files. Use /api/review with file contents.",
                "pr": f"{repo}#{number}",
            },
            status_code=200,
        )

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "pr-review-agents",
    }
    async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
        files_resp = await client.get(
            f"https://api.github.com/repos/{repo}/pulls/{number}/files"
        )
        files_resp.raise_for_status()
        files: dict[str, str] = {}
        for item in files_resp.json()[:20]:
            if item.get("status") == "removed":
                continue
            raw_url = item.get("raw_url") or item.get("contents_url")
            if not raw_url:
                continue
            # contents_url needs accept raw — prefer raw_url
            if "raw_url" in item and item["raw_url"]:
                fr = await client.get(item["raw_url"])
            else:
                continue
            if fr.status_code == 200:
                files[item["filename"]] = fr.text

        result = run_review(files, title)
        comment_resp = await client.post(
            f"https://api.github.com/repos/{repo}/issues/{number}/comments",
            json={"body": result.comment_markdown},
        )
        comment_resp.raise_for_status()

    return {"ok": True, "mode": result.mode, "findings": len(result.findings), "pr": f"{repo}#{number}"}
