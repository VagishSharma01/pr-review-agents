#!/usr/bin/env python3
"""Review local files or the bundled sample_pr/."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from app.agents import run_review  # noqa: E402


def load_dir(path: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for p in path.rglob("*"):
        if p.is_file():
            files[str(p.relative_to(path))] = p.read_text(encoding="utf-8", errors="replace")
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description="PR Review Agents CLI")
    parser.add_argument("--path", type=Path, default=ROOT / "sample_pr")
    parser.add_argument("--title", default="Local review")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    files = load_dir(args.path)
    result = run_review(files, args.title)
    if args.json:
        print(
            json.dumps(
                {
                    "mode": result.mode,
                    "agent_notes": result.agent_notes,
                    "findings": [f.__dict__ for f in result.findings],
                    "comment_markdown": result.comment_markdown,
                },
                indent=2,
            )
        )
    else:
        print(result.comment_markdown)


if __name__ == "__main__":
    main()